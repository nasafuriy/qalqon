// Package probe fetches one HTTP response from a target and renders it as
// plain text parts that templates can match against.
//
// Scope is deliberately narrow. One GET per target, no path guessing, no
// authentication attempts, no payloads — the same request a browser would make
// when you type the address. That is enough to audit security headers, cookie
// flags and TLS posture on infrastructure you run, and it is not enough to be
// useful for probing someone else's.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nasafuriy/qalqon/internal/template"
)

// Options controls a probe.
type Options struct {
	Timeout      time.Duration
	MaxBody      int64
	UserAgent    string
	MaxRedirects int
}

// Defaults used when Options leaves a field empty.
const (
	DefaultTimeout   = 10 * time.Second
	DefaultMaxBody   = 1 << 20
	DefaultUserAgent = "qalqon (+https://github.com/nasafuriy/qalqon)"
	DefaultRedirects = 5
)

// Result is one probed target rendered into matchable parts.
type Result struct {
	Target   string
	FinalURL string
	Status   int
	Parts    map[string][]byte
	// TLSVerified is false when the certificate chain did not validate; the
	// probe still completes so the template can report why.
	TLSVerified bool
	VerifyError string
}

// Fetch performs a single GET against target.
//
// Only http and https are accepted. A bare host is treated as https.
func Fetch(ctx context.Context, target string, opts Options) (*Result, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = DefaultMaxBody
	}
	if opts.UserAgent == "" {
		opts.UserAgent = DefaultUserAgent
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = DefaultRedirects
	}

	parsed, err := normalise(target)
	if err != nil {
		return nil, err
	}

	// First attempt verifies the chain. If that is the only thing that fails,
	// retry without verification so the report can say what is wrong with it.
	result, err := do(ctx, parsed, opts, false)
	if err != nil && isTLSVerifyError(err) {
		// Keep the original reason: the retry succeeds, so its own error is nil.
		verifyErr := err
		result, err = do(ctx, parsed, opts, true)
		if result != nil {
			result.TLSVerified = false
			result.VerifyError = verifyReason(verifyErr)
		}
	}
	if err != nil && result == nil {
		return nil, err
	}
	return result, nil
}

func normalise(target string) (*url.URL, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return nil, fmt.Errorf("empty target")
	}
	if !strings.Contains(t, "://") {
		t = "https://" + t
	}

	parsed, err := url.Parse(t)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", target, err)
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("%s: only http and https targets are supported", target)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%s: no host in target", target)
	}
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return parsed, nil
}

func do(ctx context.Context, target *url.URL, opts Options, skipVerify bool) (*Result, error) {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: skipVerify}, //nolint:gosec // deliberate, see Fetch
		DisableCompression:  false,
		MaxIdleConnsPerHost: 1,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= opts.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBody))

	result := &Result{
		Target:      target.String(),
		FinalURL:    resp.Request.URL.String(),
		Status:      resp.StatusCode,
		TLSVerified: true,
		Parts: map[string][]byte{
			template.PartHeader: renderHeaders(resp),
			template.PartBody:   body,
			template.PartStatus: []byte(fmt.Sprintf("%d", resp.StatusCode)),
			template.PartURL:    []byte(resp.Request.URL.String()),
			template.PartTLS:    renderTLS(resp.TLS, resp.Request.URL.Hostname()),
		},
	}
	return result, nil
}

// renderHeaders produces one canonical "Name: value" line per header value,
// sorted so template patterns behave the same run to run.
func renderHeaders(resp *http.Response) []byte {
	var lines []string
	for name, values := range resp.Header {
		for _, v := range values {
			lines = append(lines, name+": "+v)
		}
	}
	sort.Strings(lines)

	var b strings.Builder
	b.WriteString(resp.Proto + " " + resp.Status + "\n")
	for _, line := range lines {
		b.WriteString(line)
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// renderTLS flattens the connection state into keys a template can match.
// Time comparisons are done here, because a regex cannot compare dates.
func renderTLS(state *tls.ConnectionState, hostname string) []byte {
	if state == nil {
		return []byte("tls: none\nencrypted: false\n")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "tls: yes\nencrypted: true\n")
	fmt.Fprintf(&b, "version: %s\n", tlsVersion(state.Version))
	fmt.Fprintf(&b, "cipher: %s\n", tls.CipherSuiteName(state.CipherSuite))

	if len(state.PeerCertificates) == 0 {
		return []byte(b.String())
	}
	leaf := state.PeerCertificates[0]

	fmt.Fprintf(&b, "subject: %s\n", leaf.Subject.CommonName)
	fmt.Fprintf(&b, "issuer: %s\n", leaf.Issuer.CommonName)
	fmt.Fprintf(&b, "not_before: %s\n", leaf.NotBefore.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "not_after: %s\n", leaf.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "san: %s\n", strings.Join(leaf.DNSNames, ", "))
	fmt.Fprintf(&b, "signature_algorithm: %s\n", leaf.SignatureAlgorithm)
	fmt.Fprintf(&b, "key_bits: %d\n", keyBits(leaf))

	days := int(time.Until(leaf.NotAfter).Hours() / 24)
	fmt.Fprintf(&b, "days_remaining: %d\n", days)
	fmt.Fprintf(&b, "expired: %t\n", days < 0)
	fmt.Fprintf(&b, "expires_within_7d: %t\n", days >= 0 && days < 7)
	fmt.Fprintf(&b, "expires_within_30d: %t\n", days >= 0 && days < 30)

	selfSigned := leaf.Issuer.String() == leaf.Subject.String()
	fmt.Fprintf(&b, "self_signed: %t\n", selfSigned)

	mismatch := hostname != "" && leaf.VerifyHostname(hostname) != nil
	fmt.Fprintf(&b, "hostname_mismatch: %t\n", mismatch)

	return []byte(b.String())
}

func keyBits(cert *x509.Certificate) int {
	type sized interface{ Size() int }
	if k, ok := cert.PublicKey.(sized); ok {
		return k.Size() * 8
	}
	return 0
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

func isTLSVerifyError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "x509:") ||
		strings.Contains(msg, "certificate") ||
		strings.Contains(msg, "tls: failed to verify")
}

func verifyReason(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if i := strings.Index(msg, "x509:"); i >= 0 {
		return msg[i:]
	}
	return msg
}
