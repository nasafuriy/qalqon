package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// A connection reports the version it negotiated, which is the best both
// sides could agree on — not the worst the server would accept. A host that
// speaks TLS 1.3 to a current client may still accept TLS 1.0 from an old
// one, and that is the version an attacker will ask for.
//
// The only way to know is to ask for each version in turn.

// VersionSupport records which protocol versions a host accepted.
type VersionSupport struct {
	TLS10, TLS11, TLS12, TLS13 bool
	// Weakest is the lowest version that completed a handshake.
	Weakest string
	// Checked is false when the sweep did not run or could not connect.
	Checked bool
}

var probedVersions = []struct {
	id    uint16
	label string
}{
	{tls.VersionTLS10, "TLS 1.0"},
	{tls.VersionTLS11, "TLS 1.1"},
	{tls.VersionTLS12, "TLS 1.2"},
	{tls.VersionTLS13, "TLS 1.3"},
}

// CheckVersions handshakes once per protocol version and reports which ones
// the host accepted.
//
// Nothing is sent beyond the handshake itself, and the certificate is not
// verified here: the question is which protocol the server agrees to speak,
// and a self-signed certificate answers it just as well as a valid one.
func CheckVersions(ctx context.Context, address, hostname string, timeout time.Duration) VersionSupport {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var (
		mu  sync.Mutex
		out VersionSupport
		wg  sync.WaitGroup
	)

	for _, v := range probedVersions {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()
			if !handshakes(ctx, address, hostname, id, timeout) {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			switch id {
			case tls.VersionTLS10:
				out.TLS10 = true
			case tls.VersionTLS11:
				out.TLS11 = true
			case tls.VersionTLS12:
				out.TLS12 = true
			case tls.VersionTLS13:
				out.TLS13 = true
			}
		}(v.id)
	}
	wg.Wait()

	for _, v := range probedVersions {
		if (v.id == tls.VersionTLS10 && out.TLS10) ||
			(v.id == tls.VersionTLS11 && out.TLS11) ||
			(v.id == tls.VersionTLS12 && out.TLS12) ||
			(v.id == tls.VersionTLS13 && out.TLS13) {
			out.Weakest = v.label
			break
		}
	}
	out.Checked = out.Weakest != ""
	return out
}

// handshakes reports whether the host completes a handshake pinned to one
// protocol version.
func handshakes(ctx context.Context, address, hostname string, version uint16, timeout time.Duration) bool {
	cfg := &tls.Config{
		// Not a trust decision: we are asking which protocol the server
		// agrees to, and an untrusted certificate answers that too. What is
		// wrong with the certificate is reported separately.
		InsecureSkipVerify: true, //nolint:gosec // version probe, not verification
		MinVersion:         version,
		MaxVersion:         version,
		ServerName:         hostname,
	}
	// Go removed the ciphers for TLS 1.0 and 1.1 from its defaults, so a
	// handshake pinned to them fails for the wrong reason unless the old
	// suites are offered explicitly.
	if version <= tls.VersionTLS11 {
		cfg.CipherSuites = legacyCipherSuites()
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    cfg,
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// legacyCipherSuites lists what a TLS 1.0 or 1.1 server is likely to offer.
// Go marks these insecure and leaves them out of the default list, which is
// the right default for a client and the wrong one for a scanner whose job
// is to report that the server still accepts them.
func legacyCipherSuites() []uint16 {
	var out []uint16
	for _, s := range tls.CipherSuites() {
		out = append(out, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() { //nolint:gosec // deliberately reaching old servers
		out = append(out, s.ID)
	}
	return out
}

// Render writes the sweep as keys a template can match.
func (v VersionSupport) Render() string {
	if !v.Checked {
		return "versions_checked: false\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "versions_checked: true\n")
	fmt.Fprintf(&b, "supports_tls10: %t\n", v.TLS10)
	fmt.Fprintf(&b, "supports_tls11: %t\n", v.TLS11)
	fmt.Fprintf(&b, "supports_tls12: %t\n", v.TLS12)
	fmt.Fprintf(&b, "supports_tls13: %t\n", v.TLS13)
	fmt.Fprintf(&b, "weakest_version: %s\n", v.Weakest)
	fmt.Fprintf(&b, "accepts_obsolete_tls: %t\n", v.TLS10 || v.TLS11)
	fmt.Fprintf(&b, "supported_versions: %s\n", strings.Join(v.List(), ", "))
	return b.String()
}

// List returns the accepted versions, oldest first.
func (v VersionSupport) List() []string {
	var out []string
	if v.TLS10 {
		out = append(out, "TLS 1.0")
	}
	if v.TLS11 {
		out = append(out, "TLS 1.1")
	}
	if v.TLS12 {
		out = append(out, "TLS 1.2")
	}
	if v.TLS13 {
		out = append(out, "TLS 1.3")
	}
	sort.Strings(out)
	return out
}

// forwardSecrecy reports whether the negotiated suite gives up the session
// when the server's long-term key is later compromised. TLS 1.3 only defines
// suites that do; before that, RSA key exchange does not.
func forwardSecrecy(version, suite uint16) bool {
	if version >= tls.VersionTLS13 {
		return true
	}
	name := tls.CipherSuiteName(suite)
	return strings.Contains(name, "ECDHE") || strings.Contains(name, "DHE")
}
