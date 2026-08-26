package qalqon_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nasafuriy/qalqon/internal/engine"
	"github.com/nasafuriy/qalqon/internal/probe"
	"github.com/nasafuriy/qalqon/internal/template"
)

// probeServer runs the http templates against a local test server, so the
// suite never touches the network.
func probeServer(t *testing.T, srv *httptest.Server) []engine.Finding {
	t.Helper()
	set := builtin(t).OfKind(template.KindHTTP)
	if set.Len() == 0 {
		t.Fatal("no http templates loaded")
	}

	findings, failures, _, err := engine.RunTargets(context.Background(), set, []string{srv.URL}, engine.TargetOptions{})
	if err != nil {
		t.Fatalf("target run failed: %v", err)
	}
	for _, f := range failures {
		t.Fatalf("%s could not be probed: %s", f.Target, f.Err)
	}
	return findings
}

func ids(findings []engine.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		out[f.TemplateID] = true
	}
	return out
}

func mustFind(t *testing.T, got map[string]bool, want ...string) {
	t.Helper()
	for _, id := range want {
		if !got[id] {
			t.Errorf("expected %s to fire", id)
		}
	}
}

func mustNotFind(t *testing.T, got map[string]bool, unwanted ...string) {
	t.Helper()
	for _, id := range unwanted {
		if got[id] {
			t.Errorf("%s fired but should not have", id)
		}
	}
}

func TestTargetWithNoSecurityHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer srv.Close()

	got := ids(probeServer(t, srv))

	mustFind(t, got,
		"http-missing-csp",
		"http-missing-nosniff",
		"http-missing-frame-protection",
		"http-missing-referrer-policy",
		"http-served-over-plaintext",
	)
	// The HSTS rule is scoped to https, so a plain-HTTP target must not trip it.
	mustNotFind(t, got, "http-missing-hsts")
}

func TestTargetWithHeadersSetCorrectly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Add("Set-Cookie", "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
		w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer srv.Close()

	got := ids(probeServer(t, srv))

	mustNotFind(t, got,
		"http-missing-csp",
		"http-missing-nosniff",
		"http-missing-frame-protection",
		"http-missing-referrer-policy",
		"http-cookie-missing-secure",
		"http-cookie-missing-httponly",
		"http-cors-wildcard",
		"http-powered-by-disclosed",
		"http-directory-listing",
		"http-server-version-disclosed",
	)
}

func TestFrameAncestorsCountsAsFrameProtection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	mustNotFind(t, ids(probeServer(t, srv)), "http-missing-frame-protection")
}

func TestTargetCookieFlagsAndDisclosure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Set-Cookie", "session=abc; Path=/")
		h.Set("X-Powered-By", "Express")
		h.Set("Server", "nginx/1.18.0")
		h.Set("Access-Control-Allow-Origin", "*")
		w.Write([]byte("<html><head><title>Index of /uploads</title></head></html>"))
	}))
	defer srv.Close()

	mustFind(t, ids(probeServer(t, srv)),
		"http-cookie-missing-secure",
		"http-cookie-missing-httponly",
		"http-powered-by-disclosed",
		"http-server-version-disclosed",
		"http-cors-wildcard",
		"http-directory-listing",
	)
}

// httptest's TLS server presents a self-signed certificate, which exercises
// both the certificate rules and the probe's fall back to an unverified
// connection so it can report why verification failed.
func TestTargetOverTLSWithSelfSignedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	got := ids(probeServer(t, srv))

	mustFind(t, got, "tls-self-signed-certificate", "http-missing-hsts")
	mustNotFind(t, got,
		"http-served-over-plaintext",
		"tls-certificate-expired",
		"tls-obsolete-protocol",
	)
}

func TestProbeReportsVerificationFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	result, err := probe.Fetch(context.Background(), srv.URL, probe.Options{})
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if result.TLSVerified {
		t.Error("a self-signed certificate should not verify")
	}
	if result.VerifyError == "" {
		t.Error("expected the verification failure to be recorded")
	}
	if result.Status != http.StatusOK {
		t.Errorf("expected the request to still complete, got status %d", result.Status)
	}
}

// A scanner that cannot connect to a weak server cannot report it. Go's http
// client refuses anything below TLS 1.2 by default, which silently turned
// every obsolete-protocol finding into a connection error. The probe lowers
// its own floor on purpose; this is the test that keeps it lowered.
func TestProbeReachesObsoleteTLSServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	// Both bounds: a server's default MinVersion is TLS 1.2, so setting only
	// MaxVersion leaves an empty range and the handshake fails for the wrong
	// reason.
	srv.TLS = &tls.Config{ //nolint:gosec // an obsolete server is the fixture
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS11,
	}
	srv.StartTLS()
	defer srv.Close()

	result, err := probe.Fetch(context.Background(), srv.URL, probe.Options{})
	if err != nil {
		t.Fatalf("probe could not reach a TLS 1.1 server: %v", err)
	}
	if want := []byte("version: TLS 1.1"); !bytes.Contains(result.Parts["tls"], want) {
		t.Errorf("tls part does not report the negotiated version:\n%s", result.Parts["tls"])
	}

	mustFind(t, ids(probeServer(t, srv)), "tls-obsolete-protocol")
}

func TestUnreachableTargetIsNotAFinding(t *testing.T) {
	set := builtin(t).OfKind(template.KindHTTP)

	// Port 1 on localhost refuses connections immediately.
	findings, failures, _, err := engine.RunTargets(context.Background(), set,
		[]string{"http://127.0.0.1:1/"}, engine.TargetOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("an unreachable host produced %d findings", len(findings))
	}
	if len(failures) != 1 {
		t.Fatalf("expected one unreachable target, got %d", len(failures))
	}
}

func TestRejectsNonHTTPSchemes(t *testing.T) {
	for _, target := range []string{"ftp://example.com", "file:///etc/passwd", "gopher://example.com"} {
		if _, err := probe.Fetch(context.Background(), target, probe.Options{}); err == nil {
			t.Errorf("%s should have been rejected", target)
		}
	}
}

func TestFileTemplatesDoNotRunAgainstTargets(t *testing.T) {
	all := builtin(t)
	http := all.OfKind(template.KindHTTP)
	file := all.OfKind(template.KindFile)

	if http.Len()+file.Len() != all.Len() {
		t.Fatalf("every template should be exactly one kind: %d http + %d file != %d",
			http.Len(), file.Len(), all.Len())
	}
	for _, tpl := range http.Templates {
		if len(tpl.Files) != 0 {
			t.Errorf("%s is an http template but declares file globs", tpl.ID)
		}
	}
}

// The dangerous half of a CORS misconfiguration is the credentials header:
// whichever origin the response allows can then act as the logged-in user.
func TestTargetCORSWithCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Credentials", "true")
		w.Write([]byte("{}"))
	}))
	defer srv.Close()

	mustFind(t, ids(probeServer(t, srv)),
		"http-cors-credentials",
		"http-cors-wildcard",
	)
}

// A server that allows an origin but sends no credentials is a normal public
// API, and must not raise the credentials finding.
func TestTargetCORSWithoutCredentialsIsNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write([]byte("{}"))
	}))
	defer srv.Close()

	if ids(probeServer(t, srv))["http-cors-credentials"] {
		t.Fatal("http-cors-credentials fired without the credentials header")
	}
}

// The reported match is what a person reads to decide whether the finding is
// real, so it has to carry the whole version rather than stopping at the
// first digit.
func TestDisclosureFindingsCarryTheWholeValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.10.3")
		w.Header().Set("X-Powered-By", "Express/4.16.0")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	want := map[string]string{
		"http-server-version-disclosed": "nginx/1.10.3",
		"http-powered-by-disclosed":     "Express/4.16.0",
	}
	seen := map[string]bool{}
	for _, f := range probeServer(t, srv) {
		if suffix, ok := want[f.TemplateID]; ok {
			seen[f.TemplateID] = true
			if !strings.Contains(f.Match, suffix) {
				t.Errorf("%s: match %q does not contain %q", f.TemplateID, f.Match, suffix)
			}
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("%s did not fire", id)
		}
	}
}

// probeServerSweeping is probeServer with the version sweep turned on, which
// is what the new tls-accepts-obsolete-protocol rule reads.
func probeServerSweeping(t *testing.T, srv *httptest.Server) []engine.Finding {
	t.Helper()
	set := builtin(t).OfKind(template.KindHTTP)

	findings, failures, _, err := engine.RunTargets(
		context.Background(), set, []string{srv.URL},
		engine.TargetOptions{CheckTLSVersions: true})
	if err != nil {
		t.Fatalf("target run failed: %v", err)
	}
	for _, f := range failures {
		t.Fatalf("%s could not be probed: %s", f.Target, f.Err)
	}
	return findings
}

// The gap the sweep exists to close: this server prefers TLS 1.3, so the one
// connection a probe makes reports a modern version and tls-obsolete-protocol
// stays quiet — while the server would happily accept TLS 1.0 from anyone who
// asks for it.
func TestSweepFindsObsoleteVersionTheHandshakeHid(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{ //nolint:gosec // a permissive server is the fixture
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: legacySuites(),
	}
	srv.StartTLS()
	defer srv.Close()

	plain := ids(probeServer(t, srv))
	swept := ids(probeServerSweeping(t, srv))

	if plain["tls-obsolete-protocol"] {
		t.Skip("this runtime negotiated an obsolete version by default; nothing was hidden")
	}
	if !swept["tls-accepts-obsolete-protocol"] {
		t.Error("the sweep did not report a server that accepts TLS 1.0")
	}
}

// A modern-only server must stay clean, or the rule is worthless in CI.
func TestSweepIsQuietOnAModernServer(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	got := ids(probeServerSweeping(t, srv))

	mustNotFind(t, got,
		"tls-accepts-obsolete-protocol",
		"tls-obsolete-protocol",
		"tls-no-forward-secrecy",
		"tls-weak-cipher-suite",
	)
}

// Without an ephemeral key exchange, traffic captured today is readable by
// whoever eventually obtains the server's key.
func TestStaticRSAKeyExchangeIsReported(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12, // TLS 1.3 has no suite without forward secrecy
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	}
	srv.StartTLS()
	defer srv.Close()

	got := ids(probeServer(t, srv))
	mustFind(t, got, "tls-no-forward-secrecy")
}

// legacySuites offers everything the runtime can still speak, so a handshake
// pinned to an old version fails because the server refused it rather than
// because no suite was on offer.
func legacySuites() []uint16 {
	var out []uint16
	for _, s := range tls.CipherSuites() {
		out = append(out, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() { //nolint:gosec // reaching old servers on purpose
		out = append(out, s.ID)
	}
	return out
}

// RC4 and 3DES both have published practical attacks. A server offering
// nothing else is exactly what the client-side suite list exists to reach:
// without it the handshake fails and the report says "unreachable".
func TestWeakCipherSuiteIsReported(t *testing.T) {
	cases := []struct {
		name  string
		suite uint16
	}{
		{"3des", tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
		{"rc4", tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte("ok"))
				}))
			srv.TLS = &tls.Config{ //nolint:gosec // a weak server is the fixture
				MinVersion:   tls.VersionTLS10,
				MaxVersion:   tls.VersionTLS12,
				CipherSuites: []uint16{tc.suite},
			}
			srv.StartTLS()
			defer srv.Close()

			// The runtime may have dropped the suite entirely; that is not a
			// regression in the rule.
			probe, err := tls.Dial("tcp", strings.TrimPrefix(srv.URL, "https://"),
				&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, //nolint:gosec // fixture check
					CipherSuites: legacySuites()})
			if err != nil {
				t.Skipf("this Go runtime will not speak %s: %v", tc.name, err)
			}
			probe.Close()

			mustFind(t, ids(probeServer(t, srv)), "tls-weak-cipher-suite")
		})
	}
}

// probeServerWithCVEs is probeServer with the banner lookup turned on.
func probeServerWithCVEs(t *testing.T, srv *httptest.Server) []engine.Finding {
	t.Helper()
	set := builtin(t).OfKind(template.KindHTTP)

	findings, failures, _, err := engine.RunTargets(
		context.Background(), set, []string{srv.URL},
		engine.TargetOptions{ServiceCVEs: true})
	if err != nil {
		t.Fatalf("target run failed: %v", err)
	}
	for _, f := range failures {
		t.Fatalf("%s could not be probed: %s", f.Target, f.Err)
	}
	return findings
}

func TestServiceVersionLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.2.14 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/5.4.16")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Off by default: the banner lookup is opt-in, because a version string is
	// a claim rather than a measurement.
	mustNotFind(t, ids(probeServer(t, srv)),
		"service-end-of-life", "service-known-vulnerability")

	got := probeServerWithCVEs(t, srv)
	mustFind(t, ids(got), "service-end-of-life", "service-known-vulnerability")

	for _, f := range got {
		if !strings.HasPrefix(f.TemplateID, "service-") {
			continue
		}
		if f.Match == "" {
			t.Errorf("%s shows no evidence", f.Name)
		}
		if !strings.Contains(f.Remediation, "backport") {
			t.Errorf("%s does not carry the caveat about backported fixes", f.Name)
		}
	}
}

// A current server must stay silent, or the flag is not worth turning on.
func TestServiceVersionLookupIsQuietOnCurrentSoftware(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.28.0")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	mustNotFind(t, ids(probeServerWithCVEs(t, srv)),
		"service-end-of-life", "service-known-vulnerability")
}
