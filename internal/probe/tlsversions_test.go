package probe

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// serverPinnedTo starts a TLS server that accepts only the versions in the
// given range, so the sweep has something with a known answer to ask.
func serverPinnedTo(t *testing.T, min, max uint16) *httptest.Server {
	t.Helper()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	srv.TLS = &tls.Config{
		MinVersion: min,
		MaxVersion: max,
		// Old versions cannot be negotiated with the modern default list, so
		// offer everything the runtime still knows how to speak.
		CipherSuites: legacyCipherSuites(),
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckVersionsReportsModernOnly(t *testing.T) {
	srv := serverPinnedTo(t, tls.VersionTLS12, tls.VersionTLS13)
	addr := strings.TrimPrefix(srv.URL, "https://")

	got := CheckVersions(context.Background(), addr, "127.0.0.1", 3*time.Second)

	if !got.Checked {
		t.Fatal("sweep did not complete against a reachable server")
	}
	if got.TLS10 || got.TLS11 {
		t.Errorf("server pinned to 1.2+ reported as accepting obsolete versions: %+v", got)
	}
	if !got.TLS12 {
		t.Error("TLS 1.2 was offered by the server but not detected")
	}
	if got.Weakest != "TLS 1.2" {
		t.Errorf("weakest = %q, want TLS 1.2", got.Weakest)
	}
	if strings.Contains(got.Render(), "accepts_obsolete_tls: true") {
		t.Error("a modern-only server must not render accepts_obsolete_tls: true")
	}
}

func TestCheckVersionsDetectsObsolete(t *testing.T) {
	// Go can still be asked to serve TLS 1.0; if a future release removes it
	// the server itself will fail to start, and the skip keeps that from
	// looking like a regression in the sweep.
	srv := serverPinnedTo(t, tls.VersionTLS10, tls.VersionTLS12)
	addr := strings.TrimPrefix(srv.URL, "https://")

	got := CheckVersions(context.Background(), addr, "127.0.0.1", 3*time.Second)

	if !got.Checked {
		t.Fatal("sweep did not complete against a reachable server")
	}
	if !got.TLS10 {
		t.Skipf("this Go runtime would not negotiate TLS 1.0 at all: %+v", got)
	}
	if got.Weakest != "TLS 1.0" {
		t.Errorf("weakest = %q, want TLS 1.0", got.Weakest)
	}

	out := got.Render()
	for _, want := range []string{
		"versions_checked: true",
		"supports_tls10: true",
		"accepts_obsolete_tls: true",
		"weakest_version: TLS 1.0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Render() missing %q\n%s", want, out)
		}
	}
}

// The whole point of the sweep: a connection reports the best version both
// sides agreed on, which says nothing about the worst the server allows.
func TestCheckVersionsSeesPastTheNegotiatedVersion(t *testing.T) {
	srv := serverPinnedTo(t, tls.VersionTLS10, tls.VersionTLS13)
	addr := strings.TrimPrefix(srv.URL, "https://")

	client := srv.Client()
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.TLS.Version < tls.VersionTLS12 {
		t.Skip("this runtime negotiated an old version by default; nothing to contrast")
	}

	got := CheckVersions(context.Background(), addr, "127.0.0.1", 3*time.Second)
	if !got.TLS10 && !got.TLS11 {
		t.Skip("runtime cannot speak the obsolete versions this test contrasts against")
	}
	if got.Weakest == tlsVersion(resp.TLS.Version) {
		t.Errorf("sweep only found the negotiated version %s; it is meant to find older ones",
			got.Weakest)
	}
}

func TestCheckVersionsUnreachableHost(t *testing.T) {
	// Port 1 on the loopback: nothing listens, and the refusal is immediate.
	got := CheckVersions(context.Background(), "127.0.0.1:1", "127.0.0.1", 500*time.Millisecond)

	if got.Checked {
		t.Errorf("unreachable host reported as checked: %+v", got)
	}
	if out := got.Render(); out != "versions_checked: false\n" {
		t.Errorf("Render() = %q, want the unchecked marker", out)
	}
}

func TestCheckVersionsHonoursCancelledContext(t *testing.T) {
	srv := serverPinnedTo(t, tls.VersionTLS12, tls.VersionTLS13)
	addr := strings.TrimPrefix(srv.URL, "https://")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got := CheckVersions(ctx, addr, "127.0.0.1", 3*time.Second)
	if got.Checked {
		t.Errorf("cancelled sweep still reported results: %+v", got)
	}
}

func TestVersionSupportList(t *testing.T) {
	v := VersionSupport{TLS10: true, TLS12: true, Checked: true, Weakest: "TLS 1.0"}
	got := strings.Join(v.List(), ",")
	if got != "TLS 1.0,TLS 1.2" {
		t.Errorf("List() = %q, want oldest-first TLS 1.0,TLS 1.2", got)
	}
}

func TestForwardSecrecy(t *testing.T) {
	cases := []struct {
		name    string
		version uint16
		suite   uint16
		want    bool
	}{
		{"tls13 always", tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, true},
		{"ecdhe", tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, true},
		{"static rsa", tls.VersionTLS12, tls.TLS_RSA_WITH_AES_128_GCM_SHA256, false},
		{"rc4 rsa", tls.VersionTLS10, tls.TLS_RSA_WITH_RC4_128_SHA, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := forwardSecrecy(tc.version, tc.suite); got != tc.want {
				t.Errorf("forwardSecrecy(%s) = %t, want %t",
					tls.CipherSuiteName(tc.suite), got, tc.want)
			}
		})
	}
}

// The sweep is opt-in: it costs four extra handshakes per host, so a plain
// probe must not pay for it.
func TestFetchOnlySweepsWhenAsked(t *testing.T) {
	srv := serverPinnedTo(t, tls.VersionTLS12, tls.VersionTLS13)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	target := "https://" + net.JoinHostPort(host, port)

	plain, err := Fetch(context.Background(), target, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if strings.Contains(string(plain.Parts["tls"]), "versions_checked") {
		t.Error("the version sweep ran without -tls-versions")
	}

	swept, err := Fetch(context.Background(), target, Options{
		Timeout:          3 * time.Second,
		CheckTLSVersions: true,
	})
	if err != nil {
		t.Fatalf("fetch with sweep: %v", err)
	}
	out := string(swept.Parts["tls"])
	if !strings.Contains(out, "versions_checked: true") {
		t.Errorf("the sweep did not run when asked\n%s", out)
	}
	// The facts from the single connection must survive alongside it.
	if !strings.Contains(out, "forward_secrecy:") || !strings.Contains(out, "self_signed:") {
		t.Errorf("appending the sweep lost the certificate facts\n%s", out)
	}
}

func TestRenderTLSCarriesTheNewFacts(t *testing.T) {
	srv := serverPinnedTo(t, tls.VersionTLS12, tls.VersionTLS13)

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	out := string(renderTLS(resp.TLS, "127.0.0.1"))
	for _, want := range []string{
		"forward_secrecy: true",
		"chain_length: 1",
		"validity_days: ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("renderTLS missing %q\n%s", want, out)
		}
	}
}
