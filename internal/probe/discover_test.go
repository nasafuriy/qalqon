package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		spec string
		want []int
	}{
		{"", nil},
		{"80", []int{80}},
		{"443,80", []int{80, 443}},
		{"80,80,80", []int{80}}, // duplicates collapse
		{"8000-8003", []int{8000, 8001, 8002, 8003}},
		{"8003-8000", []int{8000, 8001, 8002, 8003}}, // reversed range
		{"80, 443 , 8080", []int{80, 443, 8080}},     // spaces
	}
	for _, c := range cases {
		got, err := ParsePorts(c.spec)
		if err != nil {
			t.Errorf("%q: %v", c.spec, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: got %v, want %v", c.spec, got, c.want)
		}
	}
}

func TestParsePortsRejectsNonsense(t *testing.T) {
	for _, spec := range []string{
		"http",    // not a number
		"0",       // out of range
		"65536",   // out of range
		"1-65535", // too wide to be a considered choice
		"80-abc",  // half a range
	} {
		if _, err := ParsePorts(spec); err == nil {
			t.Errorf("%q was accepted", spec)
		}
	}
}

func TestDiscoverFindsAListeningPortAndItsScheme(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer secure.Close()

	plainPort := portOf(t, plain.URL)
	securePort := portOf(t, secure.URL)

	// A port nothing is listening on, to prove the sweep does not simply
	// report everything it was asked about.
	closed := freePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	open, err := Discover(ctx, "127.0.0.1", DiscoverOptions{
		Ports:   []int{plainPort, securePort, closed},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 2 {
		t.Fatalf("got %d open ports, want 2: %+v", len(open), open)
	}

	byPort := map[int]OpenPort{}
	for _, o := range open {
		byPort[o.Port] = o
	}
	if o, ok := byPort[plainPort]; !ok || o.TLS {
		t.Errorf("plain port: %+v", o)
	}
	if o, ok := byPort[securePort]; !ok || !o.TLS {
		t.Errorf("tls port: %+v", o)
	}
	if _, ok := byPort[closed]; ok {
		t.Error("a closed port was reported as listening")
	}
}

func TestOpenPortURL(t *testing.T) {
	cases := []struct {
		port OpenPort
		host string
		want string
	}{
		{OpenPort{Port: 8080}, "10.0.0.1", "http://10.0.0.1:8080"},
		{OpenPort{Port: 8443, TLS: true}, "10.0.0.1", "https://10.0.0.1:8443"},
		// The default port for the scheme is left off, the way a person writes it.
		{OpenPort{Port: 80}, "example.com", "http://example.com"},
		{OpenPort{Port: 443, TLS: true}, "example.com", "https://example.com"},
	}
	for _, c := range cases {
		if got := c.port.URL(c.host); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

func TestDiscoverAcceptsAURLAsTheHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Pasting a URL is a reasonable thing to do; the host should be taken
	// out of it rather than treated as a hostname.
	open, err := Discover(ctx, srv.URL, DiscoverOptions{
		Ports:   []int{portOf(t, srv.URL)},
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 {
		t.Fatalf("got %d, want 1", len(open))
	}
}

func TestDiscoverStopsWhenTheContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Discover(ctx, "127.0.0.1", DiscoverOptions{
		Ports:   []int{9, 10, 11},
		Timeout: time.Second,
	})
	if err == nil {
		t.Error("a cancelled context should be reported")
	}
}

/* ---------------------------------------------------------------- helpers */

func portOf(t *testing.T, rawURL string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(stripScheme(rawURL))
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func stripScheme(s string) string {
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(s, prefix) {
			return strings.TrimPrefix(s, prefix)
		}
	}
	return s
}

// freePort asks the OS for a port and closes it again, so the number is one
// nothing is listening on for the moment.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
