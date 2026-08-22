package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Discovery finds which ports on a host are listening, and which of those
// speak HTTP, so the target rules have something to run against.
//
// This exists because "check my services" is otherwise a question you have
// to answer by hand before you can ask it. It is a TCP connect scan: the
// same thing a browser does, once per port, with no payload sent. Nothing
// here tries to exploit what it finds.
//
// Point it at hosts you operate. The default port list is deliberately
// short for the same reason the target command sends one plain GET: a tool
// that quietly sweeps 65535 ports invites use this one is not for.

// DefaultPorts covers where web services actually live. Sweeping everything
// is slower, noisier, and finds mostly things these rules cannot judge.
var DefaultPorts = []int{
	80, 81, 88, 443, 591, 3000, 3001, 4200, 4443, 5000, 5001,
	5601, 7001, 8000, 8001, 8008, 8069, 8080, 8081, 8082, 8083,
	8088, 8090, 8180, 8443, 8834, 8888, 9000, 9001, 9090, 9200,
	9443, 10000,
}

// OpenPort is a port that accepted a connection.
type OpenPort struct {
	Port int
	TLS  bool // the port completed a TLS handshake
}

// URL renders the port as something the target rules can fetch.
func (o OpenPort) URL(host string) string {
	scheme := "http"
	if o.TLS {
		scheme = "https"
	}
	// Leave off the port when it is the default for the scheme, so the
	// report reads the way a person would write it.
	if (scheme == "http" && o.Port == 80) || (scheme == "https" && o.Port == 443) {
		return fmt.Sprintf("%s://%s", scheme, host)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, o.Port)
}

// DiscoverOptions controls the sweep.
type DiscoverOptions struct {
	Ports       []int
	Timeout     time.Duration // per port
	Concurrency int
}

func (o DiscoverOptions) withDefaults() DiscoverOptions {
	if len(o.Ports) == 0 {
		o.Ports = DefaultPorts
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 64
	}
	return o
}

// Discover connects to each port in turn and reports the ones that answer.
func Discover(ctx context.Context, host string, opts DiscoverOptions) ([]OpenPort, error) {
	opts = opts.withDefaults()

	host = strings.TrimSpace(host)
	if host == "" {
		return nil, fmt.Errorf("no host given")
	}
	// A URL is a reasonable thing to paste; take the host out of it.
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	host = strings.TrimSuffix(strings.Trim(host, "/"), ".")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	var (
		mu   sync.Mutex
		open []OpenPort
		wg   sync.WaitGroup
	)
	sem := make(chan struct{}, opts.Concurrency)

	for _, port := range opts.Ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			if p, ok := probePort(ctx, host, port, opts.Timeout); ok {
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return open, err
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open, nil
}

// probePort opens a TCP connection and, if that works, tries a TLS
// handshake to decide which scheme the port wants. Nothing is written to
// the socket beyond what TLS negotiation needs.
func probePort(ctx context.Context, host string, port int, timeout time.Duration) (OpenPort, bool) {
	address := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return OpenPort{}, false
	}
	conn.Close()

	return OpenPort{Port: port, TLS: speaksTLS(ctx, address, host, timeout)}, true
}

func speaksTLS(ctx context.Context, address, host string, timeout time.Duration) bool {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			// The point is to learn whether the port negotiates TLS at all,
			// not whether its certificate is any good. What is wrong with
			// the certificate is the target rules' job to report.
			InsecureSkipVerify: true, //nolint:gosec // discovery, not verification
			MinVersion:         tls.VersionTLS10,
			ServerName:         host,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ParsePorts reads a port specification: "80", "80,443", "8000-8100", or any
// combination of those.
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	seen := map[int]bool{}
	var out []int

	add := func(p int) error {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d is out of range", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
		return nil
	}

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		if !isRange {
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("%q is not a port", part)
			}
			if err := add(n); err != nil {
				return nil, err
			}
			continue
		}

		start, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("%q is not a port", lo)
		}
		end, err := strconv.Atoi(strings.TrimSpace(hi))
		if err != nil {
			return nil, fmt.Errorf("%q is not a port", hi)
		}
		if start > end {
			start, end = end, start
		}
		if end-start > 20000 {
			return nil, fmt.Errorf("range %s is too wide; scan it in pieces", part)
		}
		for p := start; p <= end; p++ {
			if err := add(p); err != nil {
				return nil, err
			}
		}
	}

	sort.Ints(out)
	return out, nil
}
