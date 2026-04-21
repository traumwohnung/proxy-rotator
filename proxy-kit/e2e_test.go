package proxykit_test

// End-to-end tests for proxy-kit.
//
// Each test spins up real TCP listeners (random OS-assigned ports), makes actual
// proxy connections through them, and asserts on what the target server received.
// Nothing is mocked below the transport layer.
//
// Design notes:
//
//  1. HTTPDownstream.extractBasicAuth always requires a Basic Proxy-Authorization
//     header — even for anonymous pipelines. Tests that do not need auth send
//     dummy credentials (user="", pass="") so the header is always present.
//
//  2. The Upstream interface dials the *target* through the *proxy* using HTTP
//     CONNECT or SOCKS5. For tests where the "upstream proxy" is a raw-TCP echo
//     server we use directUpstream, which ignores the Proxy struct and just dials
//     the target address directly.
//
// Test categories:
//   - HTTP CONNECT tunnelling
//   - Plain HTTP forwarding
//   - SOCKS5 tunnelling
//   - Auth middleware (credential injection + rejection)
//   - Rate limiting (concurrent connections, per-user isolation, slot recovery)
//   - Session affinity (same seed → same upstream, rotation, zero-TTL, list)
//   - MITM interception (TLS termination + body rewriting + cert cache)
//   - Pipeline composition (auth → rate-limit → session → source)
//   - Gateway multi-listener wiring
//   - Chained HTTP proxies
//   - Concurrent load (HTTP + SOCKS5)

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	proxykit "proxy-kit"
	"proxy-kit/utils"
)

// ── test infrastructure ───────────────────────────────────────────────────────

// directUpstream is an Upstream that dials the target directly, ignoring the
// Proxy argument. Used when the "upstream proxy" in a test is a raw-TCP server
// that doesn't speak HTTP CONNECT.
var directUpstream = proxykit.UpstreamFunc(func(_ context.Context, _ *proxykit.Proxy, target string) (net.Conn, error) {
	return net.DialTimeout("tcp", target, 3*time.Second)
})

// echoServer starts a plain-TCP server that echoes the first received line
// back as "ECHO: <line>". Returns its address and a cleanup function.
func echoServer(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sc := bufio.NewScanner(c)
				if sc.Scan() {
					fmt.Fprintf(c, "ECHO: %s\n", sc.Text())
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// httpTargetServer starts a plain-HTTP server returning "OK: <path>".
func httpTargetServer(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "OK: %s", r.URL.Path)
		}),
	}
	go srv.Serve(ln)
	return ln.Addr().String(), func() { srv.Close() }
}

// tlsTargetServer starts an HTTPS server whose cert is signed by ca,
// returning "TLS-OK: <path>".
func tlsTargetServer(t *testing.T, ca tls.Certificate) (addr, host string, cleanup func()) {
	t.Helper()
	fp, err := proxykit.NewForgedCertProvider(ca)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := fp.CertForHost("testhost")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "TLS-OK: %s", r.URL.Path)
		}),
	}
	go srv.Serve(ln)
	return ln.Addr().String(), "testhost", func() { srv.Close() }
}

// startHTTPProxy starts an HTTP proxy on a random port using Gateway, which
// allows injecting a custom Upstream dialer.
func startHTTPProxy(t *testing.T, handler proxykit.Handler, upstream proxykit.Upstream) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	ln.Close()
	time.Sleep(5 * time.Millisecond)

	gw := proxykit.New(handler,
		proxykit.Listen(&proxykit.HTTPDownstream{}, addr),
		proxykit.WithUpstream(upstream),
	)
	go gw.ListenAndServe() //nolint:errcheck
	time.Sleep(30 * time.Millisecond)
	return addr, func() {}
}

// startSOCKS5Proxy starts a SOCKS5 proxy on a random port with the given
// handler and upstream.
func startSOCKS5Proxy(t *testing.T, handler proxykit.Handler, upstream proxykit.Upstream) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	ln.Close()
	time.Sleep(5 * time.Millisecond)

	d := &proxykit.SOCKS5Downstream{Upstream: upstream}
	go d.Serve(addr, handler) //nolint:errcheck
	time.Sleep(40 * time.Millisecond)
	return addr, func() {}
}

// connectViaHTTPProxy sends HTTP CONNECT through proxyAddr, upgrades the
// tunnel to the target, writes "hello\n" and returns the echo line.
// If user is empty, sends Basic auth with empty credentials (required by
// HTTPDownstream even for anonymous pipelines).
//
// Important: we parse the CONNECT response without a bufio.Reader to avoid
// consuming any bytes beyond the response headers into a buffer. After the
// 200 OK is received we switch to raw reads on the same conn.
func connectViaHTTPProxy(t *testing.T, proxyAddr, target, user, pass string) (string, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	req := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		target, target, creds,
	)
	io.WriteString(conn, req)

	// Read CONNECT response byte-by-byte to avoid over-consuming tunnel data.
	status, err := readHTTPStatusLine(conn)
	if err != nil {
		return "", fmt.Errorf("CONNECT response: %w", err)
	}
	if err := drainHTTPHeaders(conn); err != nil {
		return "", fmt.Errorf("draining headers: %w", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200") && !strings.HasPrefix(status, "HTTP/1.0 200") {
		return "", fmt.Errorf("proxy returned: %s", status)
	}

	// Now use the tunnel.
	io.WriteString(conn, "hello\n")
	line, err := readLine(conn)
	if err != nil {
		return "", fmt.Errorf("reading echo: %w", err)
	}
	return line, nil
}

// readHTTPStatusLine reads bytes until \r\n and returns the status line.
func readHTTPStatusLine(r io.Reader) (string, error) {
	return readLineFrom(r)
}

// drainHTTPHeaders reads and discards header lines until the blank line.
func drainHTTPHeaders(r io.Reader) error {
	for {
		line, err := readLineFrom(r)
		if err != nil {
			return err
		}
		if line == "" {
			return nil
		}
	}
}

// readLine reads one \n-terminated line from the connection (raw, no buffering).
func readLine(r io.Reader) (string, error) {
	var buf []byte
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n > 0 {
			if b[0] == '\n' {
				return strings.TrimRight(string(buf), "\r"), nil
			}
			buf = append(buf, b[0])
		}
		if err != nil {
			return string(buf), err
		}
	}
}

// readLineFrom reads one CRLF-terminated line (strips \r\n).
func readLineFrom(r io.Reader) (string, error) {
	var buf []byte
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n > 0 {
			if b[0] == '\n' {
				return strings.TrimRight(string(buf), "\r"), nil
			}
			buf = append(buf, b[0])
		}
		if err != nil {
			return string(buf), err
		}
	}
}

// connectStatusViaHTTPProxy returns the HTTP status code of the CONNECT response.
func connectStatusViaHTTPProxy(t *testing.T, proxyAddr, target, user, pass string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	req := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		target, target, creds,
	)
	io.WriteString(conn, req)

	status, err := readHTTPStatusLine(conn)
	if err != nil {
		return 0
	}
	drainHTTPHeaders(conn) //nolint:errcheck
	var code int
	var _httpVer string; fmt.Sscanf(status, "HTTP/%s %d", &_httpVer, &code)
	return code
}

// doPlainHTTPViaProxy makes a plain GET through an HTTP proxy (no CONNECT).
// HTTPDownstream always requires a Basic Proxy-Authorization header, so we
// always set credentials (empty string if none needed).
func doPlainHTTPViaProxy(t *testing.T, proxyAddr, targetURL, user, pass string) (int, string, error) {
	t.Helper()
	pu, _ := url.Parse("http://" + proxyAddr)
	// Always set credentials — HTTPDownstream requires Basic auth header.
	pu.User = url.UserPassword(user, pass)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(targetURL)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

// staticSource always resolves to the given proxy.
func staticSource(p *proxykit.Proxy) proxykit.Handler {
	return proxykit.HandlerFunc(func(_ context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		return proxykit.Resolved(p), nil
	})
}

// authInjecting wraps inner so that RawUsername/RawPassword are injected into
// context as Identity/Credential before the inner handler runs.
func authInjecting(inner proxykit.Handler) proxykit.Handler {
	return proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		ctx = proxykit.WithIdentity(ctx, req.RawUsername)
		ctx = proxykit.WithCredential(ctx, req.RawPassword)
		return inner.Resolve(ctx, req)
	})
}

// mustPort parses the port from a "host:port" address.
func mustPort(t *testing.T, addr string) uint16 {
	t.Helper()
	_, ps, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	var n int
	fmt.Sscanf(ps, "%d", &n)
	return uint16(n)
}

// caX509Pool builds an *x509.CertPool trusting the given CA tls.Certificate.
func caX509Pool(ca tls.Certificate) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}
	pool.AddCert(leaf)
	return pool, nil
}

// rawSOCKS5Dialer is a minimal SOCKS5 client (RFC 1928 + RFC 1929).
type rawSOCKS5Dialer struct{ addr, user, pass string }

func (d *rawSOCKS5Dialer) Dial(target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", d.addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socks5Handshake(conn, d.user, d.pass, target); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func socks5Handshake(conn net.Conn, user, pass, target string) error {
	// Greeting.
	if user != "" {
		conn.Write([]byte{0x05, 0x01, 0x02})
	} else {
		conn.Write([]byte{0x05, 0x01, 0x00})
	}
	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if choice[1] == 0xFF {
		return fmt.Errorf("server rejected all auth methods")
	}

	// Username/password sub-negotiation (RFC 1929).
	if choice[1] == 0x02 {
		ub, pb := []byte(user), []byte(pass)
		msg := append([]byte{0x01, byte(len(ub))}, ub...)
		msg = append(msg, byte(len(pb)))
		msg = append(msg, pb...)
		conn.Write(msg)
		var ar [2]byte
		if _, err := io.ReadFull(conn, ar[:]); err != nil {
			return fmt.Errorf("auth resp: %w", err)
		}
		if ar[1] != 0x00 {
			return fmt.Errorf("auth failed (0x%02x)", ar[1])
		}
	}

	// CONNECT request.
	host, portStr, _ := net.SplitHostPort(target)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	conn.Write(req)

	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("connect reply: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("CONNECT refused (0x%02x)", reply[1])
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

// ── 1. HTTP CONNECT tunnelling ────────────────────────────────────────────────

func TestE2E_HTTPConnect_TunnelsToEchoServer(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	// The "upstream proxy" is the echo server itself — we use directUpstream
	// so the downstream dials the target directly instead of via HTTP CONNECT.
	handler := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})
	proxyAddr, closeProxy := startHTTPProxy(t, handler, directUpstream)
	defer closeProxy()

	got, err := connectViaHTTPProxy(t, proxyAddr, echoAddr, "", "")
	if err != nil {
		t.Fatalf("tunnel failed: %v", err)
	}
	if got != "ECHO: hello" {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestE2E_HTTPConnect_RejectsWithoutCredentials(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	auth := utils.NewMapAuth(map[string]string{"alice": "secret"})
	source := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})
	handler := authInjecting(proxykit.Auth(auth, source))
	proxyAddr, closeProxy := startHTTPProxy(t, handler, directUpstream)
	defer closeProxy()

	// Send a CONNECT with no Proxy-Authorization at all (raw dial).
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr)
	statusLine, _ := readHTTPStatusLine(conn)
	drainHTTPHeaders(conn) //nolint:errcheck
	var httpVer1 string
	var statusCode int
	fmt.Sscanf(statusLine, "HTTP/%s %d", &httpVer1, &statusCode)
	if statusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407, got %d", statusCode)
	}
}

func TestE2E_HTTPConnect_AcceptsValidCredentials(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	auth := utils.NewMapAuth(map[string]string{"alice": "secret"})
	source := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})
	handler := authInjecting(proxykit.Auth(auth, source))
	proxyAddr, closeProxy := startHTTPProxy(t, handler, directUpstream)
	defer closeProxy()

	got, err := connectViaHTTPProxy(t, proxyAddr, echoAddr, "alice", "secret")
	if err != nil {
		t.Fatalf("tunnel failed: %v", err)
	}
	if got != "ECHO: hello" {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestE2E_HTTPConnect_RejectsWrongPassword(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	auth := utils.NewMapAuth(map[string]string{"alice": "secret"})
	source := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})
	handler := authInjecting(proxykit.Auth(auth, source))
	proxyAddr, closeProxy := startHTTPProxy(t, handler, directUpstream)
	defer closeProxy()

	// Resolve now happens before hijack, so a wrong password returns a proper
	// HTTP error response (403) instead of 200+EOF.
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	creds := base64.StdEncoding.EncodeToString([]byte("alice:wrong"))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		echoAddr, echoAddr, creds)

	statusLine, _ := readHTTPStatusLine(conn)
	drainHTTPHeaders(conn) //nolint:errcheck
	var httpVer string
	var statusCode int
	fmt.Sscanf(statusLine, "HTTP/%s %d", &httpVer, &statusCode)
	if statusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for wrong password, got %d", statusCode)
	}
}

// ── 2. Plain HTTP forwarding ──────────────────────────────────────────────────

func TestE2E_PlainHTTP_ForwardsGetRequest(t *testing.T) {
	targetAddr, closeTarget := httpTargetServer(t)
	defer closeTarget()

	// For plain HTTP the HTTPDownstream uses ForwardPlainHTTP which uses
	// net/http.Transport with the resolved proxy URL. We need our "upstream
	// proxy" to be a real HTTP proxy. Start a second HTTP proxy that routes
	// directly (with directUpstream).
	innerHandler := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, targetAddr)})
	// ForwardPlainHTTP sends the request to the proxy using the Proxy struct
	// (proxy.Host:proxy.Port via http.Transport). The http.Transport will try
	// to connect to proxy.Host:proxy.Port and forward the request there.
	// Since targetAddr is a plain HTTP server (not a proxy), this won't work
	// unless we make our "proxy" the target itself and use a custom transport.
	//
	// The cleanest approach: start an actual intermediate HTTP proxy that knows
	// how to forward plain HTTP. That means proxy-A (our test proxy with
	// directUpstream) proxies to proxy-B (a second instance), and proxy-B
	// points at the target. But ForwardPlainHTTP in HTTPDownstream uses
	// http.Transport with proxy URL = the resolved Proxy struct. So the resolved
	// proxy must be a real HTTP proxy server.
	//
	// Solution: Use a real HTTP proxy as the upstream. Start a second proxy
	// that uses net/http.Transport to dial the target server directly.
	//
	// Actually the simplest approach: start one proxy that resolves to a Proxy
	// struct where Host:Port = the HTTP target, and use AutoUpstream. Then
	// ForwardPlainHTTP will send the request to host:port as a proxy. But the
	// HTTP target server only knows how to handle normal requests, not
	// proxy-style absolute-URI requests.
	//
	// The real intent: for plain HTTP, the HTTP proxy sends the request to
	// its upstream proxy. The upstream proxy (HTTPUpstream) then CONNECTs
	// or forwards to the target. For plain (non-TLS) HTTP, the proxy uses
	// net/http.Transport with Proxy = upstream proxy URL, which sends an
	// HTTP/1.1 GET with absolute URI to the upstream proxy. The upstream
	// proxy then fetches and returns.
	//
	// For a self-contained test: make the upstream proxy = the outer proxy
	// itself (a chain). But that would loop. Better: the first proxy has
	// its source resolve to a proxy address, and the Upstream is AutoUpstream
	// which handles it as an HTTP CONNECT or plain forward depending on the
	// target. For plain HTTP targets, the http.Transport sends the full
	// GET http://host/path to the upstream, and the upstream (which is a real
	// HTTP server that handles proxy requests) handles it.
	//
	// Simplest self-contained test: spin up two HTTP proxy instances.
	// proxy-B: uses directUpstream, source = the plain HTTP target server.
	//          (directUpstream ignores the proxy and dials target directly;
	//           but ForwardPlainHTTP uses http.Transport + proxy URL, not
	//           directUpstream. directUpstream is only used for CONNECT tunnels.)
	//
	// For PLAIN HTTP the flow in HTTPDownstream.servePlainHTTP is:
	//   result, _ := handler.Resolve(...)  // get proxy address
	//   ForwardPlainHTTP(r, result.Proxy)  // http.Transport with proxy URL
	//
	// ForwardPlainHTTP creates an http.Transport with Proxy = result.Proxy URL.
	// This transport sends the request TO result.Proxy (not directly to target).
	// result.Proxy must be a real HTTP proxy that knows how to forward.
	//
	// So for plain HTTP e2e: we need a two-hop setup:
	//   client → proxy-A (test proxy, resolves to proxy-B) → proxy-B (real http proxy) → target
	//
	// proxy-B is just another proxykit HTTPDownstream with directUpstream and
	// source = the target.
	_ = innerHandler
	_ = closeTarget

	// Build proxy-B: serves plain HTTP by forwarding to the target.
	// proxy-B's source resolves to the target itself, but ForwardPlainHTTP
	// will send the request to proxy-B's resolved proxy (= target address).
	// That won't work because target is not an HTTP proxy.
	//
	// CONCLUSION: The plain HTTP flow requires the resolved Proxy to be a
	// real HTTP proxy. For a clean self-contained test, we use proxy-B as
	// the "upstream proxy" for proxy-A. proxy-B routes to the target with
	// ForwardPlainHTTP by resolving to *itself* and using directUpstream.
	// Actually proxy-B just needs a source that returns a non-proxy proxy
	// address and an upstream that knows how to forward plain HTTP.
	//
	// Cleanest solution: for plain HTTP testing, use a single proxy where
	// ForwardPlainHTTP dials the target directly by setting up a custom
	// Upstream that, for plain HTTP (non-CONNECT), dials the target directly.
	// The custom upstream is only invoked for CONNECT; plain HTTP uses
	// ForwardPlainHTTP which uses http.Transport internally.
	//
	// So: proxy → source returns Proxy{host=target, port=targetPort} → 
	// ForwardPlainHTTP sends GET to http://targetHost:targetPort/path via 
	// http.Transport with Proxy=targetAddr. The http.Transport will send:
	//   GET http://targetAddr/path HTTP/1.1
	// to targetAddr. Our httpTargetServer handles ANY request, including
	// those with absolute URIs, because Go's net/http normalises the URL.
	// Let's just try it directly — Go's http.DefaultServeMux ignores the
	// scheme/host in absolute-URI requests and routes by path.
	targetAddr2, closeTarget2 := httpTargetServer(t)
	defer closeTarget2()

	source := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, targetAddr2)})
	proxyAddr, closeProxy := startHTTPProxy(t, source, proxykit.AutoUpstream())
	defer closeProxy()

	status, body, err := doPlainHTTPViaProxy(t, proxyAddr, "http://"+targetAddr2+"/hello", "", "")
	if err != nil {
		t.Fatalf("plain HTTP failed: %v", err)
	}
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	if body != "OK: /hello" {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestE2E_PlainHTTP_DifferentPathsReachTarget(t *testing.T) {
	targetAddr, closeTarget := httpTargetServer(t)
	defer closeTarget()

	source := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, targetAddr)})
	proxyAddr, closeProxy := startHTTPProxy(t, source, proxykit.AutoUpstream())
	defer closeProxy()

	for _, path := range []string{"/alpha", "/beta", "/gamma"} {
		_, body, err := doPlainHTTPViaProxy(t, proxyAddr, "http://"+targetAddr+path, "", "")
		if err != nil {
			t.Fatalf("path %s: %v", path, err)
		}
		if want := "OK: " + path; body != want {
			t.Fatalf("path %s: want %q got %q", path, want, body)
		}
	}
}

// ── 3. SOCKS5 tunnelling ──────────────────────────────────────────────────────

func TestE2E_SOCKS5_TunnelsToEchoServer(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	handler := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})
	socks5Addr, _ := startSOCKS5Proxy(t, handler, directUpstream)

	d := &rawSOCKS5Dialer{addr: socks5Addr}
	conn, err := d.Dial(echoAddr)
	if err != nil {
		t.Fatalf("socks5 dial failed: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	fmt.Fprintf(conn, "world\n")
	sc := bufio.NewScanner(conn)
	sc.Scan()
	if sc.Text() != "ECHO: world" {
		t.Fatalf("unexpected: %q", sc.Text())
	}
}

func TestE2E_SOCKS5_AcceptsValidAuth(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	auth := utils.NewMapAuth(map[string]string{"bob": "pass"})
	source := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})
	socks5Addr, _ := startSOCKS5Proxy(t, authInjecting(proxykit.Auth(auth, source)), directUpstream)

	d := &rawSOCKS5Dialer{addr: socks5Addr, user: "bob", pass: "pass"}
	conn, err := d.Dial(echoAddr)
	if err != nil {
		t.Fatalf("valid-auth socks5 dial failed: %v", err)
	}
	conn.Close()
}

func TestE2E_SOCKS5_RejectsWrongPassword(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	auth := utils.NewMapAuth(map[string]string{"bob": "pass"})
	source := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})
	socks5Addr, _ := startSOCKS5Proxy(t, authInjecting(proxykit.Auth(auth, source)), directUpstream)

	d := &rawSOCKS5Dialer{addr: socks5Addr, user: "bob", pass: "wrong"}
	conn, err := d.Dial(echoAddr)
	if err == nil {
		conn.Close()
		t.Fatal("expected failure with wrong password")
	}
}

func TestE2E_SOCKS5_NoAuthMode(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	handler := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})
	socks5Addr, _ := startSOCKS5Proxy(t, handler, directUpstream)

	// No user/pass: sends no-auth method.
	d := &rawSOCKS5Dialer{addr: socks5Addr}
	conn, err := d.Dial(echoAddr)
	if err != nil {
		t.Fatalf("no-auth socks5 dial failed: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(conn, "noauth\n")
	sc := bufio.NewScanner(conn)
	sc.Scan()
	if sc.Text() != "ECHO: noauth" {
		t.Fatalf("unexpected: %q", sc.Text())
	}
}

// ── 4. Rate limiting ──────────────────────────────────────────────────────────

func TestE2E_RateLimit_BlocksExceedingConcurrentConnections(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	source := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})
	rl := proxykit.RateLimit(
		proxykit.Identity,
		source,
		proxykit.StaticLimits([]proxykit.RateLimitRule{
			{Type: proxykit.LimitConcurrentConnections, Timeframe: proxykit.Realtime, Max: 1},
		}),
	)
	handler := proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		ctx = proxykit.WithIdentity(ctx, "alice")
		return rl.Resolve(ctx, req)
	})
	proxyAddr, closeProxy := startHTTPProxy(t, handler, directUpstream)
	defer closeProxy()

	creds := base64.StdEncoding.EncodeToString([]byte(":"))
	makeReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		echoAddr, echoAddr, creds)

	// First connection: establish the tunnel and keep it open.
	conn1, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()
	conn1.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn1, makeReq)
	sl1, _ := readHTTPStatusLine(conn1)
	drainHTTPHeaders(conn1) //nolint:errcheck
	var code1 int
	var httpVerA string; fmt.Sscanf(sl1, "HTTP/%s %d", &httpVerA, &code1)
	if code1 != 200 {
		t.Fatalf("first connection should get 200, got %d", code1)
	}

	// Second connection while first is still open.
	// Resolve now happens before hijack, so rate-limit rejection returns a
	// proper HTTP error response (403) instead of 200+EOF.
	time.Sleep(20 * time.Millisecond)
	conn2, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(conn2, makeReq)
	sl2, _ := readHTTPStatusLine(conn2)
	drainHTTPHeaders(conn2) //nolint:errcheck
	var code2 int
	var httpVerB string
	fmt.Sscanf(sl2, "HTTP/%s %d", &httpVerB, &code2)
	if code2 != http.StatusForbidden {
		t.Fatalf("expected 403 for rate-limited connection, got %d", code2)
	}
}

func TestE2E_RateLimit_DifferentUsersHaveIndependentLimits(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	source := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})
	rl := proxykit.RateLimit(
		proxykit.Identity,
		source,
		proxykit.StaticLimits([]proxykit.RateLimitRule{
			{Type: proxykit.LimitConcurrentConnections, Timeframe: proxykit.Realtime, Max: 1},
		}),
	)
	var mu sync.Mutex
	currentUser := "alice"
	handler := proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		mu.Lock()
		u := currentUser
		mu.Unlock()
		ctx = proxykit.WithIdentity(ctx, u)
		return rl.Resolve(ctx, req)
	})
	proxyAddr, closeProxy := startHTTPProxy(t, handler, directUpstream)
	defer closeProxy()

	makeConnectReq := func(user string) string {
		creds := base64.StdEncoding.EncodeToString([]byte(user + ":"))
		return fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
			echoAddr, echoAddr, creds)
	}

	// Alice takes her slot and verifies it works (echo round-trip).
	mu.Lock(); currentUser = "alice"; mu.Unlock()
	connAlice, _ := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	defer connAlice.Close()
	connAlice.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(connAlice, makeConnectReq("alice"))
	readHTTPStatusLine(connAlice)  //nolint:errcheck
	drainHTTPHeaders(connAlice)    //nolint:errcheck
	io.WriteString(connAlice, "alice-msg\n")
	gotAlice, errAlice := readLine(connAlice)
	if errAlice != nil || gotAlice != "ECHO: alice-msg" {
		t.Fatalf("alice's tunnel should work, got %q err=%v", gotAlice, errAlice)
	}

	// Bob's tunnel should succeed even while alice's slot is held.
	mu.Lock(); currentUser = "bob"; mu.Unlock()
	connBob, _ := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	defer connBob.Close()
	connBob.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(connBob, makeConnectReq("bob"))
	readHTTPStatusLine(connBob) //nolint:errcheck
	drainHTTPHeaders(connBob)   //nolint:errcheck
	io.WriteString(connBob, "bob-msg\n")
	gotBob, errBob := readLine(connBob)
	if errBob != nil || gotBob != "ECHO: bob-msg" {
		t.Fatalf("bob's tunnel should not be affected by alice's rate limit, got %q err=%v", gotBob, errBob)
	}
}

func TestE2E_RateLimit_AllowsNewConnectionAfterPreviousClosed(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	source := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})
	rl := proxykit.RateLimit(
		proxykit.Identity,
		source,
		proxykit.StaticLimits([]proxykit.RateLimitRule{
			{Type: proxykit.LimitConcurrentConnections, Timeframe: proxykit.Realtime, Max: 1},
		}),
	)
	handler := proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		ctx = proxykit.WithIdentity(ctx, "carol")
		return rl.Resolve(ctx, req)
	})
	proxyAddr, closeProxy := startHTTPProxy(t, handler, directUpstream)
	defer closeProxy()

	creds := base64.StdEncoding.EncodeToString([]byte(":"))
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		echoAddr, echoAddr, creds)

	// First connection: open tunnel, do a round trip, then close it.
	conn1, _ := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	conn1.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(conn1, connectReq)
	readHTTPStatusLine(conn1) //nolint:errcheck
	drainHTTPHeaders(conn1)   //nolint:errcheck
	io.WriteString(conn1, "ping\n")
	readLine(conn1)  //nolint:errcheck – consume "ECHO: ping"
	conn1.Close()    // releases the slot via ConnTracker.Close
	time.Sleep(80 * time.Millisecond)

	// Second connection: slot should be free and tunnel should work.
	conn2, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(conn2, connectReq)
	readHTTPStatusLine(conn2) //nolint:errcheck
	drainHTTPHeaders(conn2)   //nolint:errcheck
	// If the slot was freed, the tunnel works; if not, the connection is closed immediately.
	io.WriteString(conn2, "pong\n")
	got2, err2 := readLine(conn2)
	if err2 != nil || got2 != "ECHO: pong" {
		t.Fatalf("expected working tunnel after slot freed, got %q err=%v", got2, err2)
	}
}

// ── 5. Session affinity ───────────────────────────────────────────────────────

func TestE2E_Session_SameSeedAlwaysReturnsTheSameProxy(t *testing.T) {
	proxies := []*proxykit.Proxy{
		{Host: "127.0.0.1", Port: 1001},
		{Host: "127.0.0.1", Port: 1002},
		{Host: "127.0.0.1", Port: 1003},
	}
	source := proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		seed := proxykit.GetSessionSeed(ctx)
		if seed == nil {
			return proxykit.Resolved(proxies[0]), nil
		}
		return proxykit.Resolved(proxies[seed.Pick(len(proxies))]), nil
	})
	sm := utils.NewSessionManager(source)

	topSeed := proxykit.TopLevelSeed("pinned-user")
	ctx := utils.WithTopLevelSeed(context.Background(), topSeed)
	ctx = utils.WithSeedTTL(ctx, 10*time.Second)

	r0, err := sm.Resolve(ctx, &proxykit.Request{})
	if err != nil || r0.Proxy == nil {
		t.Fatal("initial resolve failed")
	}
	firstPort := r0.Proxy.Port

	for i := 0; i < 10; i++ {
		r, _ := sm.Resolve(ctx, &proxykit.Request{})
		if r.Proxy.Port != firstPort {
			t.Fatalf("session broke at iteration %d: want %d got %d", i, firstPort, r.Proxy.Port)
		}
	}
}

func TestE2E_Session_DifferentSeedsArePinnedIndependently(t *testing.T) {
	proxies := []*proxykit.Proxy{
		{Host: "127.0.0.1", Port: 2001},
		{Host: "127.0.0.1", Port: 2002},
		{Host: "127.0.0.1", Port: 2003},
		{Host: "127.0.0.1", Port: 2004},
		{Host: "127.0.0.1", Port: 2005},
	}
	source := proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		seed := proxykit.GetSessionSeed(ctx)
		return proxykit.Resolved(proxies[seed.Pick(len(proxies))]), nil
	})
	sm := utils.NewSessionManager(source)

	users := []string{"alice", "bob", "carol", "dave"}
	pinned := map[string]uint16{}

	for _, u := range users {
		ctx := utils.WithTopLevelSeed(context.Background(), proxykit.TopLevelSeed(u))
		ctx = utils.WithSeedTTL(ctx, time.Minute)
		r, err := sm.Resolve(ctx, &proxykit.Request{})
		if err != nil || r.Proxy == nil {
			t.Fatalf("initial resolve for %s failed: %v", u, err)
		}
		pinned[u] = r.Proxy.Port
	}

	// Every subsequent resolve for each user must return the same pinned port.
	for i := 0; i < 5; i++ {
		for _, u := range users {
			ctx := utils.WithTopLevelSeed(context.Background(), proxykit.TopLevelSeed(u))
			ctx = utils.WithSeedTTL(ctx, time.Minute)
			r, _ := sm.Resolve(ctx, &proxykit.Request{})
			if r.Proxy.Port != pinned[u] {
				t.Fatalf("iteration %d: user %s session broke: want %d got %d", i, u, pinned[u], r.Proxy.Port)
			}
		}
	}
}

func TestE2E_Session_ForceRotateChangesRotationCounter(t *testing.T) {
	source := proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		seed := proxykit.GetSessionSeed(ctx)
		port := uint16(3000 + seed.Pick(1000))
		return proxykit.Resolved(&proxykit.Proxy{Host: "127.0.0.1", Port: port}), nil
	})
	sm := utils.NewSessionManager(source)

	topSeed := proxykit.TopLevelSeed("rotate-me")
	ctx := utils.WithTopLevelSeed(context.Background(), topSeed)
	ctx = utils.WithSeedTTL(ctx, 5*time.Minute)

	sm.Resolve(ctx, &proxykit.Request{}) //nolint:errcheck – establish session

	info, err := sm.ForceRotate(topSeed)
	if err != nil {
		t.Fatalf("ForceRotate: %v", err)
	}
	if info == nil {
		t.Fatal("ForceRotate returned nil")
	}
	if info.Rotation != 1 {
		t.Fatalf("expected rotation=1, got %d", info.Rotation)
	}

	// GetSession reflects the new rotation.
	session := sm.GetSession(topSeed)
	if session == nil {
		t.Fatal("session missing after rotate")
	}
	if session.Rotation != 1 {
		t.Fatalf("GetSession rotation should be 1, got %d", session.Rotation)
	}
}

func TestE2E_Session_ZeroTTLCallsSourceEveryTime(t *testing.T) {
	var calls atomic.Int64
	source := proxykit.HandlerFunc(func(_ context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		n := calls.Add(1)
		return proxykit.Resolved(&proxykit.Proxy{Host: "127.0.0.1", Port: uint16(4000 + n)}), nil
	})
	sm := utils.NewSessionManager(source)

	ctx := utils.WithTopLevelSeed(context.Background(), 42)
	ctx = utils.WithSeedTTL(ctx, 0) // zero TTL → no caching

	r1, _ := sm.Resolve(ctx, &proxykit.Request{})
	r2, _ := sm.Resolve(ctx, &proxykit.Request{})
	if r1.Proxy.Port == r2.Proxy.Port {
		t.Fatal("TTL=0 should not cache: expected different proxies each call")
	}
	if calls.Load() != 2 {
		t.Fatalf("expected 2 source calls, got %d", calls.Load())
	}
}

func TestE2E_Session_ListEntriesReturnsAllActiveSessions(t *testing.T) {
	source := proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		seed := proxykit.GetSessionSeed(ctx)
		return proxykit.Resolved(&proxykit.Proxy{Host: "127.0.0.1", Port: uint16(5000 + seed.Pick(100))}), nil
	})
	sm := utils.NewSessionManager(source)

	for _, name := range []string{"u1", "u2", "u3"} {
		ctx := utils.WithTopLevelSeed(context.Background(), proxykit.TopLevelSeed(name))
		ctx = utils.WithSeedTTL(ctx, time.Minute)
		ctx = utils.WithSessionLabel(ctx, name)
		sm.Resolve(ctx, &proxykit.Request{}) //nolint:errcheck
	}

	entries := sm.ListEntries()
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
}

// ── 6. MITM interception ──────────────────────────────────────────────────────

func TestE2E_MITM_InterceptsHTTPSAndRewritesBody(t *testing.T) {
	ca, err := proxykit.NewCA()
	if err != nil {
		t.Fatal(err)
	}

	tlsAddr, tlsHost, closeTLS := tlsTargetServer(t, ca)
	defer closeTLS()
	tlsPort := mustPort(t, tlsAddr)

	// Custom interceptor: forwards to the real TLS target and uppercases the body.
	interceptor := proxykit.InterceptorFunc(func(ctx context.Context, req *http.Request, _ string, _ *proxykit.Proxy) (*http.Response, error) {
		conn, err := tls.Dial("tcp", tlsAddr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, fmt.Errorf("tls dial target: %w", err)
		}
		defer conn.Close()

		out := req.Clone(ctx)
		out.URL.Scheme = ""
		out.URL.Host = ""
		out.RequestURI = req.URL.RequestURI()
		if out.RequestURI == "" {
			out.RequestURI = "/"
		}
		if err := out.Write(conn); err != nil {
			return nil, err
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), out)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		upper := strings.ToUpper(string(body))
		resp.Body = io.NopCloser(strings.NewReader(upper))
		resp.ContentLength = int64(len(upper))
		return resp, nil
	})

	certs, _ := proxykit.NewForgedCertProvider(ca)
	inner := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: tlsPort})
	pipeline := proxykit.MITM(certs, interceptor, inner)

	proxyAddr, closeProxy := startHTTPProxy(t, pipeline, directUpstream)
	defer closeProxy()

	// Client trusts our CA.
	caPool, err := caX509Pool(ca)
	if err != nil {
		t.Fatal(err)
	}
	// HTTPDownstream requires Basic auth; use empty credentials in proxy URL.
	proxyURL := &url.URL{
		Scheme: "http",
		Host:   proxyAddr,
		User:   url.UserPassword("", ""),
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://%s:%d/greet", tlsHost, tlsPort))
	if err != nil {
		t.Fatalf("MITM HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if !strings.HasPrefix(string(body), "TLS-OK:") {
		t.Fatalf("expected TLS-OK: prefix, got: %q", body)
	}
	if string(body) != strings.ToUpper(string(body)) {
		t.Fatalf("body should be fully uppercased, got: %q", body)
	}
}

func TestE2E_MITM_CertCacheReturnsSameCertForSameHost(t *testing.T) {
	ca, _ := proxykit.NewCA()
	fp, _ := proxykit.NewForgedCertProvider(ca)

	c1, err := fp.CertForHost("example.com")
	if err != nil {
		t.Fatal(err)
	}
	c2, _ := fp.CertForHost("example.com")
	if c1 != c2 {
		t.Fatal("cert cache: same host should return same pointer")
	}
	c3, _ := fp.CertForHost("other.com")
	if c3 == c1 {
		t.Fatal("cert cache: different host should return different cert")
	}
}

func TestE2E_MITM_PassesThroughNonConnectTarget(t *testing.T) {
	// MITM should call inner unchanged when target port != 443.
	ca, _ := proxykit.NewCA()
	certs, _ := proxykit.NewForgedCertProvider(ca)

	called := false
	inner := proxykit.HandlerFunc(func(_ context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		called = true
		return proxykit.Resolved(&proxykit.Proxy{Host: "127.0.0.1", Port: 9999}), nil
	})

	pipeline := proxykit.MITM(certs, proxykit.InterceptorFunc(func(_ context.Context, _ *http.Request, _ string, _ *proxykit.Proxy) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}}, nil
	}), inner)

	result, err := pipeline.Resolve(context.Background(), &proxykit.Request{Target: "example.com:80"})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("inner must be called for non-CONNECT target")
	}
	if result == nil || result.Proxy == nil {
		t.Fatal("expected a proxy in the result")
	}
}

func TestE2E_MITM_ResponseHookIsReturned(t *testing.T) {
	inner := proxykit.HandlerFunc(func(_ context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		r := proxykit.Resolved(&proxykit.Proxy{Host: "127.0.0.1", Port: 9})
		r.ResponseHook = func(resp *http.Response) *http.Response {
			resp.Header.Set("X-Proxied-By", "proxy-kit")
			return resp
		}
		return r, nil
	})

	result, err := inner.Resolve(context.Background(), &proxykit.Request{})
	if err != nil || result.ResponseHook == nil {
		t.Fatal("expected non-nil ResponseHook")
	}
	resp := &http.Response{Header: http.Header{}}
	result.ResponseHook(resp)
	if resp.Header.Get("X-Proxied-By") != "proxy-kit" {
		t.Fatal("ResponseHook should set the header")
	}
}

// ── 7. Pipeline composition ───────────────────────────────────────────────────

func TestE2E_Pipeline_AuthThenRateLimitThenSession(t *testing.T) {
	var sourceCallCount atomic.Int64
	proxies := []*proxykit.Proxy{
		{Host: "127.0.0.1", Port: 6001},
		{Host: "127.0.0.1", Port: 6002},
		{Host: "127.0.0.1", Port: 6003},
	}
	source := proxykit.HandlerFunc(func(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
		sourceCallCount.Add(1)
		seed := proxykit.GetSessionSeed(ctx)
		return proxykit.Resolved(proxies[seed.Pick(len(proxies))]), nil
	})

	sm := utils.NewSessionManager(source)
	auth := utils.NewMapAuth(map[string]string{"alice": "pw", "bob": "pw"})
	rl := proxykit.RateLimit(
		proxykit.Identity,
		sm,
		proxykit.StaticLimits([]proxykit.RateLimitRule{
			{Type: proxykit.LimitConcurrentConnections, Timeframe: proxykit.Realtime, Max: 10},
		}),
	)

	pipeline := proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		ctx = proxykit.WithIdentity(ctx, req.RawUsername)
		ctx = proxykit.WithCredential(ctx, req.RawPassword)
		ctx = utils.WithTopLevelSeed(ctx, proxykit.TopLevelSeed(req.RawUsername))
		ctx = utils.WithSeedTTL(ctx, time.Minute)
		return proxykit.Auth(auth, rl).Resolve(ctx, req)
	})

	resolve := func(user, pass string) (*proxykit.Result, error) {
		return pipeline.Resolve(context.Background(), &proxykit.Request{
			RawUsername: user, RawPassword: pass,
		})
	}

	// Valid credentials succeed.
	r, err := resolve("alice", "pw")
	if err != nil || r.Proxy == nil {
		t.Fatalf("alice first resolve: %v", err)
	}
	r.ConnTracker.Close(0, 0)

	// Wrong password is rejected.
	if _, err := resolve("alice", "wrong"); err == nil {
		t.Fatal("expected rejection for wrong password")
	}

	// Bob gets his own pinned session.
	rb, err := resolve("bob", "pw")
	if err != nil || rb.Proxy == nil {
		t.Fatalf("bob resolve: %v", err)
	}
	rb.ConnTracker.Close(0, 0)

	// Alice's second resolve hits the session cache — source not called again.
	before := sourceCallCount.Load()
	r2, _ := resolve("alice", "pw")
	r2.ConnTracker.Close(0, 0)
	if sourceCallCount.Load() != before {
		t.Fatalf("session cache miss: source called (before=%d after=%d)", before, sourceCallCount.Load())
	}

	// Both sessions are listed.
	entries := sm.ListEntries()
	if len(entries) < 2 {
		t.Fatalf("expected ≥2 active sessions, got %d", len(entries))
	}
}

// ── 8. Gateway multi-listener ─────────────────────────────────────────────────

func TestE2E_Gateway_HTTPAndSOCKS5ShareOnePipeline(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	source := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})

	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	httpAddr := httpLn.Addr().String()
	httpLn.Close()

	socks5Ln, _ := net.Listen("tcp", "127.0.0.1:0")
	socks5Addr := socks5Ln.Addr().String()
	socks5Ln.Close()

	time.Sleep(10 * time.Millisecond)

	gw := proxykit.New(source,
		proxykit.Listen(&proxykit.HTTPDownstream{}, httpAddr),
		proxykit.Listen(&proxykit.SOCKS5Downstream{}, socks5Addr),
		proxykit.WithUpstream(directUpstream),
	)
	go gw.ListenAndServe() //nolint:errcheck
	time.Sleep(60 * time.Millisecond)

	// HTTP CONNECT tunnel.
	got, err := connectViaHTTPProxy(t, httpAddr, echoAddr, "", "")
	if err != nil {
		t.Fatalf("HTTP gateway: %v", err)
	}
	if got != "ECHO: hello" {
		t.Fatalf("HTTP gateway unexpected: %q", got)
	}

	// SOCKS5 tunnel.
	d := &rawSOCKS5Dialer{addr: socks5Addr}
	conn, err := d.Dial(echoAddr)
	if err != nil {
		t.Fatalf("SOCKS5 gateway: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "gw\n")
	gotGW, errGW := readLine(conn)
	if errGW != nil || gotGW != "ECHO: gw" {
		t.Fatalf("SOCKS5 gateway unexpected: %q err=%v", gotGW, errGW)
	}
}

// ── 9. Chained HTTP proxies ───────────────────────────────────────────────────

func TestE2E_ChainedHTTPProxies_TwoHops(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	// proxy-A: no-auth pipeline, routes directly to the echo server.
	proxyA, closeA := startHTTPProxy(t,
		staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)}),
		directUpstream,
	)
	defer closeA()

	// proxy-B: its source returns proxy-A as the upstream.
	// HTTPUpstream sends "Proxy-Authorization: Basic <creds>" only when Username != "".
	// Since proxy-A requires a Basic header (even empty creds are fine), we set
	// a dummy username so HTTPUpstream includes the header.
	proxyB, closeB := startHTTPProxy(t,
		staticSource(&proxykit.Proxy{
			Host:     "127.0.0.1",
			Port:     mustPort(t, proxyA),
			Username: "", // HTTPUpstream won't add auth header with empty username.
		}),
		proxykit.AutoUpstream(),
	)
	defer closeB()

	// We can't make AutoUpstream send empty-credential Basic auth to proxy-A.
	// Instead, make proxy-A not require credentials by using a pass-through handler.
	// That means closing proxyA and reopening with a no-check handler is complex.
	//
	// Simpler: proxy-A doesn't do auth — it just calls extractBasicAuth which
	// errors on missing header. proxy-B's HTTPUpstream doesn't send a header
	// when username is "". So the chain will fail.
	//
	// Resolution: use proxy-B with directUpstream pointing at proxy-A's address,
	// but that defeats the "chained" purpose. Real solution: add a non-empty
	// username to the proxy struct so HTTPUpstream sends the header.
	_ = proxyB
	_ = closeB

	// Rebuild proxy-B with a non-empty username credential.
	proxyB2, closeB2 := startHTTPProxy(t,
		staticSource(&proxykit.Proxy{
			Host:     "127.0.0.1",
			Port:     mustPort(t, proxyA),
			Username: "anon", // causes HTTPUpstream to send Proxy-Authorization
			Password: "",
		}),
		proxykit.AutoUpstream(),
	)
	defer closeB2()

	got, err := connectViaHTTPProxy(t, proxyB2, echoAddr, "", "")
	if err != nil {
		t.Fatalf("chained proxy failed: %v", err)
	}
	if got != "ECHO: hello" {
		t.Fatalf("chain: unexpected %q", got)
	}
}

// ── 10. Concurrent load ───────────────────────────────────────────────────────

func TestE2E_ConcurrentHTTPConnectTunnels(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	handler := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})
	proxyAddr, closeProxy := startHTTPProxy(t, handler, directUpstream)
	defer closeProxy()

	const workers = 20
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			got, err := connectViaHTTPProxy(t, proxyAddr, echoAddr, "", "")
			if err != nil {
				errs <- fmt.Errorf("worker %d: %w", n, err)
				return
			}
			if got != "ECHO: hello" {
				errs <- fmt.Errorf("worker %d: unexpected %q", n, got)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestE2E_ConcurrentSOCKS5Tunnels(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	handler := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: mustPort(t, echoAddr)})
	socks5Addr, _ := startSOCKS5Proxy(t, handler, directUpstream)

	const workers = 10
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			d := &rawSOCKS5Dialer{addr: socks5Addr}
			conn, err := d.Dial(echoAddr)
			if err != nil {
				errs <- fmt.Errorf("worker %d dial: %w", n, err)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			fmt.Fprintf(conn, "concurrent\n")
			got, errR := readLine(conn)
			if errR != nil || got != "ECHO: concurrent" {
				errs <- fmt.Errorf("worker %d: unexpected %q err=%v", n, got, errR)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// ── 9. MITM compression handling ────────────────────────────────────────────

// portAwareInterceptor is like StandardInterceptor but dials the correct port
// instead of hardcoding 443. Needed for tests where the TLS target runs on a
// random port.
type portAwareInterceptor struct {
	port uint16
}

func (p *portAwareInterceptor) RoundTrip(ctx context.Context, httpReq *http.Request, host string, proxy *proxykit.Proxy) (*http.Response, error) {
	target := fmt.Sprintf("127.0.0.1:%d", p.port)
	conn, err := tls.Dial("tcp", target, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	out := httpReq.Clone(ctx)
	out.URL.Scheme = ""
	out.URL.Host = ""
	out.RequestURI = httpReq.URL.RequestURI()
	if out.RequestURI == "" {
		out.RequestURI = "/"
	}
	if err := out.Write(conn); err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(conn), out)
}

// gzipTargetServer starts a TLS server that returns gzip-compressed responses
// with Content-Encoding: gzip. The body is "GZIP-OK: <path>".
func gzipTargetServer(t *testing.T, ca tls.Certificate) (addr string, port uint16, cleanup func()) {
	t.Helper()
	fp, err := proxykit.NewForgedCertProvider(ca)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := fp.CertForHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := fmt.Sprintf("GZIP-OK: %s", r.URL.Path)
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "text/plain")
			gz := gzip.NewWriter(w)
			gz.Write([]byte(body))
			gz.Close()
		}),
	}
	go srv.Serve(ln)
	return ln.Addr().String(), mustPort(t, ln.Addr().String()), func() { srv.Close() }
}

// TestE2E_MITM_GzipResponse verifies that a gzip response through MITM is
// received correctly by the client — no double-decompression errors.
func TestE2E_MITM_GzipResponse(t *testing.T) {
	ca, err := proxykit.NewCA()
	if err != nil {
		t.Fatal(err)
	}

	_, tlsPort, closeTLS := gzipTargetServer(t, ca)
	defer closeTLS()

	certs, _ := proxykit.NewForgedCertProvider(ca)
	inner := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: tlsPort})
	interceptor := &portAwareInterceptor{port: tlsPort}
	pipeline := proxykit.MITM(certs, interceptor, inner)

	proxyAddr, closeProxy := startHTTPProxy(t, pipeline, directUpstream)
	defer closeProxy()

	caPool, err := caX509Pool(ca)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword("", "")}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/test", tlsPort))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}

	if string(body) != "GZIP-OK: /test" {
		t.Fatalf("body = %q, want %q", body, "GZIP-OK: /test")
	}
}

// TestE2E_MITM_GzipKeepAlive verifies that multiple requests over a single
// keep-alive connection work when the target returns gzip responses. Catches
// Content-Length mismatches that corrupt the H1 framing.
func TestE2E_MITM_GzipKeepAlive(t *testing.T) {
	ca, err := proxykit.NewCA()
	if err != nil {
		t.Fatal(err)
	}

	_, tlsPort, closeTLS := gzipTargetServer(t, ca)
	defer closeTLS()

	certs, _ := proxykit.NewForgedCertProvider(ca)
	inner := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: tlsPort})
	interceptor := &portAwareInterceptor{port: tlsPort}
	pipeline := proxykit.MITM(certs, interceptor, inner)

	proxyAddr, closeProxy := startHTTPProxy(t, pipeline, directUpstream)
	defer closeProxy()

	caPool, err := caX509Pool(ca)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword("", "")}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
		Timeout: 5 * time.Second,
	}

	for i := 0; i < 5; i++ {
		path := fmt.Sprintf("/req%d", i)
		resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d%s", tlsPort, path))
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("request %d: reading body: %v", i, err)
		}
		expected := fmt.Sprintf("GZIP-OK: %s", path)
		if string(body) != expected {
			t.Fatalf("request %d: body = %q, want %q", i, body, expected)
		}
	}
}

// TestE2E_MITM_UncompressedPassesThrough verifies that responses without
// Content-Encoding pass through the MITM unchanged.
func TestE2E_MITM_UncompressedPassesThrough(t *testing.T) {
	ca, err := proxykit.NewCA()
	if err != nil {
		t.Fatal(err)
	}

	// Use a plain TLS server (no gzip) on 127.0.0.1.
	fp, _ := proxykit.NewForgedCertProvider(ca)
	cert, _ := fp.CertForHost("127.0.0.1")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "PLAIN-OK: %s", r.URL.Path)
		}),
	}
	go srv.Serve(ln)
	defer srv.Close()
	tlsPort := mustPort(t, ln.Addr().String())

	certs, _ := proxykit.NewForgedCertProvider(ca)
	inner := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: tlsPort})
	interceptor := &portAwareInterceptor{port: tlsPort}
	pipeline := proxykit.MITM(certs, interceptor, inner)

	proxyAddr, closeProxy := startHTTPProxy(t, pipeline, directUpstream)
	defer closeProxy()

	caPool, err := caX509Pool(ca)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword("", "")}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/hello", tlsPort))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if string(body) != "PLAIN-OK: /hello" {
		t.Fatalf("body = %q, want %q", body, "PLAIN-OK: /hello")
	}
}

// TestE2E_MITM_GzipH2 verifies gzip handling over H2 between client and MITM.
func TestE2E_MITM_GzipH2(t *testing.T) {
	ca, err := proxykit.NewCA()
	if err != nil {
		t.Fatal(err)
	}

	_, tlsPort, closeTLS := gzipTargetServer(t, ca)
	defer closeTLS()

	certs, _ := proxykit.NewForgedCertProvider(ca)
	inner := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: tlsPort})
	interceptor := &portAwareInterceptor{port: tlsPort}
	pipeline := proxykit.MITM(certs, interceptor, inner)

	proxyAddr, closeProxy := startHTTPProxy(t, pipeline, directUpstream)
	defer closeProxy()

	caPool, err := caX509Pool(ca)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword("", "")}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{RootCAs: caPool},
			ForceAttemptHTTP2: true,
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/h2test", tlsPort))
	if err != nil {
		t.Fatalf("H2 request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}

	if string(body) != "GZIP-OK: /h2test" {
		t.Fatalf("body = %q, want %q", body, "GZIP-OK: /h2test")
	}
}

// TestE2E_MITM_HTTPCloakKeepAlive tests multiple sequential requests on the
// same H1 keep-alive connection using the REAL httpcloak TLS fingerprinting
// interceptor (not the simplified portAwareInterceptor). This is the exact
// code path used by the IS24 login flow.
func TestE2E_MITM_HTTPCloakKeepAlive(t *testing.T) {
	ca, err := proxykit.NewCA()
	if err != nil {
		t.Fatal(err)
	}

	// TLS target server with mixed responses
	fp, _ := proxykit.NewForgedCertProvider(ca)
	cert, _ := fp.CertForHost("127.0.0.1")
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	var reqCount int32
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&reqCount, 1)
			body := fmt.Sprintf("req%d:%s:%s", n, r.Method, r.URL.Path)

			if strings.Contains(r.URL.Path, "gzip") {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Type", "application/json")
				gz := gzip.NewWriter(w)
				gz.Write([]byte(body))
				gz.Close()
			} else {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, body)
			}
		}),
	}
	go srv.Serve(ln)
	defer srv.Close()
	tlsPort := mustPort(t, ln.Addr().String())

	// Use TLSFingerprintSpoofing — the real httpcloak interceptor.
	// Empty proxy host = httpcloak connects directly to the target (no upstream proxy).
	// insecure=true since the test target uses a self-signed cert.
	inner := staticSource(&proxykit.Proxy{})
	pipeline := utils.TLSFingerprintSpoofingWithOptions(ca, "chrome-146", true, inner)

	proxyAddr, closeProxy := startHTTPProxy(t, pipeline, directUpstream)
	defer closeProxy()

	caPool, _ := caX509Pool(ca)
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword("", "")}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			TLSClientConfig:     &tls.Config{RootCAs: caPool},
			MaxIdleConnsPerHost: 1,
			MaxConnsPerHost:     1,
		},
		Timeout: 15 * time.Second,
	}

	// Simulate IS24 login flow: 8 sequential requests, mix of GET/POST, gzip/plain
	requests := []struct {
		method string
		path   string
		body   string
	}{
		{"POST", "/nonce/gzip", `{"n":"1"}`},
		{"GET", "/authorize/gzip", ""},
		{"POST", "/introspect/plain", `{"s":"x"}`},
		{"POST", "/identify/gzip", `{"u":"test"}`},
		{"POST", "/challenge/gzip", `{"a":"1"}`},
		{"POST", "/answer/gzip", `{"p":"test"}`},
		{"GET", "/redirect/plain", ""},
		{"POST", "/token/gzip", `{"c":"abc"}`},
	}

	for i, req := range requests {
		var bodyReader io.Reader
		if req.body != "" {
			bodyReader = strings.NewReader(req.body)
		}
		httpReq, _ := http.NewRequest(req.method, fmt.Sprintf("https://127.0.0.1:%d%s", tlsPort, req.path), bodyReader)
		if req.body != "" {
			httpReq.Header.Set("Content-Type", "application/json")
		}

		resp, err := client.Do(httpReq)
		if err != nil {
			t.Fatalf("request %d (%s %s) failed: %v", i+1, req.method, req.path, err)
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("request %d: reading body: %v", i+1, err)
		}

		expected := fmt.Sprintf("req%d:%s:%s", i+1, req.method, req.path)
		if string(respBody) != expected {
			t.Fatalf("request %d: body = %q, want %q", i+1, respBody, expected)
		}
	}
	t.Logf("All %d sequential requests succeeded via httpcloak MITM", len(requests))
}

// TestE2E_MITM_MixedCompressionKeepAlive simulates the IS24 login flow:
// multiple sequential requests on the SAME H1 keep-alive connection where
// some responses are gzip-compressed and some are not. This catches
// Content-Length mismatches, body framing corruption, and connection reuse
// issues after body close.
func TestE2E_MITM_MixedCompressionKeepAlive(t *testing.T) {
	ca, err := proxykit.NewCA()
	if err != nil {
		t.Fatal(err)
	}

	// Target server: some endpoints return gzip, some don't, some return
	// chunked (no Content-Length), some return POST responses.
	fp, _ := proxykit.NewForgedCertProvider(ca)
	cert, _ := fp.CertForHost("127.0.0.1")
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	var requestCount int32
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&requestCount, 1)
			path := r.URL.Path
			body := fmt.Sprintf("req%d:%s:%s", n, r.Method, path)

			switch {
			case strings.HasSuffix(path, "/gzip"):
				// Gzip compressed with Content-Length
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Type", "application/json")
				gz := gzip.NewWriter(w)
				gz.Write([]byte(body))
				gz.Close()
			case strings.HasSuffix(path, "/chunked"):
				// Chunked (no Content-Length), not compressed
				flusher, _ := w.(http.Flusher)
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, body)
				flusher.Flush()
			case strings.HasSuffix(path, "/gzip-chunked"):
				// Gzip + chunked (no Content-Length)
				flusher, _ := w.(http.Flusher)
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Type", "application/json")
				gz := gzip.NewWriter(w)
				gz.Write([]byte(body))
				gz.Close()
				flusher.Flush()
			default:
				// Plain with Content-Length
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, body)
			}
		}),
	}
	go srv.Serve(ln)
	defer srv.Close()
	tlsPort := mustPort(t, ln.Addr().String())

	certs, _ := proxykit.NewForgedCertProvider(ca)
	inner := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: tlsPort})
	interceptor := &portAwareInterceptor{port: tlsPort}
	pipeline := proxykit.MITM(certs, interceptor, inner)

	proxyAddr, closeProxy := startHTTPProxy(t, pipeline, directUpstream)
	defer closeProxy()

	caPool, _ := caX509Pool(ca)
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword("", "")}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool},
			// Force single connection (H1 keep-alive)
			MaxIdleConnsPerHost: 1,
			MaxConnsPerHost:     1,
		},
		Timeout: 10 * time.Second,
	}

	// Simulate IS24 login flow: mix of GET/POST, gzip/plain/chunked
	requests := []struct {
		method string
		path   string
		body   string
	}{
		{"POST", "/nonce/gzip", `{"nonce":"abc"}`},       // 1: POST, gzip
		{"GET", "/authorize/gzip", ""},                    // 2: GET, gzip (like authorize URL)
		{"POST", "/introspect/chunked", `{"state":"x"}`}, // 3: POST, chunked
		{"POST", "/identify/gzip", `{"user":"test"}`},     // 4: POST, gzip
		{"POST", "/challenge/gzip", `{"pass":"test"}`},    // 5: POST, gzip
		{"POST", "/answer/gzip-chunked", `{"otp":"123"}`}, // 6: POST, gzip+chunked
		{"GET", "/redirect/plain", ""},                     // 7: GET, plain
		{"POST", "/token/gzip", `{"code":"abc"}`},          // 8: POST, gzip
	}

	for i, req := range requests {
		var bodyReader io.Reader
		if req.body != "" {
			bodyReader = strings.NewReader(req.body)
		}
		httpReq, _ := http.NewRequest(req.method, fmt.Sprintf("https://127.0.0.1:%d%s", tlsPort, req.path), bodyReader)
		if req.body != "" {
			httpReq.Header.Set("Content-Type", "application/json")
		}

		resp, err := client.Do(httpReq)
		if err != nil {
			t.Fatalf("request %d (%s %s) failed: %v", i+1, req.method, req.path, err)
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("request %d: reading body: %v", i+1, err)
		}

		// Body should start with "req<n>:"
		expected := fmt.Sprintf("req%d:%s:%s", i+1, req.method, req.path)
		if string(respBody) != expected {
			t.Fatalf("request %d: body = %q, want %q", i+1, respBody, expected)
		}
	}
	t.Logf("All %d sequential requests succeeded on same H1 keep-alive connection", len(requests))
}

// TestE2E_MITM_HTTPCloakKeepAliveWithUpstreamProxy tests session reuse through
// an actual upstream HTTP CONNECT proxy — this is the exact architecture used
// by the IS24 login flow (Bun → proxy-gateway MITM → upstream proxy → target).
// The upstream proxy is a simple CONNECT proxy running locally.
func TestE2E_MITM_HTTPCloakKeepAliveWithUpstreamProxy(t *testing.T) {
	ca, err := proxykit.NewCA()
	if err != nil {
		t.Fatal(err)
	}

	// 1. TLS target server with mixed responses
	fp, _ := proxykit.NewForgedCertProvider(ca)
	cert, _ := fp.CertForHost("127.0.0.1")
	targetLn, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	var reqCount int32
	targetSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := atomic.AddInt32(&reqCount, 1)
			body := fmt.Sprintf("req%d:%s:%s", n, r.Method, r.URL.Path)
			if strings.Contains(r.URL.Path, "gzip") {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Type", "application/json")
				gz := gzip.NewWriter(w)
				gz.Write([]byte(body))
				gz.Close()
			} else {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, body)
			}
		}),
	}
	go targetSrv.Serve(targetLn)
	defer targetSrv.Close()
	targetPort := mustPort(t, targetLn.Addr().String())

	// 2. Upstream CONNECT proxy (simulates proxying.io)
	upstreamLn, _ := net.Listen("tcp", "127.0.0.1:0")
	upstreamPort := mustPort(t, upstreamLn.Addr().String())
	go func() {
		for {
			conn, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != "CONNECT" {
					return
				}
				target, err := net.Dial("tcp", req.Host)
				if err != nil {
					fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer target.Close()
				fmt.Fprintf(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				done := make(chan struct{}, 2)
				go func() { io.Copy(target, br); done <- struct{}{} }()
				go func() { io.Copy(c, target); done <- struct{}{} }()
				<-done
			}(conn)
		}
	}()
	defer upstreamLn.Close()

	// 3. Proxy-gateway with httpcloak MITM, routing through upstream proxy
	inner := staticSource(&proxykit.Proxy{Host: "127.0.0.1", Port: upstreamPort})
	pipeline := utils.TLSFingerprintSpoofingWithOptions(ca, "chrome-146", true, inner)

	proxyAddr, closeProxy := startHTTPProxy(t, pipeline, proxykit.HTTPUpstream{})
	defer closeProxy()

	caPool, _ := caX509Pool(ca)
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr, User: url.UserPassword("", "")}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(proxyURL),
			TLSClientConfig:     &tls.Config{RootCAs: caPool},
			MaxIdleConnsPerHost: 1,
			MaxConnsPerHost:     1,
		},
		Timeout: 15 * time.Second,
	}

	requests := []struct {
		method string
		path   string
		body   string
	}{
		{"POST", "/nonce/gzip", `{"n":"1"}`},
		{"GET", "/authorize/gzip", ""},
		{"POST", "/introspect/plain", `{"s":"x"}`},
		{"POST", "/identify/gzip", `{"u":"test"}`},
		{"POST", "/challenge/gzip", `{"a":"1"}`},
		{"POST", "/answer/gzip", `{"p":"test"}`},
		{"GET", "/redirect/plain", ""},
		{"POST", "/token/gzip", `{"c":"abc"}`},
	}

	for i, req := range requests {
		var bodyReader io.Reader
		if req.body != "" {
			bodyReader = strings.NewReader(req.body)
		}
		httpReq, _ := http.NewRequest(req.method, fmt.Sprintf("https://127.0.0.1:%d%s", targetPort, req.path), bodyReader)
		if req.body != "" {
			httpReq.Header.Set("Content-Type", "application/json")
		}

		resp, err := client.Do(httpReq)
		if err != nil {
			t.Fatalf("request %d (%s %s) failed: %v", i+1, req.method, req.path, err)
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("request %d: reading body: %v", i+1, err)
		}

		expected := fmt.Sprintf("req%d:%s:%s", i+1, req.method, req.path)
		if string(respBody) != expected {
			t.Fatalf("request %d: body = %q, want %q", i+1, respBody, expected)
		}
	}
	t.Logf("All %d requests succeeded via httpcloak MITM with upstream proxy", len(requests))
}
