// Package gateway provides an HTTP proxy server (CONNECT + plain HTTP)
// that delegates proxy resolution to a core.Handler pipeline.
//
// Usage:
//
//	pipeline := middleware.Auth(myAuth,
//	    middleware.Sticky(sources.StaticFile("proxies.txt")),
//	)
//	gateway.Run(":8100", pipeline)
package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"proxy-gateway/core"
)

// Run starts the HTTP proxy server and blocks.
func Run(addr string, handler core.Handler) error {
	slog.Info("proxy gateway listening", "addr", addr)
	return http.ListenAndServe(addr, HTTPHandler(handler))
}

// HTTPHandler returns an http.Handler that serves proxy requests.
// It parses the Proxy-Authorization header to build a core.Request,
// calls handler.Resolve, and tunnels through the returned Proxy.
func HTTPHandler(handler core.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

		req, err := parseBasicAuth(r.Header.Get("Proxy-Authorization"))
		if err != nil {
			slog.Warn("auth error", "method", r.Method, "uri", r.RequestURI, "client", clientIP, "err", err)
			w.Header().Set("Proxy-Authenticate", `Basic realm="proxy-gateway"`)
			http.Error(w, err.Error(), http.StatusProxyAuthRequired)
			return
		}

		proxy, err := handler.Resolve(r.Context(), req)
		if err != nil {
			slog.Warn("resolve error", "sub", req.Sub, "set", req.Set, "err", err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if proxy == nil {
			http.Error(w, "no proxy available", http.StatusServiceUnavailable)
			return
		}

		slog.Info("routing",
			"method", r.Method,
			"uri", r.RequestURI,
			"sub", req.Sub,
			"set", req.Set,
			"upstream", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
			"client", clientIP,
		)

		// Check if the handler (or any wrapper) implements ConnectionTracker.
		var handle core.ConnHandle
		if tracker, ok := handler.(core.ConnectionTracker); ok {
			handle, err = tracker.OpenConnection(req.Sub)
			if err != nil {
				slog.Warn("connection rejected", "sub", req.Sub, "err", err)
				http.Error(w, err.Error(), http.StatusTooManyRequests)
				return
			}
		}

		if r.Method == http.MethodConnect {
			serveConnect(w, r, proxy, handle)
		} else {
			serveHTTP(w, r, proxy, handle)
		}
	})
}

// ---------------------------------------------------------------------------
// Basic auth → core.Request
// ---------------------------------------------------------------------------

func parseBasicAuth(headerVal string) (*core.Request, error) {
	b64, ok := strings.CutPrefix(headerVal, "Basic ")
	if !ok {
		return nil, fmt.Errorf("Proxy-Authorization must use Basic scheme")
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in Proxy-Authorization")
	}

	raw := string(decoded)
	colonIdx := strings.LastIndex(raw, ":")
	if colonIdx < 0 {
		return nil, fmt.Errorf("invalid Basic credentials: missing colon separator")
	}
	usernameJSON := raw[:colonIdx]
	password := raw[colonIdx+1:]
	if usernameJSON == "" {
		return nil, fmt.Errorf("empty username in Proxy-Authorization")
	}

	// Parse the JSON username: {"sub":"...", "set":"...", "minutes":N, "meta":{...}}
	var parsed struct {
		Sub     string                 `json:"sub"`
		Set     string                 `json:"set"`
		Minutes int                    `json:"minutes"`
		Meta    map[string]interface{} `json:"meta"`
	}
	if err := json.Unmarshal([]byte(usernameJSON), &parsed); err != nil {
		return nil, fmt.Errorf("username is not valid JSON: %w", err)
	}
	if parsed.Sub == "" {
		return nil, fmt.Errorf("'sub' must not be empty")
	}
	if parsed.Set == "" {
		return nil, fmt.Errorf("'set' must not be empty")
	}

	return &core.Request{
		Sub:        parsed.Sub,
		Password:   password,
		Set:        parsed.Set,
		Meta:       core.Meta(parsed.Meta),
		SessionKey: b64, // stable key for affinity
		SessionTTL: parsed.Minutes,
	}, nil
}

// ---------------------------------------------------------------------------
// CONNECT tunnel
// ---------------------------------------------------------------------------

func serveConnect(w http.ResponseWriter, r *http.Request, proxy *core.Proxy, handle core.ConnHandle) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		if handle != nil {
			handle.Close(0, 0)
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	conn, _, err := hj.Hijack()
	if err != nil {
		slog.Error("hijack failed", "err", err)
		if handle != nil {
			handle.Close(0, 0)
		}
		return
	}
	defer conn.Close()

	sent, received, err := connectTunnel(conn, r.Host, proxy, handle)
	if handle != nil {
		handle.Close(sent, received)
	}
	if err != nil {
		slog.Debug("tunnel closed", "err", err)
	}
}

func connectTunnel(clientConn net.Conn, target string, proxy *core.Proxy, handle core.ConnHandle) (sent, received int64, err error) {
	upstreamAddr := hostPort(proxy.Host, proxy.Port)
	upstreamConn, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		return 0, 0, fmt.Errorf("connecting to upstream %s: %w", upstreamAddr, err)
	}
	defer upstreamConn.Close()

	// CONNECT handshake with upstream.
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if proxy.Username != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString(
			[]byte(proxy.Username+":"+proxy.Password)) + "\r\n"
	}
	req += "\r\n"
	if _, err = fmt.Fprint(upstreamConn, req); err != nil {
		return 0, 0, fmt.Errorf("sending CONNECT: %w", err)
	}

	// Read full CONNECT response (loop until \r\n\r\n).
	var respBuf []byte
	tmp := make([]byte, 1024)
	for {
		n, readErr := upstreamConn.Read(tmp)
		if n > 0 {
			respBuf = append(respBuf, tmp[:n]...)
		}
		if readErr != nil {
			return 0, 0, fmt.Errorf("reading CONNECT response: %w", readErr)
		}
		for i := 0; i+3 < len(respBuf); i++ {
			if respBuf[i] == '\r' && respBuf[i+1] == '\n' && respBuf[i+2] == '\r' && respBuf[i+3] == '\n' {
				goto gotResponse
			}
		}
	}
gotResponse:
	resp := string(respBuf)
	if len(resp) < 12 || (resp[:12] != "HTTP/1.1 200" && resp[:12] != "HTTP/1.0 200") {
		return 0, 0, fmt.Errorf("upstream rejected CONNECT: %s", resp)
	}

	// Cancellable relay with optional traffic counting.
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelConn := func() {
		cancel()
		_ = clientConn.SetDeadline(immediateDeadline())
		_ = upstreamConn.SetDeadline(immediateDeadline())
	}

	var clientReader io.Reader = clientConn
	var upstreamReader io.Reader = upstreamConn
	if handle != nil {
		clientReader = &countingReader{r: clientConn, upstream: true, handle: handle, cancel: cancelConn}
		upstreamReader = &countingReader{r: upstreamConn, upstream: false, handle: handle, cancel: cancelConn}
	}

	type result struct {
		n   int64
		err error
	}
	sentCh := make(chan result, 1)
	recvCh := make(chan result, 1)
	go func() {
		n, err := io.Copy(upstreamConn, clientReader)
		if tc, ok := upstreamConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		sentCh <- result{n, err}
	}()
	go func() {
		n, err := io.Copy(clientConn, upstreamReader)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		recvCh <- result{n, err}
	}()

	sr := <-sentCh
	rr := <-recvCh
	return sr.n, rr.n, nil
}

// ---------------------------------------------------------------------------
// Plain HTTP forwarding
// ---------------------------------------------------------------------------

func serveHTTP(w http.ResponseWriter, r *http.Request, proxy *core.Proxy, handle core.ConnHandle) {
	var headers []string
	for name, values := range r.Header {
		if isHopByHop(name) {
			continue
		}
		for _, v := range values {
			headers = append(headers, name+": "+v)
		}
	}
	uri := r.RequestURI
	if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
		uri = "http://" + r.Host + uri
	}

	raw, err := ForwardHTTP(r.Method, uri, headers, r.Body, proxy)

	if handle != nil {
		var reqBytes int64
		if r.ContentLength > 0 {
			reqBytes = r.ContentLength
		}
		respBytes := int64(len(raw))
		handle.RecordTraffic(true, reqBytes, func() {})
		handle.RecordTraffic(false, respBytes, func() {})
		handle.Close(reqBytes, respBytes)
	}

	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeRawResponse(w, raw)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type countingReader struct {
	r        io.Reader
	upstream bool
	handle   core.ConnHandle
	cancel   func()
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		cr.handle.RecordTraffic(cr.upstream, int64(n), cr.cancel)
	}
	return n, err
}

func writeRawResponse(w http.ResponseWriter, raw []byte) {
	headerEnd := len(raw)
	for i := 0; i+4 <= len(raw); i++ {
		if raw[i] == '\r' && raw[i+1] == '\n' && raw[i+2] == '\r' && raw[i+3] == '\n' {
			headerEnd = i
			break
		}
	}
	bodyStart := headerEnd + 4
	if bodyStart > len(raw) {
		bodyStart = len(raw)
	}
	lines := strings.Split(string(raw[:headerEnd]), "\r\n")
	if len(lines) == 0 {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	statusCode := http.StatusBadGateway
	if parts := strings.SplitN(lines[0], " ", 3); len(parts) >= 2 {
		if code, err := strconv.Atoi(parts[1]); err == nil {
			statusCode = code
		}
	}
	for _, line := range lines[1:] {
		if k, v, ok := strings.Cut(line, ":"); ok {
			w.Header().Set(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write(raw[bodyStart:])
}

func hostPort(host string, port uint16) string {
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func isHopByHop(header string) bool {
	switch http.CanonicalHeaderKey(header) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade":
		return true
	}
	return false
}

func immediateDeadline() time.Time { return time.Unix(0, 1) }
