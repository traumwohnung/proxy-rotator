// Package gateway provides HTTP and SOCKS5 proxy transports.
//
// The gateway extracts raw credentials from the transport protocol and puts
// them into Request.RawUsername / RawPassword. For CONNECT requests it also
// sets Request.Conn (the hijacked client connection). For plain HTTP it sets
// Request.HTTPRequest.
//
// If a Handler returns nil Proxy and nil error, the gateway assumes the
// middleware has handled the connection itself (e.g. MITM interception).
package gateway

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"proxy-gateway/core"
)

// Run starts an HTTP proxy server on addr and blocks.
func Run(addr string, handler core.Handler) error {
	slog.Info("HTTP proxy gateway listening", "addr", addr)
	return http.ListenAndServe(addr, HTTPHandler(handler))
}

// HTTPHandler returns an http.Handler that serves HTTP proxy requests.
func HTTPHandler(handler core.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

		rawUsername, rawPassword, err := extractBasicAuth(r.Header.Get("Proxy-Authorization"))
		if err != nil {
			slog.Warn("auth error", "method", r.Method, "uri", r.RequestURI, "client", clientIP, "err", err)
			w.Header().Set("Proxy-Authenticate", `Basic realm="proxy-gateway"`)
			http.Error(w, err.Error(), http.StatusProxyAuthRequired)
			return
		}

		if r.Method == http.MethodConnect {
			serveConnect(w, r, rawUsername, rawPassword, handler)
		} else {
			servePlainHTTP(w, r, rawUsername, rawPassword, handler)
		}
	})
}

// ---------------------------------------------------------------------------
// CONNECT — hijack, set Conn, let pipeline handle it
// ---------------------------------------------------------------------------

func serveConnect(w http.ResponseWriter, r *http.Request, rawUser, rawPass string, handler core.Handler) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hj.Hijack()
	if err != nil {
		slog.Error("hijack failed", "err", err)
		return
	}

	req := &core.Request{
		RawUsername: rawUser,
		RawPassword: rawPass,
		Target:      r.Host,
		Conn:        clientConn, // middleware can take over
	}

	proxy, err := handler.Resolve(r.Context(), req)
	if err != nil {
		slog.Warn("resolve error", "target", r.Host, "err", err)
		clientConn.Close()
		return
	}

	// nil proxy + nil error = middleware handled the connection itself (e.g. MITM).
	if proxy == nil {
		return
	}

	// Normal tunnel: dial upstream and relay.
	defer clientConn.Close()

	slog.Info("tunneling",
		"target", r.Host,
		"upstream", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
		"upstream_proto", proxy.GetProtocol(),
	)

	var handle core.ConnHandle
	if tracker, ok := handler.(core.ConnectionTracker); ok {
		handle, err = tracker.OpenConnection(req.Sub)
		if err != nil {
			slog.Warn("connection rejected", "sub", req.Sub, "err", err)
			return
		}
	}

	upstreamConn, err := dialUpstream(proxy, r.Host)
	if err != nil {
		slog.Error("upstream dial failed", "err", err)
		if handle != nil {
			handle.Close(0, 0)
		}
		return
	}
	defer upstreamConn.Close()

	sent, received := relay(clientConn, upstreamConn, handle)
	if handle != nil {
		handle.Close(sent, received)
	}
}

// ---------------------------------------------------------------------------
// Plain HTTP — set HTTPRequest, let pipeline handle it
// ---------------------------------------------------------------------------

func servePlainHTTP(w http.ResponseWriter, r *http.Request, rawUser, rawPass string, handler core.Handler) {
	req := &core.Request{
		RawUsername: rawUser,
		RawPassword: rawPass,
		Target:      r.Host,
		HTTPRequest: r,
	}

	proxy, err := handler.Resolve(r.Context(), req)
	if err != nil {
		slog.Warn("resolve error", "target", r.Host, "err", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// If middleware provided a synthetic response, send it.
	if req.HTTPResponse != nil {
		writeHTTPResponse(w, req.HTTPResponse)
		return
	}

	if proxy == nil {
		http.Error(w, "no proxy available", http.StatusServiceUnavailable)
		return
	}

	slog.Info("forwarding",
		"method", r.Method,
		"uri", r.RequestURI,
		"upstream", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
	)

	var handle core.ConnHandle
	if tracker, ok := handler.(core.ConnectionTracker); ok {
		handle, err = tracker.OpenConnection(req.Sub)
		if err != nil {
			http.Error(w, err.Error(), http.StatusTooManyRequests)
			return
		}
	}

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

func extractBasicAuth(headerVal string) (username, password string, err error) {
	b64, ok := strings.CutPrefix(headerVal, "Basic ")
	if !ok {
		return "", "", fmt.Errorf("Proxy-Authorization must use Basic scheme")
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", "", fmt.Errorf("invalid base64 in Proxy-Authorization")
	}
	raw := string(decoded)
	colonIdx := strings.LastIndex(raw, ":")
	if colonIdx < 0 {
		return raw, "", nil
	}
	return raw[:colonIdx], raw[colonIdx+1:], nil
}

func writeHTTPResponse(w http.ResponseWriter, resp *http.Response) {
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		defer resp.Body.Close()
		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}
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
