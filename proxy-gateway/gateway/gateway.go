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

// ---------------------------------------------------------------------------
// HTTPDownstream — implements core.Downstream for HTTP proxy protocol
// ---------------------------------------------------------------------------

// HTTPDownstream accepts HTTP proxy connections (CONNECT + plain HTTP).
type HTTPDownstream struct {
	Upstream core.Upstream
}

// Serve implements core.Downstream.
func (d *HTTPDownstream) Serve(addr string, handler core.Handler) error {
	slog.Info("HTTP proxy gateway listening", "addr", addr)
	return http.ListenAndServe(addr, d.httpHandler(handler))
}

func (d *HTTPDownstream) httpHandler(handler core.Handler) http.Handler {
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
			d.serveConnect(w, r, rawUsername, rawPassword, handler)
		} else {
			d.servePlainHTTP(w, r, rawUsername, rawPassword, handler)
		}
	})
}

func (d *HTTPDownstream) serveConnect(w http.ResponseWriter, r *http.Request, rawUser, rawPass string, handler core.Handler) {
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
		Conn:        clientConn,
	}

	result, err := handler.Resolve(r.Context(), req)
	if err != nil {
		slog.Warn("resolve error", "target", r.Host, "err", err)
		clientConn.Close()
		return
	}

	// nil result or nil proxy = middleware handled it (e.g. MITM).
	if result == nil || result.Proxy == nil {
		return
	}

	defer clientConn.Close()

	proxy := result.Proxy
	slog.Info("tunneling",
		"target", r.Host,
		"upstream", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
		"upstream_proto", proxy.GetProtocol(),
	)

	upstreamConn, err := d.Upstream.Dial(r.Context(), proxy, r.Host)
	if err != nil {
		slog.Error("upstream dial failed", "err", err)
		if result.ConnHandle != nil {
			result.ConnHandle.Close(0, 0)
		}
		return
	}
	defer upstreamConn.Close()

	sent, received := relay(clientConn, upstreamConn, result.ConnHandle)
	if result.ConnHandle != nil {
		result.ConnHandle.Close(sent, received)
	}
}

func (d *HTTPDownstream) servePlainHTTP(w http.ResponseWriter, r *http.Request, rawUser, rawPass string, handler core.Handler) {
	req := &core.Request{
		RawUsername: rawUser,
		RawPassword: rawPass,
		Target:      r.Host,
		HTTPRequest: r,
	}

	result, err := handler.Resolve(r.Context(), req)
	if err != nil {
		slog.Warn("resolve error", "target", r.Host, "err", err)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Synthetic response from middleware.
	if result != nil && result.HTTPResponse != nil {
		resp := result.HTTPResponse
		if result.ResponseHook != nil {
			resp = result.ResponseHook(resp)
		}
		writeHTTPResponse(w, resp)
		return
	}

	if result == nil || result.Proxy == nil {
		http.Error(w, "no proxy available", http.StatusServiceUnavailable)
		return
	}

	proxy := result.Proxy
	slog.Info("forwarding",
		"method", r.Method,
		"uri", r.RequestURI,
		"upstream", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
	)

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

	if result.ConnHandle != nil {
		var reqBytes int64
		if r.ContentLength > 0 {
			reqBytes = r.ContentLength
		}
		respBytes := int64(len(raw))
		result.ConnHandle.RecordTraffic(true, reqBytes, func() {})
		result.ConnHandle.RecordTraffic(false, respBytes, func() {})
		result.ConnHandle.Close(reqBytes, respBytes)
	}

	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeRawResponse(w, raw)
}

// ---------------------------------------------------------------------------
// Legacy compatibility — Run / HTTPHandler
// ---------------------------------------------------------------------------

// Run starts an HTTP proxy gateway with the default upstream dialer.
func Run(addr string, handler core.Handler) error {
	d := &HTTPDownstream{Upstream: DefaultUpstream()}
	return d.Serve(addr, handler)
}

// HTTPHandler returns an http.Handler for mounting in a chi router or
// similar. Uses the default upstream dialer.
func HTTPHandler(handler core.Handler) http.Handler {
	d := &HTTPDownstream{Upstream: DefaultUpstream()}
	return d.httpHandler(handler)
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
