package utils

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak"
	httpcloakdns "github.com/sardanioss/httpcloak/dns"
	"github.com/sardanioss/httpcloak/fingerprint"
	httpcloaktransport "github.com/sardanioss/httpcloak/transport"
	utls "github.com/sardanioss/utls"
	"github.com/ua-parser/uap-go/uaparser"

	proxykit "proxy-kit"
)

var uaParser = uaparser.NewFromSaved()

// ---------------------------------------------------------------------------
// HTTPCloakSpec — the "httpcloak" field in the username JSON
// ---------------------------------------------------------------------------

// HTTPCloakSpec is a union type: either a named preset or a custom fingerprint.
//
// Named preset (JSON string):
//
//	"chrome-latest"
//
// Custom fingerprint (JSON object):
//
//	{"preset":"chrome-latest","ja3":"771,4865-...","akamai":"1:65536|..."}
//
// All fields of the object form are optional; Preset defaults to "chrome-latest"
// when not specified.
type HTTPCloakSpec struct {
	// Preset is the base httpcloak browser preset.
	// For the string form this is the entire value.
	// For the object form it defaults to "chrome-latest".
	Preset string `json:"preset"`

	// Custom TLS (JA3) fingerprint. Overrides the preset's TLS stack.
	// Format: TLSVersion,CipherSuites,Extensions,EllipticCurves,PointFormats
	// Example: "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"
	JA3 string `json:"ja3"`

	// Custom HTTP/2 Akamai fingerprint.
	// Format: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
	// Example: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	Akamai string `json:"akamai"`

	// ALPN overrides the preset's ALPN protocol list.
	// Example: ["h2", "http/1.1"]
	ALPN []string `json:"alpn"`

	// SignatureAlgorithms overrides the preset's TLS signature algorithms.
	// Valid values: "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", etc.
	SignatureAlgorithms []string `json:"sig_algs"`

	// CertCompression overrides the preset's cert compression algorithms.
	// Valid values: "brotli", "zlib", "zstd"
	CertCompression []string `json:"cert_compression"`

	// PermuteExtensions randomises the TLS extension order.
	PermuteExtensions bool `json:"permute_extensions"`

	// ECH controls Encrypted Client Hello (hides SNI from network observers):
	//   nil/true — auto-fetch ECH config from target's DNS (default)
	//   false    — disable ECH (SNI visible in plaintext)
	//   "domain" — fetch ECH config from this domain instead of the target
	ECH any `json:"ech,omitempty"`

	// UserAgent controls how the User-Agent header is handled:
	//   "ignore"  — pass through the client's User-Agent unchanged (default)
	//   "preset"  — replace with the preset's User-Agent
	//   "check"   — reject if the client's User-Agent doesn't match the preset's browser family
	UserAgent string `json:"user_agent"`
}

// ParseHTTPCloakSpec decodes a raw JSON value that is either:
//   - a JSON string  → treated as a preset name (e.g. "chrome-latest")
//   - a JSON object  → parsed as an HTTPCloakSpec struct
//
// Returns (nil, nil) when raw is empty or JSON null.
func ParseHTTPCloakSpec(raw json.RawMessage) (*HTTPCloakSpec, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	// null
	if string(raw) == "null" {
		return nil, nil
	}
	// Try string first (named preset shorthand)
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return nil, nil
		}
		return &HTTPCloakSpec{Preset: s}, nil
	}
	// Try object (custom fingerprint)
	var spec HTTPCloakSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("httpcloak must be a preset string or a fingerprint object: %w", err)
	}
	if spec.Preset == "" {
		spec.Preset = "chrome-latest"
	}
	switch spec.UserAgent {
	case "", "ignore", "preset", "check":
		// valid
	default:
		return nil, fmt.Errorf("httpcloak user_agent must be \"ignore\", \"preset\", or \"check\", got %q", spec.UserAgent)
	}
	// Validate ECH field: nil, bool, or string.
	if spec.ECH != nil {
		switch spec.ECH.(type) {
		case bool, string:
			// valid
		case float64:
			// JSON numbers — reject
			return nil, fmt.Errorf("httpcloak ech must be true, false, or a domain string")
		default:
			return nil, fmt.Errorf("httpcloak ech must be true, false, or a domain string, got %T", spec.ECH)
		}
	}
	return &spec, nil
}

// IsZero reports whether the spec is empty / unset.
func (s *HTTPCloakSpec) IsZero() bool {
	return s == nil || s.Preset == ""
}

// sessionOptions builds the httpcloak.SessionOption slice for this spec.
func (s *HTTPCloakSpec) sessionOptions(proxyURL string, insecure bool) []httpcloak.SessionOption {
	opts := []httpcloak.SessionOption{
		httpcloak.WithSessionTimeout(30 * time.Second),
	}
	if proxyURL != "" {
		opts = append(opts, httpcloak.WithSessionProxy(proxyURL))
	}
	if insecure {
		opts = append(opts, httpcloak.WithInsecureSkipVerify())
	}
	// ECH control.
	switch v := s.ECH.(type) {
	case bool:
		if !v {
			opts = append(opts, httpcloak.WithDisableECH())
		}
	case string:
		if v != "" {
			opts = append(opts, httpcloak.WithECHFrom(v))
		}
	}
	// Apply custom fingerprint when any custom field is set.
	if s.JA3 != "" || s.Akamai != "" || len(s.ALPN) > 0 || len(s.SignatureAlgorithms) > 0 || len(s.CertCompression) > 0 || s.PermuteExtensions {
		opts = append(opts, httpcloak.WithCustomFingerprint(httpcloak.CustomFingerprint{
			JA3:                s.JA3,
			Akamai:             s.Akamai,
			ALPN:               s.ALPN,
			SignatureAlgorithms: s.SignatureAlgorithms,
			CertCompression:    s.CertCompression,
			PermuteExtensions:  s.PermuteExtensions,
		}))
	}
	return opts
}

// applyUserAgentPolicy modifies or validates the User-Agent header based on
// the spec's UserAgent mode.
func (s *HTTPCloakSpec) applyUserAgentPolicy(headers map[string][]string) error {
	switch s.UserAgent {
	case "preset":
		preset := fingerprint.Get(s.Preset)
		if preset.UserAgent != "" {
			headers["User-Agent"] = []string{preset.UserAgent}
		}
	case "check":
		preset := fingerprint.Get(s.Preset)
		ua := ""
		for k, vs := range headers {
			if strings.EqualFold(k, "user-agent") && len(vs) > 0 {
				ua = vs[0]
				break
			}
		}
		if ua == "" {
			return fmt.Errorf("user_agent=check: no User-Agent header provided")
		}
		if !userAgentMatchesPreset(ua, preset.UserAgent) {
			return fmt.Errorf("user_agent=check: User-Agent %q is not consistent with preset %q", ua, s.Preset)
		}
	}
	// "ignore" or "": pass through unchanged
	return nil
}

// userAgentMatchesPreset checks if a User-Agent string is consistent with the
// preset's browser family. It parses both the client UA and the preset's UA
// using ua-parser and compares browser families.
func userAgentMatchesPreset(clientUA, presetUA string) bool {
	if presetUA == "" {
		return true // no preset UA to compare against
	}
	clientParsed := uaParser.Parse(clientUA)
	presetParsed := uaParser.Parse(presetUA)

	clientFamily := strings.ToLower(clientParsed.UserAgent.Family)
	presetFamily := strings.ToLower(presetParsed.UserAgent.Family)

	if clientFamily == "" || presetFamily == "" {
		return true // can't determine, allow
	}
	return clientFamily == presetFamily
}

// ---------------------------------------------------------------------------
// TLSFingerprintSpoofing — static MITM middleware (preset-only)
// ---------------------------------------------------------------------------

// TLSFingerprintSpoofing returns MITM middleware that forwards decrypted
// requests using httpcloak, making the upstream TLS handshake look like a
// real browser instead of Go's crypto/tls.
//
// Usage:
//
//	ca, _ := proxykit.NewCA()
//	pipeline := utils.TLSFingerprintSpoofing(ca, "chrome-latest", inner)
//
// Preset examples: "chrome-latest", "firefox-latest", "safari-latest"
func TLSFingerprintSpoofing(ca tls.Certificate, preset string, inner proxykit.Handler) proxykit.Handler {
	return TLSFingerprintSpoofingWithOptions(ca, preset, false, inner)
}

func TLSFingerprintSpoofingWithOptions(ca tls.Certificate, preset string, insecure bool, inner proxykit.Handler) proxykit.Handler {
	certs, err := proxykit.NewForgedCertProvider(ca)
	if err != nil {
		panic(fmt.Sprintf("tls_fingerprint_spoofing: %v", err))
	}
	return proxykit.MITM(certs, &tlsFingerprintInterceptor{
		spec:     &HTTPCloakSpec{Preset: preset},
		insecure: insecure,
		cache:    newHTTPCloakSessionCache(),
	}, inner)
}

// ---------------------------------------------------------------------------
// tlsFingerprintInterceptor
// ---------------------------------------------------------------------------

// tlsFingerprintInterceptor implements proxykit.Interceptor using httpcloak
// to spoof the upstream TLS fingerprint as a real browser or custom spec.
type tlsFingerprintInterceptor struct {
	spec     *HTTPCloakSpec
	insecure bool // skip upstream TLS cert verification (for testing only)
	cache    *httpcloakSessionCache
}

func (f *tlsFingerprintInterceptor) RoundTrip(ctx context.Context, httpReq *http.Request, host string, proxy *proxykit.Proxy) (*http.Response, error) {
	proxyURL := proxyToURL(proxy)

	var session *httpcloak.Session
	var ownsSession bool
	if f.cache != nil {
		session = f.cache.getOrCreate(ctx, f.spec, proxyURL, f.insecure)
	}
	if session == nil {
		opts := f.spec.sessionOptions(proxyURL, f.insecure)
		session = httpcloak.NewSession(f.spec.Preset, opts...)
		ownsSession = true
	}

	// Buffer request body so it can be replayed on retry (the original
	// httpReq.Body is a one-shot reader from the MITM H1 connection).
	var reqBodyBytes []byte
	if httpReq.Body != nil && httpReq.Method != http.MethodGet && httpReq.Method != http.MethodHead {
		var readErr error
		reqBodyBytes, readErr = io.ReadAll(httpReq.Body)
		httpReq.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("reading request body: %w", readErr)
		}
		httpReq.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
	}

	resp, err := f.doRoundTrip(ctx, session, httpReq, host, proxyURL)

	// Retry once on stale connection errors — the upstream proxy (e.g.
	// proxying.io) may have closed the CONNECT tunnel during idle. Evict
	// the cached session and retry with a fresh one.
	if err != nil && !ownsSession && isStaleConnectionError(err) {
		slog.Debug("httpcloak stale session, retrying with fresh",
			"host", host, "err", err)
		seed := GetTopLevelSeed(ctx)
		if seed != 0 && f.cache != nil {
			f.cache.evict(seed)
		}
		session.Close()
		opts := f.spec.sessionOptions(proxyURL, f.insecure)
		session = httpcloak.NewSession(f.spec.Preset, opts...)
		ownsSession = true
		// Reset request body for replay
		if reqBodyBytes != nil {
			httpReq.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
		}
		resp, err = f.doRoundTrip(ctx, session, httpReq, host, proxyURL)
	}

	if err != nil {
		if ownsSession {
			session.Close()
		}
		return nil, err
	}
	if ownsSession {
		session.Close()
	}
	return resp, nil
}

func (f *tlsFingerprintInterceptor) doRoundTrip(ctx context.Context, session *httpcloak.Session, httpReq *http.Request, host, proxyURL string) (*http.Response, error) {
	urlHost := httpReq.Host
	if urlHost == "" {
		urlHost = host
	}
	targetURL := fmt.Sprintf("https://%s%s", urlHost, httpReq.URL.RequestURI())

	headers := make(map[string][]string)
	for k, vs := range httpReq.Header {
		lower := strings.ToLower(k)
		if lower == "connection" || lower == "proxy-authorization" || lower == "proxy-connection" {
			continue
		}
		headers[k] = vs
	}

	if err := f.spec.applyUserAgentPolicy(headers); err != nil {
		return nil, err
	}

	cloakReq := &httpcloak.Request{
		Method:  httpReq.Method,
		URL:     targetURL,
		Headers: headers,
	}
	if httpReq.Body != nil && httpReq.Method != http.MethodGet && httpReq.Method != http.MethodHead {
		cloakReq.Body = httpReq.Body
	}

	resp, err := session.Do(ctx, cloakReq)
	if err != nil {
		return nil, fmt.Errorf("httpcloak %s: %w", targetURL, err)
	}

	data, err := resp.Bytes()
	if err != nil {
		return nil, fmt.Errorf("reading httpcloak body for %s: %w", targetURL, err)
	}

	httpResp := &http.Response{
		StatusCode:    resp.StatusCode,
		Status:        fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
	}
	for k, vs := range resp.Headers {
		for _, v := range vs {
			httpResp.Header.Add(k, v)
		}
	}
	httpResp.Header.Del("Content-Encoding")
	httpResp.Header.Del("Content-Length")
	httpResp.Header.Del("Transfer-Encoding")
	return httpResp, nil
}

// isStaleConnectionError detects errors from stale/closed upstream connections.
func isStaleConnectionError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "EOF") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "closed") ||
		strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "CONNECT failed") ||
		strings.Contains(s, "dial_proxy")
}

// closeHTTPCloakBody closes just the underlying HTTP response body of an
// httpcloak StreamResponse, without canceling the session context. This frees
// the H2 stream / H1 connection for reuse while keeping the session alive.
//
// httpcloak's StreamResponse.Close() always calls cancel() which poisons the
// DialTLS implements proxykit.WebSocketDialer. It dials the target with a
// browser-like TLS fingerprint using utls, optionally through an upstream proxy.
// target is "host:port".
func (f *tlsFingerprintInterceptor) DialTLS(ctx context.Context, target string, proxy *proxykit.Proxy) (net.Conn, error) {
	preset := fingerprint.Get(f.spec.Preset)
	host, _, _ := net.SplitHostPort(target)

	dialer := &net.Dialer{Timeout: 30 * time.Second}
	httpcloaktransport.SetDialerControl(dialer, &preset.TCPFingerprint)

	var rawConn net.Conn
	var err error
	if proxy.Host == "" {
		rawConn, err = dialer.DialContext(ctx, "tcp", target)
	} else {
		rawConn, err = dialThroughProxy(ctx, dialer, proxy, target)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}

	tlsConfig := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: f.insecure,
	}

	// Fetch ECH config unless disabled.
	if echDisabled, ok := f.spec.ECH.(bool); !ok || echDisabled != false {
		echDomain := host
		if domain, ok := f.spec.ECH.(string); ok && domain != "" {
			echDomain = domain
		}
		if echConfig, err := httpcloakdns.FetchECHConfigs(ctx, echDomain); err == nil && echConfig != nil {
			tlsConfig.EncryptedClientHelloConfigList = echConfig
		}
	}

	tlsConn := utls.UClient(rawConn, tlsConfig, preset.ClientHelloID)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake %s: %w", host, err)
	}
	return tlsConn, nil
}

// dialThroughProxy establishes a CONNECT tunnel through an upstream HTTP proxy
// and returns the raw tunnel connection.
func dialThroughProxy(ctx context.Context, dialer *net.Dialer, proxy *proxykit.Proxy, target string) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", proxy.Host, proxy.Port)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to proxy %s: %w", addr, err)
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if proxy.Username != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(proxy.Username + ":" + proxy.Password))
		req += "Proxy-Authorization: Basic " + creds + "\r\n"
	}
	req += "\r\n"

	if _, err := fmt.Fprint(conn, req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("sending CONNECT: %w", err)
	}

	// Read response.
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	var respBuf []byte
	tmp := make([]byte, 1024)
	for {
		n, readErr := conn.Read(tmp)
		if n > 0 {
			respBuf = append(respBuf, tmp[:n]...)
		}
		if readErr != nil {
			conn.Close()
			return nil, fmt.Errorf("reading CONNECT response: %w", readErr)
		}
		if containsCRLFCRLF(respBuf) {
			break
		}
	}
	conn.SetDeadline(time.Time{})

	resp := string(respBuf)
	if len(resp) < 12 || (resp[:12] != "HTTP/1.1 200" && resp[:12] != "HTTP/1.0 200") {
		conn.Close()
		return nil, fmt.Errorf("proxy rejected CONNECT: %s", resp)
	}
	return conn, nil
}

func containsCRLFCRLF(b []byte) bool {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// proxyToURL
// ---------------------------------------------------------------------------

// proxyToURL converts a proxykit.Proxy to a URL string for httpcloak.
// Returns "" when proxy.Host is empty, meaning a direct connection (no upstream proxy).
func proxyToURL(proxy *proxykit.Proxy) string {
	if proxy.Host == "" {
		return ""
	}
	var scheme string
	switch proxy.Proto() {
	case proxykit.ProtocolSOCKS5:
		scheme = "socks5"
	default:
		scheme = "http"
	}
	if proxy.Username != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%d", scheme, proxy.Username, proxy.Password, proxy.Host, proxy.Port)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, proxy.Host, proxy.Port)
}

// ---------------------------------------------------------------------------
// ConditionalFingerprintMITM
// ---------------------------------------------------------------------------

// ConditionalFingerprintMITM returns a Handler that activates MITM + httpcloak
// fingerprint spoofing only when getSpec returns a non-nil, non-zero spec.
// When getSpec returns nil the request is forwarded unchanged through inner.
//
// getSpec is typically wired to a context getter set by credential-parsing
// middleware (e.g. getHTTPCloakSpec from proxy-gateway's username.go).
//
// The CA certificate is used to forge per-host TLS certificates for MITM.
// All forged certificates share a single cert cache for efficiency.
//
// Set PROXY_MITM_INSECURE_UPSTREAM=true to skip upstream TLS cert verification
// (useful when testing against servers with self-signed certificates).
func ConditionalFingerprintMITM(ca tls.Certificate, getSpec func(context.Context) *HTTPCloakSpec, inner proxykit.Handler) proxykit.Handler {
	certs, err := proxykit.NewForgedCertProvider(ca)
	if err != nil {
		panic(fmt.Sprintf("ConditionalFingerprintMITM: %v", err))
	}
	insecure := os.Getenv("PROXY_MITM_INSECURE_UPSTREAM") == "true"
	cache := newHTTPCloakSessionCache()
	return &conditionalMITMHandler{
		certs:    certs,
		getSpec:  getSpec,
		inner:    inner,
		insecure: insecure,
		cache:    cache,
	}
}

type conditionalMITMHandler struct {
	certs    *proxykit.ForgedCertProvider
	getSpec  func(context.Context) *HTTPCloakSpec
	inner    proxykit.Handler
	insecure bool
	cache    *httpcloakSessionCache
}

func (h *conditionalMITMHandler) Resolve(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
	spec := h.getSpec(ctx)
	if spec.IsZero() {
		return h.inner.Resolve(ctx, req)
	}
	interceptor := &tlsFingerprintInterceptor{spec: spec, insecure: h.insecure, cache: h.cache}
	mitmHandler := proxykit.MITM(h.certs, interceptor, h.inner)
	return mitmHandler.Resolve(ctx, req)
}
