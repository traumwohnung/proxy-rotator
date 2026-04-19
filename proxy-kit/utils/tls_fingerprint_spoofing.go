package utils

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak"
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
	certs, err := proxykit.NewForgedCertProvider(ca)
	if err != nil {
		panic(fmt.Sprintf("tls_fingerprint_spoofing: %v", err))
	}
	return proxykit.MITM(certs, &tlsFingerprintInterceptor{spec: &HTTPCloakSpec{Preset: preset}}, inner)
}

// ---------------------------------------------------------------------------
// tlsFingerprintInterceptor
// ---------------------------------------------------------------------------

// tlsFingerprintInterceptor implements proxykit.Interceptor using httpcloak
// to spoof the upstream TLS fingerprint as a real browser or custom spec.
type tlsFingerprintInterceptor struct {
	spec     *HTTPCloakSpec
	insecure bool // skip upstream TLS cert verification (for testing only)
}

func (f *tlsFingerprintInterceptor) RoundTrip(ctx context.Context, httpReq *http.Request, host string, proxy *proxykit.Proxy) (*http.Response, error) {
	proxyURL := proxyToURL(proxy)
	opts := f.spec.sessionOptions(proxyURL, f.insecure)

	session := httpcloak.NewSession(f.spec.Preset, opts...)

	// Prefer httpReq.Host for the target URL: it preserves non-standard ports
	// (e.g. localhost:8443) that the MITM's targetHost() would strip.
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

	// Apply user_agent policy.
	if err := f.spec.applyUserAgentPolicy(headers); err != nil {
		session.Close()
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
		session.Close()
		return nil, fmt.Errorf("httpcloak %s: %w", targetURL, err)
	}

	httpResp := &http.Response{
		StatusCode:    resp.StatusCode,
		Status:        fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          &sessionClosingBody{ReadCloser: resp.Body, session: session},
		ContentLength: -1,
	}
	for k, vs := range resp.Headers {
		for _, v := range vs {
			httpResp.Header.Add(k, v)
		}
	}
	// Preserve upstream Content-Length when present so the MITM loop can
	// keep the client connection alive across HTTP/1.1 keep-alive requests.
	if cl := httpResp.Header.Get("Content-Length"); cl != "" {
		fmt.Sscanf(cl, "%d", &httpResp.ContentLength)
	}
	// Remove Transfer-Encoding — Go's resp.Write will set it based on ContentLength.
	httpResp.Header.Del("Transfer-Encoding")
	return httpResp, nil
}

// sessionClosingBody wraps the httpcloak response body and closes the
// httpcloak session when the body is closed. This ties the session lifetime
// to the body consumption, enabling streaming without buffering.
type sessionClosingBody struct {
	io.ReadCloser
	session *httpcloak.Session
}

func (b *sessionClosingBody) Close() error {
	err := b.ReadCloser.Close()
	b.session.Close()
	return err
}

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
	return &conditionalMITMHandler{
		certs:    certs,
		getSpec:  getSpec,
		inner:    inner,
		insecure: insecure,
	}
}

type conditionalMITMHandler struct {
	certs    *proxykit.ForgedCertProvider
	getSpec  func(context.Context) *HTTPCloakSpec
	inner    proxykit.Handler
	insecure bool
}

func (h *conditionalMITMHandler) Resolve(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
	spec := h.getSpec(ctx)
	if spec.IsZero() {
		return h.inner.Resolve(ctx, req)
	}
	interceptor := &tlsFingerprintInterceptor{spec: spec, insecure: h.insecure}
	mitmHandler := proxykit.MITM(h.certs, interceptor, h.inner)
	return mitmHandler.Resolve(ctx, req)
}
