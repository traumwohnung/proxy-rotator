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
		// Return redirect responses as-is to the MITM caller. Following
		// redirects inside the proxy is wrong for two reasons:
		//   1. Apps commonly redirect to non-HTTP schemes for deep links
		//      (custom URL schemes like "appscheme:/callback?code=..." for
		//      mobile deep-linking). httpcloak's URL parser mangles those
		//      into ":80" CONNECT targets that the upstream residential
		//      proxy correctly rejects as 500s.
		//   2. The caller (browser, mobile app, scraper) has its own redirect
		//      policy. Silently following in the proxy bypasses it and can
		//      leak cookies, expose intermediate URLs, or consume auth codes
		//      the caller wanted to inspect.
		// Go's http.Client uses `http.ErrUseLastResponse` for the same
		// purpose.
		httpcloak.WithoutRedirects(),
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

// RoundTrip forwards a single decrypted request through the httpcloak session.
//
// There is deliberately no silent retry here. Any error — pooled tunnel
// closed by upstream, CONNECT rejected, dial failure — is surfaced to the
// caller as-is. Transparently reconnecting would open a fresh CONNECT to the
// residential proxy, which performs a new sticky-session lookup and may land
// on a different exit IP. For flows whose state is IP-bound (auth tokens,
// cookie-bound CSRF, OAuth state), a "successful" reconnect is worse than
// a hard failure because it silently invalidates downstream state.
//
// Request body handling: the MITM's http.ReadRequest hands us a *http.body
// whose lifetime is entangled with the keep-alive loop's bufio.Reader. At
// least one path through that machinery closes the body before httpcloak's
// writer finishes reading it, producing
// "http: invalid Read on closed Body" mid-request. We dodge the whole class
// by fully buffering the request body here and handing httpcloak a
// self-contained *bytes.Reader — which also lets httpcloak type-detect
// Content-Length (http.NewRequestWithContext has a switch on *bytes.Reader)
// instead of falling back to chunked transfer-encoding, which some upstream
// APIs reject as malformed.
// tunnelSessionKey uniquely identifies a session within a tunnel scope. Two
// requests on the same tunnel with the same preset + upstream proxy share the
// session; a different preset or different upstream proxy gets a separate
// session within the same tunnel.
type tunnelSessionKey struct {
	preset   string
	proxyURL string
	insecure bool
}

func (f *tlsFingerprintInterceptor) RoundTrip(ctx context.Context, httpReq *http.Request, host string, proxy *proxykit.Proxy) (*http.Response, error) {
	proxyURL := proxyToURL(proxy)
	start := time.Now()
	seed := GetTopLevelSeed(ctx)

	// Prefer a tunnel-scoped session when available (normal MITM path). The
	// session lives exactly as long as the client TLS tunnel, so cookies and
	// connection pools cannot leak into a subsequent tunnel that shares the
	// same affinity seed. Falls back to the old seed-keyed cross-tunnel cache
	// only when called outside a TunnelScope (tests, direct use).
	var session *httpcloak.Session
	var ownsSession bool
	sessionSource := "fresh"
	if scope := proxykit.GetTunnelScope(ctx); scope != nil {
		key := tunnelSessionKey{preset: f.spec.Preset, proxyURL: proxyURL, insecure: f.insecure}
		v := scope.GetOrSet(key, func() (any, func()) {
			opts := f.spec.sessionOptions(proxyURL, f.insecure)
			s := httpcloak.NewSession(f.spec.Preset, opts...)
			return s, s.Close
		})
		session = v.(*httpcloak.Session)
		sessionSource = "tunnel-scoped"
	} else if f.cache != nil {
		session = f.cache.getOrCreate(ctx, f.spec, proxyURL, f.insecure)
		if session != nil {
			sessionSource = "cached"
		}
	}
	if session == nil {
		opts := f.spec.sessionOptions(proxyURL, f.insecure)
		session = httpcloak.NewSession(f.spec.Preset, opts...)
		ownsSession = true
	}

	// Cookie-transparency: forward only the cookies the client sent; do not
	// let httpcloak inject state it accumulated from previous requests.
	//
	// httpcloak's Session is designed as an HTTP client with its own cookie
	// jar. When a session is reused across flows (for TLS connection reuse,
	// sticky-session affinity, etc.) the jar persists session/SSO cookies
	// set by a successful authentication — and on the next flow, injects
	// those into subsequent auth endpoints, making the target server
	// short-circuit past the login form because the user appears already
	// authenticated. Downstream clients then get a response they don't
	// expect.
	//
	// Clearing before each request makes the jar a no-op on the outbound
	// path. The inbound path still copies every Set-Cookie response header
	// back to the MITM client, so the real cookie state lives with the
	// client — which is the correct place for it in a forwarding proxy.
	session.ClearCookies()

	slog.Debug("mitm.request.begin",
		"host", host,
		"method", httpReq.Method,
		"path", httpReq.URL.RequestURI(),
		"seed", seed,
		"session", sessionSource,
		"upstream_proxy", redactProxyURL(proxyURL),
		"preset", f.spec.Preset)

	// Buffer the request body. See function docstring for why.
	var reqBody io.Reader
	var bodyLen int
	if httpReq.Body != nil && httpReq.Method != http.MethodGet && httpReq.Method != http.MethodHead {
		bodyBytes, readErr := io.ReadAll(httpReq.Body)
		httpReq.Body.Close()
		if readErr != nil {
			slog.Warn("MITM request body buffering failed",
				"host", host, "method", httpReq.Method, "path", httpReq.URL.RequestURI(),
				"err", readErr)
			if ownsSession {
				session.Close()
			}
			return nil, fmt.Errorf("buffering request body: %w", readErr)
		}
		bodyLen = len(bodyBytes)
		if bodyLen > 0 {
			// Pass *bytes.Reader untyped so httpcloak's
			// http.NewRequestWithContext can type-assert for ContentLength.
			reqBody = bytes.NewReader(bodyBytes)
		}
	}

	resp, err := f.doRoundTrip(ctx, session, httpReq, reqBody, host, proxyURL)
	elapsed := time.Since(start)

	// Unified request event. Every MITM request produces exactly one of
	// these — success or failure — with the same field shape. Grep/aggregate
	// by `mitm.request`; classify errors by `err_kind` not by error string.
	event := MITMRequestEvent{
		Host:       host,
		Seed:       seed,
		Preset:     f.spec.Preset,
		SessionSrc: sessionSource,
		Method:     httpReq.Method,
		Path:       httpReq.URL.RequestURI(),
		BodyLen:    bodyLen,
		Elapsed:    elapsed,
	}
	if resp != nil {
		event.Status = resp.StatusCode
		event.ContentLen = resp.ContentLength
	}

	if err != nil {
		event.Err = err
		event.ErrKind = ClassifyError(err)
		switch sessionSource {
		case "fresh":
			session.Close()
		case "cached":
			if seed != 0 && f.cache != nil {
				f.cache.evict(seed)
			}
		case "tunnel-scoped":
			// Tunnel owns session lifecycle; leave in place.
		}
		slog.Warn("mitm.request",
			"host", event.Host,
			"method", event.Method,
			"path", event.Path,
			"seed", event.Seed,
			"preset", event.Preset,
			"session", event.SessionSrc,
			"body_len", event.BodyLen,
			"status", event.Status,
			"elapsed_ms", event.Elapsed.Milliseconds(),
			"err_kind", string(event.ErrKind),
			"err", event.Err,
			"retryable", event.ErrKind.IsSafeToRetry())
		return nil, err
	}

	slog.Debug("mitm.request",
		"host", event.Host,
		"method", event.Method,
		"path", event.Path,
		"seed", event.Seed,
		"preset", event.Preset,
		"session", event.SessionSrc,
		"body_len", event.BodyLen,
		"status", event.Status,
		"content_length", event.ContentLen,
		"elapsed_ms", event.Elapsed.Milliseconds())

	if ownsSession {
		session.Close()
	}
	return resp, nil
}

// redactProxyURL returns the proxy URL with password stripped — the username
// contains sticky-session identifiers which ARE useful for correlation, so we
// keep those.
func redactProxyURL(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	j := strings.Index(u[i+3:], "@")
	if j < 0 {
		return u
	}
	authPart := u[i+3 : i+3+j]
	colon := strings.Index(authPart, ":")
	if colon < 0 {
		return u
	}
	return u[:i+3] + authPart[:colon] + ":<redacted>" + u[i+3+j:]
}

func (f *tlsFingerprintInterceptor) doRoundTrip(ctx context.Context, session *httpcloak.Session, httpReq *http.Request, reqBody io.Reader, host, proxyURL string) (*http.Response, error) {
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
		Body:    reqBody,
	}

	slog.Debug("httpcloak session.Do begin",
		"target", targetURL, "method", httpReq.Method,
		"header_count", len(headers), "has_body", reqBody != nil)
	doStart := time.Now()

	resp, err := session.Do(ctx, cloakReq)
	if err != nil {
		slog.Debug("httpcloak session.Do failed",
			"target", targetURL, "method", httpReq.Method,
			"elapsed_ms", time.Since(doStart).Milliseconds(),
			"err", err)
		return nil, fmt.Errorf("httpcloak %s: %w", targetURL, err)
	}
	slog.Debug("httpcloak session.Do returned",
		"target", targetURL, "method", httpReq.Method,
		"status", resp.StatusCode, "protocol", resp.Protocol,
		"elapsed_ms", time.Since(doStart).Milliseconds())

	bodyStart := time.Now()
	data, err := resp.Bytes()
	if err != nil {
		slog.Debug("httpcloak body read failed",
			"target", targetURL, "status", resp.StatusCode,
			"elapsed_ms", time.Since(bodyStart).Milliseconds(),
			"err", err)
		return nil, fmt.Errorf("reading httpcloak body for %s: %w", targetURL, err)
	}
	slog.Debug("httpcloak body read complete",
		"target", targetURL, "bytes", len(data),
		"elapsed_ms", time.Since(bodyStart).Milliseconds())

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
