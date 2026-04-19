package utils

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sardanioss/httpcloak"

	"proxy-kit"
)

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
	defer session.Close()

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

	body, _ := resp.Bytes()
	httpResp := &http.Response{
		StatusCode:    resp.StatusCode,
		Status:        fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(string(body))),
		ContentLength: int64(len(body)),
	}
	for k, vs := range resp.Headers {
		for _, v := range vs {
			httpResp.Header.Add(k, v)
		}
	}
	// Ensure Content-Length is consistent with the body we buffered so that
	// the MITM loop can keep the client connection alive across requests.
	httpResp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return httpResp, nil
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
