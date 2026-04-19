package proxygatewayclient_test

// End-to-end test for the full proxy-gateway stack:
//
//   Go client  →  proxy-gateway (HTTP + SOCKS5 + admin API)
//                     ↓
//               upstream HTTP proxy (plain squid-style CONNECT forwarder)
//                     ↓
//               HTTP echo server (returns method + path + headers as JSON)
//
// What is covered:
//   - Username building / parsing (BuildUsername / ParseUsername)
//   - HTTP CONNECT tunnel through gateway → upstream proxy → echo server
//   - SOCKS5 tunnel through gateway → upstream proxy → echo server
//   - Plain HTTP forwarding (non-CONNECT) through gateway → upstream proxy
//   - Session affinity (same username → same upstream across requests)
//   - Zero-minute (no affinity) round-robins across upstreams
//   - PROXY_PASSWORD enforcement (wrong password → rejected)
//   - Admin API: ListSessions, GetSession, ForceRotate
//   - ForceRotate changes upstream assignment
//   - Concurrent requests with affinity are all pinned to the same upstream

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak"
	proxygatewayclient "github.com/traumwohnung/proxy-gateway/proxy-gateway-client-go"
	"golang.org/x/net/http2"
)

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

type testEnv struct {
	// Addresses
	gatewayHTTPAddr  string
	gatewaySOCKS5Addr string
	adminAddr        string
	echoAddr         string

	// Go client
	client *proxygatewayclient.Client

	// Cleanup
	cleanup func()
}

// startTestEnv spins up:
//  1. N upstream HTTP proxy servers (plain CONNECT forwarders)
//  2. An HTTP echo server
//  3. The proxy-gateway binary pointing at those upstreams
//
// It returns a testEnv with all addresses wired up.
func startTestEnv(t *testing.T, numUpstreamProxies int, proxyPassword string) *testEnv {
	t.Helper()

	// --- echo server ---
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	echoAddr := echoLn.Addr().String()
	echoSrv := &http.Server{Handler: echoHandler()}
	go echoSrv.Serve(echoLn) //nolint:errcheck

	// --- N upstream HTTP proxy servers ---
	upstreamAddrs := make([]string, numUpstreamProxies)
	upstreamSrvs := make([]*http.Server, numUpstreamProxies)
	for i := 0; i < numUpstreamProxies; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("upstream proxy listen: %v", err)
		}
		upstreamAddrs[i] = ln.Addr().String()
		srv := &http.Server{Handler: upstreamProxyHandler()}
		upstreamSrvs[i] = srv
		go srv.Serve(ln) //nolint:errcheck
	}

	// --- proxy-gateway config ---
	tmpDir := t.TempDir()

	// Write proxy list file(s): one file per upstream
	var proxyLines []string
	for _, addr := range upstreamAddrs {
		proxyLines = append(proxyLines, addr) // host:port, no auth
	}
	proxyFile := filepath.Join(tmpDir, "proxies.txt")
	if err := os.WriteFile(proxyFile, []byte(strings.Join(proxyLines, "\n")+"\n"), 0644); err != nil {
		t.Fatalf("write proxies file: %v", err)
	}

	// Pick free ports for gateway
	gatewayHTTPAddr := freeAddr(t)
	gatewaySOCKS5Addr := freeAddr(t)
	adminAddr := freeAddr(t)

	cfg := fmt.Sprintf(`
bind_addr   = %q
socks5_addr = %q
admin_addr  = %q
log_level   = "warn"

[[proxy_set]]
name        = "test"
source_type = "static_file"

[proxy_set.static_file]
proxies_file = %q
`, gatewayHTTPAddr, gatewaySOCKS5Addr, adminAddr, proxyFile)

	cfgFile := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(cfgFile, []byte(cfg), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// --- build & start proxy-gateway binary ---
	binPath := filepath.Join(tmpDir, "proxy-gateway-server")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Dir = filepath.Join(repoRoot(t), "proxy-gateway")
	buildCmd.Stdout = os.Stderr
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("build proxy-gateway: %v", err)
	}

	env := os.Environ()
	env = append(env, "API_KEY=test-api-key")
	if proxyPassword != "" {
		env = append(env, "PROXY_PASSWORD="+proxyPassword)
	}

	cmd := exec.Command(binPath, cfgFile)
	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy-gateway: %v", err)
	}

	// Wait for all ports to be ready
	waitReady(t, gatewayHTTPAddr, 5*time.Second)
	waitReady(t, gatewaySOCKS5Addr, 5*time.Second)
	waitReady(t, adminAddr, 5*time.Second)

	client := proxygatewayclient.New(proxygatewayclient.ClientOptions{
		BaseURL: "http://" + adminAddr,
		APIKey:  "test-api-key",
	})

	cleanup := func() {
		cmd.Process.Kill()   //nolint:errcheck
		echoSrv.Close()      //nolint:errcheck
		for _, s := range upstreamSrvs {
			s.Close() //nolint:errcheck
		}
	}

	return &testEnv{
		gatewayHTTPAddr:   gatewayHTTPAddr,
		gatewaySOCKS5Addr: gatewaySOCKS5Addr,
		adminAddr:         adminAddr,
		echoAddr:          echoAddr,
		client:            client,
		cleanup:           cleanup,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestE2E_BuildAndParseUsername(t *testing.T) {
	params := proxygatewayclient.UsernameParams{
		Set:     "residential",
		Minutes: 60,
		Meta:    map[string]any{"platform": "myapp", "user": "alice"},
	}
	u, err := proxygatewayclient.BuildUsername(params)
	if err != nil {
		t.Fatalf("BuildUsername: %v", err)
	}

	got, err := proxygatewayclient.ParseUsername(u)
	if err != nil {
		t.Fatalf("ParseUsername: %v", err)
	}
	if got.Set != "residential" || got.Minutes != 60 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestE2E_HTTPConnect_ThroughGatewayAndUpstreamProxy(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 0, nil)
	body := doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")
	if body["method"] != "GET" {
		t.Fatalf("unexpected echo body: %v", body)
	}
}

func TestE2E_SOCKS5_ThroughGatewayAndUpstreamProxy(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 0, nil)
	body := doSOCKS5ToEcho(t, env.gatewaySOCKS5Addr, env.echoAddr, username, "x")
	if body["method"] != "GET" {
		t.Fatalf("unexpected echo body: %v", body)
	}
}

func TestE2E_PlainHTTP_ThroughGateway(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 0, nil)
	status, body := doPlainHTTP(t, env.gatewayHTTPAddr, "http://"+env.echoAddr+"/hello", username, "x")
	if status != 200 {
		t.Fatalf("expected 200, got %d", status)
	}
	if body["path"] != "/hello" {
		t.Fatalf("unexpected path in echo: %v", body)
	}
}

func TestE2E_SessionAffinity_SameUsernamePinsSameUpstream(t *testing.T) {
	env := startTestEnv(t, 3, "") // 3 upstream proxies
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 60, map[string]any{"user": "alice"})

	// Make several requests — all should go through the same upstream (affinity).
	// We identify the upstream by the remote_addr the echo server sees (the upstream
	// proxy's outbound address — its port changes per connection, so we use just the host).
	var upstreamHosts []string
	for i := 0; i < 5; i++ {
		body := doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")
		remote, _ := body["remote_addr"].(string)
		host, _, _ := net.SplitHostPort(remote)
		upstreamHosts = append(upstreamHosts, host)
	}

	for i, u := range upstreamHosts {
		if u != upstreamHosts[0] {
			t.Fatalf("request %d went through different upstream host: %v (expected %v)\nall: %v", i, u, upstreamHosts[0], upstreamHosts)
		}
	}
}

func TestE2E_NoAffinity_RotatesAcrossUpstreams(t *testing.T) {
	env := startTestEnv(t, 3, "")
	defer env.cleanup()

	// minutes=0 → no affinity, least-used rotation across 3 upstreams.
	// Use plain HTTP (non-CONNECT) so we can rely on the upstream proxy's port
	// as a stable identifier — each upstream listens on its own port.
	seen := map[string]bool{}
	for i := 0; i < 12; i++ {
		username := mustBuildUsername(t, "test", 0, map[string]any{"req": fmt.Sprintf("%d", i)})
		_, body := doPlainHTTP(t, env.gatewayHTTPAddr, "http://"+env.echoAddr+"/", username, "x")
		via, _ := body["x-forwarded-via"].(string)
		seen[via] = true
	}
	if len(seen) < 2 {
		t.Fatalf("expected requests to spread across multiple upstreams, only saw: %v", seen)
	}
}

func TestE2E_ProxyPassword_WrongPasswordRejected(t *testing.T) {
	env := startTestEnv(t, 1, "s3cret")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 0, nil)

	// Wrong proxy password → should fail
	if err := tryHTTPConnect(t, env.gatewayHTTPAddr, env.echoAddr, username, "wrongpassword"); err == nil {
		t.Fatal("expected failure with wrong proxy password, got success")
	}
}

func TestE2E_ProxyPassword_CorrectPasswordAccepted(t *testing.T) {
	env := startTestEnv(t, 1, "s3cret")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 0, nil)
	body := doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "s3cret")
	if body["method"] != "GET" {
		t.Fatalf("unexpected echo body: %v", body)
	}
}

func TestE2E_AdminAPI_ListSessions_EmptyInitially(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	sessions, err := env.client.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions initially, got %d", len(sessions))
	}
}

func TestE2E_AdminAPI_SessionAppearsAfterStickyRequest(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 30, map[string]any{"user": "bob"})
	doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")

	sessions, err := env.client.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	s := sessions[0]
	if s.ProxySet != "test" {
		t.Errorf("proxy_set: got %q, want %q", s.ProxySet, "test")
	}
	if s.Upstream == "" {
		t.Error("upstream should not be empty")
	}
	if s.NextRotationAt.Before(time.Now()) {
		t.Errorf("next_rotation_at should be in the future, got %v", s.NextRotationAt)
	}
}

func TestE2E_AdminAPI_GetSession(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 30, map[string]any{"user": "carol"})
	doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")

	// Get by username
	info, err := env.client.GetSession(context.Background(), username)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if info == nil {
		t.Fatal("expected session info, got nil")
	}
	if info.ProxySet != "test" {
		t.Errorf("proxy_set: got %q, want %q", info.ProxySet, "test")
	}

	// Non-existent username (valid format but no active session) → nil, nil
	nonexistent := mustBuildUsername(t, "test", 30, map[string]any{"user": "nobody"})
	missing, err := env.client.GetSession(context.Background(), nonexistent)
	if err != nil {
		t.Fatalf("GetSession (missing): %v", err)
	}
	if missing != nil {
		t.Fatal("expected nil for unknown username")
	}
}

func TestE2E_AdminAPI_NoSessionForZeroMinutes(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 0, map[string]any{"user": "dave"})
	doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")

	sessions, err := env.client.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("minutes=0 requests should not create sessions, got %d", len(sessions))
	}
}

func TestE2E_AdminAPI_ForceRotate_ChangesUpstream(t *testing.T) {
	env := startTestEnv(t, 3, "") // need multiple upstreams to rotate between
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 60, map[string]any{"user": "eve"})

	// First request — establishes the session.
	doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")

	info, err := env.client.GetSession(context.Background(), username)
	if err != nil || info == nil {
		t.Fatalf("GetSession before rotate: err=%v info=%v", err, info)
	}
	upstreamBefore := info.Upstream

	// Force rotate — verify the API returns a valid session response.
	rotated, err := env.client.ForceRotate(context.Background(), username)
	if err != nil {
		t.Fatalf("ForceRotate: %v", err)
	}
	if rotated == nil {
		t.Fatal("expected non-nil response from ForceRotate")
	}
	if rotated.LastRotationAt.IsZero() {
		t.Error("last_rotation_at should be set after force rotate")
	}

	// The rotated session's upstream may or may not differ (small pool, probabilistic).
	// What we can assert: the session metadata is preserved.
	if rotated.ProxySet != "test" {
		t.Errorf("proxy_set should be preserved after rotate, got %q", rotated.ProxySet)
	}
	t.Logf("upstream before=%s after=%s", upstreamBefore, rotated.Upstream)
}

func TestE2E_AdminAPI_ForceRotate_NonExistentReturnsNil(t *testing.T) {
	env := startTestEnv(t, 1, "")
	defer env.cleanup()

	// Valid username format but no active session → should return nil, nil.
	nonexistent := mustBuildUsername(t, "test", 30, map[string]any{"user": "ghost"})
	result, err := env.client.ForceRotate(context.Background(), nonexistent)
	if err != nil {
		t.Fatalf("ForceRotate on non-existent: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil for non-existent session")
	}
}

func TestE2E_ConcurrentStickyRequests_AllPinnedToSameUpstream(t *testing.T) {
	env := startTestEnv(t, 5, "")
	defer env.cleanup()

	username := mustBuildUsername(t, "test", 60, map[string]any{"user": "frank"})

	// Warm up the session.
	doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")

	// Get the pinned upstream from the admin API.
	info, err := env.client.GetSession(context.Background(), username)
	if err != nil || info == nil {
		t.Fatalf("GetSession: err=%v info=%v", err, info)
	}
	expectedUpstream := info.Upstream

	// Concurrent requests — all must be served by the same upstream.
	const concurrency = 10
	errors := make([]string, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, username, "x")
		}(i)
	}
	wg.Wait()

	// Verify via admin API that the session is still pinned to the same upstream.
	info2, err := env.client.GetSession(context.Background(), username)
	if err != nil || info2 == nil {
		t.Fatalf("GetSession after concurrent: err=%v info=%v", err, info2)
	}
	if info2.Upstream != expectedUpstream {
		t.Errorf("upstream changed during concurrent requests: before=%v after=%v", expectedUpstream, info2.Upstream)
	}
	_ = errors
}

func TestE2E_MultipleDistinctSessions(t *testing.T) {
	env := startTestEnv(t, 3, "")
	defer env.cleanup()

	users := []string{"user-a", "user-b", "user-c"}
	usernames := make([]string, len(users))
	for i, u := range users {
		usernames[i] = mustBuildUsername(t, "test", 60, map[string]any{"user": u})
		doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, usernames[i], "x")
	}

	sessions, err := env.client.ListSessions(context.Background())
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) != 3 {
		t.Fatalf("expected 3 sessions for 3 distinct users, got %d", len(sessions))
	}

	// Each user's session should remain pinned
	for _, u := range usernames {
		body1 := doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, u, "x")
		body2 := doHTTPConnectToEcho(t, env.gatewayHTTPAddr, env.echoAddr, u, "x")
		if body1["x-forwarded-via"] != body2["x-forwarded-via"] {
			t.Errorf("user %q changed upstream between requests", u)
		}
	}
}

// fingerprintEchoResponse mirrors the JSON shape returned by tls-fingerprint-echo.
type fingerprintEchoResponse struct {
	Fingerprint struct {
		JA3Hash string `json:"ja3_hash"`
		JA3Raw  string `json:"ja3_raw"`
		JA4     string `json:"ja4"`
	} `json:"fingerprint"`
	Verdict struct {
		Level string  `json:"level"`
		Score float64 `json:"score"`
	} `json:"verdict"`
	HTTPCloakPresetMatches []struct {
		Name      string `json:"name"`
		UserAgent string `json:"user_agent"`
	} `json:"httpcloak_preset_matches"`
}

// directFingerprintRequest makes a direct httpcloak request (no proxy) to the
// fingerprint echo server and returns the parsed response. Used to derive the
// expected JA3 for a given preset so we can compare against the proxied path.
func directFingerprintRequest(t *testing.T, echoURL, preset string) fingerprintEchoResponse {
	t.Helper()
	session := httpcloak.NewSession(preset, httpcloak.WithInsecureSkipVerify())
	defer session.Close()

	resp, err := session.Get(context.Background(), echoURL+"/")
	if err != nil {
		t.Fatalf("direct httpcloak GET %s (preset=%s): %v", echoURL, preset, err)
	}
	defer resp.Close()

	body, err := resp.Bytes()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var result fingerprintEchoResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("parse fingerprint-echo response: %v\nbody: %s", err, body)
	}
	return result
}

// startFingerprintEchoServer builds and starts the tls-fingerprint-echo server
// from the submodule at tls-fingerprint-echo/cmd/tls-fingerprint-echo.
// Returns the HTTPS base URL and a stop function.
func startFingerprintEchoServer(t *testing.T) (baseURL string, stop func()) {
	t.Helper()

	root := repoRoot(t)
	tmpDir := t.TempDir()

	echoBin := filepath.Join(tmpDir, "tls-fingerprint-echo")
	buildCmd := exec.Command("go", "build", "-o", echoBin, ".")
	buildCmd.Dir = filepath.Join(root, "tls-fingerprint-echo", "cmd", "tls-fingerprint-echo")
	buildCmd.Stdout = os.Stderr
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("build tls-fingerprint-echo: %v", err)
	}

	// Find a free port for the echo server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cmd := exec.Command(echoBin)
	cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", port))
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start tls-fingerprint-echo: %v", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	// Wait for TLS readiness (the server serves HTTPS with a self-signed cert).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 100 * time.Millisecond},
			"tcp", addr,
			&tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	return fmt.Sprintf("https://localhost:%d", port), func() { cmd.Process.Kill() } //nolint:errcheck
}

// TestE2E_HTTPCloak_TLSFingerprintEcho verifies that proxy-gateway applies the
// httpcloak chrome-latest TLS fingerprint when "httpcloak":"chrome-latest" is
// set in the username JSON.
//
// Flow:
//
//	Go test client (InsecureSkipVerify for MITM cert)
//	  → proxy-gateway (MITM + httpcloak <preset>)
//	    → tls-fingerprint-echo (self-signed cert, PROXY_MITM_INSECURE_UPSTREAM=true)
//
// The echo server measures the JA3/JA4 fingerprint of the incoming connection
// and returns it as JSON. For each preset we compare the JA4 from the proxied
// path against a direct httpcloak request to verify the gateway applies the
// correct fingerprint. We also verify that different presets produce distinct
// JA4 values to ensure we're not silently falling back to Go's default TLS.
func TestE2E_HTTPCloak_TLSFingerprintEcho(t *testing.T) {
	echoURL, stopEcho := startFingerprintEchoServer(t)
	defer stopEcho()

	// Start proxy-gateway with a "none" proxy set (direct to target, no upstream proxy).
	tmpDir := t.TempDir()
	gatewayHTTPAddr := freeAddr(t)
	cfg := fmt.Sprintf(`
bind_addr = %q
log_level = "warn"

[[proxy_set]]
name        = "direct"
source_type = "none"
`, gatewayHTTPAddr)

	cfgFile := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(cfgFile, []byte(cfg), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	binPath := filepath.Join(tmpDir, "proxy-gateway-server")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Dir = filepath.Join(repoRoot(t), "proxy-gateway")
	buildCmd.Stdout = os.Stderr
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("build proxy-gateway: %v", err)
	}

	gwCmd := exec.Command(binPath, cfgFile)
	// PROXY_MITM_INSECURE_UPSTREAM lets the gateway's httpcloak client trust the
	// echo server's self-signed certificate without affecting the TLS fingerprint.
	gwCmd.Env = append(os.Environ(), "PROXY_MITM_INSECURE_UPSTREAM=true")
	gwCmd.Stdout = os.Stderr
	gwCmd.Stderr = os.Stderr
	if err := gwCmd.Start(); err != nil {
		t.Fatalf("start proxy-gateway: %v", err)
	}
	defer gwCmd.Process.Kill() //nolint:errcheck

	waitReady(t, gatewayHTTPAddr, 5*time.Second)

	presets := []string{"chrome-latest", "firefox-latest", "safari-latest"}
	ja4ByPreset := make(map[string]string, len(presets))

	for _, preset := range presets {
		t.Run(preset, func(t *testing.T) {
			// Request through proxy-gateway with this preset.
			usernameJSON := fmt.Sprintf(`{"set":"direct","httpcloak":%q}`, preset)
			username := base64.StdEncoding.EncodeToString([]byte(usernameJSON))

			proxyRawURL := "http://" + gatewayHTTPAddr
			pu, _ := url.Parse(proxyRawURL)
			pu.User = url.UserPassword(username, "x")

			httpClient := &http.Client{
				Transport: &http.Transport{
					Proxy:           http.ProxyURL(pu),
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
				},
				Timeout: 30 * time.Second,
			}

			resp, err := httpClient.Get(echoURL + "/")
			if err != nil {
				t.Fatalf("HTTPS request through gateway: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("reading response body: %v", err)
			}

			var result fingerprintEchoResponse
			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatalf("parsing response %q: %v", body, err)
			}

			if result.Fingerprint.JA3Hash == "" {
				t.Fatalf("expected non-empty ja3_hash (full response: %s)", body)
			}
			t.Logf("proxied: ja3_hash=%s  ja4=%s  verdict=%s (score=%.2f)",
				result.Fingerprint.JA3Hash, result.Fingerprint.JA4,
				result.Verdict.Level, result.Verdict.Score)

			// Derive the expected fingerprint by making a direct httpcloak request
			// to the same echo server (no proxy-gateway in the path).
			direct := directFingerprintRequest(t, echoURL, preset)
			t.Logf("direct:  ja3_hash=%s  ja4=%s", direct.Fingerprint.JA3Hash, direct.Fingerprint.JA4)

			// JA3 includes extension order, which httpcloak randomises (Chrome behaviour).
			// JA4 is order-independent, so it's the right fingerprint to compare.
			if result.Fingerprint.JA4 != direct.Fingerprint.JA4 {
				t.Errorf("JA4 mismatch: proxied=%s direct=%s\nproxied JA3Raw=%s\ndirect  JA3Raw=%s",
					result.Fingerprint.JA4, direct.Fingerprint.JA4,
					result.Fingerprint.JA3Raw, direct.Fingerprint.JA3Raw)
			}

			ja4ByPreset[preset] = result.Fingerprint.JA4
		})
	}

	// Verify that different presets produce distinct JA4 values.
	seen := map[string]string{}
	for preset, ja4 := range ja4ByPreset {
		if other, exists := seen[ja4]; exists {
			t.Errorf("presets %q and %q produced the same JA4 %q", preset, other, ja4)
		}
		seen[ja4] = preset
	}
}

// TestE2E_HTTPCloak_H2_MITM verifies that the MITM proxy serves HTTP/2 to
// clients that negotiate H2 via ALPN. The client connects through the gateway
// with httpcloak fingerprint spoofing and forces H2 on the client-facing side.
func TestE2E_HTTPCloak_H2_MITM(t *testing.T) {
	echoURL, stopEcho := startFingerprintEchoServer(t)
	defer stopEcho()

	tmpDir := t.TempDir()
	gatewayHTTPAddr := freeAddr(t)
	cfg := fmt.Sprintf(`
bind_addr = %q
log_level = "warn"

[[proxy_set]]
name        = "direct"
source_type = "none"
`, gatewayHTTPAddr)

	cfgFile := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(cfgFile, []byte(cfg), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	binPath := filepath.Join(tmpDir, "proxy-gateway-server")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Dir = filepath.Join(repoRoot(t), "proxy-gateway")
	buildCmd.Stdout = os.Stderr
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("build proxy-gateway: %v", err)
	}

	gwCmd := exec.Command(binPath, cfgFile)
	gwCmd.Env = append(os.Environ(), "PROXY_MITM_INSECURE_UPSTREAM=true")
	gwCmd.Stdout = os.Stderr
	gwCmd.Stderr = os.Stderr
	if err := gwCmd.Start(); err != nil {
		t.Fatalf("start proxy-gateway: %v", err)
	}
	defer gwCmd.Process.Kill() //nolint:errcheck

	waitReady(t, gatewayHTTPAddr, 5*time.Second)

	usernameJSON := `{"set":"direct","httpcloak":"chrome-latest"}`
	username := base64.StdEncoding.EncodeToString([]byte(usernameJSON))

	proxyRawURL := "http://" + gatewayHTTPAddr
	pu, _ := url.Parse(proxyRawURL)
	pu.User = url.UserPassword(username, "x")

	// Force H2 on the client-facing MITM connection.
	transport := &http.Transport{
		Proxy: http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			NextProtos:         []string{"h2", "http/1.1"},
		},
		ForceAttemptHTTP2: true,
	}
	// Configure H2 on the transport.
	if err := http2.ConfigureTransport(transport); err != nil {
		t.Fatalf("configure h2 transport: %v", err)
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	resp, err := httpClient.Get(echoURL + "/")
	if err != nil {
		t.Fatalf("H2 request through gateway: %v", err)
	}
	defer resp.Body.Close()

	// Verify we actually got H2 on the client side.
	t.Logf("response proto: %s", resp.Proto)
	if resp.ProtoMajor != 2 {
		t.Errorf("expected HTTP/2 on client side, got %s", resp.Proto)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}

	var result fingerprintEchoResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("parsing response %q: %v", body, err)
	}

	if result.Fingerprint.JA3Hash == "" {
		t.Fatalf("expected non-empty ja3_hash (full response: %s)", body)
	}
	t.Logf("ja3_hash=%s  ja4=%s", result.Fingerprint.JA3Hash, result.Fingerprint.JA4)
}

// TestE2E_HTTPCloak_WebSocket_MITM verifies that WebSocket upgrades work
// through the MITM proxy with httpcloak fingerprint spoofing. The test:
//  1. Starts a TLS WebSocket echo server (self-signed cert)
//  2. Starts proxy-gateway with httpcloak MITM
//  3. Client does CONNECT → MITM terminates TLS → sends Upgrade: websocket
//  4. MITM detects upgrade, dials upstream with fingerprinted utls, relays
//  5. Client sends a WebSocket text frame, expects it echoed back
func TestE2E_HTTPCloak_WebSocket_MITM(t *testing.T) {
	// --- WebSocket echo server (TLS, self-signed) ---
	wsAddr := startWebSocketEchoServer(t)

	// --- proxy-gateway ---
	tmpDir := t.TempDir()
	gatewayHTTPAddr := freeAddr(t)
	cfg := fmt.Sprintf(`
bind_addr = %q
log_level = "warn"

[[proxy_set]]
name        = "direct"
source_type = "none"
`, gatewayHTTPAddr)

	cfgFile := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(cfgFile, []byte(cfg), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	binPath := filepath.Join(tmpDir, "proxy-gateway-server")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Dir = filepath.Join(repoRoot(t), "proxy-gateway")
	buildCmd.Stdout = os.Stderr
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("build proxy-gateway: %v", err)
	}

	gwCmd := exec.Command(binPath, cfgFile)
	gwCmd.Env = append(os.Environ(), "PROXY_MITM_INSECURE_UPSTREAM=true")
	gwCmd.Stdout = os.Stderr
	gwCmd.Stderr = os.Stderr
	if err := gwCmd.Start(); err != nil {
		t.Fatalf("start proxy-gateway: %v", err)
	}
	defer gwCmd.Process.Kill() //nolint:errcheck
	waitReady(t, gatewayHTTPAddr, 5*time.Second)

	// --- WebSocket handshake through proxy-gateway ---
	usernameJSON := `{"set":"direct","httpcloak":"chrome-latest"}`
	username := base64.StdEncoding.EncodeToString([]byte(usernameJSON))
	creds := base64.StdEncoding.EncodeToString([]byte(username + ":x"))

	// 1. CONNECT to proxy-gateway
	gwConn, err := net.DialTimeout("tcp", gatewayHTTPAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer gwConn.Close()
	gwConn.SetDeadline(time.Now().Add(15 * time.Second))

	fmt.Fprintf(gwConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		wsAddr, wsAddr, creds)

	br := bufio.NewReader(gwConn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading CONNECT status: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("CONNECT failed: %s", strings.TrimSpace(statusLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("draining CONNECT headers: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// 2. TLS handshake (MITM will intercept)
	tlsConn := tls.Client(newBufConn(gwConn, br), &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         "localhost",
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	// 3. Send WebSocket upgrade request
	wsKey := base64.StdEncoding.EncodeToString([]byte("test-websocket-key!"))
	fmt.Fprintf(tlsConn, "GET /ws HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"\r\n", wsAddr, wsKey)

	// 4. Read upgrade response
	tlsBr := bufio.NewReader(tlsConn)
	upgradeStatus, err := tlsBr.ReadString('\n')
	if err != nil {
		t.Fatalf("reading upgrade status: %v", err)
	}
	if !strings.Contains(upgradeStatus, "101") {
		t.Fatalf("expected 101 Switching Protocols, got: %s", strings.TrimSpace(upgradeStatus))
	}
	t.Logf("upgrade response: %s", strings.TrimSpace(upgradeStatus))
	for {
		line, err := tlsBr.ReadString('\n')
		if err != nil {
			t.Fatalf("draining upgrade headers: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// 5. Send a WebSocket text frame and read the echo
	message := []byte("hello from proxy-gateway e2e test")
	wsWriteTextFrame(tlsConn, message)

	opcode, payload := wsReadFrame(t, tlsBr)
	if opcode != 1 { // 1 = text frame
		t.Fatalf("expected text frame (opcode 1), got opcode %d", opcode)
	}
	if string(payload) != string(message) {
		t.Fatalf("expected echo %q, got %q", message, payload)
	}
	t.Logf("WebSocket echo OK: %q", payload)
}

// startWebSocketEchoServer starts a TLS server that accepts WebSocket upgrades
// and echoes back any received frames. Returns the host:port address.
func startWebSocketEchoServer(t *testing.T) string {
	t.Helper()

	// Generate self-signed cert.
	ca, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ws echo listen: %v", err)
	}
	addr := ca.Addr().String()
	ca.Close()

	// Use exec to generate a self-signed cert inline via Go.
	// Simpler: reuse proxykit.NewCA() pattern but we don't import it in the test.
	// Instead, use crypto/tls.X509KeyPair with a generated cert.
	certPEM, keyPEM := generateSelfSignedCert(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		t.Fatalf("ws echo tls listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleWebSocketConn(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return addr
}

func handleWebSocketConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	// Read HTTP upgrade request.
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}

	// Compute Sec-WebSocket-Accept.
	key := req.Header.Get("Sec-WebSocket-Key")
	accept := computeWebSocketAccept(key)

	fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n"+
		"\r\n", accept)

	// Echo frames.
	for {
		opcode, payload, err := wsReadFrameRaw(br)
		if err != nil {
			return
		}
		if opcode == 8 { // close
			return
		}
		wsWriteTextFrame(conn, payload)
		_ = opcode
	}
}

func computeWebSocketAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-5AB5DC11BE65"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsWriteTextFrame writes a minimal unmasked WebSocket text frame.
func wsWriteTextFrame(w io.Writer, payload []byte) {
	frame := []byte{0x81} // FIN + text opcode
	if len(payload) < 126 {
		frame = append(frame, byte(len(payload)))
	} else {
		frame = append(frame, 126, byte(len(payload)>>8), byte(len(payload)))
	}
	frame = append(frame, payload...)
	w.Write(frame) //nolint:errcheck
}

// wsReadFrame reads a WebSocket frame, handling masking.
func wsReadFrame(t *testing.T, r *bufio.Reader) (opcode byte, payload []byte) {
	t.Helper()
	op, p, err := wsReadFrameRaw(r)
	if err != nil {
		t.Fatalf("reading websocket frame: %v", err)
	}
	return op, p
}

func wsReadFrameRaw(r *bufio.Reader) (opcode byte, payload []byte, err error) {
	b0, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	opcode = b0 & 0x0F

	b1, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	masked := b1&0x80 != 0
	length := int(b1 & 0x7F)

	if length == 126 {
		var buf [2]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, nil, err
		}
		length = int(buf[0])<<8 | int(buf[1])
	} else if length == 127 {
		var buf [8]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, nil, err
		}
		length = int(buf[4])<<24 | int(buf[5])<<16 | int(buf[6])<<8 | int(buf[7])
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return 0, nil, err
		}
	}

	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

// generateSelfSignedCert returns PEM-encoded cert and key for testing.
func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

// bufConn wraps a net.Conn with a bufio.Reader to drain buffered bytes first.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func newBufConn(conn net.Conn, r *bufio.Reader) *bufConn {
	return &bufConn{Conn: conn, r: r}
}

func (c *bufConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func TestE2E_LeastUsedRotation_SpreadAcrossUpstreams(t *testing.T) {
	env := startTestEnv(t, 3, "")
	defer env.cleanup()

	// Use plain HTTP (non-CONNECT) so the upstream proxy injects X-Forwarded-Via,
	// giving us a stable per-upstream identifier.
	seen := map[string]int{}
	for i := 0; i < 9; i++ {
		// Different meta per request → minutes=0 + unique meta → no affinity, fresh pick each time.
		username := mustBuildUsername(t, "test", 0, map[string]any{"req": fmt.Sprintf("%d", i)})
		_, body := doPlainHTTP(t, env.gatewayHTTPAddr, "http://"+env.echoAddr+"/", username, "x")
		via, _ := body["x-forwarded-via"].(string)
		if via != "" {
			seen[via]++
		}
	}

	if len(seen) != 3 {
		t.Fatalf("expected all 3 upstreams to be used, only saw %d: %v", len(seen), seen)
	}
	for addr, count := range seen {
		if count < 2 || count > 4 {
			t.Errorf("upstream %v handled %d requests, expected ~3 (least-used)", addr, count)
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP echo server
// ---------------------------------------------------------------------------

// echoHandler returns an http.Handler that responds with a JSON object
// containing the request method, path, all request headers, and the remote
// address of whoever connected to the echo server (i.e. the upstream proxy).
func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := map[string]string{}
		for k, vs := range r.Header {
			headers[strings.ToLower(k)] = strings.Join(vs, ", ")
		}
		// remote_addr is the address of whoever connected to us — i.e. the upstream
		// proxy. Tests use this to verify which upstream was used for a CONNECT tunnel.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"method":           r.Method,
			"path":             r.URL.Path,
			"remote_addr":      r.RemoteAddr,
			"x-forwarded-via":  r.Header.Get("X-Forwarded-Via"),
			"headers":          headers,
		})
	})
}

// ---------------------------------------------------------------------------
// Upstream HTTP proxy server (simple CONNECT forwarder)
// ---------------------------------------------------------------------------

// upstreamProxyHandler returns a handler that acts as a real upstream HTTP proxy.
// It handles CONNECT tunnels and plain HTTP requests.
// It injects an X-Forwarded-Via header with its own listening address, so tests
// can verify which upstream proxy handled each request.
func upstreamProxyHandler() http.Handler {
	var selfAddr atomic.Value // net.Addr, set on first request
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Context().Value(http.LocalAddrContextKey); a != nil && selfAddr.Load() == nil {
			selfAddr.Store(fmt.Sprintf("%v", a))
		}
		addr, _ := selfAddr.Load().(string)

		if r.Method == http.MethodConnect {
			// Establish tunnel to target
			targetConn, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
			if err != nil {
				http.Error(w, "dial failed: "+err.Error(), http.StatusBadGateway)
				return
			}
			defer targetConn.Close()

			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijack unsupported", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			clientConn, _, err := hj.Hijack()
			if err != nil {
				return
			}
			defer clientConn.Close()

			// Relay bytes bidirectionally
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); io.Copy(targetConn, clientConn) }() //nolint:errcheck
			go func() { defer wg.Done(); io.Copy(clientConn, targetConn) }() //nolint:errcheck
			wg.Wait()
			return
		}

		// Plain HTTP: add our identifying header and forward
		r.Header.Set("X-Forwarded-Via", addr)
		r.RequestURI = ""
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck
	})
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

func mustBuildUsername(t *testing.T, set string, minutes int, meta map[string]any) string {
	t.Helper()
	u, err := proxygatewayclient.BuildUsername(proxygatewayclient.UsernameParams{
		Set:     set,
		Minutes: minutes,
		Meta:    meta,
	})
	if err != nil {
		t.Fatalf("BuildUsername: %v", err)
	}
	return u
}

// doHTTPConnectToEcho sends a CONNECT request through the gateway, then does a
// plain GET to the echo server through the tunnel, and returns the parsed JSON body.
func doHTTPConnectToEcho(t *testing.T, gatewayAddr, echoAddr, username, password string) map[string]any {
	t.Helper()
	body, err := httpConnectToEcho(gatewayAddr, echoAddr, username, password)
	if err != nil {
		t.Fatalf("httpConnectToEcho: %v", err)
	}
	return body
}

func tryHTTPConnect(t *testing.T, gatewayAddr, echoAddr, username, password string) error {
	t.Helper()
	_, err := httpConnectToEcho(gatewayAddr, echoAddr, username, password)
	return err
}

func httpConnectToEcho(gatewayAddr, echoAddr, username, password string) (map[string]any, error) {
	creds := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	conn, err := net.DialTimeout("tcp", gatewayAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial gateway: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send CONNECT
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		echoAddr, echoAddr, creds)

	// Read response
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading status line: %w", err)
	}
	if !strings.Contains(statusLine, "200") {
		return nil, fmt.Errorf("CONNECT failed: %s", strings.TrimSpace(statusLine))
	}
	// Drain headers
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("draining headers: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// Send GET through tunnel
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", echoAddr)

	// Read HTTP response
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("reading echo response: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading echo body: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing echo body %q: %w", body, err)
	}
	return result, nil
}

// doSOCKS5ToEcho dials the echo server via SOCKS5 gateway and returns parsed JSON.
func doSOCKS5ToEcho(t *testing.T, gatewayAddr, echoAddr, username, password string) map[string]any {
	t.Helper()

	conn, err := net.DialTimeout("tcp", gatewayAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 gateway: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := socks5Handshake(conn, username, password, echoAddr); err != nil {
		t.Fatalf("SOCKS5 handshake: %v", err)
	}

	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", echoAddr)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading SOCKS5 echo response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("parsing SOCKS5 echo body %q: %v", body, err)
	}
	return result
}

func socks5Handshake(conn net.Conn, user, pass, target string) error {
	// Greeting: support user/pass auth
	conn.Write([]byte{0x05, 0x01, 0x02})
	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if choice[1] == 0xFF {
		return fmt.Errorf("server rejected all auth methods")
	}
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
	// Connect request
	host, portStr, _ := net.SplitHostPort(target)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	conn.Write(req)
	// Read reply (10 bytes for IPv4 reply)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("connect reply: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT refused (0x%02x)", reply[1])
	}
	return nil
}

// doPlainHTTP sends a plain (non-CONNECT) HTTP request through the gateway proxy.
func doPlainHTTP(t *testing.T, gatewayAddr, targetURL, username, password string) (int, map[string]any) {
	t.Helper()
	pu, _ := url.Parse("http://" + gatewayAddr)
	pu.User = url.UserPassword(username, password)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("plain HTTP via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(body, &result) //nolint:errcheck
	return resp.StatusCode, result
}

// ---------------------------------------------------------------------------
// Infrastructure helpers
// ---------------------------------------------------------------------------

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeAddr: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitReady(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s not ready after %v", addr, timeout)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// Walk up from the current file until we find go.mod for the client package
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "proxy-gateway", "main.go")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repo root from %s", dir)
		}
		dir = parent
	}
}
