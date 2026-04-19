package proxygatewayclient_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak"
)

// fingerprintEchoResponse mirrors the JSON shape returned by tls-fingerprint-echo.
type fingerprintEchoResponse struct {
	Fingerprint struct {
		JA3Hash string `json:"ja3_hash"`
		JA3Raw  string `json:"ja3_raw"`
		JA4     string `json:"ja4"`
	} `json:"fingerprint"`
	UAConsistent bool `json:"ua_consistent"`
}

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

// startMITMGateway builds and starts a proxy-gateway with source_type=none and
// PROXY_MITM_INSECURE_UPSTREAM=true. Returns the gateway HTTP address and a
// stop function.
func startMITMGateway(t *testing.T) (gatewayAddr string, stop func()) {
	t.Helper()

	tmpDir := t.TempDir()
	gatewayAddr = freeAddr(t)
	cfg := fmt.Sprintf(`
bind_addr = %q
log_level = "warn"

[[proxy_set]]
name        = "direct"
source_type = "none"
`, gatewayAddr)

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

	waitReady(t, gatewayAddr, 5*time.Second)
	return gatewayAddr, func() { gwCmd.Process.Kill() } //nolint:errcheck
}

func TestE2E_HTTPCloak_TLSFingerprintEcho(t *testing.T) {
	echoURL, stopEcho := startFingerprintEchoServer(t)
	defer stopEcho()

	gatewayHTTPAddr, stopGW := startMITMGateway(t)
	defer stopGW()

	presets := []string{"chrome-latest", "firefox-latest", "safari-latest"}
	ja4ByPreset := make(map[string]string, len(presets))

	for _, preset := range presets {
		t.Run(preset, func(t *testing.T) {
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
			t.Logf("proxied: ja3_hash=%s  ja4=%s  ua_consistent=%v",
				result.Fingerprint.JA3Hash, result.Fingerprint.JA4,
				result.UAConsistent)

			direct := directFingerprintRequest(t, echoURL, preset)
			t.Logf("direct:  ja3_hash=%s  ja4=%s", direct.Fingerprint.JA3Hash, direct.Fingerprint.JA4)

			if result.Fingerprint.JA4 != direct.Fingerprint.JA4 {
				t.Errorf("JA4 mismatch: proxied=%s direct=%s\nproxied JA3Raw=%s\ndirect  JA3Raw=%s",
					result.Fingerprint.JA4, direct.Fingerprint.JA4,
					result.Fingerprint.JA3Raw, direct.Fingerprint.JA3Raw)
			}

			ja4ByPreset[preset] = result.Fingerprint.JA4
		})
	}

	seen := map[string]string{}
	for preset, ja4 := range ja4ByPreset {
		if other, exists := seen[ja4]; exists {
			t.Errorf("presets %q and %q produced the same JA4 %q", preset, other, ja4)
		}
		seen[ja4] = preset
	}
}
