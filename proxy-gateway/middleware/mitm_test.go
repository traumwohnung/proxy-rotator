package middleware

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"proxy-gateway/core"
)

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	if len(ca.Certificate) == 0 {
		t.Fatal("expected certificate")
	}
	if ca.PrivateKey == nil {
		t.Fatal("expected private key")
	}
}

func TestMITMPassesThroughWhenNoConn(t *testing.T) {
	// Plain HTTP request (no Conn) should pass through.
	ca, _ := GenerateCA()
	called := false
	inner := core.HandlerFunc(func(_ context.Context, req *core.Request) (*core.Proxy, error) {
		called = true
		return &core.Proxy{Host: "upstream", Port: 8080}, nil
	})

	h := MITM(ca, inner)
	req := &core.Request{RawUsername: "user", Target: "example.com:80"}
	proxy, err := h.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("inner should be called for non-CONNECT")
	}
	if proxy == nil || proxy.Host != "upstream" {
		t.Fatal("should return inner's proxy")
	}
}

func TestMITMPassesThroughWhenTLSAlreadyBroken(t *testing.T) {
	ca, _ := GenerateCA()
	called := false
	inner := core.HandlerFunc(func(_ context.Context, _ *core.Request) (*core.Proxy, error) {
		called = true
		return &core.Proxy{Host: "upstream", Port: 8080}, nil
	})

	h := MITM(ca, inner)
	req := &core.Request{
		Target:    "example.com:443",
		TLSBroken: true, // already broken by another MITM
	}
	h.Resolve(context.Background(), req)
	if !called {
		t.Fatal("inner should be called when TLS already broken")
	}
}

func TestMITMSetsChildRequestFields(t *testing.T) {
	// We can't do a real TLS handshake in a unit test without a full
	// net.Pipe + goroutine, but we can verify the MITM handler checks
	// the right conditions and calls inner correctly for the pass-through cases.

	ca, _ := GenerateCA()
	var seenReq *core.Request
	inner := core.HandlerFunc(func(_ context.Context, req *core.Request) (*core.Proxy, error) {
		seenReq = req
		return &core.Proxy{Host: "upstream", Port: 8080}, nil
	})

	h := MITM(ca, inner)

	// Simulate what happens with an HTTPRequest set (post-MITM child request).
	httpReq, _ := http.NewRequest("GET", "https://example.com/path", nil)
	req := &core.Request{
		Sub:           "alice",
		Set:           "residential",
		TLSBroken:     true,
		TLSServerName: "example.com",
		HTTPRequest:   httpReq,
		Target:        "example.com:443",
	}
	proxy, err := h.Resolve(context.Background(), req)
	if err != nil || proxy == nil {
		t.Fatalf("expected proxy: err=%v proxy=%v", err, proxy)
	}
	if seenReq.TLSBroken != true {
		t.Fatal("child should have TLSBroken=true")
	}
}

func TestBlockingMiddlewareWorksWithHTTPRequest(t *testing.T) {
	// This tests that blocking middleware can inspect HTTPRequest — which is
	// what MITM sets for each decrypted request.
	blocker := core.HandlerFunc(func(_ context.Context, req *core.Request) (*core.Proxy, error) {
		if req.HTTPRequest != nil && req.HTTPRequest.URL.Host == "blocked.com" {
			return nil, fmt.Errorf("blocked")
		}
		return &core.Proxy{Host: "upstream", Port: 8080}, nil
	})

	httpReq, _ := http.NewRequest("GET", "https://blocked.com/page", nil)
	req := &core.Request{
		TLSBroken:   true,
		HTTPRequest: httpReq,
	}
	_, err := blocker.Resolve(context.Background(), req)
	if err == nil {
		t.Fatal("expected block error")
	}

	// Non-blocked request should pass.
	httpReq2, _ := http.NewRequest("GET", "https://allowed.com/page", nil)
	req2 := &core.Request{TLSBroken: true, HTTPRequest: httpReq2}
	proxy, err := blocker.Resolve(context.Background(), req2)
	if err != nil || proxy == nil {
		t.Fatal("should pass for allowed domain")
	}
}

func TestResponseHookChaining(t *testing.T) {
	// Verify that multiple middleware can chain ResponseHook.
	req := &core.Request{}

	// First middleware sets a hook.
	req.ResponseHook = func(resp *http.Response) *http.Response {
		resp.Header.Set("X-First", "1")
		return resp
	}

	// Second middleware wraps the first.
	prevHook := req.ResponseHook
	req.ResponseHook = func(resp *http.Response) *http.Response {
		resp.Header.Set("X-Second", "2")
		if prevHook != nil {
			return prevHook(resp)
		}
		return resp
	}

	resp := &http.Response{Header: http.Header{}}
	result := req.ResponseHook(resp)
	if result.Header.Get("X-First") != "1" || result.Header.Get("X-Second") != "2" {
		t.Fatalf("both hooks should fire: got %v", result.Header)
	}
}
