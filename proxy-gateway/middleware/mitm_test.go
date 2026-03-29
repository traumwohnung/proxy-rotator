package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"

	"proxy-gateway/core"
)

// stubUpstream for testing — never actually dials.
type stubUpstream struct{}

func (stubUpstream) Dial(_ context.Context, _ *core.Proxy, _ string) (net.Conn, error) {
	return nil, fmt.Errorf("stub: not dialing")
}

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
	ca, _ := GenerateCA()
	called := false
	inner := core.HandlerFunc(func(_ context.Context, _ *core.Request) (*core.Result, error) {
		called = true
		return core.ProxyResult(&core.Proxy{Host: "upstream", Port: 8080}), nil
	})

	h := MITM(ca, stubUpstream{}, inner)
	req := &core.Request{RawUsername: "user", Target: "example.com:80"}
	result, err := h.Resolve(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("inner should be called for non-CONNECT")
	}
	if result == nil || result.Proxy == nil || result.Proxy.Host != "upstream" {
		t.Fatal("should return inner's proxy")
	}
}

func TestMITMPassesThroughWhenTLSAlreadyBroken(t *testing.T) {
	ca, _ := GenerateCA()
	called := false
	inner := core.HandlerFunc(func(_ context.Context, _ *core.Request) (*core.Result, error) {
		called = true
		return core.ProxyResult(&core.Proxy{Host: "upstream", Port: 8080}), nil
	})

	h := MITM(ca, stubUpstream{}, inner)
	ctx := core.WithTLSState(context.Background(), core.TLSState{Broken: true})
	req := &core.Request{Target: "example.com:443"}
	h.Resolve(ctx, req)
	if !called {
		t.Fatal("inner should be called when TLS already broken")
	}
}

func TestBlockingMiddlewareWorksWithHTTPRequest(t *testing.T) {
	blocker := core.HandlerFunc(func(_ context.Context, req *core.Request) (*core.Result, error) {
		if req.HTTPRequest != nil && req.HTTPRequest.URL.Host == "blocked.com" {
			return nil, fmt.Errorf("blocked")
		}
		return core.ProxyResult(&core.Proxy{Host: "upstream", Port: 8080}), nil
	})

	httpReq, _ := http.NewRequest("GET", "https://blocked.com/page", nil)
	req := &core.Request{HTTPRequest: httpReq}
	ctx := core.WithTLSState(context.Background(), core.TLSState{Broken: true})
	_, err := blocker.Resolve(ctx, req)
	if err == nil {
		t.Fatal("expected block error")
	}

	httpReq2, _ := http.NewRequest("GET", "https://allowed.com/page", nil)
	req2 := &core.Request{HTTPRequest: httpReq2}
	result, err := blocker.Resolve(ctx, req2)
	if err != nil || result == nil || result.Proxy == nil {
		t.Fatal("should pass for allowed domain")
	}
}

func TestResponseHookOnResult(t *testing.T) {
	// ResponseHook is now on Result, not Request.
	result := &core.Result{
		Proxy: &core.Proxy{Host: "upstream", Port: 8080},
		ResponseHook: func(resp *http.Response) *http.Response {
			resp.Header.Set("X-Hooked", "yes")
			return resp
		},
	}

	resp := &http.Response{Header: http.Header{}}
	result.ResponseHook(resp)
	if resp.Header.Get("X-Hooked") != "yes" {
		t.Fatal("hook should fire")
	}
}
