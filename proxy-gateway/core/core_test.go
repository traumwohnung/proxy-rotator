package core

import (
	"context"
	"testing"
)

func TestHandlerFunc(t *testing.T) {
	h := HandlerFunc(func(ctx context.Context, _ *Request) (*Result, error) {
		return ProxyResult(&Proxy{Host: "test", Port: 8080, Username: Sub(ctx)}), nil
	})
	ctx := WithSub(context.Background(), "alice")
	r, err := h.Resolve(ctx, &Request{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Proxy.Username != "alice" {
		t.Fatalf("expected alice, got %s", r.Proxy.Username)
	}
}

func TestMetaGetString(t *testing.T) {
	m := Meta{"k": "v", "n": float64(42)}
	if m.GetString("k") != "v" {
		t.Fatal("expected v")
	}
	if m.GetString("n") != "" {
		t.Fatal("expected empty for non-string")
	}
	if m.GetString("missing") != "" {
		t.Fatal("expected empty for missing")
	}
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	ctx = WithSub(ctx, "alice")
	ctx = WithPassword(ctx, "secret")
	ctx = WithSet(ctx, "residential")
	ctx = WithSessionKey(ctx, "key123")
	ctx = WithSessionTTL(ctx, 5)
	ctx = WithMeta(ctx, Meta{"app": "test"})
	ctx = WithTLSState(ctx, TLSState{Broken: true, ServerName: "example.com"})

	if Sub(ctx) != "alice" {
		t.Fatal("Sub")
	}
	if Password(ctx) != "secret" {
		t.Fatal("Password")
	}
	if Set(ctx) != "residential" {
		t.Fatal("Set")
	}
	if SessionKey(ctx) != "key123" {
		t.Fatal("SessionKey")
	}
	if SessionTTL(ctx) != 5 {
		t.Fatal("SessionTTL")
	}
	if GetMeta(ctx).GetString("app") != "test" {
		t.Fatal("Meta")
	}
	ts := GetTLSState(ctx)
	if !ts.Broken || ts.ServerName != "example.com" {
		t.Fatal("TLSState")
	}
}

func TestChainHandles(t *testing.T) {
	// nil + nil
	if ChainHandles(nil, nil) != nil {
		t.Fatal("nil+nil should be nil")
	}

	// nil + handle
	called := 0
	h := &testHandle{onClose: func() { called++ }}
	if ChainHandles(nil, h) != h {
		t.Fatal("nil+h should be h")
	}
	if ChainHandles(h, nil) != h {
		t.Fatal("h+nil should be h")
	}

	// both
	a := &testHandle{onClose: func() { called++ }}
	b := &testHandle{onClose: func() { called += 10 }}
	c := ChainHandles(a, b)
	c.Close(0, 0)
	if called != 11 {
		t.Fatalf("expected 11, got %d", called)
	}
}

type testHandle struct {
	onClose func()
}

func (h *testHandle) RecordTraffic(_ bool, _ int64, _ func()) {}
func (h *testHandle) Close(_, _ int64)                        { h.onClose() }

func TestProxyResult(t *testing.T) {
	p := &Proxy{Host: "test", Port: 8080}
	r := ProxyResult(p)
	if r.Proxy != p {
		t.Fatal("ProxyResult should wrap the proxy")
	}
	if r.ConnHandle != nil || r.ResponseHook != nil || r.HTTPResponse != nil {
		t.Fatal("other fields should be nil")
	}
}
