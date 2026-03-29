package main

import (
	"context"
	"testing"

	"proxy-gateway/core"
)

var testProxy = &core.Proxy{Host: "upstream", Port: 8080}
var testSource = core.HandlerFunc(func(_ context.Context, _ *core.Request) (*core.Result, error) {
	return core.ProxyResult(testProxy), nil
})

// ---------------------------------------------------------------------------
// SimpleAuth
// ---------------------------------------------------------------------------

func TestSimpleAuthCorrect(t *testing.T) {
	a := NewSimpleAuth("alice", "pw")
	if err := a.Authenticate("alice", "pw"); err != nil {
		t.Fatal(err)
	}
}

func TestSimpleAuthWrong(t *testing.T) {
	a := NewSimpleAuth("alice", "pw")
	if err := a.Authenticate("alice", "wrong"); err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// MultiAuth
// ---------------------------------------------------------------------------

func TestMultiAuthCorrect(t *testing.T) {
	a := NewMultiAuth(map[string]string{"alice": "pw1", "bob": "pw2"})
	if err := a.Authenticate("alice", "pw1"); err != nil {
		t.Fatal(err)
	}
	if err := a.Authenticate("bob", "pw2"); err != nil {
		t.Fatal(err)
	}
}

func TestMultiAuthUnknown(t *testing.T) {
	a := NewMultiAuth(map[string]string{"alice": "pw"})
	if err := a.Authenticate("charlie", "pw"); err == nil {
		t.Fatal("expected error for unknown user")
	}
}

// ---------------------------------------------------------------------------
// ParseJSONCreds
// ---------------------------------------------------------------------------

func TestParseJSONCredsPopulatesContext(t *testing.T) {
	h := ParseJSONCreds(core.HandlerFunc(func(ctx context.Context, _ *core.Request) (*core.Result, error) {
		if core.Sub(ctx) != "alice" || core.Set(ctx) != "res" || core.SessionTTL(ctx) != 5 {
			t.Fatalf("unexpected: sub=%q set=%q ttl=%d", core.Sub(ctx), core.Set(ctx), core.SessionTTL(ctx))
		}
		if core.Password(ctx) != "s3cret" {
			t.Fatalf("expected password=s3cret, got %q", core.Password(ctx))
		}
		if core.GetMeta(ctx).GetString("app") != "test" {
			t.Fatal("expected meta.app=test")
		}
		return core.ProxyResult(testProxy), nil
	}))
	req := &core.Request{
		RawUsername: `{"sub":"alice","set":"res","minutes":5,"meta":{"app":"test"}}`,
		RawPassword: "s3cret",
	}
	r, err := h.Resolve(context.Background(), req)
	if err != nil || r.Proxy.Host != "upstream" {
		t.Fatalf("unexpected: err=%v result=%+v", err, r)
	}
}

func TestParseJSONCredsRejectsEmptyUsername(t *testing.T) {
	h := ParseJSONCreds(testSource)
	if _, err := h.Resolve(context.Background(), &core.Request{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseJSONCredsRejectsInvalidJSON(t *testing.T) {
	h := ParseJSONCreds(testSource)
	if _, err := h.Resolve(context.Background(), &core.Request{RawUsername: "notjson"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseJSONCredsRejectsMissingSub(t *testing.T) {
	h := ParseJSONCreds(testSource)
	if _, err := h.Resolve(context.Background(), &core.Request{RawUsername: `{"set":"res","minutes":0,"meta":{}}`}); err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// Full pipeline (our server's composition)
// ---------------------------------------------------------------------------

func TestFullPipeline(t *testing.T) {
	pipeline := ParseJSONCreds(
		core.Auth(
			NewSimpleAuth("alice", "pw"),
			core.Sticky(testSource),
		),
	)

	req := &core.Request{
		RawUsername: `{"sub":"alice","set":"test","minutes":5,"meta":{}}`,
		RawPassword: "pw",
	}
	r, err := pipeline.Resolve(context.Background(), req)
	if err != nil || r == nil || r.Proxy == nil {
		t.Fatalf("expected proxy, got err=%v", err)
	}

	// Same raw username → same sticky session.
	r2, _ := pipeline.Resolve(context.Background(), &core.Request{
		RawUsername: `{"sub":"alice","set":"test","minutes":5,"meta":{}}`,
		RawPassword: "pw",
	})
	if r2.Proxy.Port != r.Proxy.Port {
		t.Fatal("sticky should return same proxy")
	}

	// Bad password.
	_, err = pipeline.Resolve(context.Background(), &core.Request{
		RawUsername: `{"sub":"alice","set":"test","minutes":5,"meta":{}}`,
		RawPassword: "wrong",
	})
	if err == nil {
		t.Fatal("expected auth error")
	}
}
