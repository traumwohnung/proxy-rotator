package main

import (
	"context"
	"testing"

	"proxy-gateway/core"
)

var testProxy = &core.Proxy{Host: "upstream", Port: 8080}
var testSource = core.HandlerFunc(func(_ context.Context, _ *core.Request) (*core.Proxy, error) {
	return testProxy, nil
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

func TestParseJSONCredsPopulatesFields(t *testing.T) {
	h := ParseJSONCreds(core.HandlerFunc(func(_ context.Context, req *core.Request) (*core.Proxy, error) {
		if req.Sub != "alice" || req.Set != "res" || req.SessionTTL != 5 {
			t.Fatalf("unexpected: sub=%q set=%q ttl=%d", req.Sub, req.Set, req.SessionTTL)
		}
		if req.Password != "s3cret" {
			t.Fatalf("expected password=s3cret, got %q", req.Password)
		}
		if req.Meta.GetString("app") != "test" {
			t.Fatal("expected meta.app=test")
		}
		return testProxy, nil
	}))
	req := &core.Request{
		RawUsername: `{"sub":"alice","set":"res","minutes":5,"meta":{"app":"test"}}`,
		RawPassword: "s3cret",
	}
	p, err := h.Resolve(context.Background(), req)
	if err != nil || p.Host != "upstream" {
		t.Fatalf("unexpected: err=%v proxy=%+v", err, p)
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
	p, err := pipeline.Resolve(context.Background(), req)
	if err != nil || p == nil {
		t.Fatalf("expected proxy, got err=%v", err)
	}

	// Same raw username → same sticky session.
	p2, _ := pipeline.Resolve(context.Background(), &core.Request{
		RawUsername: `{"sub":"alice","set":"test","minutes":5,"meta":{}}`,
		RawPassword: "pw",
	})
	if p2.Port != p.Port {
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
