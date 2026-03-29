package core

import (
	"context"
	"fmt"
	"testing"
)

type stubAuth struct{ sub, pw string }

func (a *stubAuth) Authenticate(sub, password string) error {
	if sub != a.sub || password != a.pw {
		return fmt.Errorf("invalid")
	}
	return nil
}

func TestAuthPassesOnValidCredentials(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return ProxyResult(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	h := Auth(&stubAuth{"alice", "pw"}, source)
	ctx := WithSub(context.Background(), "alice")
	ctx = WithPassword(ctx, "pw")
	r, err := h.Resolve(ctx, &Request{})
	if err != nil || r == nil || r.Proxy == nil {
		t.Fatalf("expected proxy, got err=%v", err)
	}
}

func TestAuthRejectsInvalidCredentials(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return ProxyResult(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	h := Auth(&stubAuth{"alice", "pw"}, source)
	ctx := WithSub(context.Background(), "alice")
	ctx = WithPassword(ctx, "wrong")
	_, err := h.Resolve(ctx, &Request{})
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}
