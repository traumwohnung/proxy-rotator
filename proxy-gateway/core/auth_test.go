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
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Proxy, error) {
		return &Proxy{Host: "upstream", Port: 8080}, nil
	})
	h := Auth(&stubAuth{"alice", "pw"}, source)
	p, err := h.Resolve(context.Background(), &Request{Sub: "alice", Password: "pw"})
	if err != nil || p == nil {
		t.Fatalf("expected proxy, got err=%v", err)
	}
}

func TestAuthRejectsInvalidCredentials(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Proxy, error) {
		return &Proxy{Host: "upstream", Port: 8080}, nil
	})
	h := Auth(&stubAuth{"alice", "pw"}, source)
	_, err := h.Resolve(context.Background(), &Request{Sub: "alice", Password: "wrong"})
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}
