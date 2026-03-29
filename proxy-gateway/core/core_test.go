package core

import (
	"context"
	"testing"
)

func TestHandlerFunc(t *testing.T) {
	h := HandlerFunc(func(_ context.Context, req *Request) (*Proxy, error) {
		return &Proxy{Host: "test", Port: 8080, Username: req.Sub}, nil
	})
	p, err := h.Resolve(context.Background(), &Request{Sub: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Username != "alice" {
		t.Fatalf("expected alice, got %s", p.Username)
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
