package core

import (
	"context"
	"testing"
)

func TestStickyAffinityPins(t *testing.T) {
	counter := 0
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		counter++
		return ProxyResult(&Proxy{Host: "host", Port: uint16(counter)}), nil
	})
	s := Sticky(source)
	ctx := WithSessionKey(context.Background(), "key1")
	ctx = WithSessionTTL(ctx, 5)
	r1, _ := s.Resolve(ctx, &Request{})
	r2, _ := s.Resolve(ctx, &Request{})
	if r1.Proxy.Port != r2.Proxy.Port {
		t.Fatalf("sticky should pin: got %d and %d", r1.Proxy.Port, r2.Proxy.Port)
	}
}

func TestStickyZeroTTLPassesThrough(t *testing.T) {
	counter := 0
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		counter++
		return ProxyResult(&Proxy{Host: "host", Port: uint16(counter)}), nil
	})
	s := Sticky(source)
	ctx := WithSessionKey(context.Background(), "key1")
	// SessionTTL defaults to 0 — no affinity
	r1, _ := s.Resolve(ctx, &Request{})
	r2, _ := s.Resolve(ctx, &Request{})
	if r1.Proxy.Port == r2.Proxy.Port {
		t.Fatal("0 TTL should not pin")
	}
}

func TestStickyListSessions(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return ProxyResult(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	s := Sticky(source)
	ctx := context.Background()
	s.Resolve(WithSessionTTL(WithSessionKey(ctx, "a"), 5), &Request{})
	s.Resolve(WithSessionTTL(WithSessionKey(ctx, "b"), 5), &Request{})
	s.Resolve(WithSessionKey(ctx, "c"), &Request{}) // no TTL
	if len(s.ListSessions()) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(s.ListSessions()))
	}
}

func TestStickyForceRotate(t *testing.T) {
	counter := 0
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		counter++
		return ProxyResult(&Proxy{Host: "host", Port: uint16(counter)}), nil
	})
	s := Sticky(source)
	ctx := WithSessionTTL(WithSessionKey(context.Background(), "k"), 60)
	s.Resolve(ctx, &Request{})
	before := s.GetSession("k")
	info, _ := s.ForceRotate(context.Background(), "k")
	if info == nil {
		t.Fatal("expected session info")
	}
	if info.SessionID != before.SessionID {
		t.Fatal("session ID should be preserved")
	}
}

func TestDirectLibraryUsage(t *testing.T) {
	source := HandlerFunc(func(ctx context.Context, _ *Request) (*Result, error) {
		return ProxyResult(&Proxy{Host: "proxy-" + Set(ctx), Port: 8080}), nil
	})
	ctx := WithSet(context.Background(), "residential")
	r, err := source.Resolve(ctx, &Request{})
	if err != nil || r.Proxy.Host != "proxy-residential" {
		t.Fatalf("unexpected: err=%v proxy=%+v", err, r)
	}
}
