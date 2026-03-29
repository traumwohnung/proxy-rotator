package core

import (
	"context"
	"testing"
)

func TestStickyAffinityPins(t *testing.T) {
	counter := 0
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Proxy, error) {
		counter++
		return &Proxy{Host: "host", Port: uint16(counter)}, nil
	})
	s := Sticky(source)
	req := &Request{SessionKey: "key1", SessionTTL: 5}
	p1, _ := s.Resolve(context.Background(), req)
	p2, _ := s.Resolve(context.Background(), req)
	if p1.Port != p2.Port {
		t.Fatalf("sticky should pin: got %d and %d", p1.Port, p2.Port)
	}
}

func TestStickyZeroTTLPassesThrough(t *testing.T) {
	counter := 0
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Proxy, error) {
		counter++
		return &Proxy{Host: "host", Port: uint16(counter)}, nil
	})
	s := Sticky(source)
	req := &Request{SessionKey: "key1", SessionTTL: 0}
	p1, _ := s.Resolve(context.Background(), req)
	p2, _ := s.Resolve(context.Background(), req)
	if p1.Port == p2.Port {
		t.Fatal("0 TTL should not pin")
	}
}

func TestStickyListSessions(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Proxy, error) {
		return &Proxy{Host: "upstream", Port: 8080}, nil
	})
	s := Sticky(source)
	s.Resolve(context.Background(), &Request{SessionKey: "a", SessionTTL: 5})
	s.Resolve(context.Background(), &Request{SessionKey: "b", SessionTTL: 5})
	s.Resolve(context.Background(), &Request{SessionKey: "c", SessionTTL: 0})
	if len(s.ListSessions()) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(s.ListSessions()))
	}
}

func TestStickyForceRotate(t *testing.T) {
	counter := 0
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Proxy, error) {
		counter++
		return &Proxy{Host: "host", Port: uint16(counter)}, nil
	})
	s := Sticky(source)
	s.Resolve(context.Background(), &Request{SessionKey: "k", SessionTTL: 60})
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
	source := HandlerFunc(func(_ context.Context, req *Request) (*Proxy, error) {
		return &Proxy{Host: "proxy-" + req.Set, Port: 8080}, nil
	})
	p, err := source.Resolve(context.Background(), &Request{Set: "residential"})
	if err != nil || p.Host != "proxy-residential" {
		t.Fatalf("unexpected: err=%v proxy=%+v", err, p)
	}
}
