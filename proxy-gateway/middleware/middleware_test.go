package middleware

import (
	"context"
	"testing"

	"proxy-gateway/core"
)

// ---------------------------------------------------------------------------
// RateLimiting
// ---------------------------------------------------------------------------

func TestRateLimitConcurrentConnections(t *testing.T) {
	source := core.HandlerFunc(func(_ context.Context, _ *core.Request) (*core.Proxy, error) {
		return &core.Proxy{Host: "upstream", Port: 8080}, nil
	})
	rl := RateLimiting(source, StaticLimits([]RateLimit{
		{Type: LimitConcurrentConnections, Timeframe: Realtime, Max: 2},
	}))
	h1, err := rl.OpenConnection("alice")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := rl.OpenConnection("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rl.OpenConnection("alice"); err == nil {
		t.Fatal("expected connection limit error")
	}
	h1.Close(0, 0)
	if _, err := rl.OpenConnection("alice"); err != nil {
		t.Fatalf("should succeed after close: %v", err)
	}
	h2.Close(0, 0)
}

func TestRateLimitBandwidthMidConnection(t *testing.T) {
	source := core.HandlerFunc(func(_ context.Context, _ *core.Request) (*core.Proxy, error) {
		return &core.Proxy{Host: "upstream", Port: 8080}, nil
	})
	rl := RateLimiting(source, StaticLimits([]RateLimit{
		{Type: LimitUploadBytes, Timeframe: Hourly, Window: 1, Max: 100},
	}))
	h, err := rl.OpenConnection("alice")
	if err != nil {
		t.Fatal(err)
	}
	cancelled := false
	h.RecordTraffic(true, 80, func() { cancelled = true })
	if cancelled {
		t.Fatal("should not cancel yet")
	}
	h.RecordTraffic(true, 30, func() { cancelled = true })
	if !cancelled {
		t.Fatal("expected cancel when upload limit exceeded")
	}
	h.Close(110, 0)
}
