package core

import (
	"context"
	"testing"
)

func resolveWithSub(t *testing.T, h Handler, sub string) *Result {
	t.Helper()
	ctx := WithSub(context.Background(), sub)
	result, err := h.Resolve(ctx, &Request{})
	if err != nil {
		t.Fatalf("unexpected resolve error: %v", err)
	}
	return result
}

func TestRateLimitConcurrentConnections(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	rl := RateLimit(source, StaticLimits([]RateLimitRule{
		{Type: LimitConcurrentConnections, Timeframe: Realtime, Max: 2},
	}))

	r1 := resolveWithSub(t, rl, "alice")
	r2 := resolveWithSub(t, rl, "alice")

	// Third should be rejected.
	ctx := WithSub(context.Background(), "alice")
	if _, err := rl.Resolve(ctx, &Request{}); err == nil {
		t.Fatal("expected connection limit error on third resolve")
	}

	// After closing one, fourth should succeed.
	r1.ConnTracker.Close(0, 0)
	resolveWithSub(t, rl, "alice").ConnTracker.Close(0, 0)

	r2.ConnTracker.Close(0, 0)
}

func TestRateLimitBandwidthMidConnection(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	rl := RateLimit(source, StaticLimits([]RateLimitRule{
		{Type: LimitUploadBytes, Timeframe: Hourly, Window: 1, Max: 100},
	}))

	r := resolveWithSub(t, rl, "alice")
	cancelled := false
	r.ConnTracker.RecordTraffic(true, 80, func() { cancelled = true })
	if cancelled {
		t.Fatal("should not cancel yet at 80 bytes")
	}
	r.ConnTracker.RecordTraffic(true, 30, func() { cancelled = true })
	if !cancelled {
		t.Fatal("expected cancel when upload limit exceeded (80+30 > 100)")
	}
	r.ConnTracker.Close(110, 0)
}

func TestRateLimitWrapsResultConnTracker(t *testing.T) {
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	rl := RateLimit(source, StaticLimits([]RateLimitRule{
		{Type: LimitConcurrentConnections, Timeframe: Realtime, Max: 10},
	}))

	result := resolveWithSub(t, rl, "alice")
	if result.ConnTracker == nil {
		t.Fatal("expected ConnTracker in result")
	}
	result.ConnTracker.Close(0, 0)
}

func TestRateLimitEmptySubFallback(t *testing.T) {
	// When no sub is in context, rate limiting still works — all
	// anonymous traffic shares the "" bucket.
	source := HandlerFunc(func(_ context.Context, _ *Request) (*Result, error) {
		return Resolved(&Proxy{Host: "upstream", Port: 8080}), nil
	})
	rl := RateLimit(source, StaticLimits([]RateLimitRule{
		{Type: LimitConcurrentConnections, Timeframe: Realtime, Max: 1},
	}))

	// First resolves fine.
	r, err := rl.Resolve(context.Background(), &Request{})
	if err != nil {
		t.Fatal(err)
	}
	// Second (same empty sub bucket) should be rejected.
	if _, err := rl.Resolve(context.Background(), &Request{}); err == nil {
		t.Fatal("expected limit exceeded for shared anonymous bucket")
	}
	r.ConnTracker.Close(0, 0)
}
