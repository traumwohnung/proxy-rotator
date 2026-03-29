package core

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// LimitType defines what resource the limit applies to.
type LimitType int

const (
	LimitConcurrentConnections LimitType = iota
	LimitTotalConnections
	LimitUploadBytes
	LimitDownloadBytes
	LimitTotalBytes
)

// Timeframe defines the rolling window size.
type Timeframe int

const (
	Realtime Timeframe = iota
	Secondly
	Minutely
	Hourly
	Daily
	Weekly
	Monthly
)

func (tf Timeframe) duration() time.Duration {
	switch tf {
	case Secondly:
		return time.Second
	case Minutely:
		return time.Minute
	case Hourly:
		return time.Hour
	case Daily:
		return 24 * time.Hour
	case Weekly:
		return 7 * 24 * time.Hour
	case Monthly:
		return 30 * 24 * time.Hour
	default:
		return 0
	}
}

// RateLimit describes a single rate limit rule.
type RateLimitRule struct {
	Type      LimitType
	Timeframe Timeframe
	Window    int // multiplier (e.g. Hourly, Window=6 → 6h rolling)
	Max       int64
}

func (r RateLimitRule) windowDuration() time.Duration {
	w := r.Window
	if w < 1 {
		w = 1
	}
	return r.Timeframe.duration() * time.Duration(w)
}

// RateLimiter wraps an inner Handler with rate limiting.
// It injects a ConnTracker into the Result for connection-level tracking.
type RateLimiter struct {
	next   Handler
	limits func(sub string) []RateLimitRule
	mu     sync.RWMutex
	state  map[string]*userState
}

// RateLimitOption configures a RateLimiter.
type RateLimitOption func(*RateLimiter)

// WithLimits sets a dynamic limit function.
func WithLimits(fn func(sub string) []RateLimitRule) RateLimitOption {
	return func(h *RateLimiter) { h.limits = fn }
}

// StaticLimits sets the same limits for all users.
func StaticLimits(limits []RateLimitRule) RateLimitOption {
	return WithLimits(func(_ string) []RateLimitRule { return limits })
}

// RateLimiting wraps next with rate limiting. Unlike the old ConnectionTracker
// interface, this works at any position in the pipeline — it wraps
// Result.ConnTracker so the gateway always sees the tracker.
func RateLimit(next Handler, opts ...RateLimitOption) *RateLimiter {
	h := &RateLimiter{
		next:  next,
		state: make(map[string]*userState),
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.limits == nil {
		h.limits = func(_ string) []RateLimitRule { return nil }
	}
	return h
}

// Resolve implements Handler. It checks pre-connection limits,
// delegates to the inner handler, then wraps the Result.ConnTracker.
//
// Rate limits are keyed by Sub(ctx). If no sub is set (empty string),
// all traffic shares a single anonymous bucket — limits apply globally
// across all unauthenticated connections.
func (h *RateLimiter) Resolve(ctx context.Context, req *Request) (*Result, error) {
	sub := Sub(ctx)
	limits := h.limits(sub)
	if len(limits) == 0 {
		return h.next.Resolve(ctx, req)
	}

	st := h.getState(sub, limits)

	// Check windowed limits before resolving.
	if err := checkWindowedLimits(limits, st); err != nil {
		return nil, err
	}

	result, err := h.next.Resolve(ctx, req)
	if err != nil || result == nil || result.Proxy == nil {
		return result, err
	}

	// Create a ConnTracker for this connection and chain it with any inner one.
	handle, err := h.openConnection(sub, limits, st)
	if err != nil {
		return nil, err
	}
	result.ConnTracker = ChainTrackers(handle, result.ConnTracker)

	return result, nil
}

// openConnection creates a tracked ConnTracker, checking concurrent/total limits.
func (h *RateLimiter) openConnection(sub string, limits []RateLimitRule, st *userState) (ConnTracker, error) {
	for _, rl := range limits {
		if rl.Type != LimitConcurrentConnections {
			continue
		}
		current := st.concurrent.Add(1)
		if current > rl.Max {
			st.concurrent.Add(-1)
			return nil, fmt.Errorf("concurrent connection limit (%d) exceeded for %q", rl.Max, sub)
		}
	}

	for i, rl := range limits {
		if rl.Type != LimitTotalConnections || st.counters[i] == nil {
			continue
		}
		if st.counters[i].Add(1) > rl.Max {
			st.concurrent.Add(-1)
			return nil, fmt.Errorf("total connection limit (%d) exceeded for %q", rl.Max, sub)
		}
	}

	return &rlConnTracker{limits: limits, state: st}, nil
}

func (h *RateLimiter) getState(sub string, limits []RateLimitRule) *userState {
	h.mu.RLock()
	st, ok := h.state[sub]
	h.mu.RUnlock()
	if ok {
		return st
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if st, ok = h.state[sub]; ok {
		return st
	}
	st = newUserState(limits)
	h.state[sub] = st
	return st
}

func checkWindowedLimits(limits []RateLimitRule, st *userState) error {
	for i, rl := range limits {
		switch rl.Type {
		case LimitConcurrentConnections, LimitTotalConnections:
			continue
		}
		if st.counters[i] != nil && st.counters[i].Total() >= rl.Max {
			return fmt.Errorf("rate limit exceeded: %s", limitLabel(rl))
		}
	}
	return nil
}

func limitLabel(rl RateLimitRule) string {
	switch rl.Type {
	case LimitUploadBytes:
		return "upload"
	case LimitDownloadBytes:
		return "download"
	case LimitTotalBytes:
		return "total bandwidth"
	default:
		return "limit"
	}
}

// ---------------------------------------------------------------------------
// Internal state tracking
// ---------------------------------------------------------------------------

type userState struct {
	concurrent atomic.Int64
	counters   []*rollingCounter
}

func newUserState(limits []RateLimitRule) *userState {
	st := &userState{counters: make([]*rollingCounter, len(limits))}
	for i, rl := range limits {
		if rl.Timeframe == Realtime || rl.Type == LimitConcurrentConnections {
			continue
		}
		st.counters[i] = newRollingCounter(rl.windowDuration())
	}
	return st
}

type rlConnTracker struct {
	limits []RateLimitRule
	state  *userState
}

func (h *rlConnTracker) RecordTraffic(upstream bool, delta int64, cancel func()) {
	for i, rl := range h.limits {
		var applies bool
		switch rl.Type {
		case LimitUploadBytes:
			applies = upstream
		case LimitDownloadBytes:
			applies = !upstream
		case LimitTotalBytes:
			applies = true
		default:
			continue
		}
		if !applies || h.state.counters[i] == nil {
			continue
		}
		if h.state.counters[i].Add(delta) >= rl.Max {
			cancel()
			return
		}
	}
}

func (h *rlConnTracker) Close(_, _ int64) {
	if h.state.concurrent.Load() > 0 {
		h.state.concurrent.Add(-1)
	}
}

type noopHandle struct{}

func (noopHandle) RecordTraffic(_ bool, _ int64, _ func()) {}
func (noopHandle) Close(_, _ int64)                        {}

// ---------------------------------------------------------------------------
// Rolling counter
// ---------------------------------------------------------------------------

const numBuckets = 60

type rollingCounter struct {
	mu       sync.Mutex
	buckets  []atomic.Int64
	times    []time.Time
	slotSize time.Duration
}

func newRollingCounter(window time.Duration) *rollingCounter {
	slotSize := window / numBuckets
	if slotSize < time.Millisecond {
		slotSize = time.Millisecond
	}
	c := &rollingCounter{
		buckets:  make([]atomic.Int64, numBuckets),
		times:    make([]time.Time, numBuckets),
		slotSize: slotSize,
	}
	now := time.Now()
	for i := range c.times {
		c.times[i] = now
	}
	return c
}

func (c *rollingCounter) Add(delta int64) int64 {
	c.evict()
	idx := int(time.Now().UnixNano()/int64(c.slotSize)) % len(c.buckets)
	c.buckets[idx].Add(delta)
	return c.sum()
}

func (c *rollingCounter) Total() int64 {
	c.evict()
	return c.sum()
}

func (c *rollingCounter) evict() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	windowSize := c.slotSize * time.Duration(len(c.buckets))
	for i := range c.buckets {
		if now.Sub(c.times[i]) >= windowSize {
			c.buckets[i].Store(0)
			c.times[i] = now
		}
	}
}

func (c *rollingCounter) sum() int64 {
	var total int64
	for i := range c.buckets {
		total += c.buckets[i].Load()
	}
	return total
}
