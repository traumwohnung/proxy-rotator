package middleware

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"proxy-gateway/core"
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

// RateLimit describes a single constraint.
type RateLimit struct {
	Type      LimitType
	Timeframe Timeframe
	Window    int // multiplier (e.g. Hourly, Window=6 → 6h rolling)
	Max       int64
}

func (r RateLimit) windowDuration() time.Duration {
	w := r.Window
	if w < 1 {
		w = 1
	}
	return r.Timeframe.duration() * time.Duration(w)
}

// RateLimitHandler wraps an inner Handler and enforces per-sub rate limits.
// It also implements core.ConnectionTracker so the gateway can feed it
// real-time traffic data for mid-connection enforcement.
type RateLimitHandler struct {
	next   core.Handler
	limits func(sub string) []RateLimit
	mu     sync.RWMutex
	state  map[string]*userState
}

// RateLimitOption configures the rate limit handler.
type RateLimitOption func(*RateLimitHandler)

// WithLimits sets a per-sub limit function.
func WithLimits(fn func(sub string) []RateLimit) RateLimitOption {
	return func(h *RateLimitHandler) { h.limits = fn }
}

// StaticLimits applies the same limits to all subs.
func StaticLimits(limits []RateLimit) RateLimitOption {
	return WithLimits(func(_ string) []RateLimit { return limits })
}

// RateLimit creates a rate-limiting middleware.
func RateLimiting(next core.Handler, opts ...RateLimitOption) *RateLimitHandler {
	h := &RateLimitHandler{
		next:  next,
		state: make(map[string]*userState),
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.limits == nil {
		h.limits = func(_ string) []RateLimit { return nil }
	}
	return h
}

// Resolve implements core.Handler.
func (h *RateLimitHandler) Resolve(ctx context.Context, req *core.Request) (*core.Proxy, error) {
	limits := h.limits(req.Sub)
	if len(limits) == 0 {
		return h.next.Resolve(ctx, req)
	}
	st := h.getState(req.Sub, limits)
	if err := checkWindowedLimits(limits, st); err != nil {
		return nil, err
	}
	return h.next.Resolve(ctx, req)
}

// OpenConnection implements core.ConnectionTracker.
func (h *RateLimitHandler) OpenConnection(sub string) (core.ConnHandle, error) {
	limits := h.limits(sub)
	if len(limits) == 0 {
		return &noopHandle{}, nil
	}
	st := h.getState(sub, limits)

	if err := checkWindowedLimits(limits, st); err != nil {
		return nil, err
	}

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
			st.concurrent.Add(-1) // rollback concurrent
			return nil, fmt.Errorf("total connection limit (%d) exceeded for %q", rl.Max, sub)
		}
	}

	return &rlConnHandle{limits: limits, state: st}, nil
}

// ResetUser clears all counters for sub.
func (h *RateLimitHandler) ResetUser(sub string) {
	h.mu.Lock()
	delete(h.state, sub)
	h.mu.Unlock()
}

func (h *RateLimitHandler) getState(sub string, limits []RateLimit) *userState {
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

func checkWindowedLimits(limits []RateLimit, st *userState) error {
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

func limitLabel(rl RateLimit) string {
	typ := ""
	switch rl.Type {
	case LimitUploadBytes:
		typ = "upload"
	case LimitDownloadBytes:
		typ = "download"
	case LimitTotalBytes:
		typ = "total bandwidth"
	default:
		typ = "limit"
	}
	return typ
}

type userState struct {
	concurrent atomic.Int64
	counters   []*rollingCounter
}

func newUserState(limits []RateLimit) *userState {
	st := &userState{counters: make([]*rollingCounter, len(limits))}
	for i, rl := range limits {
		if rl.Timeframe == Realtime || rl.Type == LimitConcurrentConnections {
			continue
		}
		st.counters[i] = newRollingCounter(rl.windowDuration())
	}
	return st
}

type rlConnHandle struct {
	limits []RateLimit
	state  *userState
}

func (h *rlConnHandle) RecordTraffic(upstream bool, delta int64, cancel func()) {
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

func (h *rlConnHandle) Close(_, _ int64) {
	if h.state.concurrent.Load() > 0 {
		h.state.concurrent.Add(-1)
	}
}

type noopHandle struct{}

func (noopHandle) RecordTraffic(_ bool, _ int64, _ func()) {}
func (noopHandle) Close(_, _ int64)                        {}

// ---------------------------------------------------------------------------
// rolling counter
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
