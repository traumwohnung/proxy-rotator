package utils

import (
	"context"
	"sync"
	"time"

	"github.com/sardanioss/httpcloak"
)

const (
	// Sessions unused for this long are evicted. Kept low to avoid holding
	// stale connections — residential upstream proxies commonly close idle
	// CONNECT tunnels after ~30-60s.
	httpcloakSessionIdleTimeout = 90 * time.Second
	// How often the cleanup goroutine runs.
	httpcloakSessionCleanupInterval = 30 * time.Second
)

type httpcloakCacheEntry struct {
	session    *httpcloak.Session
	proxyURL   string
	preset     string
	lastUsedAt time.Time
}

// httpcloakSessionCache caches httpcloak sessions keyed by topLevelSeed so
// that requests from the same proxy-gateway session reuse TLS connections,
// get session resumption, and skip redundant ECH DNS lookups.
type httpcloakSessionCache struct {
	mu      sync.Mutex
	entries map[uint64]*httpcloakCacheEntry
	done    chan struct{}
}

func newHTTPCloakSessionCache() *httpcloakSessionCache {
	c := &httpcloakSessionCache{
		entries: make(map[uint64]*httpcloakCacheEntry),
		done:    make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

// getOrCreate returns a cached session if the topLevelSeed, proxy, and preset
// match. Otherwise creates a new session and caches it.
//
// For topLevelSeed == 0 (no affinity), returns nil — caller should create a
// per-request session.
func (c *httpcloakSessionCache) getOrCreate(ctx context.Context, spec *HTTPCloakSpec, proxyURL string, insecure bool) *httpcloak.Session {
	seed := GetTopLevelSeed(ctx)
	if seed == 0 {
		return nil // no affinity, no caching
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[seed]; ok {
		// Reuse if proxy and preset match.
		if entry.proxyURL == proxyURL && entry.preset == spec.Preset {
			entry.lastUsedAt = time.Now()
			return entry.session
		}
		// Proxy or preset changed (e.g. after rotation) — close old session.
		entry.session.Close()
		delete(c.entries, seed)
	}

	opts := spec.sessionOptions(proxyURL, insecure)
	session := httpcloak.NewSession(spec.Preset, opts...)

	c.entries[seed] = &httpcloakCacheEntry{
		session:    session,
		proxyURL:   proxyURL,
		preset:     spec.Preset,
		lastUsedAt: time.Now(),
	}
	return session
}

// evict closes and removes the cached session for the given topLevelSeed.
func (c *httpcloakSessionCache) evict(seed uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[seed]; ok {
		entry.session.Close()
		delete(c.entries, seed)
	}
}

// close shuts down the cleanup goroutine and closes all cached sessions.
func (c *httpcloakSessionCache) close() {
	close(c.done)
	c.mu.Lock()
	defer c.mu.Unlock()
	for seed, entry := range c.entries {
		entry.session.Close()
		delete(c.entries, seed)
	}
}

func (c *httpcloakSessionCache) cleanupLoop() {
	ticker := time.NewTicker(httpcloakSessionCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.pruneIdle()
		}
	}
}

func (c *httpcloakSessionCache) pruneIdle() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-httpcloakSessionIdleTimeout)
	for seed, entry := range c.entries {
		if entry.lastUsedAt.Before(cutoff) {
			entry.session.Close()
			delete(c.entries, seed)
		}
	}
}
