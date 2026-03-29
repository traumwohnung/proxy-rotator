package middleware

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"proxy-gateway/core"
)

// SessionInfo describes an active sticky session (for API introspection).
type SessionInfo struct {
	SessionID      uint64    `json:"session_id"`
	SessionKey     string    `json:"session_key"`
	Upstream       string    `json:"upstream"`
	CreatedAt      time.Time `json:"created_at"`
	NextRotationAt time.Time `json:"next_rotation_at"`
	LastRotationAt time.Time `json:"last_rotation_at"`
	Meta           core.Meta `json:"metadata"`
}

type stickyEntry struct {
	sessionID      uint64
	proxy          core.Proxy
	startedAt      time.Time
	nextRotationAt time.Time
	lastRotationAt time.Time
	duration       time.Duration
	meta           core.Meta
}

// StickyHandler wraps an inner Handler and provides sticky-session affinity.
// Requests with the same SessionKey get the same upstream proxy for the
// configured TTL.
//
// StickyHandler also exposes session introspection methods for the REST API.
type StickyHandler struct {
	next     core.Handler
	mu       sync.RWMutex
	sessions map[string]*stickyEntry
	nextID   atomic.Uint64
}

// Sticky creates a StickyHandler that pins sessions to the same upstream
// for the TTL encoded in req.SessionTTL. If SessionTTL is 0 or SessionKey
// is empty, the request passes straight through to next.
func Sticky(next core.Handler) *StickyHandler {
	return &StickyHandler{
		next:     next,
		sessions: make(map[string]*stickyEntry),
	}
}

// Resolve implements core.Handler.
func (s *StickyHandler) Resolve(ctx context.Context, req *core.Request) (*core.Proxy, error) {
	if req.SessionTTL <= 0 || req.SessionKey == "" {
		return s.next.Resolve(ctx, req)
	}

	duration := time.Duration(req.SessionTTL) * time.Minute

	// Fast path: valid existing session.
	s.mu.RLock()
	entry, ok := s.sessions[req.SessionKey]
	if ok && time.Since(entry.startedAt) < entry.duration {
		p := entry.proxy
		s.mu.RUnlock()
		return &p, nil
	}
	s.mu.RUnlock()

	// Ask inner handler for a new proxy.
	proxy, err := s.next.Resolve(ctx, req)
	if err != nil || proxy == nil {
		return proxy, err
	}

	now := time.Now().UTC()
	newEntry := &stickyEntry{
		sessionID:      s.nextID.Add(1) - 1,
		proxy:          *proxy,
		startedAt:      now,
		nextRotationAt: now.Add(duration),
		lastRotationAt: now,
		duration:       duration,
		meta:           req.Meta,
	}

	s.mu.Lock()
	// Double-check under write lock.
	if existing, ok := s.sessions[req.SessionKey]; ok && time.Since(existing.startedAt) < existing.duration {
		p := existing.proxy
		s.mu.Unlock()
		return &p, nil
	}
	s.sessions[req.SessionKey] = newEntry
	s.mu.Unlock()

	return proxy, nil
}

// GetSession returns info for an active session, or nil.
func (s *StickyHandler) GetSession(key string) *SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.sessions[key]
	if !ok || time.Since(e.startedAt) >= e.duration {
		return nil
	}
	return infoFrom(key, e)
}

// ListSessions returns all active (non-expired) sessions.
func (s *StickyHandler) ListSessions() []SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []SessionInfo
	for key, e := range s.sessions {
		if time.Since(e.startedAt) < e.duration {
			out = append(out, *infoFrom(key, e))
		}
	}
	return out
}

// ForceRotate gets a new proxy from the inner handler and replaces the
// session's pinned proxy.
func (s *StickyHandler) ForceRotate(ctx context.Context, key string) (*SessionInfo, error) {
	s.mu.RLock()
	e, ok := s.sessions[key]
	if !ok || time.Since(e.startedAt) >= e.duration {
		s.mu.RUnlock()
		return nil, nil
	}
	meta := e.meta
	duration := e.duration
	s.mu.RUnlock()

	proxy, err := s.next.Resolve(ctx, &core.Request{
		SessionKey: key,
		Meta:       meta,
	})
	if err != nil || proxy == nil {
		return nil, err
	}

	now := time.Now().UTC()
	s.mu.Lock()
	e, ok = s.sessions[key]
	if !ok {
		s.mu.Unlock()
		return nil, nil
	}
	e.proxy = *proxy
	e.lastRotationAt = now
	e.nextRotationAt = now.Add(duration)
	info := infoFrom(key, e)
	s.mu.Unlock()

	return info, nil
}

// SpawnCleanup starts a goroutine that evicts expired sessions every 60s.
func (s *StickyHandler) SpawnCleanup() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			s.mu.Lock()
			for key, e := range s.sessions {
				if time.Since(e.startedAt) >= e.duration {
					delete(s.sessions, key)
				}
			}
			s.mu.Unlock()
		}
	}()
}

func infoFrom(key string, e *stickyEntry) *SessionInfo {
	return &SessionInfo{
		SessionID:      e.sessionID,
		SessionKey:     key,
		Upstream:       fmt.Sprintf("%s:%d", e.proxy.Host, e.proxy.Port),
		CreatedAt:      e.startedAt,
		NextRotationAt: e.nextRotationAt,
		LastRotationAt: e.lastRotationAt,
		Meta:           e.meta,
	}
}
