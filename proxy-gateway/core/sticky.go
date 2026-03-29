package core

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// SessionInfo describes an active sticky session (for API introspection).
type SessionInfo struct {
	SessionID      uint64    `json:"session_id"`
	SessionKey     string    `json:"session_key"`
	Upstream       string    `json:"upstream"`
	CreatedAt      time.Time `json:"created_at"`
	NextRotationAt time.Time `json:"next_rotation_at"`
	LastRotationAt time.Time `json:"last_rotation_at"`
	Meta           Meta      `json:"metadata"`
}

type stickyEntry struct {
	sessionID      uint64
	proxy          Proxy
	startedAt      time.Time
	nextRotationAt time.Time
	lastRotationAt time.Time
	duration       time.Duration
	meta           Meta
}

// StickyHandler wraps an inner Handler and provides sticky-session affinity.
// Requests with the same SessionKey get the same upstream proxy for the
// configured TTL.
type StickyHandler struct {
	next     Handler
	mu       sync.RWMutex
	sessions map[string]*stickyEntry
	nextID   atomic.Uint64
}

// Sticky creates a StickyHandler that pins sessions to the same upstream
// for the TTL encoded in SessionTTL(ctx). If SessionTTL is 0 or SessionKey
// is empty, the request passes straight through to next.
func Sticky(next Handler) *StickyHandler {
	return &StickyHandler{
		next:     next,
		sessions: make(map[string]*stickyEntry),
	}
}

// Resolve implements Handler.
func (s *StickyHandler) Resolve(ctx context.Context, req *Request) (*Result, error) {
	sessionKey := SessionKey(ctx)
	sessionTTL := SessionTTL(ctx)

	if sessionTTL <= 0 || sessionKey == "" {
		return s.next.Resolve(ctx, req)
	}

	duration := time.Duration(sessionTTL) * time.Minute

	s.mu.RLock()
	entry, ok := s.sessions[sessionKey]
	if ok && time.Since(entry.startedAt) < entry.duration {
		p := entry.proxy
		s.mu.RUnlock()
		return ProxyResult(&p), nil
	}
	s.mu.RUnlock()

	result, err := s.next.Resolve(ctx, req)
	if err != nil || result == nil || result.Proxy == nil {
		return result, err
	}

	now := time.Now().UTC()
	newEntry := &stickyEntry{
		sessionID:      s.nextID.Add(1) - 1,
		proxy:          *result.Proxy,
		startedAt:      now,
		nextRotationAt: now.Add(duration),
		lastRotationAt: now,
		duration:       duration,
		meta:           GetMeta(ctx),
	}

	s.mu.Lock()
	if existing, ok := s.sessions[sessionKey]; ok && time.Since(existing.startedAt) < existing.duration {
		p := existing.proxy
		s.mu.Unlock()
		return ProxyResult(&p), nil
	}
	s.sessions[sessionKey] = newEntry
	s.mu.Unlock()

	return result, nil
}

// GetSession returns info about an active session, or nil.
func (s *StickyHandler) GetSession(key string) *SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.sessions[key]
	if !ok || time.Since(e.startedAt) >= e.duration {
		return nil
	}
	return infoFrom(key, e)
}

// ListSessions returns info about all active sessions.
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

// ForceRotate resolves a new proxy for the given session key.
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

	ctx = WithSessionKey(ctx, key)
	ctx = WithMeta(ctx, meta)

	result, err := s.next.Resolve(ctx, &Request{})
	if err != nil || result == nil || result.Proxy == nil {
		return nil, err
	}

	now := time.Now().UTC()
	s.mu.Lock()
	e, ok = s.sessions[key]
	if !ok {
		s.mu.Unlock()
		return nil, nil
	}
	e.proxy = *result.Proxy
	e.lastRotationAt = now
	e.nextRotationAt = now.Add(duration)
	info := infoFrom(key, e)
	s.mu.Unlock()

	return info, nil
}

// SpawnCleanup starts a background goroutine that prunes expired sessions.
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
