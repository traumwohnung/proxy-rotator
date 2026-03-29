// Package middleware provides composable Handler wrappers for the proxy pipeline.
package core

import (
	"context"
	"fmt"
)

// Authenticator validates (sub, password) credentials.
// This is the only interface auth backends need to implement.
type Authenticator interface {
	Authenticate(sub, password string) error
}

// Auth wraps an inner Handler with credential validation.
// The Request.Sub and Request.Password must already be populated
// (by the gateway's Basic-auth parsing, or programmatically).
func Auth(auth Authenticator, next Handler) Handler {
	return HandlerFunc(func(ctx context.Context, req *Request) (*Proxy, error) {
		if err := auth.Authenticate(req.Sub, req.Password); err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}
		return next.Resolve(ctx, req)
	})
}
