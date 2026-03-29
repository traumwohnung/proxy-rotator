package core

import (
	"context"
	"fmt"
)

// Authenticator validates credentials.
type Authenticator interface {
	Authenticate(sub, password string) error
}

// Auth is middleware that checks credentials from context before delegating.
func Auth(auth Authenticator, next Handler) Handler {
	return HandlerFunc(func(ctx context.Context, req *Request) (*Result, error) {
		if err := auth.Authenticate(Sub(ctx), Password(ctx)); err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}
		return next.Resolve(ctx, req)
	})
}
