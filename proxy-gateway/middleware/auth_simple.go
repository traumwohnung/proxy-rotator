package middleware

import "fmt"

// SimpleAuth validates a single (sub, password) pair.
type SimpleAuth struct {
	sub      string
	password string
}

// NewSimpleAuth creates a SimpleAuth authenticator.
func NewSimpleAuth(sub, password string) *SimpleAuth {
	return &SimpleAuth{sub: sub, password: password}
}

func (a *SimpleAuth) Authenticate(sub, password string) error {
	if sub != a.sub || password != a.password {
		return fmt.Errorf("invalid credentials")
	}
	return nil
}
