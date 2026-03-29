package main

import "fmt"

// MultiAuth validates against a map of sub → password.
type MultiAuth struct {
	users map[string]string
}

// NewMultiAuth creates an authenticator from a user→password map.
func NewMultiAuth(users map[string]string) *MultiAuth {
	return &MultiAuth{users: users}
}

func (a *MultiAuth) Authenticate(sub, password string) error {
	expected, ok := a.users[sub]
	if !ok {
		return fmt.Errorf("unknown user %q", sub)
	}
	if password != expected {
		return fmt.Errorf("invalid credentials")
	}
	return nil
}
