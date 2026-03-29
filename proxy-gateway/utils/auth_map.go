package utils

import "fmt"

// MapAuth validates credentials against a map of sub → password.
type MapAuth struct {
	users map[string]string
}

// NewMapAuth creates a MapAuth authenticator from a user/password map.
func NewMapAuth(users map[string]string) *MapAuth {
	return &MapAuth{users: users}
}

// Authenticate implements core.Authenticator.
func (a *MapAuth) Authenticate(sub, password string) error {
	expected, ok := a.users[sub]
	if !ok {
		return fmt.Errorf("unknown user %q", sub)
	}
	if password != expected {
		return fmt.Errorf("invalid credentials")
	}
	return nil
}
