package proxygatewayclient

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// UsernameParams holds the decoded components of a proxy-gateway username.
type UsernameParams struct {
	// Set is the proxy set name — must match a [[proxy_set]] name in the server config.
	Set string `json:"set"`
	// Minutes is the affinity duration (0 = new proxy every request, 1–1440 = sticky session).
	Minutes int `json:"minutes"`
	// Meta is an arbitrary key/value map that, together with Set, forms the affinity key.
	Meta map[string]any `json:"meta,omitempty"`
}

// BuildUsername encodes the given parameters into a base64 proxy-gateway username.
// The returned string is used as the Proxy-Authorization username; the password is always "x".
//
//	username := proxygatewayclient.BuildUsername(proxygatewayclient.UsernameParams{
//	    Set:     "residential",
//	    Minutes: 60,
//	    Meta:    map[string]any{"platform": "myapp", "user": "alice"},
//	})
func BuildUsername(p UsernameParams) (string, error) {
	if p.Set == "" {
		return "", errors.New("proxy set name must not be empty")
	}
	if p.Minutes < 0 || p.Minutes > 1440 {
		return "", fmt.Errorf("minutes must be between 0 and 1440, got %d", p.Minutes)
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshalling username: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// MustBuildUsername is like BuildUsername but panics on error.
// Intended for use with static/compile-time-known parameters.
func MustBuildUsername(p UsernameParams) string {
	u, err := BuildUsername(p)
	if err != nil {
		panic("proxygatewayclient.MustBuildUsername: " + err.Error())
	}
	return u
}

// ParseUsername decodes a base64 proxy-gateway username back into its components.
func ParseUsername(username string) (*UsernameParams, error) {
	raw, err := base64.StdEncoding.DecodeString(username)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(username)
		if err != nil {
			return nil, fmt.Errorf("decoding base64 username: %w", err)
		}
	}
	var p UsernameParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parsing username JSON: %w", err)
	}
	if p.Set == "" {
		return nil, errors.New("username JSON missing 'set' field")
	}
	return &p, nil
}
