// Package proxygatewayclient provides a client for the proxy-gateway admin API,
// plus helpers for building and parsing proxy usernames.
package proxygatewayclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SessionInfo represents an active sticky session returned by the admin API.
type SessionInfo struct {
	// Internal session ID, assigned at creation (starts at 0, increments per session).
	SessionID uint64 `json:"session_id"`
	// The raw base64 username string used as the affinity key.
	Username string `json:"username"`
	// The proxy set name.
	ProxySet string `json:"proxy_set"`
	// The upstream proxy address (host:port).
	Upstream string `json:"upstream"`
	// Session creation time — never changes.
	CreatedAt time.Time `json:"created_at"`
	// When the current proxy assignment expires. Reset on ForceRotate.
	NextRotationAt time.Time `json:"next_rotation_at"`
	// When the proxy was last assigned — equals CreatedAt unless ForceRotate was called.
	LastRotationAt time.Time `json:"last_rotation_at"`
	// The decoded metadata object from the username JSON.
	Metadata map[string]any `json:"metadata"`
}

// APIError is returned by the server when a request fails.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("proxy-gateway %d: %s", e.StatusCode, e.Message)
}

// ClientOptions configures a Client.
type ClientOptions struct {
	// BaseURL is the base URL of the proxy-gateway admin server, e.g. "http://proxy-gateway:9000".
	BaseURL string
	// APIKey is the Bearer token for authenticating with the admin API.
	APIKey string
	// HTTPClient is an optional custom HTTP client. Defaults to a client with a 10s timeout.
	HTTPClient *http.Client
}

// Client is a typed client for the proxy-gateway admin API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// New creates a new Client with the given options.
func New(opts ClientOptions) *Client {
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		baseURL:    strings.TrimRight(opts.BaseURL, "/"),
		apiKey:     opts.APIKey,
		httpClient: hc,
	}
}

// ListSessions returns all active sticky sessions across all proxy sets.
// Sessions with 0 minutes (no affinity) are not tracked.
func (c *Client) ListSessions(ctx context.Context) ([]SessionInfo, error) {
	var sessions []SessionInfo
	if err := c.get(ctx, "/api/sessions", &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

// GetSession returns the active session for the given base64 username.
// Returns nil, nil if no active session exists for that username.
func (c *Client) GetSession(ctx context.Context, username string) (*SessionInfo, error) {
	var info SessionInfo
	path := "/api/sessions/" + url.PathEscape(username)
	err := c.get(ctx, path, &info)
	if err != nil {
		var apiErr *APIError
		if isAPIError(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &info, nil
}

// ForceRotate force-rotates the upstream proxy for an existing session.
// It immediately reassigns the upstream proxy and resets the session TTL.
// Returns nil, nil if no active session exists for that username.
func (c *Client) ForceRotate(ctx context.Context, username string) (*SessionInfo, error) {
	var info SessionInfo
	path := "/api/sessions/" + url.PathEscape(username) + "/rotate"
	err := c.post(ctx, path, &info)
	if err != nil {
		var apiErr *APIError
		if isAPIError(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &info, nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, out)
}

func (c *Client) post(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodPost, path, out)
}

func (c *Client) do(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &apiErr)
		msg := apiErr.Error
		if msg == "" {
			msg = string(body)
		}
		return &APIError{StatusCode: resp.StatusCode, Message: msg}
	}

	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

func isAPIError(err error, target **APIError) bool {
	if e, ok := err.(*APIError); ok {
		*target = e
		return true
	}
	return false
}
