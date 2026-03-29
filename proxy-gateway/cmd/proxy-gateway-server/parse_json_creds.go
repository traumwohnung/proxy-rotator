package main

import (
	"context"
	"encoding/json"
	"fmt"

	"proxy-gateway/core"
)

// ParseJSONCreds is middleware that parses RawUsername as a JSON object and
// populates context with Sub, Set, SessionTTL, Meta, SessionKey, and Password.
//
// Expected JSON format:
//
//	{"sub":"alice", "set":"residential", "minutes":5, "meta":{"app":"crawler"}}
//
// This is specific to our username encoding — other systems can write their
// own credential-parsing middleware that populates context differently.
func ParseJSONCreds(next core.Handler) core.Handler {
	return core.HandlerFunc(func(ctx context.Context, req *core.Request) (*core.Result, error) {
		if req.RawUsername == "" {
			return nil, fmt.Errorf("empty username")
		}

		var parsed struct {
			Sub     string                 `json:"sub"`
			Set     string                 `json:"set"`
			Minutes int                    `json:"minutes"`
			Meta    map[string]interface{} `json:"meta"`
		}
		if err := json.Unmarshal([]byte(req.RawUsername), &parsed); err != nil {
			return nil, fmt.Errorf("username is not valid JSON: %w", err)
		}
		if parsed.Sub == "" {
			return nil, fmt.Errorf("'sub' must not be empty")
		}
		if parsed.Set == "" {
			return nil, fmt.Errorf("'set' must not be empty")
		}

		ctx = core.WithSub(ctx, parsed.Sub)
		ctx = core.WithPassword(ctx, req.RawPassword)
		ctx = core.WithSet(ctx, parsed.Set)
		ctx = core.WithSessionTTL(ctx, parsed.Minutes)
		ctx = core.WithMeta(ctx, core.Meta(parsed.Meta))
		ctx = core.WithSessionKey(ctx, req.RawUsername) // stable key for affinity

		return next.Resolve(ctx, req)
	})
}
