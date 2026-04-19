package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"proxy-kit"
	"proxy-kit/utils"
)

// Username is the parsed proxy-gateway username JSON.
//
//	{"set":"residential", "minutes":5, "meta":{"platform":"myapp","user":"alice"}}
//	{"set":"direct", "httpcloak":"chrome-latest"}
//	{"set":"direct", "httpcloak":{"preset":"chrome-latest","ja3":"771,...","akamai":"1:65536|..."}}
type Username struct {
	Affinity  AffinityParams
	Minutes   int
	Httpcloak *utils.HTTPCloakSpec // optional; triggers MITM + TLS fingerprint spoofing
	Raw       string               // original JSON string, stored as session label
}

// ParseUsername parses a raw JSON username string.
func ParseUsername(raw string) (*Username, error) {
	// Accept both raw JSON and base64-encoded JSON (as produced by the client SDKs).
	jsonBytes := []byte(raw)
	if len(raw) > 0 && raw[0] != '{' {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(raw)
			if err != nil {
				return nil, fmt.Errorf("username is neither JSON nor valid base64: %w", err)
			}
		}
		jsonBytes = decoded
	}
	var j struct {
		Set      string                 `json:"set"`
		Minutes  int                    `json:"minutes"`
		Meta     map[string]interface{} `json:"meta"`
		Httpcloak json.RawMessage       `json:"httpcloak"`
	}
	if err := json.Unmarshal(jsonBytes, &j); err != nil {
		return nil, fmt.Errorf("username is not valid JSON: %w", err)
	}
	if j.Set == "" {
		return nil, fmt.Errorf("'set' must not be empty")
	}
	spec, err := utils.ParseHTTPCloakSpec(j.Httpcloak)
	if err != nil {
		return nil, fmt.Errorf("httpcloak: %w", err)
	}
	return &Username{
		Affinity:  AffinityParams{Set: j.Set, Meta: j.Meta},
		Minutes:   j.Minutes,
		Httpcloak: spec,
		Raw:       string(jsonBytes),
	}, nil
}

// ---------------------------------------------------------------------------
// Context keys
// ---------------------------------------------------------------------------

type ctxKey int

const (
	ctxSet ctxKey = iota
	ctxAffinityJSON
	ctxHTTPCloakPreset
)

func withSet(ctx context.Context, set string) context.Context {
	return context.WithValue(ctx, ctxSet, set)
}

func getSet(ctx context.Context) string {
	v, _ := ctx.Value(ctxSet).(string)
	return v
}

func withAffinityJSON(ctx context.Context, json string) context.Context {
	return context.WithValue(ctx, ctxAffinityJSON, json)
}

func getAffinityJSON(ctx context.Context) string {
	v, _ := ctx.Value(ctxAffinityJSON).(string)
	return v
}

func withHTTPCloakSpec(ctx context.Context, spec *utils.HTTPCloakSpec) context.Context {
	return context.WithValue(ctx, ctxHTTPCloakPreset, spec)
}

func getHTTPCloakSpec(ctx context.Context) *utils.HTTPCloakSpec {
	v, _ := ctx.Value(ctxHTTPCloakPreset).(*utils.HTTPCloakSpec)
	return v
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// ParseJSONCreds is middleware that parses RawUsername as a JSON object and
// populates context with set, seed TTL, top-level seed, and session label.
func ParseJSONCreds(next proxykit.Handler) proxykit.Handler {
	return proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		if req.RawUsername == "" {
			return nil, fmt.Errorf("empty username")
		}
		u, err := ParseUsername(req.RawUsername)
		if err != nil {
			return nil, err
		}

		ctx = withSet(ctx, u.Affinity.Set)
		ctx = withAffinityJSON(ctx, u.Affinity.CanonicalJSON())
		ctx = utils.WithSeedTTL(ctx, time.Duration(u.Minutes)*time.Minute)
		ctx = utils.WithTopLevelSeed(ctx, u.Affinity.Seed())
		ctx = utils.WithSessionLabel(ctx, u.Raw)
		ctx = withHTTPCloakSpec(ctx, u.Httpcloak)

		return next.Resolve(ctx, req)
	})
}

// PasswordAuth is middleware that checks req.RawPassword against a fixed
// password. If password is empty, all requests pass through.
func PasswordAuth(password string, next proxykit.Handler) proxykit.Handler {
	if password == "" {
		return next
	}
	return proxykit.HandlerFunc(func(ctx context.Context, req *proxykit.Request) (*proxykit.Result, error) {
		if req.RawPassword != password {
			return nil, fmt.Errorf("invalid credentials")
		}
		return next.Resolve(ctx, req)
	})
}
