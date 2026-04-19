package utils

import (
	"context"

	proxykit "proxy-kit"
)

// NoneSource is a proxy source that signals a direct connection to the target
// (no upstream proxy). Use source_type = "none" in the config.
//
// The returned Proxy has an empty Host, which causes the downstream to connect
// directly to the target instead of tunnelling through an upstream proxy.
type NoneSource struct{}

// NewNoneSource returns a new NoneSource.
func NewNoneSource() *NoneSource { return &NoneSource{} }

func (n *NoneSource) Resolve(_ context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
	return proxykit.Resolved(&proxykit.Proxy{}), nil
}
