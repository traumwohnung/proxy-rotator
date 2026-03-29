package core

import (
	"context"
	"net"
)

// Downstream is a listener that accepts client connections and dispatches
// them through a Handler pipeline.
type Downstream interface {
	Serve(addr string, handler Handler) error
}

// UpstreamAware is an optional interface for Downstream implementations
// that need an Upstream dialer injected by the Gateway. The Gateway calls
// SetUpstream before calling Serve.
type UpstreamAware interface {
	SetUpstream(u Upstream)
}

// Upstream dials a target through an upstream proxy.
type Upstream interface {
	Dial(ctx context.Context, proxy *Proxy, target string) (net.Conn, error)
}

// UpstreamFunc adapts a function to the Upstream interface.
type UpstreamFunc func(ctx context.Context, proxy *Proxy, target string) (net.Conn, error)

func (f UpstreamFunc) Dial(ctx context.Context, proxy *Proxy, target string) (net.Conn, error) {
	return f(ctx, proxy, target)
}
