package core

import (
	"fmt"
	"sync"
)

// Gateway is a multi-protocol proxy gateway. It wires multiple downstream
// listeners to a single handler pipeline, using pluggable upstream dialers.
type Gateway struct {
	handler   Handler
	upstream  Upstream
	listeners []listener
}

type listener struct {
	downstream Downstream
	addr       string
}

// Option configures a Gateway.
type Option func(*Gateway)

// WithUpstream sets the upstream dialer. Default is AutoUpstream().
func WithUpstream(u Upstream) Option {
	return func(g *Gateway) { g.upstream = u }
}

// Listen adds a downstream listener at the given address.
func Listen(d Downstream, addr string) Option {
	return func(g *Gateway) {
		g.listeners = append(g.listeners, listener{downstream: d, addr: addr})
	}
}

// New creates a Gateway with the given handler pipeline and options.
func New(handler Handler, opts ...Option) *Gateway {
	g := &Gateway{handler: handler}
	for _, opt := range opts {
		opt(g)
	}
	if g.upstream == nil {
		g.upstream = AutoUpstream()
	}
	return g
}

// ListenAndServe starts all downstream listeners. Blocks until one returns
// an error.
func (g *Gateway) ListenAndServe() error {
	if len(g.listeners) == 0 {
		return fmt.Errorf("no listeners configured")
	}

	errc := make(chan error, len(g.listeners))
	var wg sync.WaitGroup

	for _, l := range g.listeners {
		// Inject upstream into any downstream that supports it.
		if ua, ok := l.downstream.(UpstreamAware); ok {
			ua.SetUpstream(g.upstream)
		}

		wg.Add(1)
		go func(l listener) {
			defer wg.Done()
			errc <- l.downstream.Serve(l.addr, g.handler)
		}(l)
	}

	// Return the first error.
	err := <-errc
	return err
}
