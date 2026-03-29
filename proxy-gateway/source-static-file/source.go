package staticfile

import (
	"context"
	"fmt"
	"path/filepath"

	"proxy-gateway/core"
)

// Source is a proxy source backed by a fixed list loaded from a text file.
type Source struct {
	pool        *core.CountingPool[core.Proxy]
	pathDisplay string
}

func Load(path string, format core.ProxyFormat) (*Source, error) {
	if format == "" {
		format = core.DefaultProxyFormat
	}
	proxies, err := LoadProxies(path, format)
	if err != nil {
		return nil, err
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("no proxies found in %s", path)
	}
	return &Source{
		pool:        core.NewCountingPool(proxies),
		pathDisplay: path,
	}, nil
}

func BuildSource(cfg *Config, configDir string) (*Source, error) {
	path := cfg.ProxiesFile
	if !filepath.IsAbs(path) {
		path = filepath.Join(configDir, path)
	}
	return Load(path, cfg.Format)
}

// Resolve implements core.Handler — returns the least-used proxy.
func (s *Source) Resolve(_ context.Context, _ *core.Request) (*core.Result, error) {
	p := s.pool.Next()
	if p == nil {
		return nil, fmt.Errorf("empty proxy pool")
	}
	cp := *p
	return core.ProxyResult(&cp), nil
}

func (s *Source) Describe() string {
	return fmt.Sprintf("static file %q with %d entries", s.pathDisplay, s.pool.Len())
}
