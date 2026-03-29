package utils

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"proxy-gateway/core"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// StaticFileConfig is the configuration for a static proxy file source.
type StaticFileConfig struct {
	ProxiesFile string      `toml:"proxies_file" yaml:"proxies_file" json:"proxies_file"`
	Format      ProxyFormat `toml:"format"       yaml:"format"       json:"format"`
}

// ---------------------------------------------------------------------------
// Source
// ---------------------------------------------------------------------------

// StaticFileSource is a proxy source backed by a fixed list loaded from a text file.
type StaticFileSource struct {
	pool        *CountingPool[core.Proxy]
	pathDisplay string
}

// LoadStaticFileSource loads proxies from a file.
func LoadStaticFileSource(path string, format ProxyFormat) (*StaticFileSource, error) {
	if format == "" {
		format = DefaultProxyFormat
	}
	proxies, err := loadProxiesFromFile(path, format)
	if err != nil {
		return nil, err
	}
	if len(proxies) == 0 {
		return nil, fmt.Errorf("no proxies found in %s", path)
	}
	return &StaticFileSource{
		pool:        NewCountingPool(proxies),
		pathDisplay: path,
	}, nil
}

// NewStaticFileSource creates a StaticFileSource from config.
func NewStaticFileSource(cfg *StaticFileConfig, configDir string) (*StaticFileSource, error) {
	path := cfg.ProxiesFile
	if !filepath.IsAbs(path) {
		path = filepath.Join(configDir, path)
	}
	return LoadStaticFileSource(path, cfg.Format)
}

// Resolve implements core.Handler — returns the least-used proxy.
func (s *StaticFileSource) Resolve(_ context.Context, _ *core.Request) (*core.Result, error) {
	p := s.pool.Next()
	if p == nil {
		return nil, fmt.Errorf("empty proxy pool")
	}
	cp := *p
	return core.Resolved(&cp), nil
}

// Describe returns a human-readable description.
func (s *StaticFileSource) Describe() string {
	return fmt.Sprintf("static file %q with %d entries", s.pathDisplay, s.pool.Len())
}

// ---------------------------------------------------------------------------
// File parsing
// ---------------------------------------------------------------------------

func loadProxiesFromFile(path string, format ProxyFormat) ([]core.Proxy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()

	var proxies []core.Proxy
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := ParseProxyLine(line, format)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid proxy entry %q: %w", path, lineNum, line, err)
		}
		proxies = append(proxies, p)
	}
	return proxies, scanner.Err()
}
