package geonode

import (
	"context"
	"fmt"
	"os"
	"strings"

	"proxy-gateway/core"
)

type Source struct {
	config   Config
	password string
}

func FromConfig(cfg *Config) (*Source, error) {
	password := os.Getenv(cfg.PasswordEnv)
	if password == "" {
		return nil, fmt.Errorf("geonode: env var %q not set or empty", cfg.PasswordEnv)
	}
	return &Source{config: *cfg, password: password}, nil
}

func BuildSource(cfg *Config) (core.Handler, error) {
	return FromConfig(cfg)
}

func (s *Source) Resolve(_ context.Context, _ *core.Request) (*core.Proxy, error) {
	proto := core.ProtocolHTTP
	if s.config.Protocol == GeonodeProtocolSocks5 {
		proto = core.ProtocolSOCKS5
	}
	return &core.Proxy{
		Host:     s.config.Host(),
		Port:     s.config.Port(),
		Username: BuildUsername(&s.config),
		Password: s.password,
		Protocol: proto,
	}, nil
}

func (s *Source) Describe() string {
	parts := []string{"geonode"}
	if len(s.config.Countries) > 0 {
		codes := make([]string, len(s.config.Countries))
		for i, c := range s.config.Countries {
			codes[i] = strings.ToUpper(c.AsParamStr())
		}
		parts = append(parts, strings.Join(codes, ","))
	}
	parts = append(parts, fmt.Sprintf("%s@%s:%d", s.config.Username, s.config.Host(), s.config.Port()))
	return strings.Join(parts, " ")
}
