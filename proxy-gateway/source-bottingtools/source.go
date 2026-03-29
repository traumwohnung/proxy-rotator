package bottingtools

import (
	"context"
	"fmt"
	"os"

	"proxy-gateway/core"
)

type Source struct {
	accountUser string
	password    string
	host        string
	product     ProductConfig
}

func FromConfig(cfg *Config) (*Source, error) {
	password := os.Getenv(cfg.PasswordEnv)
	if password == "" {
		return nil, fmt.Errorf("environment variable %q not set or empty", cfg.PasswordEnv)
	}
	return &Source{
		accountUser: cfg.Username,
		password:    password,
		host:        cfg.Host,
		product:     cfg.Product,
	}, nil
}

func BuildSource(cfg *Config) (core.Handler, error) {
	return FromConfig(cfg)
}

func (s *Source) Resolve(_ context.Context, req *core.Request) (*core.Proxy, error) {
	username := BuildUsername(s.accountUser, s.product, req.Meta)
	return &core.Proxy{
		Host:     s.host,
		Port:     1337,
		Username: username,
		Password: s.password,
	}, nil
}

func (s *Source) Describe() string {
	var product string
	switch s.product.Type {
	case "residential":
		product = fmt.Sprintf("residential(%s)", s.product.Residential.Quality.AsTypeStr())
	case "isp":
		product = "isp"
	case "datacenter":
		product = "datacenter"
	}
	return fmt.Sprintf("bottingtools %s %s@%s", product, s.accountUser, s.host)
}
