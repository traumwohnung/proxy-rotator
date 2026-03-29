package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"proxy-gateway/core"
	"proxy-gateway/utils"
)

type Config struct {
	BindAddr     string        `toml:"bind_addr"       yaml:"bind_addr"       json:"bind_addr"`
	Socks5Addr   string        `toml:"socks5_addr"     yaml:"socks5_addr"     json:"socks5_addr"`
	LogLevel     string        `toml:"log_level"       yaml:"log_level"       json:"log_level"`
	AuthSub      string        `toml:"auth_sub"       yaml:"auth_sub"       json:"auth_sub"`
	AuthPassword string        `toml:"auth_password"  yaml:"auth_password"  json:"auth_password"`
	ProxySets    []ProxySetRaw `toml:"proxy_set"      yaml:"proxy_set"      json:"proxy_set"`
}

type ProxySetRaw struct {
	Name       string                 `toml:"name"        yaml:"name"        json:"name"`
	SourceType string                 `toml:"source_type" yaml:"source_type" json:"source_type"`
	Source     map[string]interface{} `toml:"source"      yaml:"source"      json:"source"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	cfg := &Config{BindAddr: "127.0.0.1:8100", LogLevel: "info"}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, cfg)
	case ".json":
		err = json.Unmarshal(data, cfg)
	default:
		err = toml.Unmarshal(data, cfg)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return cfg, nil
}

// BuildPipeline constructs the full handler pipeline from config.
func BuildPipeline(cfg *Config, configDir string) (core.Handler, *core.SessionHandler, error) {
	if cfg.AuthSub == "" || cfg.AuthPassword == "" {
		return nil, nil, fmt.Errorf("auth_sub and auth_password are required")
	}

	sources := make(map[string]core.Handler)
	for _, raw := range cfg.ProxySets {
		src, err := buildSource(raw.SourceType, raw.Source, configDir)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy set %q: %w", raw.Name, err)
		}
		sources[raw.Name] = src
	}

	router := core.HandlerFunc(func(ctx context.Context, req *core.Request) (*core.Result, error) {
		set := core.Set(ctx)
		h, ok := sources[set]
		if !ok {
			return nil, fmt.Errorf("unknown proxy set %q", set)
		}
		return h.Resolve(ctx, req)
	})

	sticky := core.Session(router)

	pipeline := ParseJSONCreds(
		core.Auth(
			utils.NewMapAuth(map[string]string{cfg.AuthSub: cfg.AuthPassword}),
			sticky,
		),
	)

	return pipeline, sticky, nil
}

func buildSource(sourceType string, rawSource map[string]interface{}, configDir string) (core.Handler, error) {
	jsonBytes, err := json.Marshal(normalizeMap(rawSource))
	if err != nil {
		return nil, fmt.Errorf("re-encoding source config: %w", err)
	}

	switch sourceType {
	case "static_file":
		var cfg utils.StaticFileConfig
		cfg.Format = utils.DefaultProxyFormat
		if err := json.Unmarshal(jsonBytes, &cfg); err != nil {
			return nil, fmt.Errorf("invalid static_file config: %w", err)
		}
		return utils.NewStaticFileSource(&cfg, configDir)

	case "bottingtools":
		var rawCfg struct {
			Username    string                             `json:"username"`
			PasswordEnv string                             `json:"password_env"`
			Host        string                             `json:"host"`
			Product     utils.BottingtoolsRawProductConfig `json:"product"`
		}
		if err := json.Unmarshal(jsonBytes, &rawCfg); err != nil {
			return nil, fmt.Errorf("invalid bottingtools config: %w", err)
		}
		product, err := utils.ParseBottingtoolsProductConfig(rawCfg.Product)
		if err != nil {
			return nil, err
		}
		return utils.NewBottingtoolsSource(&utils.BottingtoolsConfig{
			Username: rawCfg.Username, PasswordEnv: rawCfg.PasswordEnv,
			Host: rawCfg.Host, Product: product,
		})

	case "geonode":
		var cfg utils.GeonodeConfig
		cfg.Protocol = utils.GeonodeProtocolHTTP
		if err := json.Unmarshal(jsonBytes, &cfg); err != nil {
			return nil, fmt.Errorf("invalid geonode config: %w", err)
		}
		if cfg.Session.Type == "" {
			cfg.Session.Type = utils.GeonodeSessionRotating
		}
		return utils.NewGeonodeSource(&cfg)

	default:
		return nil, fmt.Errorf("unknown source type %q", sourceType)
	}
}

func normalizeMap(v interface{}) interface{} {
	switch val := v.(type) {
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, v := range val {
			out[fmt.Sprintf("%v", k)] = normalizeMap(v)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, v := range val {
			out[k] = normalizeMap(v)
		}
		return out
	case []interface{}:
		for i, item := range val {
			val[i] = normalizeMap(item)
		}
		return val
	default:
		return val
	}
}
