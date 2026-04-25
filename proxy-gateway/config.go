package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"proxy-kit/utils"
)

// Config is the top-level server configuration.
type Config struct {
	BindAddr   string `toml:"bind_addr"  yaml:"bind_addr"  json:"bind_addr"`
	Socks5Addr string `toml:"socks5_addr" yaml:"socks5_addr" json:"socks5_addr"`
	AdminAddr  string `toml:"admin_addr"  yaml:"admin_addr"  json:"admin_addr"`
	LogLevel   string `toml:"log_level"  yaml:"log_level"  json:"log_level"`

	// MITMCACert and MITMCAKey are paths to PEM-encoded CA certificate and
	// private key used for MITM TLS interception (httpcloak fingerprint
	// spoofing). When omitted, a new CA is generated at startup.
	MITMCACert string `toml:"mitm_ca_cert" yaml:"mitm_ca_cert" json:"mitm_ca_cert"`
	MITMCAKey  string `toml:"mitm_ca_key"  yaml:"mitm_ca_key"  json:"mitm_ca_key"`

	ProxySets []ProxySetConfig `toml:"proxy_set" yaml:"proxy_set" json:"proxy_set"`
}

// ProxySetConfig describes one named proxy set in the config file.
type ProxySetConfig struct {
	Name       string `toml:"name"     yaml:"name"     json:"name"`
	SourceType string `toml:"provider" yaml:"provider" json:"provider"`

	// Source is parsed lazily into a typed config by buildSource.
	StaticFile   *utils.StaticFileConfig   `toml:"static_file"  yaml:"static_file"  json:"static_file"`
	Bottingtools *utils.BottingtoolsConfig `toml:"bottingtools" yaml:"bottingtools" json:"bottingtools"`
	Geonode      *utils.GeonodeConfig      `toml:"geonode"      yaml:"geonode"      json:"geonode"`
	ProxyingIO   *utils.ProxyingIOConfig   `toml:"proxyingio"   yaml:"proxyingio"   json:"proxyingio"`
	Webshare     *utils.WebshareConfig     `toml:"webshare"     yaml:"webshare"     json:"webshare"`
}

// LoadConfig reads and parses a TOML, YAML, or JSON config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	cfg := &Config{
		BindAddr: "127.0.0.1:8100",
		LogLevel: "info",
	}
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
