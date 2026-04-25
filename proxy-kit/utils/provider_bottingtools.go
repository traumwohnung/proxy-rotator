package utils

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"proxy-kit"
)

const bottingtoolsDefaultHost = "proxy.bottingtools.com"

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// BottingtoolsConfig is the configuration for the bottingtools proxy source.
// Product is stored as the raw (flat) representation that TOML/YAML can decode
// directly; NewBottingtoolsSource converts it to the typed BottingtoolsProductConfig.
type BottingtoolsConfig struct {
	Username    string                       `toml:"username"     yaml:"username"     json:"username"`
	PasswordEnv string                       `toml:"password_env" yaml:"password_env" json:"password_env"`
	Host        string                       `toml:"host"         yaml:"host"         json:"host"`
	Product     BottingtoolsRawProductConfig `toml:"product"      yaml:"product"      json:"product"`
}

// BottingtoolsProductConfig holds the product type and its specific parameters.
type BottingtoolsProductConfig struct {
	Type        string                         `toml:"type" yaml:"type" json:"type"`
	Residential *BottingtoolsResidentialConfig `toml:"-"    yaml:"-"    json:"-"`
	ISP         *BottingtoolsISPConfig         `toml:"-"    yaml:"-"    json:"-"`
	Datacenter  *BottingtoolsDatacenterConfig  `toml:"-"    yaml:"-"    json:"-"`
}

// BottingtoolsResidentialConfig holds residential-specific parameters.
type BottingtoolsResidentialConfig struct {
	Quality   BottingtoolsResidentialQuality `toml:"quality"   yaml:"quality"   json:"quality"`
	Countries []Country                      `toml:"countries" yaml:"countries" json:"countries"`
	City      string                         `toml:"city"      yaml:"city"      json:"city"`
}

// Validate checks residential config constraints.
func (r *BottingtoolsResidentialConfig) Validate() error {
	if r.City != "" && len(r.Countries) != 1 {
		return fmt.Errorf("residential `city` requires exactly one country, but %d are configured", len(r.Countries))
	}
	return nil
}

// BottingtoolsISPConfig holds ISP-specific parameters.
type BottingtoolsISPConfig struct {
	Countries []Country `toml:"countries" yaml:"countries" json:"countries"`
}

// BottingtoolsDatacenterConfig holds datacenter-specific parameters.
type BottingtoolsDatacenterConfig struct {
	Countries []Country `toml:"countries" yaml:"countries" json:"countries"`
}

// BottingtoolsResidentialQuality is the residential proxy quality tier.
type BottingtoolsResidentialQuality string

const (
	BottingtoolsResidentialQualityLow  BottingtoolsResidentialQuality = "low"
	BottingtoolsResidentialQualityHigh BottingtoolsResidentialQuality = "high"
)

// AsTypeStr returns the string used in the upstream username.
func (q BottingtoolsResidentialQuality) AsTypeStr() string {
	if q == BottingtoolsResidentialQualityLow {
		return "low"
	}
	return "high"
}

// BottingtoolsRawProductConfig is used for unmarshaling before dispatching to the typed config.
type BottingtoolsRawProductConfig struct {
	Type      string    `toml:"type"      yaml:"type"      json:"type"`
	Quality   string    `toml:"quality"   yaml:"quality"   json:"quality"`
	Countries []Country `toml:"countries" yaml:"countries" json:"countries"`
	City      string    `toml:"city"      yaml:"city"      json:"city"`
	SessTime  int       `toml:"sess_time" yaml:"sess_time" json:"sess_time"`
}

// ParseBottingtoolsProductConfig converts a raw product table into a typed config.
func ParseBottingtoolsProductConfig(raw BottingtoolsRawProductConfig) (BottingtoolsProductConfig, error) {
	switch raw.Type {
	case "residential":
		quality := BottingtoolsResidentialQualityHigh
		if raw.Quality == "low" {
			quality = BottingtoolsResidentialQualityLow
		}
		cfg := &BottingtoolsResidentialConfig{
			Quality:   quality,
			Countries: raw.Countries,
			City:      raw.City,
		}
		if err := cfg.Validate(); err != nil {
			return BottingtoolsProductConfig{}, err
		}
		return BottingtoolsProductConfig{Type: "residential", Residential: cfg}, nil
	case "isp":
		return BottingtoolsProductConfig{Type: "isp", ISP: &BottingtoolsISPConfig{Countries: raw.Countries}}, nil
	case "datacenter":
		return BottingtoolsProductConfig{Type: "datacenter", Datacenter: &BottingtoolsDatacenterConfig{Countries: raw.Countries}}, nil
	default:
		return BottingtoolsProductConfig{}, fmt.Errorf("unknown bottingtools product type %q (expected: residential, isp, datacenter)", raw.Type)
	}
}

// ---------------------------------------------------------------------------
// Source
// ---------------------------------------------------------------------------

// BottingtoolsSource is a proxy source backed by the bottingtools API.
type BottingtoolsSource struct {
	accountUser string
	password    string
	host        string
	product     BottingtoolsProductConfig
}

// NewBottingtoolsSource creates a BottingtoolsSource from config.
func NewBottingtoolsSource(cfg *BottingtoolsConfig) (*BottingtoolsSource, error) {
	password := os.Getenv(cfg.PasswordEnv)
	if password == "" {
		return nil, fmt.Errorf("environment variable %q not set or empty", cfg.PasswordEnv)
	}
	product, err := ParseBottingtoolsProductConfig(cfg.Product)
	if err != nil {
		return nil, fmt.Errorf("invalid product config: %w", err)
	}
	host := cfg.Host
	if host == "" {
		host = bottingtoolsDefaultHost
	}
	return &BottingtoolsSource{
		accountUser: cfg.Username,
		password:    password,
		host:        host,
		product:     product,
	}, nil
}

// Resolve implements proxykit.Handler.
func (s *BottingtoolsSource) Resolve(ctx context.Context, _ *proxykit.Request) (*proxykit.Result, error) {
	seed := proxykit.GetSessionSeed(ctx)
	username := btBuildUsername(s.accountUser, s.product, GetMeta(ctx), GetSeedTTL(ctx), seed)
	return proxykit.Resolved(&proxykit.Proxy{
		Host:     s.host,
		Port:     1337,
		Username: username,
		Password: s.password,
	}), nil
}

// Describe returns a human-readable description.
func (s *BottingtoolsSource) Describe() string {
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

// ---------------------------------------------------------------------------
// Username building
// ---------------------------------------------------------------------------

func btBuildUsername(accountUser string, product BottingtoolsProductConfig, meta Meta, ttl time.Duration, seed *proxykit.SessionSeed) string {
	switch product.Type {
	case "residential":
		return btBuildResidential(accountUser, product.Residential, meta, ttl, seed)
	case "isp":
		return btBuildISP(accountUser, product.ISP, meta, ttl, seed)
	case "datacenter":
		return btBuildDatacenter(accountUser, product.Datacenter, seed)
	default:
		return accountUser
	}
}

func btBuildResidential(accountUser string, cfg *BottingtoolsResidentialConfig, meta Meta, ttl time.Duration, seed *proxykit.SessionSeed) string {
	parts := []string{fmt.Sprintf("%s_pool-custom_type-%s", accountUser, cfg.Quality.AsTypeStr())}
	if country := pickCountry(cfg.Countries, seed); country != "" {
		parts = append(parts, fmt.Sprintf("country-%s", strings.ToUpper(country.AsParamStr())))
	}
	if cfg.City != "" {
		parts = append(parts, fmt.Sprintf("city-%s", cfg.City))
	}
	parts = append(parts, fmt.Sprintf("session-%s", deriveSessionID(seed)))
	if v := btSesstimeStr(meta, ttl); v != "" {
		parts = append(parts, fmt.Sprintf("sesstime-%s", v))
	}
	if meta.GetString("fastmode") == "true" {
		parts = append(parts, "fastmode-true")
	}
	return strings.Join(parts, "_")
}

func btBuildISP(accountUser string, cfg *BottingtoolsISPConfig, meta Meta, ttl time.Duration, seed *proxykit.SessionSeed) string {
	parts := []string{fmt.Sprintf("%s_pool-isp", accountUser)}
	if country := pickCountry(cfg.Countries, seed); country != "" {
		parts = append(parts, fmt.Sprintf("country-%s", country.AsParamStr()))
	}
	parts = append(parts, fmt.Sprintf("session-%s", deriveSessionID(seed)))
	if v := btSesstimeStr(meta, ttl); v != "" {
		parts = append(parts, fmt.Sprintf("sesstime-%s", v))
	}
	return strings.Join(parts, "_")
}

func btBuildDatacenter(accountUser string, cfg *BottingtoolsDatacenterConfig, seed *proxykit.SessionSeed) string {
	parts := []string{fmt.Sprintf("%s_pool-dc", accountUser)}
	if country := pickCountry(cfg.Countries, seed); country != "" {
		parts = append(parts, fmt.Sprintf("country-%s", country.AsParamStr()))
	}
	return strings.Join(parts, "_")
}

func btSesstimeStr(meta Meta, ttl time.Duration) string {
	v := meta["sesstime"]
	if v == nil {
		if ttl > 0 {
			return fmt.Sprintf("%d", int(ttl/time.Minute))
		}
		return ""
	}
	switch vv := v.(type) {
	case string:
		return vv
	case float64:
		return fmt.Sprintf("%g", vv)
	default:
		return fmt.Sprintf("%v", vv)
	}
}
