package staticfile

import "proxy-gateway/core"

type Config struct {
	ProxiesFile string           `toml:"proxies_file" yaml:"proxies_file" json:"proxies_file"`
	Format      core.ProxyFormat `toml:"format"       yaml:"format"       json:"format"`
}
