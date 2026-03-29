package staticfile

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"proxy-gateway/core"
)

func LoadProxies(path string, format core.ProxyFormat) ([]core.Proxy, error) {
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
		p, err := core.ParseProxyLine(line, format)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid proxy entry %q: %w", path, lineNum, line, err)
		}
		proxies = append(proxies, p)
	}
	return proxies, scanner.Err()
}
