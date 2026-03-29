package core

import (
	"fmt"
	"strconv"
	"strings"
)

type ProxyFormat string

const (
	ProxyFormatHostPortUserPass   ProxyFormat = "host_port_user_pass"
	ProxyFormatUserPassAtHostPort ProxyFormat = "user_pass_at_host_port"
	ProxyFormatUserPassHostPort   ProxyFormat = "user_pass_host_port"
	DefaultProxyFormat                        = ProxyFormatHostPortUserPass
)

func ParseProxyLine(s string, format ProxyFormat) (Proxy, error) {
	s = stripProtocol(s)
	switch format {
	case ProxyFormatUserPassAtHostPort:
		return parseUserPassAtHostPort(s)
	case ProxyFormatUserPassHostPort:
		return parseUserPassHostPort(s)
	default:
		return parseHostPortUserPass(s)
	}
}

func stripProtocol(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		return s[i+3:]
	}
	return s
}

func parseUserPassAtHostPort(s string) (Proxy, error) {
	at := strings.LastIndex(s, "@")
	if at < 0 {
		host, port, err := parseHostPort(s)
		if err != nil {
			return Proxy{}, err
		}
		return Proxy{Host: host, Port: port}, nil
	}
	creds := s[:at]
	hostPort := s[at+1:]
	host, port, err := parseHostPort(hostPort)
	if err != nil {
		return Proxy{}, err
	}
	user, pass, err := splitUserPass(creds)
	if err != nil {
		return Proxy{}, err
	}
	return Proxy{Host: host, Port: port, Username: user, Password: pass}, nil
}

func parseUserPassHostPort(s string) (Proxy, error) {
	parts := rSplitN(s, ':', 3)
	if len(parts) == 3 {
		if port, err := strconv.ParseUint(parts[2], 10, 16); err == nil {
			host := parts[1]
			creds := parts[0]
			if ci := strings.Index(creds, ":"); ci >= 0 {
				user := creds[:ci]
				pass := creds[ci+1:]
				if user != "" {
					return Proxy{Host: host, Port: uint16(port), Username: user, Password: pass}, nil
				}
			}
		}
	}
	host, port, err := parseHostPort(s)
	if err != nil {
		return Proxy{}, fmt.Errorf("expected user:pass:host:port or host:port, got %q", s)
	}
	return Proxy{Host: host, Port: port}, nil
}

func parseHostPortUserPass(s string) (Proxy, error) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return Proxy{}, fmt.Errorf("unclosed bracket in %q", s)
		}
		host := s[1:end]
		rest := s[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return Proxy{}, fmt.Errorf("expected ':' after ']' in %q", s)
		}
		return parsePortAndOptionalCreds(host, rest[1:])
	}
	parts := strings.SplitN(s, ":", 4)
	switch len(parts) {
	case 2:
		port, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return Proxy{}, fmt.Errorf("invalid port in %q", s)
		}
		return Proxy{Host: parts[0], Port: uint16(port)}, nil
	case 4:
		port, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return Proxy{}, fmt.Errorf("invalid port in %q", s)
		}
		return Proxy{Host: parts[0], Port: uint16(port), Username: parts[2], Password: parts[3]}, nil
	default:
		return Proxy{}, fmt.Errorf("expected host:port or host:port:user:pass, got %q", s)
	}
}

func parsePortAndOptionalCreds(host, rest string) (Proxy, error) {
	parts := strings.SplitN(rest, ":", 3)
	switch len(parts) {
	case 1:
		port, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return Proxy{}, fmt.Errorf("invalid port %q", parts[0])
		}
		return Proxy{Host: host, Port: uint16(port)}, nil
	case 3:
		port, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return Proxy{}, fmt.Errorf("invalid port %q", parts[0])
		}
		return Proxy{Host: host, Port: uint16(port), Username: parts[1], Password: parts[2]}, nil
	default:
		return Proxy{}, fmt.Errorf("expected port or port:user:pass after host, got %q", rest)
	}
}

func parseHostPort(s string) (string, uint16, error) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("unclosed bracket in %q", s)
		}
		host := s[1:end]
		rest := s[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", 0, fmt.Errorf("expected ':' after ']' in %q", s)
		}
		port, err := strconv.ParseUint(rest[1:], 10, 16)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port in %q", s)
		}
		return host, uint16(port), nil
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, fmt.Errorf("expected host:port, got %q", s)
	}
	port, err := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in %q", s)
	}
	return s[:i], uint16(port), nil
}

func splitUserPass(s string) (string, string, error) {
	i := strings.Index(s, ":")
	if i < 0 {
		return "", "", fmt.Errorf("expected user:pass, got %q", s)
	}
	return s[:i], s[i+1:], nil
}

func rSplitN(s string, c byte, n int) []string {
	parts := make([]string, 0, n)
	remaining := s
	for len(parts) < n-1 {
		i := strings.LastIndexByte(remaining, c)
		if i < 0 {
			break
		}
		parts = append(parts, remaining[i+1:])
		remaining = remaining[:i]
	}
	parts = append(parts, remaining)
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}
