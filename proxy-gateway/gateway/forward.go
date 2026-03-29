package gateway

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"

	"proxy-gateway/core"
)

// ForwardHTTP sends a plain HTTP request through an upstream proxy.
func ForwardHTTP(method, uri string, headers []string, body io.Reader, proxy *core.Proxy) ([]byte, error) {
	conn, err := net.Dial("tcp", hostPort(proxy.Host, proxy.Port))
	if err != nil {
		return nil, fmt.Errorf("connecting to upstream %s: %w", hostPort(proxy.Host, proxy.Port), err)
	}
	defer conn.Close()

	req := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, uri)
	for _, h := range headers {
		req += h + "\r\n"
	}
	if proxy.Username != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(proxy.Username + ":" + proxy.Password))
		req += "Proxy-Authorization: Basic " + creds + "\r\n"
	}
	req += "\r\n"

	if _, err := fmt.Fprint(conn, req); err != nil {
		return nil, err
	}
	if body != nil {
		if _, err := io.Copy(conn, body); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(conn)
}
