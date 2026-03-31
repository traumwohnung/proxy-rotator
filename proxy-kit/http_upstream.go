package proxykit

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"time"
)

// DefaultUpstreamDialTimeout is used by HTTPUpstream when no context deadline
// is set and no explicit timeout is configured.
const DefaultUpstreamDialTimeout = 15 * time.Second

type HTTPUpstream struct {
	// DialTimeout overrides DefaultUpstreamDialTimeout.
	// Zero means use the default.
	DialTimeout time.Duration
}

func (u HTTPUpstream) dialTimeout() time.Duration {
	if u.DialTimeout != 0 {
		return u.DialTimeout
	}
	return DefaultUpstreamDialTimeout
}

func (u HTTPUpstream) Dial(ctx context.Context, proxy *Proxy, target string) (net.Conn, error) {
	addr := hostPort(proxy.Host, proxy.Port)

	// Use context deadline if set, otherwise fall back to the configured timeout.
	dialer := &net.Dialer{Timeout: u.dialTimeout()}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to upstream %s: %w", addr, err)
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if proxy.Username != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(proxy.Username + ":" + proxy.Password))
		req += "Proxy-Authorization: Basic " + creds + "\r\n"
	}
	req += "\r\n"
	if _, err := fmt.Fprint(conn, req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("sending CONNECT: %w", err)
	}

	// Apply a read deadline while waiting for the CONNECT response.
	conn.SetDeadline(time.Now().Add(u.dialTimeout()))
	var respBuf []byte
	tmp := make([]byte, 1024)
	for {
		n, readErr := conn.Read(tmp)
		if n > 0 {
			respBuf = append(respBuf, tmp[:n]...)
		}
		if readErr != nil {
			conn.Close()
			return nil, fmt.Errorf("reading CONNECT response: %w", readErr)
		}
		if containsCRLFCRLF(respBuf) {
			break
		}
	}
	conn.SetDeadline(time.Time{}) // clear deadline for tunnel use

	resp := string(respBuf)
	if len(resp) < 12 || (resp[:12] != "HTTP/1.1 200" && resp[:12] != "HTTP/1.0 200") {
		conn.Close()
		return nil, fmt.Errorf("upstream rejected CONNECT: %s", resp)
	}
	return conn, nil
}

func containsCRLFCRLF(b []byte) bool {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return true
		}
	}
	return false
}
