package gateway

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"

	"proxy-gateway/core"
)

// ---------------------------------------------------------------------------
// HTTPUpstream — dials through an HTTP CONNECT proxy
// ---------------------------------------------------------------------------

// HTTPUpstream implements core.Upstream using the HTTP CONNECT method.
type HTTPUpstream struct{}

func (HTTPUpstream) Dial(_ context.Context, proxy *core.Proxy, target string) (net.Conn, error) {
	addr := hostPort(proxy.Host, proxy.Port)
	conn, err := net.Dial("tcp", addr)
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

	// Read full response (loop until \r\n\r\n).
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
	resp := string(respBuf)
	if len(resp) < 12 || (resp[:12] != "HTTP/1.1 200" && resp[:12] != "HTTP/1.0 200") {
		conn.Close()
		return nil, fmt.Errorf("upstream rejected CONNECT: %s", resp)
	}
	return conn, nil
}

// ---------------------------------------------------------------------------
// SOCKS5Upstream — dials through a SOCKS5 proxy
// ---------------------------------------------------------------------------

// SOCKS5Upstream implements core.Upstream using the SOCKS5 protocol.
type SOCKS5Upstream struct{}

func (SOCKS5Upstream) Dial(_ context.Context, proxy *core.Proxy, target string) (net.Conn, error) {
	addr := hostPort(proxy.Host, proxy.Port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to SOCKS5 upstream %s: %w", addr, err)
	}

	host, port, err := splitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid target %q: %w", target, err)
	}

	if err := socks5Handshake(conn, host, port, proxy.Username, proxy.Password); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake with %s: %w", addr, err)
	}
	return conn, nil
}

// socks5Handshake performs the SOCKS5 greeting + connect request.
func socks5Handshake(conn net.Conn, host string, port uint16, username, password string) error {
	needsAuth := username != ""
	if needsAuth {
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return err
		}
	}

	var methodResp [2]byte
	if _, err := io.ReadFull(conn, methodResp[:]); err != nil {
		return fmt.Errorf("reading method selection: %w", err)
	}
	if methodResp[0] != 0x05 {
		return fmt.Errorf("unexpected SOCKS version %d", methodResp[0])
	}

	if methodResp[1] == 0x02 && needsAuth {
		authReq := []byte{0x01, byte(len(username))}
		authReq = append(authReq, []byte(username)...)
		authReq = append(authReq, byte(len(password)))
		authReq = append(authReq, []byte(password)...)
		if _, err := conn.Write(authReq); err != nil {
			return err
		}
		var authResp [2]byte
		if _, err := io.ReadFull(conn, authResp[:]); err != nil {
			return fmt.Errorf("reading auth response: %w", err)
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("SOCKS5 authentication failed (status %d)", authResp[1])
		}
	} else if methodResp[1] == 0xFF {
		return fmt.Errorf("SOCKS5 server rejected all auth methods")
	}

	connectReq := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		connectReq = append(connectReq, 0x01)
		connectReq = append(connectReq, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil && ip != nil {
		connectReq = append(connectReq, 0x04)
		connectReq = append(connectReq, ip6...)
	} else {
		connectReq = append(connectReq, 0x03, byte(len(host)))
		connectReq = append(connectReq, []byte(host)...)
	}
	connectReq = append(connectReq, byte(port>>8), byte(port))

	if _, err := conn.Write(connectReq); err != nil {
		return err
	}

	var respHeader [4]byte
	if _, err := io.ReadFull(conn, respHeader[:]); err != nil {
		return fmt.Errorf("reading CONNECT response: %w", err)
	}
	if respHeader[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT failed with status %d", respHeader[1])
	}

	// Consume the bound address.
	switch respHeader[3] {
	case 0x01:
		var skip [4 + 2]byte
		io.ReadFull(conn, skip[:])
	case 0x04:
		var skip [16 + 2]byte
		io.ReadFull(conn, skip[:])
	case 0x03:
		var domLen [1]byte
		io.ReadFull(conn, domLen[:])
		skip := make([]byte, int(domLen[0])+2)
		io.ReadFull(conn, skip)
	}

	return nil
}

// ---------------------------------------------------------------------------
// DefaultUpstream — dispatches by proxy.Protocol
// ---------------------------------------------------------------------------

// DefaultUpstream returns a core.Upstream that dispatches to HTTPUpstream
// or SOCKS5Upstream based on the proxy's Protocol field.
func DefaultUpstream() core.Upstream {
	http := HTTPUpstream{}
	socks5 := SOCKS5Upstream{}
	return core.UpstreamFunc(func(ctx context.Context, proxy *core.Proxy, target string) (net.Conn, error) {
		switch proxy.GetProtocol() {
		case core.ProtocolSOCKS5:
			return socks5.Dial(ctx, proxy, target)
		default:
			return http.Dial(ctx, proxy, target)
		}
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func containsCRLFCRLF(b []byte) bool {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return true
		}
	}
	return false
}

func splitHostPort(addr string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	var port uint16
	_, err = fmt.Sscanf(portStr, "%d", &port)
	return host, port, err
}
