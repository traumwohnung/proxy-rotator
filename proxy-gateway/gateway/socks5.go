package gateway

import (
	"fmt"
	"io"
	"log/slog"
	"net"

	"proxy-gateway/core"
)

// ---------------------------------------------------------------------------
// SOCKS5Downstream — implements core.Downstream for SOCKS5 protocol
// ---------------------------------------------------------------------------

// SOCKS5Downstream accepts SOCKS5 proxy connections.
type SOCKS5Downstream struct {
	Upstream core.Upstream
}

// Serve implements core.Downstream.
func (d *SOCKS5Downstream) Serve(addr string, handler core.Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 listen %s: %w", addr, err)
	}
	slog.Info("SOCKS5 proxy gateway listening", "addr", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go d.handleConn(conn, handler)
	}
}

func (d *SOCKS5Downstream) handleConn(conn net.Conn, handler core.Handler) {
	defer conn.Close()

	// Greeting.
	var version [1]byte
	if _, err := io.ReadFull(conn, version[:]); err != nil {
		return
	}
	if version[0] != 0x05 {
		return
	}
	var nMethods [1]byte
	io.ReadFull(conn, nMethods[:])
	methods := make([]byte, nMethods[0])
	io.ReadFull(conn, methods)

	hasUserPass := false
	for _, m := range methods {
		if m == 0x02 {
			hasUserPass = true
		}
	}

	var rawUsername, rawPassword string
	if hasUserPass {
		conn.Write([]byte{0x05, 0x02})
		var authVer [1]byte
		io.ReadFull(conn, authVer[:])
		var uLen [1]byte
		io.ReadFull(conn, uLen[:])
		uBytes := make([]byte, uLen[0])
		io.ReadFull(conn, uBytes)
		var pLen [1]byte
		io.ReadFull(conn, pLen[:])
		pBytes := make([]byte, pLen[0])
		io.ReadFull(conn, pBytes)
		rawUsername = string(uBytes)
		rawPassword = string(pBytes)
		conn.Write([]byte{0x01, 0x00})
	} else {
		conn.Write([]byte{0x05, 0x00})
	}

	// CONNECT request.
	var reqHeader [4]byte
	if _, err := io.ReadFull(conn, reqHeader[:]); err != nil {
		return
	}
	if reqHeader[1] != 0x01 {
		sendSOCKS5Reply(conn, 0x07)
		return
	}

	target, err := readSOCKS5Address(conn, reqHeader[3])
	if err != nil {
		sendSOCKS5Reply(conn, 0x01)
		return
	}

	req := &core.Request{
		RawUsername: rawUsername,
		RawPassword: rawPassword,
		Target:      target,
		Conn:        conn,
	}

	result, err := handler.Resolve(nil, req)
	if err != nil {
		slog.Warn("resolve error", "err", err)
		sendSOCKS5Reply(conn, 0x02)
		return
	}

	// nil result or nil proxy = middleware handled it (e.g. MITM).
	if result == nil || result.Proxy == nil {
		return
	}

	proxy := result.Proxy
	upstreamConn, err := d.Upstream.Dial(nil, proxy, target)
	if err != nil {
		slog.Error("upstream dial failed", "err", err)
		sendSOCKS5Reply(conn, 0x05)
		if result.ConnHandle != nil {
			result.ConnHandle.Close(0, 0)
		}
		return
	}
	defer upstreamConn.Close()

	sendSOCKS5Reply(conn, 0x00)

	slog.Info("SOCKS5 routing",
		"target", target,
		"upstream", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
		"upstream_proto", proxy.GetProtocol(),
	)

	sent, received := relay(conn, upstreamConn, result.ConnHandle)
	if result.ConnHandle != nil {
		result.ConnHandle.Close(sent, received)
	}
}

// ---------------------------------------------------------------------------
// Legacy compatibility
// ---------------------------------------------------------------------------

// RunSOCKS5 starts a SOCKS5 proxy gateway with the default upstream dialer.
func RunSOCKS5(addr string, handler core.Handler) error {
	d := &SOCKS5Downstream{Upstream: DefaultUpstream()}
	return d.Serve(addr, handler)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func readSOCKS5Address(conn net.Conn, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case 0x03:
		var domLen [1]byte
		if _, err := io.ReadFull(conn, domLen[:]); err != nil {
			return "", err
		}
		dom := make([]byte, domLen[0])
		if _, err := io.ReadFull(conn, dom); err != nil {
			return "", err
		}
		host = string(dom)
	case 0x04:
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return "", err
	}
	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
	return fmt.Sprintf("%s:%d", host, port), nil
}

func sendSOCKS5Reply(conn net.Conn, status byte) {
	conn.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}
