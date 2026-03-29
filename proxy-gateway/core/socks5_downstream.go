package core

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

const socks5HandshakeTimeout = 10 * time.Second

// SOCKS5Downstream accepts SOCKS5 proxy connections.
type SOCKS5Downstream struct {
	Upstream Upstream
}

// SetUpstream implements UpstreamAware.
func (d *SOCKS5Downstream) SetUpstream(u Upstream) { d.Upstream = u }

// Serve implements Downstream.
func (d *SOCKS5Downstream) Serve(addr string, handler Handler) error {
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

func (d *SOCKS5Downstream) handleConn(conn net.Conn, handler Handler) {
	defer conn.Close()

	// Set a deadline for the entire SOCKS5 handshake phase.
	conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout))

	rawUsername, rawPassword, err := socks5ServerHandshake(conn)
	if err != nil {
		slog.Debug("SOCKS5 handshake failed", "err", err)
		return
	}

	target, err := socks5ReadRequest(conn)
	if err != nil {
		slog.Debug("SOCKS5 request failed", "err", err)
		sendSOCKS5Reply(conn, 0x01) // general failure
		return
	}

	// Handshake done — clear the deadline for the tunnel phase.
	conn.SetDeadline(time.Time{})

	req := &Request{
		RawUsername: rawUsername,
		RawPassword: rawPassword,
		Target:      target,
		Conn:        conn,
	}

	ctx := context.Background()
	result, err := handler.Resolve(ctx, req)
	if err != nil {
		slog.Warn("SOCKS5 resolve error", "target", target, "err", err)
		sendSOCKS5Reply(conn, 0x02) // not allowed by ruleset
		return
	}

	// nil result or nil proxy = middleware handled it (e.g. MITM).
	if result == nil || result.Proxy == nil {
		return
	}

	proxy := result.Proxy
	upstreamConn, err := d.Upstream.Dial(ctx, proxy, target)
	if err != nil {
		slog.Error("SOCKS5 upstream dial failed", "target", target, "err", err)
		sendSOCKS5Reply(conn, 0x05) // connection refused
		if result.ConnTracker != nil {
			result.ConnTracker.Close(0, 0)
		}
		return
	}
	defer upstreamConn.Close()

	sendSOCKS5Reply(conn, 0x00) // success

	slog.Info("SOCKS5 routing",
		"target", target,
		"upstream", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
		"upstream_proto", proxy.Proto(),
	)

	sent, received := relay(conn, upstreamConn, result.ConnTracker)
	if result.ConnTracker != nil {
		result.ConnTracker.Close(sent, received)
	}
}

// socks5ServerHandshake negotiates the SOCKS5 greeting and auth sub-negotiation.
// Returns the raw username and password (empty if no auth was offered).
func socks5ServerHandshake(conn net.Conn) (username, password string, err error) {
	// Version byte.
	var ver [1]byte
	if _, err := io.ReadFull(conn, ver[:]); err != nil {
		return "", "", fmt.Errorf("reading version: %w", err)
	}
	if ver[0] != 0x05 {
		return "", "", fmt.Errorf("unsupported SOCKS version %d", ver[0])
	}

	// Method count + methods.
	var nMethods [1]byte
	if _, err := io.ReadFull(conn, nMethods[:]); err != nil {
		return "", "", fmt.Errorf("reading method count: %w", err)
	}
	methods := make([]byte, nMethods[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", "", fmt.Errorf("reading methods: %w", err)
	}

	hasUserPass := false
	for _, m := range methods {
		if m == 0x02 {
			hasUserPass = true
			break
		}
	}

	if hasUserPass {
		// Select username/password auth.
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return "", "", fmt.Errorf("writing method selection: %w", err)
		}

		// Read sub-negotiation (RFC 1929).
		var authVer [1]byte
		if _, err := io.ReadFull(conn, authVer[:]); err != nil {
			return "", "", fmt.Errorf("reading auth version: %w", err)
		}
		var uLen [1]byte
		if _, err := io.ReadFull(conn, uLen[:]); err != nil {
			return "", "", fmt.Errorf("reading username length: %w", err)
		}
		uBytes := make([]byte, uLen[0])
		if _, err := io.ReadFull(conn, uBytes); err != nil {
			return "", "", fmt.Errorf("reading username: %w", err)
		}
		var pLen [1]byte
		if _, err := io.ReadFull(conn, pLen[:]); err != nil {
			return "", "", fmt.Errorf("reading password length: %w", err)
		}
		pBytes := make([]byte, pLen[0])
		if _, err := io.ReadFull(conn, pBytes); err != nil {
			return "", "", fmt.Errorf("reading password: %w", err)
		}

		// We respond with success here; actual credential validation
		// happens in the pipeline (handler.Resolve). The SOCKS5 spec
		// requires a response before the CONNECT phase.
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return "", "", fmt.Errorf("writing auth response: %w", err)
		}

		return string(uBytes), string(pBytes), nil
	}

	// No auth.
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", "", fmt.Errorf("writing no-auth selection: %w", err)
	}
	return "", "", nil
}

// socks5ReadRequest reads the CONNECT request and returns the target host:port.
func socks5ReadRequest(conn net.Conn) (string, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", fmt.Errorf("reading request header: %w", err)
	}
	if header[0] != 0x05 {
		return "", fmt.Errorf("unexpected version in request: %d", header[0])
	}
	if header[1] != 0x01 {
		// Only CONNECT (0x01) is supported; reject others properly.
		sendSOCKS5Reply(conn, 0x07) // command not supported
		return "", fmt.Errorf("unsupported command %d (only CONNECT supported)", header[1])
	}

	return readSOCKS5Address(conn, header[3])
}

// ListenSOCKS5 starts a SOCKS5 proxy gateway with the default upstream dialer.
func ListenSOCKS5(addr string, handler Handler) error {
	d := &SOCKS5Downstream{Upstream: AutoUpstream()}
	return d.Serve(addr, handler)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func readSOCKS5Address(conn net.Conn, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", fmt.Errorf("reading IPv4 address: %w", err)
		}
		host = net.IP(ip[:]).String()
	case 0x03: // domain name
		var domLen [1]byte
		if _, err := io.ReadFull(conn, domLen[:]); err != nil {
			return "", fmt.Errorf("reading domain length: %w", err)
		}
		dom := make([]byte, domLen[0])
		if _, err := io.ReadFull(conn, dom); err != nil {
			return "", fmt.Errorf("reading domain: %w", err)
		}
		host = string(dom)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", fmt.Errorf("reading IPv6 address: %w", err)
		}
		host = net.IP(ip[:]).String()
	default:
		return "", fmt.Errorf("unsupported address type 0x%02x", atyp)
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return "", fmt.Errorf("reading port: %w", err)
	}
	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
	return fmt.Sprintf("%s:%d", host, port), nil
}

func sendSOCKS5Reply(conn net.Conn, status byte) {
	// REP field + BND.ADDR as 0.0.0.0:0 (IPv4)
	conn.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}
