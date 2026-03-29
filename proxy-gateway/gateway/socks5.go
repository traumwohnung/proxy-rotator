package gateway

import (
	"fmt"
	"io"
	"log/slog"
	"net"

	"proxy-gateway/core"
)

// RunSOCKS5 starts a SOCKS5 proxy server.
// Raw credentials go into Request.RawUsername / RawPassword.
// Request.Conn is set to the client connection.
func RunSOCKS5(addr string, handler core.Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	defer ln.Close()
	slog.Info("SOCKS5 proxy gateway listening", "addr", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go handleSOCKS5Conn(conn, handler)
	}
}

func handleSOCKS5Conn(conn net.Conn, handler core.Handler) {
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
		Conn:        conn, // middleware can take over
	}

	proxy, err := handler.Resolve(nil, req)
	if err != nil {
		slog.Warn("resolve error", "err", err)
		sendSOCKS5Reply(conn, 0x02)
		return
	}

	// nil proxy = middleware handled it (e.g. MITM).
	if proxy == nil {
		return
	}

	// Normal tunnel.
	var handle core.ConnHandle
	if tracker, ok := handler.(core.ConnectionTracker); ok {
		handle, err = tracker.OpenConnection(req.Sub)
		if err != nil {
			slog.Warn("connection rejected", "sub", req.Sub, "err", err)
			sendSOCKS5Reply(conn, 0x02)
			return
		}
	}

	upstreamConn, err := dialUpstream(proxy, target)
	if err != nil {
		slog.Error("upstream dial failed", "err", err)
		sendSOCKS5Reply(conn, 0x05)
		if handle != nil {
			handle.Close(0, 0)
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

	sent, received := relay(conn, upstreamConn, handle)
	if handle != nil {
		handle.Close(sent, received)
	}
}

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
