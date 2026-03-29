package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"proxy-gateway/core"
)

// RunSOCKS5 starts a SOCKS5 proxy server that delegates resolution to the pipeline.
//
// The SOCKS5 server accepts CONNECT commands. The username is expected to be
// a JSON string (same format as the HTTP proxy: {"sub":"...","set":"...","minutes":N,"meta":{...}})
// and the password is the credential for auth middleware.
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

	// Check if username/password auth (0x02) is offered.
	hasUserPass := false
	for _, m := range methods {
		if m == 0x02 {
			hasUserPass = true
		}
	}

	var username, password string
	if hasUserPass {
		// Select username/password auth.
		conn.Write([]byte{0x05, 0x02})

		// Read sub-negotiation (RFC 1929).
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

		username = string(uBytes)
		password = string(pBytes)

		// Accept (auth validation happens in the pipeline).
		conn.Write([]byte{0x01, 0x00})
	} else {
		// No auth.
		conn.Write([]byte{0x05, 0x00})
	}

	// Read CONNECT request.
	var reqHeader [4]byte
	if _, err := io.ReadFull(conn, reqHeader[:]); err != nil {
		return
	}
	if reqHeader[1] != 0x01 { // only CONNECT supported
		sendSOCKS5Reply(conn, 0x07) // command not supported
		return
	}

	target, err := readSOCKS5Address(conn, reqHeader[3])
	if err != nil {
		sendSOCKS5Reply(conn, 0x01)
		return
	}

	// Build core.Request from the SOCKS5 username (JSON) + password.
	req := buildSOCKS5Request(username, password)

	proxy, err := handler.Resolve(context.Background(), req)
	if err != nil {
		slog.Warn("resolve error", "err", err)
		sendSOCKS5Reply(conn, 0x02) // connection not allowed
		return
	}
	if proxy == nil {
		sendSOCKS5Reply(conn, 0x01) // general failure
		return
	}

	// Check for connection tracker.
	var handle core.ConnHandle
	if tracker, ok := handler.(core.ConnectionTracker); ok {
		handle, err = tracker.OpenConnection(req.Sub)
		if err != nil {
			slog.Warn("connection rejected", "sub", req.Sub, "err", err)
			sendSOCKS5Reply(conn, 0x02)
			return
		}
	}

	// Dial upstream (protocol-aware).
	upstreamConn, err := dialUpstream(proxy, target)
	if err != nil {
		slog.Error("upstream dial failed", "err", err)
		sendSOCKS5Reply(conn, 0x05) // connection refused
		if handle != nil {
			handle.Close(0, 0)
		}
		return
	}
	defer upstreamConn.Close()

	// Success reply.
	sendSOCKS5Reply(conn, 0x00)

	slog.Info("SOCKS5 routing",
		"target", target,
		"sub", req.Sub,
		"upstream", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
		"upstream_proto", proxy.GetProtocol(),
	)

	// Bidirectional relay with optional counting.
	sent, received := relay(conn, upstreamConn, handle)
	if handle != nil {
		handle.Close(sent, received)
	}
}

func readSOCKS5Address(conn net.Conn, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case 0x03: // Domain
		var domLen [1]byte
		if _, err := io.ReadFull(conn, domLen[:]); err != nil {
			return "", err
		}
		dom := make([]byte, domLen[0])
		if _, err := io.ReadFull(conn, dom); err != nil {
			return "", err
		}
		host = string(dom)
	case 0x04: // IPv6
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
	// Reply: ver=5, rep=status, rsv=0, atyp=IPv4, addr=0.0.0.0:0
	conn.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func buildSOCKS5Request(usernameJSON, password string) *core.Request {
	// The username may be a JSON blob like the HTTP proxy, or empty.
	req := &core.Request{Password: password}
	if usernameJSON == "" {
		return req
	}
	// Try to parse as JSON. If it fails, treat as plain sub.
	parsed, err := parseUsernameJSON(usernameJSON)
	if err != nil {
		req.Sub = usernameJSON
		return req
	}
	req.Sub = parsed.Sub
	req.Set = parsed.Set
	req.SessionTTL = parsed.Minutes
	req.Meta = core.Meta(parsed.Meta)
	req.SessionKey = usernameJSON // use the raw JSON as the affinity key
	return req
}

// parseUsernameJSON is a minimal JSON parser for the SOCKS5 username field.
type parsedJSON struct {
	Sub     string                 `json:"sub"`
	Set     string                 `json:"set"`
	Minutes int                    `json:"minutes"`
	Meta    map[string]interface{} `json:"meta"`
}

func parseUsernameJSON(s string) (*parsedJSON, error) {
	var p parsedJSON
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		return nil, err
	}
	if p.Sub == "" || p.Set == "" {
		return nil, fmt.Errorf("missing sub or set")
	}
	return &p, nil
}

// relay bidirectionally copies between two connections with optional traffic counting.
func relay(client, upstream net.Conn, handle core.ConnHandle) (sent, received int64) {
	cancelConn := func() {
		client.SetDeadline(time.Unix(0, 1))
		upstream.SetDeadline(time.Unix(0, 1))
	}

	var clientReader io.Reader = client
	var upstreamReader io.Reader = upstream
	if handle != nil {
		clientReader = &countingReader{r: client, upstream: true, handle: handle, cancel: cancelConn}
		upstreamReader = &countingReader{r: upstream, upstream: false, handle: handle, cancel: cancelConn}
	}

	type result struct {
		n   int64
		err error
	}
	sentCh := make(chan result, 1)
	recvCh := make(chan result, 1)
	go func() {
		n, err := io.Copy(upstream, clientReader)
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		sentCh <- result{n, err}
	}()
	go func() {
		n, err := io.Copy(client, upstreamReader)
		if tc, ok := client.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		recvCh <- result{n, err}
	}()

	sr := <-sentCh
	rr := <-recvCh
	return sr.n, rr.n
}
