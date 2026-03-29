package core

import (
	"io"
	"net"
	"time"
)

// countingReader wraps an io.Reader and calls RecordTraffic on every Read.
type countingReader struct {
	r        io.Reader
	outbound bool // true = client→upstream (upload), false = upstream→client (download)
	handle   ConnTracker
	cancel   func()
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		cr.handle.RecordTraffic(cr.outbound, int64(n), cr.cancel)
	}
	return n, err
}

// relay bidirectionally copies between two connections with optional traffic counting.
func relay(client, upstream net.Conn, handle ConnTracker) (sent, received int64) {
	cancelConn := func() {
		client.SetDeadline(time.Unix(0, 1))
		upstream.SetDeadline(time.Unix(0, 1))
	}

	var clientReader io.Reader = client
	var upstreamReader io.Reader = upstream
	if handle != nil {
		clientReader = &countingReader{r: client, outbound: true, handle: handle, cancel: cancelConn}
		upstreamReader = &countingReader{r: upstream, outbound: false, handle: handle, cancel: cancelConn}
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
