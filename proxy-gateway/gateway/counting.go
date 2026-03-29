package gateway

import (
	"io"

	"proxy-gateway/core"
)

// countingReader wraps an io.Reader and calls RecordTraffic on every Read.
type countingReader struct {
	r        io.Reader
	upstream bool // true = client→upstream, false = upstream→client
	handle   core.ConnHandle
	cancel   func()
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		cr.handle.RecordTraffic(cr.upstream, int64(n), cr.cancel)
	}
	return n, err
}
