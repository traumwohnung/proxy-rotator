package core

import (
	"sync"
	"time"
)

type xorshift64State struct{ x uint64 }

func (s *xorshift64State) next() uint64 {
	s.x ^= s.x << 13
	s.x ^= s.x >> 7
	s.x ^= s.x << 17
	return s.x
}

var rngPool = sync.Pool{
	New: func() interface{} {
		seed := uint64(time.Now().UnixNano()) ^ 0x517cc1b727220a95
		if seed == 0 {
			seed = 0x517cc1b727220a95
		}
		return &xorshift64State{x: seed}
	},
}

// CheapRandom returns a fast non-cryptographic random uint64.
func CheapRandom() uint64 {
	s := rngPool.Get().(*xorshift64State)
	v := s.next()
	rngPool.Put(s)
	return v
}
