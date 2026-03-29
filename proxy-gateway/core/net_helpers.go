package core

import (
	"fmt"
	"net/netip"
)

// hostPort formats a host+port into a dial address, bracketing IPv6.
func hostPort(host string, port uint16) string {
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
