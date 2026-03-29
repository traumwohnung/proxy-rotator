package core

import "testing"

func TestParseHostPortUserPass(t *testing.T) {
	p, err := ParseProxyLine("host.com:8080:user:pass", ProxyFormatHostPortUserPass)
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "host.com" || p.Port != 8080 || p.Username != "user" || p.Password != "pass" {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestParseUserPassAtHostPort(t *testing.T) {
	p, err := ParseProxyLine("user:pass@host.com:8080", ProxyFormatUserPassAtHostPort)
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "host.com" || p.Port != 8080 || p.Username != "user" {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestParseUserPassHostPort(t *testing.T) {
	p, err := ParseProxyLine("user:pass:host.com:8080", ProxyFormatUserPassHostPort)
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "host.com" || p.Port != 8080 || p.Username != "user" {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestParseNoCreds(t *testing.T) {
	p, err := ParseProxyLine("host.com:8080", ProxyFormatHostPortUserPass)
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "host.com" || p.Port != 8080 || p.Username != "" {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestParseIPv6(t *testing.T) {
	p, err := ParseProxyLine("[::1]:3128", ProxyFormatHostPortUserPass)
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "::1" || p.Port != 3128 {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestParseWithProtocol(t *testing.T) {
	p, err := ParseProxyLine("http://user:pass@host.com:3128", ProxyFormatUserPassAtHostPort)
	if err != nil {
		t.Fatal(err)
	}
	if p.Host != "host.com" || p.Port != 3128 {
		t.Fatalf("unexpected: %+v", p)
	}
}
