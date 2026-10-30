package web

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type fakeResolver struct {
	hosts map[string][]netip.Addr
	ptr   map[string][]string
}

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f.hosts[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func (f fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return f.ptr[addr], nil
}

func TestCheckHost(t *testing.T) {
	v4, v6 := netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("2001:db8:1::5")
	res := fakeResolver{
		hosts: map[string][]netip.Addr{"mail.example.com": {v4}},
		ptr:   map[string][]string{"203.0.113.5": {"Mail.Example.com."}, "2001:db8:1::5": {"static.provider.example."}},
	}
	hc := checkHost(context.Background(), res, "mail.example.com", []netip.Addr{v4, v6})
	if hc.Err != "" || len(hc.Addrs) != 2 {
		t.Fatalf("%+v", hc)
	}
	if a := hc.Addrs[0]; !a.Public || !a.Forward || !a.PTROK {
		t.Errorf("IPv4 should match both ways: %+v", a)
	}
	if a := hc.Addrs[1]; a.Forward || a.PTROK || !hc.IPv6Bad {
		t.Errorf("IPv6 without AAAA and PTR must be flagged: %+v %v", a, hc.IPv6Bad)
	}
	lab := checkHost(context.Background(), res, "unknown.example.com", []netip.Addr{netip.MustParseAddr("192.168.1.10")})
	if lab.Err == "" || lab.Addrs[0].Public || lab.IPv6Bad {
		t.Errorf("lab: %+v", lab)
	}
}
