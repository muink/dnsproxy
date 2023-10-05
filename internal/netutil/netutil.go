// Package netutil contains network-related utilities common among dnsproxy
// packages.
//
// TODO(a.garipov): Move improved versions of these into netutil in module
// golibs.
package netutil

import (
	"net"
	"net/netip"
	"strings"

	glnetutil "github.com/AdguardTeam/golibs/netutil"
	"golang.org/x/exp/slices"
)

// SortIPAddrs sorts addrs in accordance with the protocol preferences.  Invalid
// addresses are sorted near the end.  Zones are ignored.
//
// TODO(a.garipov): Use netip.Addr instead of net.IPAddr everywhere where this
// is called.
func SortIPAddrs(addrs []net.IPAddr, preferIPv6 bool) {
	l := len(addrs)
	if l <= 1 {
		return
	}

	slices.SortStableFunc(addrs, func(addrA, addrB net.IPAddr) (res int) {
		// Assume that len(addrs) is mostly small, so these conversions aren't
		// as expensive as they could have been.
		a, err := glnetutil.IPToAddrNoMapped(addrA.IP)
		if err != nil {
			return 1
		}

		b, err := glnetutil.IPToAddrNoMapped(addrB.IP)
		if err != nil {
			return -1
		}

		aIs4, bIs4 := a.Is4(), b.Is4()
		if aIs4 == bIs4 {
			return a.Compare(b)
		}

		if aIs4 {
			if preferIPv6 {
				return 1
			}

			return -1
		}

		if preferIPv6 {
			return -1
		}

		return 1
	})
}

// SortNetIPAddrs sorts addrs in accordance with the protocol preferences.
// Invalid addresses are sorted near the end.  Zones are ignored.
func SortNetIPAddrs(addrs []netip.Addr, preferIPv6 bool) {
	l := len(addrs)
	if l <= 1 {
		return
	}

	slices.SortStableFunc(addrs, func(addrA, addrB netip.Addr) (res int) {
		if !addrA.IsValid() {
			return 1
		} else if !addrB.IsValid() {
			return -1
		}

		aIs4, bIs4 := addrA.Is4(), addrB.Is4()
		if aIs4 == bIs4 {
			return addrA.Compare(addrB)
		}

		if aIs4 {
			if preferIPv6 {
				return 1
			}

			return -1
		}

		if preferIPv6 {
			return -1
		}

		return 1
	})
}

// ParseSubnet parses s either as a CIDR prefix itself, or as an IP address,
// returning the corresponding single-IP CIDR prefix.
//
// TODO(e.burkov):  Move to golibs.
func ParseSubnet(s string) (p netip.Prefix, err error) {
	if strings.Contains(s, "/") {
		p, err = netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
	} else {
		var ip netip.Addr
		ip, err = netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}

		p = netip.PrefixFrom(ip, ip.BitLen())
	}

	return p, nil
}
