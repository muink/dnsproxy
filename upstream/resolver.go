package upstream

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"golang.org/x/exp/slices"
)

// Resolver is an alias for [bootstrap.Resolver] to avoid the import cycle.
type Resolver = bootstrap.Resolver

// NewUpstreamResolver creates an upstream that can be used as [Resolver].
// resolverAddress format is the same as in the [AddressToUpstream], except that
// it also shouldn't need a bootstrap, i.e. have an IP address in hostname, or
// be a DNSCrypt.  resolverAddress must not be empty, use another [Resolver]
// instead, e.g.  [net.Resolver].
func NewUpstreamResolver(resolverAddress string, opts *Options) (r Resolver, err error) {
	upsOpts := &Options{}

	// TODO(ameshkov):  Aren't other options needed here?
	if opts != nil {
		upsOpts.Timeout = opts.Timeout
		upsOpts.VerifyServerCertificate = opts.VerifyServerCertificate
		upsOpts.PreferIPv6 = opts.PreferIPv6
	}

	ups, err := AddressToUpstream(resolverAddress, upsOpts)
	if err != nil {
		err = fmt.Errorf("creating upstream: %w", err)
		log.Error("upstream bootstrap: %s", err)

		return StaticResolver{}, err
	}

	return asBootstrap(ups, upsOpts.PreferIPv6)
}

// asBootstrap converts an Upstream to a bootstrap Resolver if it's possible.
// It returns an error otherwise, which explains why the conversion failed.
func asBootstrap(u Upstream, preferIPv6 bool) (r Resolver, err error) {
	var upsURL *url.URL
	switch u := u.(type) {
	case *dnsCrypt:
		return UpstreamResolver{
			Upstream:   u,
			PreferIPv6: preferIPv6,
		}, nil
	case *plainDNS:
		upsURL = u.addr
	case *dnsOverTLS:
		upsURL = u.addr
	case *dnsOverHTTPS:
		upsURL = u.addr
	case *dnsOverQUIC:
		upsURL = u.addr
	default:
		return StaticResolver{}, fmt.Errorf("unknown upstream type: %T", u)
	}

	// Make sure the upstream doesn't need a bootstrap.
	_, err = netip.ParseAddr(upsURL.Hostname())
	if err != nil {
		return StaticResolver{}, fmt.Errorf("bootstrap %s: %w", u.Address(), err)
	}

	return UpstreamResolver{
		Upstream:   u,
		PreferIPv6: preferIPv6,
	}, nil
}

// UpstreamResolver is a wrapper around Upstream that implements the
// [bootstrap.Resolver] interface.
type UpstreamResolver struct {
	// Upstream is used for lookups.  It must not be nil.
	Upstream Upstream

	// PreferIPv6 is true if IPv6 addresses should be preferred over IPv4 ones.
	PreferIPv6 bool
}

// type check
var _ Resolver = UpstreamResolver{}

// LookupNetIP implements the [Resolver] interface for upstreamResolver.
//
// TODO(e.burkov):  Use context.
func (r UpstreamResolver) LookupNetIP(
	_ context.Context,
	network string,
	host string,
) (ipAddrs []netip.Addr, err error) {
	if host == "" {
		return []netip.Addr{}, nil
	}

	host = dns.Fqdn(host)

	var answers []dns.RR
	var errs []error
	switch network {
	case "ip4", "ip6":
		qtype := dns.TypeA
		if network == "ip6" {
			qtype = dns.TypeAAAA
		}

		var resp *dns.Msg
		resp, err = r.resolve(host, qtype)
		if err != nil {
			return []netip.Addr{}, err
		}

		answers = resp.Answer
	case "ip":
		resCh := make(chan any, 2)

		go r.resolveAsync(resCh, host, dns.TypeA)
		go r.resolveAsync(resCh, host, dns.TypeAAAA)

		for i := 0; i < 2; i++ {
			switch res := <-resCh; res := res.(type) {
			case error:
				errs = append(errs, res)
			case *dns.Msg:
				answers = append(answers, res.Answer...)
			}
		}

		// Use the previous dnsproxy behavior: prefer IPv4 by default.
		//
		// TODO(a.garipov): Consider unexporting this entire method or
		// documenting that the order of addrs is undefined.
		proxynetutil.SortNetIPAddrs(ipAddrs, r.PreferIPv6)
	default:
		return []netip.Addr{}, fmt.Errorf("unsupported network %s", network)
	}

	for _, rr := range answers {
		if addr, ok := netip.AddrFromSlice(proxyutil.IPFromRR(rr)); ok {
			ipAddrs = append(ipAddrs, addr)
		}
	}

	// TODO(e.burkov):  Use [errors.Join] in Go 1.20.
	if len(ipAddrs) == 0 && len(errs) > 0 {
		return []netip.Addr{}, errors.List("resolving", errs...)
	}

	return ipAddrs, nil
}

// resolve performs a single DNS lookup of host.
func (r UpstreamResolver) resolve(host string, qtype uint16) (resp *dns.Msg, err error) {
	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   host,
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		}},
	}

	return r.Upstream.Exchange(req)
}

// resolveAsync performs a single DNS lookup and sends the result to ch.  It's
// intended to be used as a goroutine.
func (r UpstreamResolver) resolveAsync(resCh chan<- any, host string, qtype uint16) {
	resp, err := r.resolve(host, qtype)
	if err != nil {
		resCh <- err
	} else {
		resCh <- resp
	}
}

// StaticResolver is a resolver which always responds with an underlying slice
// of IP addresses.
type StaticResolver []netip.Addr

// type check
var _ Resolver = StaticResolver(nil)

// LookupNetIP implements the [Resolver] interface for ipSliceResolver.
func (r StaticResolver) LookupNetIP(
	ctx context.Context,
	network,
	host string,
) (addrs []netip.Addr, err error) {
	return slices.Clone(r), nil
}

// ConsequentResolver is a slice of resolvers that are queried in order until
// the first successful response.
type ConsequentResolver []Resolver

// type check
var _ Resolver = ConsequentResolver(nil)

// LookupNetIP implements the [Resolver] interface for consequentResolver.
func (r ConsequentResolver) LookupNetIP(
	ctx context.Context,
	network,
	host string,
) (addrs []netip.Addr, err error) {
	if len(r) == 0 {
		return nil, bootstrap.ErrNoResolvers
	}

	var errs []error
	for _, res := range r {
		addrs, err = res.LookupNetIP(ctx, network, host)
		if err == nil {
			return addrs, nil
		}

		errs = append(errs, err)
	}

	return nil, errors.Join(errs...)
}

// ParallelResolver is a slice of resolvers that are queried concurrently.  The
// first successful response is returned.
type ParallelResolver = bootstrap.ParallelResolver
