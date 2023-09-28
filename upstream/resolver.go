package upstream

import (
	"context"
	"fmt"
	"net/netip"

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

// UpstreamResolver is an interface extension for [Upstream] that may appear
// usable as [Resolver] without bootstrap.
type UpstreamResolver interface {
	// AsResolver returns a [Resolver] made of upstream, but only in case the
	// latter doesn't need bootstrap.
	AsResolver() (r Resolver, err error)
}

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

		return r, err
	}

	if b, ok := ups.(UpstreamResolver); !ok {
		err = fmt.Errorf("unknown upstream type: %T", ups)
	} else if r, err = b.AsResolver(); err != nil {
		err = fmt.Errorf("bootstrap %s: %w", ups.Address(), err)
	}

	return r, err
}

// upstreamResolver is a wrapper around Upstream that implements the
// [bootstrap.Resolver] interface.  It sorts the resolved addresses preferring
// IPv4.
type upstreamResolver struct {
	// Upstream is embedded here to avoid implementing another Upstream's
	// methods.
	Upstream
}

// type check
var _ Resolver = upstreamResolver{}

// LookupNetIP implements the [Resolver] interface for upstreamResolver.
//
// TODO(e.burkov):  Use context.
func (r upstreamResolver) LookupNetIP(
	_ context.Context,
	network string,
	host string,
) (ipAddrs []netip.Addr, err error) {
	// TODO(e.burkov):  Investigate when [r.Upstream] is nil and why.
	if r.Upstream == nil || host == "" {
		return []netip.Addr{}, nil
	}

	host = dns.Fqdn(host)

	answers := make([][]dns.RR, 1, 2)
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

		answers[0] = resp.Answer
	case "ip":
		resCh := make(chan *resolveResult, 2)

		go r.resolveAsync(resCh, host, dns.TypeA)
		go r.resolveAsync(resCh, host, dns.TypeAAAA)

		answers = answers[:0:cap(answers)]
		for i := 0; i < 2; i++ {
			res := <-resCh
			if res.err != nil {
				errs = append(errs, res.err)

				continue
			}

			answers = append(answers, res.resp.Answer)
		}
	default:
		return []netip.Addr{}, fmt.Errorf("unsupported network %s", network)
	}

	for _, ans := range answers {
		for _, rr := range ans {
			if addr, ok := netip.AddrFromSlice(proxyutil.IPFromRR(rr)); ok {
				ipAddrs = append(ipAddrs, addr)
			}
		}
	}

	// TODO(e.burkov):  Use [errors.Join] in Go 1.20.
	if len(ipAddrs) == 0 && len(errs) > 0 {
		return []netip.Addr{}, errs[0]
	}

	// Use the previous dnsproxy behavior: prefer IPv4 by default.
	//
	// TODO(a.garipov): Consider unexporting this entire method or
	// documenting that the order of addrs is undefined.
	proxynetutil.SortNetIPAddrs(ipAddrs, false)

	return ipAddrs, nil
}

// resolve performs a single DNS lookup of host.
func (r upstreamResolver) resolve(host string, qtype uint16) (resp *dns.Msg, err error) {
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

	return r.Exchange(req)
}

// resolveResult is the result of a single concurrent lookup.
type resolveResult = struct {
	resp *dns.Msg
	err  error
}

// resolveAsync performs a single DNS lookup and sends the result to ch.  It's
// intended to be used as a goroutine.
func (r upstreamResolver) resolveAsync(
	resCh chan<- *resolveResult,
	host string,
	qtype uint16,
) {
	resp, err := r.resolve(host, qtype)
	resCh <- &resolveResult{resp: resp, err: err}
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
