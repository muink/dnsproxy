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

// Resolver is an alias for the internal [bootstrap.Resolver] to allow custom
// implementations.  Note, that the [net.Resolver] from standard library also
// implements this interface.
type Resolver = bootstrap.Resolver

// UpstreamResolver is a wrapper around Upstream that implements the
// [bootstrap.Resolver] interface.
type UpstreamResolver struct {
	// Upstream is used for lookups.  It must not be nil.
	Upstream Upstream

	// PreferIPv6 is true if IPv6 addresses should be preferred over IPv4 ones.
	PreferIPv6 bool
}

// NewUpstreamResolver creates an upstream that can be used as bootstrap
// [Resolver].  resolverAddress format is the same as in the
// [AddressToUpstream].  If the upstream can't be used as a bootstrap, the
// returned error will have the underlying type of [NotBootstrapError], and r
// itself will be fully usable.
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

		return nil, err
	}

	return UpstreamResolver{
		Upstream:   ups,
		PreferIPv6: upsOpts.PreferIPv6,
	}, validateBootstrap(ups)
}

// NotBootstrapError is returned by [AddressToUpstream] when the parsed upstream
// can't be used as a bootstrap and wraps the actual reason.
type NotBootstrapError struct {
	why error
}

// type check
var _ error = NotBootstrapError{}

// Error implements the [error] interface for NotBootstrapError.
func (e NotBootstrapError) Error() (msg string) {
	return fmt.Sprintf("not a bootstrap: %s", e.why)
}

// type check
var _ errors.Wrapper = NotBootstrapError{}

// Unwrap implements the [errors.Wrapper] interface.
func (e NotBootstrapError) Unwrap() (reason error) {
	return e.why
}

// validateBootstrap returns an error if u can't be used as a bootstrap.
func validateBootstrap(u Upstream) (err error) {
	var upsURL *url.URL
	switch u := u.(type) {
	case *dnsCrypt:
		return nil
	case *plainDNS:
		upsURL = u.addr
	case *dnsOverTLS:
		upsURL = u.addr
	case *dnsOverHTTPS:
		upsURL = u.addr
	case *dnsOverQUIC:
		upsURL = u.addr
	default:
		return fmt.Errorf("unknown upstream type: %T", u)
	}

	// Make sure the upstream doesn't need a bootstrap.
	_, err = netip.ParseAddr(upsURL.Hostname())
	if err != nil {
		return NotBootstrapError{why: err}
	}

	return nil
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

	var errs []error
	switch network {
	case "ip4", "ip6":
		var answers []dns.RR
		answers, err = r.resolve(host, network)
		if err != nil {
			errs = append(errs, err)
		} else {
			ipAddrs = appendRRs(ipAddrs, answers)
		}
	case "ip":
		resCh := make(chan any, 2)
		go r.resolveAsync(resCh, host, "ip4")
		go r.resolveAsync(resCh, host, "ip6")

		for i := 0; i < 2; i++ {
			switch res := <-resCh; res := res.(type) {
			case error:
				errs = append(errs, res)
			case []dns.RR:
				ipAddrs = appendRRs(ipAddrs, res)
			}
		}

		proxynetutil.SortNetIPAddrs(ipAddrs, r.PreferIPv6)
	default:
		return []netip.Addr{}, fmt.Errorf("unsupported network %s", network)
	}

	if len(ipAddrs) == 0 && len(errs) > 0 {
		return []netip.Addr{}, errors.Join(errs...)
	}

	return ipAddrs, nil
}

// appendRRs appends valid addresses from rrs to addrs.
func appendRRs(addrs []netip.Addr, rrs []dns.RR) (res []netip.Addr) {
	for _, rr := range rrs {
		if addr := proxyutil.IPFromRR(rr); addr.IsValid() {
			addrs = append(addrs, addr)
		}
	}

	return addrs
}

// resolve performs a single DNS lookup of host and returns the answer section.
func (r UpstreamResolver) resolve(host, network string) (ans []dns.RR, err error) {
	qtype := dns.TypeA
	if network == "ip6" {
		qtype = dns.TypeAAAA
	}

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

	resp, err := r.Upstream.Exchange(req)
	if err != nil {
		return nil, err
	}

	return resp.Answer, nil
}

// resolveAsync performs a single DNS lookup and sends the result to ch.  It's
// intended to be used as a goroutine.
func (r UpstreamResolver) resolveAsync(resCh chan<- any, host, network string) {
	resp, err := r.resolve(host, network)
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

// ParallelResolver is an alias for the internal [bootstrap.ParallelResolver] to
// allow it's usage outside of the module.
type ParallelResolver = bootstrap.ParallelResolver
