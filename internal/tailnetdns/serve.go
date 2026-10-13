// Package tailnetdns resolves DNS names for tailnet nodes, VIP services
// and tag-based CNAMEs.
//
// Based on github.com/damomurf/coredns-tailscale (Copyright (c) 2022
// coredns-tailscale Authors, MIT licensed), from which the DNS record
// mapping and serving logic are copied with these changes:
//
//   - the tsnet.Server is injected by the caller (main) instead of being
//     created inside the plugin, so the same tailnet node can also host
//     the tailnet DNS listeners;
//   - start() errors are returned to the caller instead of being
//     swallowed at setup time;
//   - the entries map is treated as immutable once published (each
//     tailnet state update swaps in a fresh map), so queries read it
//     without holding a lock across fallthrough calls into forward;
//   - the IPN bus watcher closes each watcher on reconnect instead of
//     deferring across the retry loop.
package tailnetdns

import (
	"context"
	"net"
	"strings"

	"github.com/miekg/dns"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin("tailscale")

const (
	TypeAll = iota
	TypeA
	TypeAAAA
)

// ServeDNS implements the plugin.Handler interface. It is called for
// queries on the zone configured in the Corefile, after the "errors" and
// "log" wrappers and before "forward".
func (t *Handler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true

	// Snapshot the published map; netmap updates replace the whole map, so
	// this snapshot stays valid and immutable for the rest of the query.
	t.mu.RLock()
	entries := t.entries
	t.mu.RUnlock()

	name := r.Question[0].Name
	log.Debugf("Received request for name: %v", name)
	log.Debugf("Tailscale peers list has %d entries", len(entries))

	switch r.Question[0].Qtype {
	case dns.TypeA:
		log.Debug("Handling A record lookup")
		resolveA(entries, name, &msg)

	case dns.TypeAAAA:
		log.Debug("Handling AAAA record lookup")
		resolveAAAA(entries, name, &msg)

	case dns.TypeCNAME:
		log.Debug("Handling CNAME record lookup")
		resolveCNAME(entries, name, &msg, TypeAll)
	}

	if len(msg.Answer) == 0 {
		return t.handleNoRecords(ctx, w, r, &msg)
	}

	log.Debugf("Writing response: %+v", msg)
	w.WriteMsg(&msg)
	return dns.RcodeSuccess, nil
}

func resolveA(entries map[string]map[string][]string, domainName string, msg *dns.Msg) {
	name := strings.Split(strings.ToLower(domainName), ".")[0]
	ips, ok := entries[name]["A"]
	if ok {
		log.Debugf("Found an v4 entry after lookup for: %s", name)
		for _, entry := range ips {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: domainName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 600},
				A:   net.ParseIP(entry),
			})
		}
	} else {
		// There's no A record, so see if a CNAME exists
		log.Debug("No v4 entry after lookup, so trying CNAME")
		resolveCNAME(entries, domainName, msg, TypeA)
	}
}

func resolveAAAA(entries map[string]map[string][]string, domainName string, msg *dns.Msg) {
	name := strings.Split(strings.ToLower(domainName), ".")[0]
	ips, ok := entries[name]["AAAA"]
	if ok {
		log.Debugf("Found a v6 entry after lookup for: %s", name)
		for _, entry := range ips {
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domainName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 600},
				AAAA: net.ParseIP(entry),
			})
		}
	} else {
		// There's no AAAA record, so see if a CNAME exists
		log.Debug("No v6 entry after lookup, so trying CNAME")
		resolveCNAME(entries, domainName, msg, TypeAAAA)
	}
}

func resolveCNAME(entries map[string]map[string][]string, domainName string, msg *dns.Msg, lookupType int) {
	name := strings.Split(strings.ToLower(domainName), ".")[0]
	targets, ok := entries[name]["CNAME"]
	if ok {
		log.Debugf("Found a CNAME entry after lookup for: %s", name)
		for _, target := range targets {
			msg.Answer = append(msg.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: domainName, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 600},
				Target: target,
			})

			// Resolve local zone A or AAAA records if they exist for the referenced target
			if lookupType == TypeAll || lookupType == TypeA {
				log.Debug("CNAME record found, lookup up local recursive A")
				resolveA(entries, target, msg)
			}
			if lookupType == TypeAll || lookupType == TypeAAAA {
				log.Debug("CNAME record found, lookup up local recursive AAAA")
				resolveAAAA(entries, target, msg)
			}
		}
	}
}

func (t *Handler) handleNoRecords(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, msg *dns.Msg) (int, error) {
	if t.fall.Through(r.Question[0].Name) {
		log.Debug("falling through")
		return plugin.NextOrFailure(t.Name(), t.next, ctx, w, r)
	}
	log.Debugf("Writing response: %+v", msg)
	w.WriteMsg(msg)
	return dns.RcodeNameError, nil
}
