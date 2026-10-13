package tailnetdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/netmap"
	"tailscale.com/util/dnsname"
)

// Handler is the plugin.Handler that answers queries from the tailnet
// netmap. It is created by the tailscale directive (see setup.go) and
// exposed to main via Active().
type Handler struct {
	next plugin.Handler
	zone string
	fall fall.F
	cfg  *dnsserver.Config // server block this handler belongs to

	srv *tsnet.Server // nil when talking to a local tailscaled
	lc  *local.Client

	mu sync.RWMutex
	// entries maps lowercased node names (and CNAME/VIP names) to
	// "A"/"AAAA"/"CNAME" -> values. Readers snapshot the map reference
	// under RLock; writers build a fresh map and swap it under Lock, so a
	// snapshot is safe to read without the lock afterwards.
	entries map[string]map[string][]string

	// nmu guards the live node table below. In production only the IPN
	// bus watcher goroutine writes it; the mutex also keeps it safe when
	// tests drive handleNotify from another goroutine. The only lock
	// nesting is nmu -> mu (in publish).
	nmu         sync.Mutex
	self        *nodeInfo      // this node, nil until the tailnet is up
	selfID      tailcfg.NodeID // identity of self, to filter it out of peer deltas
	peers       map[tailcfg.NodeID]*nodeInfo
	magicSuffix string // tailnet MagicDNS suffix, for deriving node labels from FQDNs
}

// nodeInfo is the DNS-relevant view of one tailnet node, assembled either
// from a full tailcfg.Node (the bus SelfChange/PeersChanged messages) or
// from an ipnstate.PeerStatus (the InitialStatus snapshot). Once built it
// is treated as immutable.
type nodeInfo struct {
	name  string       // MagicDNS base name; the key in the entries map
	addrs []netip.Addr // tailnet addresses
	tags  []string
	// services holds the VIP service definitions visible to this node.
	// Only self carries them (they come from self's CapMap); nil for peers.
	services []tailcfg.ServiceDetails
}

// Name implements the plugin.Handler interface.
func (t *Handler) Name() string { return "tailscale" }

// Start connects to the tailnet and starts keeping the DNS entries up to
// date. When srv is non-nil it is an already configured embedded tsnet
// node owned by the caller (main) and is connected to through it; when
// nil, a local tailscaled socket is used.
func (t *Handler) Start(srv *tsnet.Server) error {
	t.srv = srv
	if srv != nil {
		var err error
		t.lc, err = srv.LocalClient()
		if err != nil {
			return err
		}
	} else {
		// zero value local.Client connects to the local tailscaled socket
		t.lc = &local.Client{}
	}

	go t.watchIPNBus()
	return nil
}

// busMask is the IPN bus subscription used by watchIPNBus — the same
// bits upstream's containerboot uses.
//
// The deprecated ipn.Notify.NetMap field this replaces no longer exists:
// the daemon used to send it on runtime notifications only when running
// on Windows, and a NetMap-driven watcher on Linux therefore started
// empty or froze on the startup snapshot. The supported replacement is:
//
//   - NotifyInitialStatus: the complete current state (self + peers, the
//     latter populated because we also set NotifyPeerChanges) as the
//     first Notify of the session, re-delivered after every reconnect;
//   - NotifyPeerChanges: PeersChanged upserts (without NotifyPeerPatches
//     the daemon promotes every narrow per-field patch into a full Node,
//     so every per-peer mutation is observed) and PeersRemoved;
//
// plus Notify.SelfChange, which the daemon always delivers when the full
// tailcfg.Node of this node changes. Together they stitch a continuous
// view of the netmap without the netmap.
const busMask = ipn.NotifyInitialStatus | ipn.NotifyPeerChanges

// watchIPNBus watches the Tailscale IPN bus and keeps the DNS entries up
// to date from the resulting notifications. It does not return; if
// watching fails it retries every minute.
func (t *Handler) watchIPNBus() {
	for {
		watcher, err := t.lc.WatchIPNBus(context.Background(), busMask)
		if err != nil {
			log.Warningf("unable to read from Tailscale event bus, retrying in 1 minute: %v", err)
			time.Sleep(1 * time.Minute)
			continue
		}
		if err := t.consumeWatcher(watcher); err != nil {
			// Watch failed; reconnect. The new session re-delivers
			// InitialStatus, which rebuilds the whole node table, so a
			// delta missed across the gap can never strand the entries.
			log.Debugf("Tailscale event bus watch ended: %v", err)
		}
		watcher.Close()
	}
}

// consumeWatcher pumps notifications from w into handleNotify until the
// watch fails. It returns the (uninteresting) failure for logging.
func (t *Handler) consumeWatcher(watcher *local.IPNBusWatcher) error {
	for {
		n, err := watcher.Next()
		if err != nil {
			return err
		}
		t.handleNotify(&n)
	}
}

// handleNotify folds one IPN bus notification into the node table and,
// when anything changed, republishes the DNS entries. It is split out
// from watchIPNBus so the mapping is testable without a live daemon.
func (t *Handler) handleNotify(n *ipn.Notify) {
	t.nmu.Lock()
	defer t.nmu.Unlock()
	dirty := false

	// InitialStatus is a complete snapshot of self + peers, delivered as
	// the first Notify of a session. Treat it as authoritative rather
	// than as a delta to stitch.
	if n.InitialStatus != nil {
		t.mergeStatus(n.InitialStatus)
		dirty = true
	}

	// SelfChange carries the full new self node: addresses, name, tags
	// and CapMap (which holds the VIP service definitions visible to us).
	if n.SelfChange != nil {
		log.Debugf("Self tags: %+v", n.SelfChange.Tags)
		if suffix := netmap.MagicDNSSuffixOfNodeName(n.SelfChange.Name); suffix != "" {
			t.magicSuffix = suffix
		}
		ni := nodeInfoFromNode(n.SelfChange, t.magicSuffix)
		if ni != nil {
			ni.services = nodeServices(n.SelfChange)
		}
		t.self = ni
		if n.SelfChange.ID != 0 {
			t.selfID = n.SelfChange.ID
			delete(t.peers, t.selfID) // self never lives in the peer table
		}
		dirty = true
	}

	for _, p := range n.PeersChanged {
		if p == nil || (p.ID != 0 && p.ID == t.selfID) {
			continue // self rides SelfChange, not peer deltas
		}
		ni := nodeInfoFromNode(p, t.magicSuffix)
		if ni == nil {
			// Filtered out (WireGuard-only, shared or foreign node): it
			// is absent from the DNS view, same as a removal.
			if _, ok := t.peers[p.ID]; ok {
				delete(t.peers, p.ID)
				dirty = true
			}
			continue
		}
		if t.peers == nil {
			t.peers = map[tailcfg.NodeID]*nodeInfo{}
		}
		t.peers[p.ID] = ni
		dirty = true
	}

	for _, id := range n.PeersRemoved {
		if _, ok := t.peers[id]; ok {
			delete(t.peers, id)
			dirty = true
		}
	}

	if dirty {
		t.publish()
	}
}

// mergeStatus rebuilds the node table from an ipnstate.Status snapshot
// (Notify.InitialStatus). t.nmu must be held.
func (t *Handler) mergeStatus(st *ipnstate.Status) {
	if st.CurrentTailnet != nil && st.CurrentTailnet.MagicDNSSuffix != "" {
		t.magicSuffix = st.CurrentTailnet.MagicDNSSuffix
	} else if st.MagicDNSSuffix != "" {
		t.magicSuffix = st.MagicDNSSuffix // pre-CurrentTailnet daemons
	}

	var self *nodeInfo
	var selfID tailcfg.NodeID
	if st.Self != nil {
		selfID = st.Self.NodeID
		self = nodeInfoFromStatus(st.Self, t.magicSuffix)
		if self != nil && st.Self.CapMap != nil {
			// Status.Self.CapMap carries the same VIP service
			// definitions as self's tailcfg.Node CapMap.
			self.services = nodeServices(&tailcfg.Node{CapMap: st.Self.CapMap})
		}
	}

	peers := make(map[tailcfg.NodeID]*nodeInfo, len(st.Peer))
	for _, ps := range st.Peer {
		if ps == nil || ps.NodeID == 0 || ps.NodeID == selfID {
			// NodeID is needed to apply PeersRemoved against this entry;
			// current daemons always set it.
			continue
		}
		if ni := nodeInfoFromStatus(ps, t.magicSuffix); ni != nil {
			peers[ps.NodeID] = ni
		}
	}

	t.self, t.selfID, t.peers = self, selfID, peers
}

// nodeInfoFromNode builds a nodeInfo from a full tailcfg.Node (as carried
// by Notify.SelfChange and Notify.PeersChanged), or nil when the node is
// filtered out of the DNS view.
func nodeInfoFromNode(n *tailcfg.Node, magicSuffix string) *nodeInfo {
	if n == nil || n.IsWireGuardOnly {
		// A plain WireGuard peer (e.g. a Mullvad-style exit node), not a
		// tailnet node with a tailnet name.
		return nil
	}
	if !n.Sharer.IsZero() {
		// Skip shared nodes: they don't necessarily have unique
		// hostnames within this tailnet.
		return nil
	}

	// Peers arriving over the IPN bus carry ComputedName (controlclient
	// computes it from Name + Hostinfo); fall back to deriving it the
	// same way for any source that does not.
	hostname := n.ComputedName
	if hostname == "" {
		hostname = displayName(n.Name, magicSuffix, hostDisplayName(n.Hostinfo), n.Key.String())
	}
	if !validLabel(hostname) {
		// Name is not under the tailnet's MagicDNS suffix (a foreign or
		// WireGuard-only peer; shared-in nodes were filtered above), or
		// there is no usable name at all.
		return nil
	}

	ni := &nodeInfo{name: hostname, tags: slices.Clone(n.Tags)}
	for _, pfx := range n.Addresses {
		// mirrors the old netmap mapping: every address prefix
		// contributes its address (in practice they are all single IPs).
		ni.addrs = append(ni.addrs, pfx.Addr())
	}
	return ni
}

// nodeInfoFromStatus builds a nodeInfo from an ipnstate.PeerStatus (as
// carried by Notify.InitialStatus), or nil when the node is filtered out
// of the DNS view.
func nodeInfoFromStatus(ps *ipnstate.PeerStatus, magicSuffix string) *nodeInfo {
	if ps == nil {
		return nil
	}
	if !ps.AltSharerUserID.IsZero() {
		// Shared node (status's view of tailcfg.Node.Sharer): skip it,
		// as nodeInfoFromNode does — it doesn't necessarily have a
		// unique hostname within this tailnet.
		return nil
	}
	// The status view has no IsWireGuardOnly/Sharer fields; nodes whose
	// DNSName does not trim to a single label under our suffix are
	// foreign or WireGuard-only peers, and the ones with no hostname at
	// all are unusable anyway.
	hostname := displayName(ps.DNSName, magicSuffix, dnsname.SanitizeHostname(ps.HostName), "")
	if !validLabel(hostname) {
		return nil
	}
	ni := &nodeInfo{
		name:  hostname,
		addrs: slices.Clone(ps.TailscaleIPs),
	}
	if len(ni.addrs) == 0 {
		return nil // no tailnet address, nothing to resolve to
	}
	if ps.Tags != nil {
		ni.tags = ps.Tags.AsSlice()
	}
	return ni
}

// displayName derives the MagicDNS base name of a node from its FQDN,
// mirroring tailcfg.Node.InitDisplayNames: trim the tailnet suffix, fall
// back to hostname, then to keyFallback.
func displayName(fqdn, magicSuffix, hostname, keyFallback string) string {
	name := dnsname.TrimSuffix(fqdn, magicSuffix)
	if strings.EqualFold(name, hostname) {
		hostname = "" // same thing, don't duplicate it
	}
	if name == "" {
		name = hostname
		if name == "" {
			name = keyFallback // "" yields a filtered node, same as before
		}
	}
	return name
}

// hostDisplayName extracts the sanitized hostname from a Hostinfo view,
// mirroring what InitDisplayNames feeds to the fallback logic.
func hostDisplayName(hv tailcfg.HostinfoView) string {
	if !hv.Valid() {
		return ""
	}
	return dnsname.SanitizeHostname(hv.Hostname())
}

// validLabel reports whether name is usable as a single DNS label in the
// served zone.
func validLabel(name string) bool {
	return name != "" && !strings.Contains(name, ".")
}

// nodeServices extracts the VIP service definitions from a node's
// CapMap: the "services/..." capability entries hold one JSON-encoded
// tailcfg.ServiceDetails each, which is how control announces VIP
// services to the node that offers them.
func nodeServices(n *tailcfg.Node) []tailcfg.ServiceDetails {
	if n == nil || len(n.CapMap) == 0 {
		return nil
	}
	prefix := string(tailcfg.NodeAttrPrefixServices)
	var out []tailcfg.ServiceDetails
	for cap, vals := range n.CapMap {
		if !strings.HasPrefix(string(cap), prefix) {
			continue
		}
		for _, v := range vals {
			var svc tailcfg.ServiceDetails
			if err := json.Unmarshal([]byte(v), &svc); err != nil {
				log.Debugf("skipping unparsable service %v: %v", cap, err)
				continue
			}
			out = append(out, svc)
		}
	}
	return out
}

// publish rebuilds the DNS entries map from the current node table and
// swaps it in atomically. t.nmu must be held.
func (t *Handler) publish() {
	entries := map[string]map[string][]string{}

	addAddrs := func(entry map[string][]string, addrs []netip.Addr) map[string][]string {
		for _, addr := range addrs {
			switch {
			case addr.Is4():
				entry["A"] = append(entry["A"], addr.String())
			case addr.Is6():
				entry["AAAA"] = append(entry["AAAA"], addr.String())
			}
		}
		return entry
	}

	addNode := func(ni *nodeInfo) {
		if ni == nil || !validLabel(ni.name) {
			return
		}
		entry, ok := entries[ni.name]
		if !ok {
			entry = map[string][]string{}
		}
		entries[ni.name] = addAddrs(entry, ni.addrs)

		// Process tags looking for cname- prefixed ones.
		for _, raw := range ni.tags {
			if tag, ok := strings.CutPrefix(raw, "tag:cname-"); ok {
				if _, ok := entries[tag]; !ok {
					entries[tag] = map[string][]string{}
				}
				entries[tag]["CNAME"] = append(entries[tag]["CNAME"], fmt.Sprintf("%s.%s.", ni.name, t.zone))
			}
		}
	}

	addNode(t.self)
	for _, ni := range t.peers {
		addNode(ni)
	}

	// Service (VIP) definitions, visible to the self node only.
	if t.self != nil {
		for _, svc := range t.self.services {
			name := svc.Name.WithoutPrefix()
			if !validLabel(name) {
				continue
			}
			entry, ok := entries[name]
			if !ok {
				entry = map[string][]string{}
			}
			entries[name] = addAddrs(entry, svc.Addrs)
		}
	}

	t.mu.Lock()
	t.entries = entries
	t.mu.Unlock()
	log.Debugf("updated %d Tailscale entries", len(entries))
}
