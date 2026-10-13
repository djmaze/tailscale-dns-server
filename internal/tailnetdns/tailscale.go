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
// netmap. The tailscale directive creates it (setup.go); main retrieves
// it via Active().
type Handler struct {
	next plugin.Handler
	zone string
	fall fall.F
	cfg  *dnsserver.Config // server block this handler belongs to

	srv *tsnet.Server // nil when talking to a local tailscaled
	lc  *local.Client

	mu sync.RWMutex
	// entries maps lowercased node, CNAME and VIP names to
	// "A"/"AAAA"/"CNAME" -> values. Writers swap in a fresh map under
	// Lock, so a snapshot taken under RLock stays valid after unlocking.
	entries map[string]map[string][]string

	// nmu guards the node table below. Only the IPN bus watcher writes it
	// in production; the lock also covers tests calling handleNotify.
	// The only lock nesting is nmu -> mu (in publish).
	nmu         sync.Mutex
	self        *nodeInfo      // this node, nil until the tailnet is up
	selfID      tailcfg.NodeID // identity of self, to filter it out of peer deltas
	peers       map[tailcfg.NodeID]*nodeInfo
	magicSuffix string // tailnet MagicDNS suffix, for deriving node labels from FQDNs
}

// nodeInfo is the immutable DNS-relevant view of one tailnet node, built
// from a tailcfg.Node (SelfChange/PeersChanged) or an
// ipnstate.PeerStatus (the InitialStatus snapshot).
type nodeInfo struct {
	name  string       // MagicDNS base name; the key in the entries map
	addrs []netip.Addr // tailnet addresses
	tags  []string
	// services are self's VIP services, from its CapMap; nil for peers.
	services []tailcfg.ServiceDetails
}

// Name implements the plugin.Handler interface.
func (t *Handler) Name() string { return "tailscale" }

// Start connects to the tailnet and keeps the DNS entries up to date.
// A non-nil srv is a configured embedded tsnet node owned by main; nil
// connects to a local tailscaled socket.
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

// busMask is the IPN bus subscription used by watchIPNBus (the same bits
// upstream's containerboot uses). Together these notifications cover
// every netmap change —
//
//   - InitialStatus: the complete self+peer snapshot, the first Notify of
//     each session, re-delivered after every reconnect;
//   - PeerChanges: PeersChanged and PeersRemoved. Without
//     NotifyPeerPatches the daemon upgrades narrow per-field patches to
//     full Nodes, so no change is missed;
//   - Notify.SelfChange: always delivered when self's full node changes.
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
			// Reconnect: the new session re-delivers InitialStatus, so a
			// delta missed across the gap can't strand the entries.
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

	// SelfChange carries self's full node: addresses, name, tags and
	// CapMap (which holds our VIP service definitions).
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
			// Filtered out of the DNS view: treat as a removal.
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
			// Same VIP service definitions as self's tailcfg.Node CapMap.
			self.services = nodeServices(&tailcfg.Node{CapMap: st.Self.CapMap})
		}
	}

	peers := make(map[tailcfg.NodeID]*nodeInfo, len(st.Peer))
	for _, ps := range st.Peer {
		if ps == nil || ps.NodeID == 0 || ps.NodeID == selfID {
			// NodeID is needed to apply PeersRemoved; daemons set it.
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

	// Peers over the IPN bus carry ComputedName (computed by
	// controlclient); derive it ourselves for sources that don't.
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
		// Same as the old netmap mapping: in practice all single IPs.
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
		// Shared node: skip, as nodeInfoFromNode does (no guarantee of
		// a unique hostname in this tailnet).
		return nil
	}
	// The status view lacks IsWireGuardOnly/Sharer; nodes whose DNSName
	// doesn't trim to one label under our suffix are foreign or
	// WireGuard-only, and unnamed ones are unusable anyway.
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

// nodeServices extracts VIP service definitions from a node's CapMap:
// each "services/..." capability entry holds one JSON-encoded
// tailcfg.ServiceDetails — how control announces VIP services to the
// node offering them.
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
