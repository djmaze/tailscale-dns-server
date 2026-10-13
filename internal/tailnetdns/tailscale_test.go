package tailnetdns

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/miekg/dns"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// node builds a full tailcfg.Node as it arrives on the IPN bus
// (SelfChange / PeersChanged).
func node(id tailcfg.NodeID, name, v4, v6 string, tags ...string) *tailcfg.Node {
	n := &tailcfg.Node{ID: id, ComputedName: name, Tags: tags}
	if v4 != "" {
		n.Addresses = append(n.Addresses, netip.MustParsePrefix(v4+"/32"))
	}
	if v6 != "" {
		n.Addresses = append(n.Addresses, netip.MustParsePrefix(v6+"/128"))
	}
	return n
}

// statusPeer builds the ipnstate.PeerStatus entry of an InitialStatus
// snapshot.
func statusPeer(id tailcfg.NodeID, fqdn, host string, ips ...string) *ipnstate.PeerStatus {
	ps := &ipnstate.PeerStatus{NodeID: id, DNSName: fqdn, HostName: host}
	for _, ip := range ips {
		ps.TailscaleIPs = append(ps.TailscaleIPs, netip.MustParseAddr(ip))
	}
	return ps
}

// newTestHandler feeds the notification sequence a live daemon produces:
// InitialStatus (the session's authoritative snapshot), then SelfChange,
// then a full PeersChanged batch (which is what tailscaled emits to
// PeerChanges watchers on the first netmap sync).
func newTestHandler() *Handler {
	h := &Handler{
		zone:    "example.com",
		fall:    fall.Root, // fallthrough for everything, like our Corefile
		entries: map[string]map[string][]string{},
	}
	h.handleNotify(&ipn.Notify{
		InitialStatus: &ipnstate.Status{
			CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: "example.net"},
			Self: &ipnstate.PeerStatus{
				NodeID: 1, DNSName: "dns.example.net.", HostName: "dns",
				TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a::1")},
			},
			Peer: map[key.NodePublic]*ipnstate.PeerStatus{
				{}: statusPeer(2, "db.example.net.", "db", "100.64.0.2", "fd7a::2"),
			},
		},
	})
	h.handleNotify(&ipn.Notify{
		SelfChange: node(1, "dns", "100.64.0.1", "fd7a::1", "tag:cname-resolver"),
	})
	h.handleNotify(&ipn.Notify{
		PeersChanged: []*tailcfg.Node{node(2, "db", "100.64.0.2", "fd7a::2")},
	})
	return h
}

// fakeWriter captures the response message.
type fakeWriter struct{ msg *dns.Msg }

func (f *fakeWriter) LocalAddr() net.Addr       { return &net.UDPAddr{} }
func (f *fakeWriter) RemoteAddr() net.Addr      { return &net.UDPAddr{} }
func (f *fakeWriter) WriteMsg(m *dns.Msg) error { f.msg = m; return nil }
func (f *fakeWriter) Write([]byte) (int, error) { return 0, nil }
func (f *fakeWriter) Close() error              { return nil }
func (f *fakeWriter) TsigStatus() error         { return nil }
func (f *fakeWriter) TsigTimersOnly(bool)       {}
func (f *fakeWriter) Hijack()                   {}

func query(t *Handler, name string, qtype uint16) (*dns.Msg, *fakeWriter) {
	r := new(dns.Msg)
	r.SetQuestion(dns.Fqdn(name), qtype)
	w := &fakeWriter{}
	t.ServeDNS(context.Background(), w, r)
	return r, w
}

func TestResolveSelfA(t *testing.T) {
	h := newTestHandler()
	_, w := query(h, "dns.example.com", dns.TypeA)
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("want 1 answer, got %+v", w.msg)
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok || a.A.String() != "100.64.0.1" {
		t.Fatalf("want 100.64.0.1, got %+v", w.msg.Answer[0])
	}
}

func TestResolvePeerAAAA(t *testing.T) {
	h := newTestHandler()
	_, w := query(h, "db.example.com", dns.TypeAAAA)
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("want 1 answer, got %+v", w.msg)
	}
	aaaa, ok := w.msg.Answer[0].(*dns.AAAA)
	if !ok || aaaa.AAAA.String() != "fd7a::2" {
		t.Fatalf("want fd7a::2, got %+v", w.msg.Answer[0])
	}
}

func TestResolveSelfFromStatusOnly(t *testing.T) {
	// The InitialStatus snapshot alone must already be answerable —
	// SelfChange/PeersChanged are refinements, not the only source.
	h := &Handler{zone: "example.com", fall: fall.Root, entries: map[string]map[string][]string{}}
	h.handleNotify(&ipn.Notify{
		InitialStatus: &ipnstate.Status{
			CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: "example.net"},
			Self:           statusPeer(1, "dns.example.net.", "dns", "100.64.0.1"),
		},
	})
	_, w := query(h, "dns.example.com", dns.TypeA)
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("want 1 answer from status snapshot, got %+v", w.msg)
	}
}

func TestResolvePeerAddedAfterStart(t *testing.T) {
	// The core of the NetMap deprecation fix: a peer that appears only
	// after startup must become resolvable through the delta stream.
	h := newTestHandler()
	if _, w := query(h, "new.example.com", dns.TypeA); w.msg != nil {
		t.Fatalf("new should not exist yet, got %+v", w.msg)
	}
	h.handleNotify(&ipn.Notify{
		PeersChanged: []*tailcfg.Node{node(7, "new", "100.64.0.7", "")},
	})
	_, w := query(h, "new.example.com", dns.TypeA)
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("want 1 answer after PeersChanged, got %+v", w.msg)
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok || a.A.String() != "100.64.0.7" {
		t.Fatalf("want 100.64.0.7, got %+v", w.msg.Answer[0])
	}
}

func TestPeerRemoved(t *testing.T) {
	h := newTestHandler()
	h.handleNotify(&ipn.Notify{PeersRemoved: []tailcfg.NodeID{2}})
	_, w := query(h, "db.example.com", dns.TypeA)
	if w.msg != nil {
		t.Fatalf("want fallthrough after removal, got %+v", w.msg)
	}
}

func TestSelfAddressChange(t *testing.T) {
	h := newTestHandler()
	// SelfChange carrying a new address must update the answer.
	h.handleNotify(&ipn.Notify{SelfChange: node(1, "dns", "100.64.0.9", "")})
	_, w := query(h, "dns.example.com", dns.TypeA)
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("want 1 answer, got %+v", w.msg)
	}
	if a, ok := w.msg.Answer[0].(*dns.A); !ok || a.A.String() != "100.64.0.9" {
		t.Fatalf("want 100.64.0.9, got %+v", w.msg.Answer[0])
	}
}

func TestSharedAndWireGuardOnlyFiltered(t *testing.T) {
	h := newTestHandler()
	shared := node(8, "shared", "100.64.0.8", "")
	shared.Sharer = 42
	wg := node(9, "wgonly", "100.64.0.9", "")
	wg.IsWireGuardOnly = true
	h.handleNotify(&ipn.Notify{PeersChanged: []*tailcfg.Node{shared, wg}})
	if _, w := query(h, "shared.example.com", dns.TypeA); w.msg != nil {
		t.Fatalf("shared node should be filtered, got %+v", w.msg)
	}
	if _, w := query(h, "wgonly.example.com", dns.TypeA); w.msg != nil {
		t.Fatalf("wireguard-only node should be filtered, got %+v", w.msg)
	}
}

func TestVIPServices(t *testing.T) {
	h := newTestHandler()
	// VIP services ride in self's CapMap under the services/ prefix.
	self := node(1, "dns", "100.64.0.1", "")
	self.CapMap = tailcfg.NodeCapMap{
		"services/svc:vip": []tailcfg.RawMessage{
			tailcfg.RawMessage(`{"Name":"svc:vip","Addrs":["100.100.0.1"]}`),
		},
	}
	h.handleNotify(&ipn.Notify{SelfChange: self})
	_, w := query(h, "vip.example.com", dns.TypeA)
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("want 1 answer for VIP, got %+v", w.msg)
	}
	if a, ok := w.msg.Answer[0].(*dns.A); !ok || a.A.String() != "100.100.0.1" {
		t.Fatalf("want 100.100.0.1, got %+v", w.msg.Answer[0])
	}
}

func TestResolveSelfKeyExcludedFromPeers(t *testing.T) {
	// A daemon that also rides self through PeersChanged must not
	// duplicate or shadow self (self is keyed by SelfChange).
	h := newTestHandler()
	h.handleNotify(&ipn.Notify{PeersChanged: []*tailcfg.Node{node(1, "dns", "100.99.99.99", "")}})
	_, w := query(h, "dns.example.com", dns.TypeA)
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("want exactly 1 answer, got %+v", w.msg)
	}
	if a, ok := w.msg.Answer[0].(*dns.A); !ok || a.A.String() != "100.64.0.1" {
		t.Fatalf("self entry must survive, want 100.64.0.1, got %+v", w.msg.Answer[0])
	}
}

func TestReconnectResyncs(t *testing.T) {
	// A fresh bus session re-delivers InitialStatus; it must replace the
	// table wholesale, dropping peers the daemon no longer reports.
	h := newTestHandler()
	h.handleNotify(&ipn.Notify{
		InitialStatus: &ipnstate.Status{
			CurrentTailnet: &ipnstate.TailnetStatus{MagicDNSSuffix: "example.net"},
			Self:           statusPeer(1, "dns.example.net.", "dns", "100.64.0.1"),
		},
	})
	if _, w := query(h, "db.example.com", dns.TypeA); w.msg != nil {
		t.Fatalf("db must be gone after resync, got %+v", w.msg)
	}
	if _, w := query(h, "dns.example.com", dns.TypeA); w.msg == nil || len(w.msg.Answer) != 1 {
		t.Fatalf("want 1 answer after resync, got %+v", w.msg)
	}
}

func TestResolveCNAMEFromTag(t *testing.T) {
	// newTestHandler's self node carries tag:cname-resolver, so
	// resolver.example.com must CNAME to dns.example.com. with glue A.
	h := newTestHandler()
	_, w := query(h, "resolver.example.com", dns.TypeA)
	if w.msg == nil || len(w.msg.Answer) != 2 {
		t.Fatalf("want CNAME + A glue, got %+v", w.msg)
	}
	cn, ok := w.msg.Answer[0].(*dns.CNAME)
	if !ok || cn.Target != "dns.example.com." {
		t.Fatalf("want CNAME to dns.example.com., got %+v", w.msg.Answer[0])
	}
	if a, ok := w.msg.Answer[1].(*dns.A); !ok || a.A.String() != "100.64.0.1" {
		t.Fatalf("want glue A 100.64.0.1, got %+v", w.msg.Answer[1])
	}

	// SelfChange rebuilds tags from the new node: drop the tag and the
	// CNAME must go away.
	h.handleNotify(&ipn.Notify{SelfChange: node(1, "dns", "100.64.0.1", "")})
	_, w = query(h, "resolver.example.com", dns.TypeA)
	if w.msg != nil {
		t.Fatalf("want fallthrough after tag removal, got %+v", w.msg)
	}
}

func TestMissingNameFallsThrough(t *testing.T) {
	h := newTestHandler()
	// next is nil: with fallthrough set, plugin.NextOrFailure must be
	// reached; it writes nothing and errors, proving we fell through
	// instead of answering locally.
	_, w := query(h, "nowhere.example.com", dns.TypeA)
	if w.msg != nil {
		t.Fatalf("expected fallthrough without a local answer, got %+v", w.msg)
	}

	// Without fallthrough we answer ourselves. Note the (upstream-preserved)
	// quirk: handleNoRecords writes a reply with 0 answers — NOERROR NODATA
	// on the wire, because ClientWrite(RcodeNameError) is true and dnsserver
	// leaves an already-written message alone — while returning NXDOMAIN to
	// the framework.
	h.fall = fall.Zero
	rc, _ := h.ServeDNS(context.Background(), w, newQuery("nowhere.example.com"))
	if rc != dns.RcodeNameError {
		t.Fatalf("handler should return NXDOMAIN rcode, got %d", rc)
	}
	if w.msg == nil || w.msg.Rcode != dns.RcodeSuccess || len(w.msg.Answer) != 0 {
		t.Fatalf("want NOERROR NODATA written, got %+v", w.msg)
	}
}

func newQuery(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

func TestNetmapSwapIsAtomicSnapshot(t *testing.T) {
	h := newTestHandler()
	_, w := query(h, "db.example.com", dns.TypeA) // snapshot taken
	// Simulate db disappearing before it would be read: the in-flight
	// snapshot must still answer.
	h.handleNotify(&ipn.Notify{PeersRemoved: []tailcfg.NodeID{2}})
	if w.msg == nil || len(w.msg.Answer) == 0 {
		t.Fatal("stale snapshot should have answered from the old map")
	}
	// A fresh query sees the new map: db is gone, fallthrough is Root, so
	// the handler must fall through (no local answer written).
	_, w = query(h, "db.example.com", dns.TypeA)
	if w.msg != nil {
		t.Fatalf("want fallthrough after removal, got %+v", w.msg)
	}
}
