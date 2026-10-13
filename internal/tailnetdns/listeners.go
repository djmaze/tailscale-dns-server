package tailnetdns

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"tailscale.com/tsnet"
)

// ServeTailnet attaches DNS listeners on the tailnet addresses of srv and
// serves them through the same plugin chain (cfg) that backs the loopback
// server. tsnet routes traffic for the node's own tailnet IPs to these
// listeners, so tailnet peers can reach this DNS server without a TUN
// device or extra privileges.
//
// It waits for the node to come Up, then binds:
//
//	tcp  :<port>          (a tsnet listener without IP matches both tailnet IPs)
//	udp4 <ip4>:<port>     (tsnet ListenPacket requires an explicit IP)
//	udp6 [<ip6>]:<port>   (when the node has an IPv6 tailnet address)
//
// On success it returns a shutdown func; a background goroutine rebinds
// the listeners if the node's tailnet addresses change. Cancelling ctx
// also stops the tailnet servers.
func ServeTailnet(ctx context.Context, srv *tsnet.Server, cfg *dnsserver.Config) (func(), error) {
	upCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if _, err := srv.Up(upCtx); err != nil {
		return nil, fmt.Errorf("waiting for tailnet: %w", err)
	}

	t := &tailnet{srv: srv, cfg: cfg}
	if err := t.bind(); err != nil {
		return nil, err
	}
	go t.reconcile(ctx)
	return t.close, nil
}

// tailnet owns the listeners and dnsservers bound on the tailnet
// addresses of one tsnet node.
type tailnet struct {
	srv *tsnet.Server
	cfg *dnsserver.Config

	mu      sync.Mutex
	servers []*dnsserver.Server
	conns   []io.Closer
	ip4     netip.Addr // addresses the current bindings are for
	ip6     netip.Addr
	closed  bool
}

// bind creates the tailnet listeners and starts serving on them. Each
// listener gets its own dnsserver.Server from cfg. Recompiling the same
// cfg is safe: the plugins it holds are shared and its AddPlugin
// closures are idempotent.
func (t *tailnet) bind() error {
	ip4, ip6 := t.srv.TailscaleIPs()
	if !ip4.IsValid() && !ip6.IsValid() {
		return fmt.Errorf("tailnet bind: node has no tailnet addresses yet")
	}
	port := t.cfg.Port

	var servers []*dnsserver.Server
	var conns []io.Closer
	stop := func() { stopAll(servers, conns) }

	// TCP: one wildcard listener matches traffic to both tailnet IPs.
	ln, err := t.srv.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("tailnet tcp listen: %w", err)
	}
	ds, err := dnsserver.NewServer("dns://tailnet:"+port, []*dnsserver.Config{t.cfg})
	if err != nil {
		ln.Close()
		return fmt.Errorf("tailnet tcp server: %w", err)
	}
	conns = append(conns, ln)
	servers = append(servers, ds)
	go serve("tcp :"+port, func() error { return ds.Serve(ln) })
	log.Infof("serving DNS on tailnet TCP :%s (for %v %v)", port, ip4, ip6)

	// UDP: explicit address per family (required by tsnet.ListenPacket).
	for _, ip := range []netip.Addr{ip4, ip6} {
		if !ip.IsValid() {
			continue
		}
		network := "udp4"
		if ip.Is6() {
			network = "udp6"
		}
		pc, err := t.srv.ListenPacket(network, net.JoinHostPort(ip.String(), port))
		if err != nil {
			stop()
			return fmt.Errorf("tailnet %s listen on %s: %w", network, ip, err)
		}
		ds, err := dnsserver.NewServer("dns://tailnet:"+port, []*dnsserver.Config{t.cfg})
		if err != nil {
			pc.Close()
			stop()
			return fmt.Errorf("tailnet %s server: %w", network, err)
		}
		conns = append(conns, pc)
		servers = append(servers, ds)
		go serve("udp "+net.JoinHostPort(ip.String(), port), func() error { return ds.ServePacket(pc) })
		log.Infof("serving DNS on tailnet %s %s", network, net.JoinHostPort(ip.String(), port))
	}

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		stop()
		return nil
	}
	t.servers, t.conns, t.ip4, t.ip6 = servers, conns, ip4, ip6
	t.mu.Unlock()
	return nil
}

func serve(what string, run func() error) {
	if err := run(); err != nil {
		log.Debugf("tailnet %s server: %v", what, err)
	}
}

// reconcile rebinds the tailnet listeners when the node's tailnet
// addresses change (e.g. after re-registration).
func (t *tailnet) reconcile(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ip4, ip6 := t.srv.TailscaleIPs()
			t.mu.Lock()
			changed, closed := ip4 != t.ip4 || ip6 != t.ip6, t.closed
			t.mu.Unlock()
			if closed || !changed {
				continue
			}
			if !ip4.IsValid() && !ip6.IsValid() {
				continue // transient (reconnecting); keep current bindings
			}
			log.Infof("tailnet addresses changed to (%v %v), rebinding", ip4, ip6)
			t.rebind()
		}
	}
}

// rebind stops the current tailnet servers and binds fresh ones.
func (t *tailnet) rebind() {
	t.mu.Lock()
	servers, conns := t.servers, t.conns
	t.servers, t.conns = nil, nil
	t.mu.Unlock()
	stopAll(servers, conns)

	if err := t.bind(); err != nil {
		log.Warningf("tailnet rebind: %v", err)
	}
}

// close stops all tailnet servers and closes their listeners; after it
// returns, reconcile stops rebinding.
func (t *tailnet) close() {
	t.mu.Lock()
	t.closed = true
	servers, conns := t.servers, t.conns
	t.servers, t.conns = nil, nil
	t.mu.Unlock()
	stopAll(servers, conns)
}

func stopAll(servers []*dnsserver.Server, conns []io.Closer) {
	// Close the transports first so blocked Accept/ReadFrom return, then
	// stop the servers gracefully.
	for _, c := range conns {
		c.Close()
	}
	for _, ds := range servers {
		if err := ds.Stop(); err != nil {
			log.Debugf("tailnet server stop: %v", err)
		}
	}
}
