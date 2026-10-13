package tailnetdns

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

// active is the handler built by the tailscale directive of the last
// parsed server block; main retrieves it after caddy.Start to connect it
// to the tailnet and to reuse its server-block Config for the tailnet
// listeners.
var active *Handler

func init() { plugin.Register("tailscale", setup) }

// setup parses the tailscale directive:
//
//	tailscale <tailscale-domain> {
//		fallthrough [zones...]
//	}
//
// Unlike the upstream plugin it has no authkey/hostname subdirectives:
// the embedded tsnet node (if any) is owned by main and injected later
// via Handler.Start.
func setup(c *caddy.Controller) error {
	ts := &Handler{entries: map[string]map[string][]string{}}
	for c.Next() {
		args := c.RemainingArgs()
		if len(args) != 1 {
			return plugin.Error("tailscale", c.ArgErr())
		}
		ts.zone = args[0]

		for c.NextBlock() {
			switch c.Val() {
			case "fallthrough":
				ts.fall.SetZonesFromArgs(c.RemainingArgs())
			default:
				return plugin.Error("tailscale", c.ArgErr())
			}
		}
	}

	cfg := dnsserver.GetConfig(c)
	ts.cfg = cfg

	// The closure runs once per compiled dnsserver.Server that includes
	// this Config (the loopback one and each tailnet one), always handing
	// out the same handler instance. Recompiling just rewires its next
	// pointer, which is why repeated compilation is safe.
	cfg.AddPlugin(func(next plugin.Handler) plugin.Handler {
		ts.next = next
		return ts
	})

	active = ts
	return nil
}

// Active returns the handler installed by the tailscale directive, or nil
// if no server block used it.
func Active() *Handler { return active }

// Config returns the server-block Config this handler belongs to; main
// passes it to ServeTailnet so tailnet listeners reuse the same plugins.
func (t *Handler) Config() *dnsserver.Config { return t.cfg }
