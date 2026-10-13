package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/debug"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/forward"
	_ "github.com/coredns/coredns/plugin/log"
	"tailscale.com/tsnet"

	"github.com/djmaze/tailscale-dns-server/internal/tailnetdns"
)

// Default for the optional tailscale hostname setting. The two domains
// have no defaults and must be provided explicitly.
const defaultTailscaleHostname = "coredns-test"

// Default for the optional upstream resolver setting: the system
// resolvers. Inside a container /etc/resolv.conf is written by the
// container runtime and does not always answer, so prefer setting
// explicit resolvers via UPSTREAM_DNS there.
const defaultUpstreamDNS = "/etc/resolv.conf"

// validDomain accepts the labels we need to interpolate into the Caddyfile
// without quoting: letters, digits, hyphens, underscores and dots.
var validDomain = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?)*$`)

// validAuthKey accepts tailscale node/auth keys (tskey-...) as a bare
// Caddyfile token: no whitespace, quotes or braces.
var validAuthKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// validPort accepts a decimal DNS port 1-65535.
var validPort = regexp.MustCompile(`^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$`)

// validUpstreamFile accepts the path of a resolver config (such as
// /etc/resolv.conf) as a bare Caddyfile token.
var validUpstreamFile = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// validUpstreamHost accepts the host part of a forward target: a hostname
// or an address. IPv6 must be bracketed, which is what forward wants for
// IPv6 targets anyway.
var validUpstreamHost = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?)*)$`)

// parseUpstreamDNS validates the upstream resolver setting and returns the
// targets space separated, ready to interpolate into the forward directive.
// Each target is either a resolver address (host, host:port or
// [v6]:port) or the path of a resolver config file; several may be given,
// separated by whitespace.
func parseUpstreamDNS(raw string) (string, error) {
	tokens := strings.Fields(raw)
	if len(tokens) == 0 {
		return "", errors.New("empty: want a resolver address or the path of a resolv.conf")
	}
	for _, tok := range tokens {
		if validUpstreamFile.MatchString(tok) {
			continue
		}
		host := tok
		if h, port, err := net.SplitHostPort(tok); err == nil {
			host = h
			if strings.HasPrefix(tok, "[") {
				host = "[" + h + "]" // SplitHostPort strips the brackets
			}
			if !validPort.MatchString(port) {
				return "", fmt.Errorf("invalid port in upstream %q: want 1-65535", tok)
			}
		}
		if !validUpstreamHost.MatchString(host) {
			return "", fmt.Errorf("invalid upstream %q: want host, host:port, [ipv6]:port or a resolv.conf path", tok)
		}
	}
	return strings.Join(tokens, " "), nil
}

// envOr returns the trimmed value of the environment variable named key,
// falling back to def when it is unset or empty.
func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// envBoolOr interprets the environment variable named key as a boolean
// (strconv.ParseBool syntax, e.g. true/1/on), falling back to def when it
// is unset, empty or not parseable.
func envBoolOr(key string, def bool) bool {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

// caddyfileTemplate is the CoreDNS Caddyfile, parameterized by the
// served DNS zone (%[1]s), the listen port (%[2]s), the tailscale domain
// to resolve (%[3]s), the upstream resolver targets for everything that
// misses the tailnet (%[4]s, space separated) and the optional debug
// directive (%[5]s, the debug line or empty). Tailnet listeners are
// attached separately in main once the tsnet node is up; the node's
// hostname is a main-level setting, not a directive option.
const caddyfileTemplate = `
%[1]s:%[2]s {
	tailscale %[3]s {
		fallthrough
	}
	forward . %[4]s%[5]s
	log
	errors
}
`

// renderCaddyfile renders the Caddyfile contents. The debug directive is
// only emitted when debug is enabled; without it CoreDNS suppresses
// debug-level messages and keeps its automatic panic recovery. (With the
// errors plugin in the chain a recover handler is installed either way,
// so the directive mainly controls log verbosity.)
func renderCaddyfile(dnsDomain, dnsPort, tailscaleDomain, upstream string, debug bool) string {
	debugDirective := ""
	if debug {
		debugDirective = "\n\tdebug"
	}
	return fmt.Sprintf(caddyfileTemplate, dnsDomain, dnsPort, tailscaleDomain, upstream, debugDirective)
}

func main() {
	var (
		dnsDomain = flag.String("dns-domain", envOr("DNS_DOMAIN", ""),
			"DNS zone to serve (required; env DNS_DOMAIN)")
		tailscaleDomain = flag.String("tailscale-domain", envOr("TAILSCALE_DOMAIN", ""),
			"tailscale domain to resolve (required; env TAILSCALE_DOMAIN)")
		tailscaleHostname = flag.String("tailscale-hostname", envOr("TS_HOSTNAME", defaultTailscaleHostname),
			fmt.Sprintf("hostname this node registers with on the tailnet (env TS_HOSTNAME), e.g. %s", defaultTailscaleHostname))
		tailscaleAuthKey = flag.String("tailscale-authkey", envOr("TS_AUTHKEY", ""),
			"optional auth key for the embedded tailscale node (env TS_AUTHKEY); when empty, connect to a local tailscaled socket")
		dnsPort = flag.String("dns-port", envOr("DNS_PORT", "53"),
			"DNS listen port on all addresses including the tailnet (env DNS_PORT)")
		upstreamDNS = flag.String("upstream-dns", envOr("UPSTREAM_DNS", defaultUpstreamDNS),
			"upstream resolver(s) for names outside the tailnet, space separated: resolver addresses (host[:port] or [ipv6]:port) and/or resolv.conf paths (env UPSTREAM_DNS)")
		tsDir = flag.String("ts-dir", envOr("TS_DIR", ""),
			"state dir for the embedded tailscale node (env TS_DIR); default $HOME/tsnet")
		debug = flag.Bool("debug", envBoolOr("DEBUG", false),
			"enable the CoreDNS debug directive: prints debug-level log messages to stdout and inhibits the server's panic recovery (env DEBUG)")
	)
	flag.Parse()

	if *dnsDomain == "" {
		fmt.Fprintln(os.Stderr, "missing dns domain: set -dns-domain or DNS_DOMAIN")
		os.Exit(2)
	}
	if *tailscaleDomain == "" {
		fmt.Fprintln(os.Stderr, "missing tailscale domain: set -tailscale-domain or TAILSCALE_DOMAIN")
		os.Exit(2)
	}

	for name, domain := range map[string]string{
		"dns domain":         *dnsDomain,
		"tailscale domain":   *tailscaleDomain,
		"tailscale hostname": *tailscaleHostname,
	} {
		if !validDomain.MatchString(domain) {
			fmt.Fprintf(os.Stderr, "invalid %s %q: want a domain-like name\n", name, domain)
			os.Exit(2)
		}
	}
	if !validPort.MatchString(*dnsPort) {
		fmt.Fprintf(os.Stderr, "invalid dns port %q: want 1-65535\n", *dnsPort)
		os.Exit(2)
	}
	if *tailscaleAuthKey != "" && !validAuthKey.MatchString(*tailscaleAuthKey) {
		fmt.Fprintln(os.Stderr, "invalid tailscale auth key: must not contain whitespace or special characters")
		os.Exit(2)
	}
	upstream, err := parseUpstreamDNS(*upstreamDNS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid upstream dns %q: %v\n", *upstreamDNS, err)
		fmt.Fprintln(os.Stderr, "set -upstream-dns or UPSTREAM_DNS, e.g. \"1.1.1.1:53 8.8.8.8:53\" or \"/etc/resolv.conf\"")
		os.Exit(2)
	}

	// With an auth key main owns an embedded tailscale node (tsnet): the
	// handler resolves names through it and tailnet listeners attach on
	// its tailnet IPs. Without one the handler uses a local tailscaled
	// socket and tailnet listeners are not possible.
	var srv *tsnet.Server
	if *tailscaleAuthKey != "" {
		dir := *tsDir
		if dir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot derive tsnet state dir: %v (set -ts-dir or TS_DIR)\n", err)
				os.Exit(2)
			}
			dir = filepath.Join(home, "tsnet")
		}
		srv = &tsnet.Server{
			Dir:      dir,
			Hostname: *tailscaleHostname,
			AuthKey:  *tailscaleAuthKey,
			// Surface tsnet status (including the auth URL when a key
			// needs interactive login) on stdout.
			Logf: func(format string, a ...any) { fmt.Printf("tsnet: "+format+"\n", a...) },
		}
		if err := srv.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "starting embedded tailscale node: %v\n", err)
			os.Exit(1)
		}
	}

	mode := "tailscaled socket"
	if srv != nil {
		mode = "embedded tsnet, auth key set"
	}
	debugMode := "off"
	if *debug {
		debugMode = "on"
	}
	fmt.Printf("Serving DNS domain %s on port %s, tailscale domain %s, upstream %s (hostname %s, %s, debug %s)\n",
		*dnsDomain, *dnsPort, *tailscaleDomain, upstream, *tailscaleHostname, mode, debugMode)

	// dnsserver.Directives is the order plugins handle a request in, NOT
	// the Caddyfile order above: the chain is compiled from this slice.
	// log and errors are wrappers, so they must run before the plugins
	// that answer and write the response; tailscale must run before
	// forward so tailnet names resolve there first and only misses fall
	// through. debug is always listed but only set up when -debug is on.
	dnsserver.Directives = []string{"debug", "errors", "log", "tailscale", "forward"}
	instance, err := caddy.Start(caddy.CaddyfileInput{
		Filepath:       "Corefile",
		Contents:       []byte(renderCaddyfile(*dnsDomain, *dnsPort, *tailscaleDomain, upstream, *debug)),
		ServerTypeName: "dns",
	})
	if err != nil {
		panic(err)
	}

	// Connect the tailscale handler to the tailnet now that the server
	// block has compiled cleanly (setup intentionally deferred this).
	th := tailnetdns.Active()
	if th == nil {
		panic("tailscale plugin not active in config")
	}
	if err := th.Start(srv); err != nil {
		panic(fmt.Sprintf("starting tailscale handler: %v", err))
	}

	// Serve DNS on the node's own tailnet IPs too: CoreDNS itself bound
	// 0.0.0.0:53, which the tailnet cannot route to because the embedded
	// node has no interface. These tsnet listeners do.
	ctx, cancel := context.WithCancel(context.Background())
	var stopTailnet func()
	if srv != nil {
		stopTailnet, err = tailnetdns.ServeTailnet(ctx, srv, th.Config())
		if err != nil {
			cancel()
			panic(fmt.Sprintf("serving DNS on tailnet: %v", err))
		}
	}

	defer func() {
		if stopTailnet != nil {
			stopTailnet()
		}
		cancel()
		if srv != nil {
			defer srv.Close()
		}
		shutdownErr := errors.Join(instance.ShutdownCallbacks()...)
		stopErr := instance.Stop()
		instance.Wait()
		if err := errors.Join(shutdownErr, stopErr); err != nil {
			panic(err)
		}
	}()

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Blocking, press ctrl+c to continue...")
	<-done
}
