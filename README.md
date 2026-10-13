# tailscale-dns-server

A DNS server for your [Tailscale](https://tailscale.com/) tailnet in a single
container. It resolves tailnet names — nodes by their MagicDNS name,
`cname-<name>` tag CNAMEs, and VIP services — under the zone you configure,
and forwards the rest of that zone to a regular upstream resolver. No TUN
device and no sidecar `tailscaled`: give it an auth key and it runs its own
tailscale node.

## Quick start (Docker Compose)

```bash
cp .env.example .env     # set DNS_DOMAIN and TAILSCALE_DOMAIN, add TS_AUTHKEY
docker compose up -d --build
docker compose logs -f
```

- `DNS_DOMAIN` — the zone this server is authoritative for (e.g.
  `example.com`). Names in this zone that aren't tailnet nodes are forwarded
  upstream; queries for other zones are refused (see
  [Point clients at it with split DNS](#point-clients-at-it-with-split-dns)).
- `TAILSCALE_DOMAIN` — your tailnet's MagicDNS domain (e.g.
  `your-tailnet.ts.net` or a custom one). Nodes are served under
  `DNS_DOMAIN` by their tailnet name: node `printer` resolves as
  `printer.<DNS_DOMAIN>`. Make `DNS_DOMAIN` equal to (or a parent of)
  `TAILSCALE_DOMAIN` if the MagicDNS names themselves — and the tag-CNAME
  targets, which point there — should also resolve through this server.
- `TS_AUTHKEY` — create a key at
  [login.tailscale.com/admin/settings/keys](https://login.tailscale.com/admin/settings/keys).
  With it, the server joins the tailnet itself and is reachable **on its
  tailnet IPs**, so other tailnet devices can use it as their resolver with
  no port mapping at all. Without a key it talks to a local `tailscaled`
  socket instead and only serves LAN clients.

Keep the `data` volume mounted: it stores the node key so the server doesn't
re-join the tailnet on every restart.

To let LAN clients use it too, uncomment the `ports` mapping in
`compose.yaml` (53/udp and 53/tcp; the container listens on `DNS_PORT`).

### Try it

```bash
dig @<server-tailnet-ip> printer.<DNS_DOMAIN>            # a tailnet node
dig @<server-tailnet-ip> example.com                     # in-zone miss -> forwarded
dig @<server-tailnet-ip> google.com                      # outside the zone -> REFUSED
```

### Point clients at it with split DNS

This server handles queries under `DNS_DOMAIN` only — tailnet names are
answered from the netmap, other names in the zone are forwarded upstream, and
anything outside the zone is refused. Never set it as a device's or your
tailnet's *global* nameserver; route just the zone it serves to it:

- **On the tailnet:** in the admin console under *DNS → Nameservers*, add
  this node's tailnet address as a nameserver **for a specific domain**
  (Split DNS), namely `DNS_DOMAIN` — tailnet nodes then resolve there as
  `<node>.<DNS_DOMAIN>`.
- **On the LAN:** use it where your existing resolver can forward a single
  zone, e.g. dnsmasq `server=/example.com/100.68.x.x` or an Unbound
  `forward-zone` for the same domain — not as the router's only DNS server
  unless your router itself supports per-domain forwarding.

## Plain Docker

```bash
docker build -t tailscale-dns-server .
docker run -d --name dns \
  -e DNS_DOMAIN=example.com \
  -e TAILSCALE_DOMAIN=your-tailnet.ts.net \
  -e TS_AUTHKEY=tskey-auth-... \
  -p 53:53/udp -p 53:53/tcp \
  -v dns-data:/data \
  tailscale-dns-server
```

## Configuration

Every setting can be given as an environment variable (what `.env`/compose
uses) or as a command-line flag; `--help` lists the flags. Flags win over the
environment.

| Setting | Default | Meaning |
| --- | --- | --- |
| `DNS_DOMAIN` / `-dns-domain` | *required* | zone this server serves; queries outside it are refused — route it here with split DNS |
| `TAILSCALE_DOMAIN` / `-tailscale-domain` | *required* | tailnet MagicDNS domain whose nodes are served, under `DNS_DOMAIN` |
| `TS_AUTHKEY` / `-tailscale-authkey` | *(empty)* | `tskey-...` auth key; when set, an embedded tailscale node is started and the server is also served on its tailnet IPs |
| `TS_HOSTNAME` / `-tailscale-hostname` | `dns` | hostname the node registers on the tailnet |
| `DNS_PORT` / `-dns-port` | `53` | DNS listen port (LAN and tailnet) |
| `UPSTREAM_DNS` / `-upstream-dns` | `/etc/resolv.conf` | resolver(s) for non-tailnet names, space separated: `host[:port]`, `[ipv6]:port`, and/or `resolv.conf` paths. Set explicitly inside containers; never point it at this server itself (DNS loop). compose defaults to `1.1.1.1:53 8.8.8.8:53` |
| `TS_DIR` / `-ts-dir` | `$HOME/tsnet` | state dir of the embedded node (`/data/tsnet` in the image, persisted by the volume) |
| `DEBUG` / `-debug` | `false` | verbose CoreDNS debug logging |

## Notes

- Records served for the tailnet: `A`/`AAAA` per node address, `CNAME`s from
  node tags of the form `cname-<name>`, and VIP services defined on this
  node.
- Runs without privileges: no `NET_ADMIN`, no TUN, and the DNS chain has
  built-in panic recovery plus query logging (`log`, `errors`).
- Built on CoreDNS with a tailscale plugin derived from
  [damomurf/coredns-tailscale](https://github.com/damomurf/coredns-tailscale)
  (MIT).

## About this project

This project was coded with AI assistance, but steered, reviewed and tested
by a human.

## Development

```bash
go build .        # build the binary
go test ./...     # unit tests
```
