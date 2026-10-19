# openvpn-server — vpndogs inbound OpenVPN node

An OpenVPN server for the [vpndogs](https://github.com/nimaboubanian) stack:
clients connect on **TCP 1064**, their traffic is decrypted by `openvpn`,
policy-routed into a sing-box `tun`, which SOCKS-es out through the stack's
router chain (`vpndogs-router:1070`) — client traffic exits wherever the
chain exits.

Use this where **UDP is blocked or throttled** and the WireGuard or AmneziaWG
siblings cannot connect. It is the slowest inbound node; see *Performance*
below before enabling it. Any subset of the four inbounds can run at once
(separate pools, separate ports).

Authentication is **username and password**. No client certificates, no
bring-your-own keys, no `easy-rsa`.

Enable with `COMPOSE_PROFILES=ovpn-inbound` in the stack's `.env`.

## How it works

```
client --openvpn (tls-crypt-v2)--> host:1064/tcp
                        |  (openvpn, owns tun0)
                        v
                      policy route: from 10.10.40.0/24 lookup 200 -> tun1
                        |  (sing-box tun inbound)
                        v
                      socks://vpndogs-router:1070  -> (VPN chain exit)
```

The container runs **two** supervised daemons. Unlike the WireGuard sibling
there is no host kernel prerequisite at all: `openvpn` creates `tun0` itself
from `dev tun` + `server`, and sing-box takes `tun1`. The policy rule sends
only pool-sourced traffic through the tun, so the daemons' own sockets keep
the normal route.

A CA and a single server certificate are generated at boot into the
`ovpn-state` volume. **The CA private key is deleted immediately** — exactly
one certificate is ever issued, so it is never needed again. Clients are
authenticated by password and the channel is sealed with `tls-crypt-v2`; the
server sends no `ca` because it never verifies a client certificate.

## Server-side setup

1. Pick/verify env (see `.env.example`):
   - `OVPN_USERS=name:password,...` — **required**, comma-separated
   - `VPN_SERVER_ADDR=` — **required**, the public IP/hostname clients dial
   - `OVPN_POOL=10.10.40.0/24` — optional, must not overlap the container's
     own subnet (the entrypoint refuses to boot if it does)
   - `CLIENT_DNS=1.1.1.1`, `CHAIN_SOCKS_HOST=vpndogs-router`,
     `CHAIN_SOCKS_PORT=1070` — optional
2. Host prerequisites: `/dev/net/tun` + `NET_ADMIN` (compose grants them) and
   host **TCP 1064** free. No kernel module needed.
3. `docker compose up -d vpndogs-ovpn-inbound` (or via the stack compose with
   `COMPOSE_PROFILES=ovpn-inbound`).
4. Check the server is up: `docker compose exec vpndogs-ovpn-inbound report.sh`.
   The `== OpenVPN ==` section lists connected clients with byte counters.

## Client setup

There is nothing to generate and no key to copy. Issue a profile per user:

```sh
docker exec vpndogs-ovpn-inbound entrypoint.sh client-conf alice > alice.ovpn
```

Each profile embeds the CA certificate and its **own** `tls-crypt-v2`
client key — minted for that one user and useless to anyone else — and it
carries **no password** — OpenVPN Connect prompts on connect. That is
deliberate: the passwords live only in the server's `.env`, so a profile is
safe to hand to a phone while credentials are not.

Transfer `alice.ovpn` to the device and import it. `VPN_SERVER_ADDR` must be
exactly the host in the profile's `remote` line — it becomes the server
certificate's CN and SAN, and clients verify it (`remote-cert-tls server`).

## Env

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `OVPN_USERS` | yes | — | `user:pass` pairs, comma-separated, split on the **first** colon |
| `VPN_SERVER_ADDR` | yes | — | public IP or hostname clients dial; becomes the cert CN and SAN |
| `OVPN_POOL` | no | `10.10.40.0/24` | client address pool |
| `CLIENT_DNS` | no | `1.1.1.1` | pushed via `dhcp-option DNS` |
| `CHAIN_SOCKS_HOST` | no | `vpndogs-router` | sing-box socks target |
| `CHAIN_SOCKS_PORT` | no | `1070` | sing-box socks port |

Passwords may contain colons (the split is on the first colon). They may
**not** contain a comma or a newline — the format cannot express either, and
the entrypoint rejects them rather than silently truncating.

## Performance

**Performance, stated plainly.** OpenVPN over TCP is genuinely slower than
the WireGuard and AmneziaWG nodes. Inner TCP and UDP both travel inside one
reliable TCP stream, so a single loss makes both the outer and inner TCP
layers retransmit and back off — a stall the client experiences as a
multi-second freeze. Nothing in the OpenVPN configuration disables this; it
is the cost of the property that makes this node worth having.

What the configuration *does* do: `tun-mtu 1500` on both interfaces (the
`tun0 → tun1` hop is a local kernel forward, nothing is encapsulated),
`tcp-nodelay`, AEAD ciphers only, and no `mssfix`/`fragment`/`compress`
(UDP-transport-only directives or removed in 2.6). Socket buffers are left
at the kernel default.

## Troubleshooting

**Host firewall on 1064/tcp.** The node listens and publishes TCP only. If a
client on a UDP-blocked network cannot connect at all, check the firewall
before anything else — nothing about OpenVPN is UDP-specific.

**Container shows healthy but no clients can connect.** The healthcheck is a
TCP connect: it passes as soon as openvpn holds the socket, even if the process
is stuck and not completing handshakes. `docker compose exec vpndogs-ovpn-inbound
report.sh` shows the real state — process liveness, interface status, and the
`ROUTING TABLE` of connected clients.

**Handshake fails with a certificate error after the volume was recreated.**
Losing `ovpn-state` mints a new CA, server certificate and `tls-crypt-v2`
server key, and every previously issued profile is dead — each profile's client
key unwraps only under the server key it was issued against. Re-issue them with
`client-conf`. This is the one failure mode that breaks all clients at once —
see below.

**`FATAL: OVPN_USERS is required`.** The profile is enabled but credentials
are missing or empty. The container restart-loops; the rest of the stack is
unaffected.

**The client still leaks IPv6.** This node sets `block-ipv6` and pushes both
`block-ipv6` and `redirect-gateway def1 bypass-dhcp ipv6`, so a client's IPv6 is
rejected with ICMPv6 `no route to host` instead of escaping beside the tunnel.
If a hand-edited profile has `route-nopull` or `pull-filter ignore "block-ipv6"`,
remove that override.

**Everything black-holes after changing `OVPN_POOL`.** A pool overlapping the
container's own subnet routes decrypted traffic back inside the netns. The
entrypoint refuses to boot on that overlap rather than serving a silent black
hole, but a pool that overlaps *your LAN* still needs care.

## Volume loss

`ovpn-state` holds the CA certificate, the server certificate and key, the
`tls-crypt-v2` **server** key, and `ipp.txt` (pool assignments, so client
addresses survive a restart).

Deleting it is supported and idempotent — the node regenerates everything on
the next boot — but it is destructive to clients:

```sh
docker volume rm vpndogs_ovpn-state
```

After that, **every existing `.ovpn` stops working** and must be re-issued.

## E2E checklist

1. `docker compose exec vpndogs-ovpn-inbound report.sh` — openvpn and
   sing-box both UP, `tun0`/`tun1` UP, table 200 holds
   `default dev tun1`.
2. Issue a profile and connect a real client.
3. `report.sh` again — the `== OpenVPN ==` `ROUTING TABLE` shows the client's
   address with rising byte counters.
4. From the client, `curl https://api64.ipify.org` — the answer must be the
   chain's egress IP, not the host's own. If it is the host's, the tunnel is
   up but the policy route is not.
