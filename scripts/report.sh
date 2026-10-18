#!/bin/sh
# report.sh — quick diagnostics. Invoked via `docker exec <container> report.sh`.
set -u

# Same overrides as the entrypoint, defaults unchanged: lets the suite exercise
# the redaction paths without a container.
STATE_DIR="${STATE_DIR:-/etc/openvpn/state}"
OVPN_DIR="${OVPN_DIR:-/etc/openvpn}"

echo "== Processes =="
for p in openvpn sing-box; do
    pid=$(pgrep -x "$p" 2>/dev/null | head -1)
    if [ -n "$pid" ]; then echo "  $p UP   pid=$pid"; else echo "  $p NOT RUNNING"; fi
done
for t in tun0 tun1; do
    ip link show "$t" >/dev/null 2>&1 && echo "  $t interface UP" || echo "  $t interface DOWN"
done

echo
echo "== Interfaces and routing =="
ip -4 -o addr show 2>/dev/null | sed 's/^/  /'
ip rule show 2>/dev/null | sed 's/^/  /'
# `cmd | sed || fallback` never runs the fallback: the pipeline's status is sed's.
if ! ip route show table 200 2>/dev/null | grep -q .; then
    echo "  (table 200 empty — policy route not installed)"
else
    ip route show table 200 2>/dev/null | sed 's/^/  /'
fi

echo
echo "== OpenVPN =="
# status-version 1: the ROUTING TABLE carries each connected client's address
# and byte counters, which is what "is anyone connected" means here.
if [ -f $OVPN_DIR/status.log ]; then
    cat $OVPN_DIR/status.log 2>/dev/null | sed 's/^/  /'
else
    echo "  (status.log not written yet — no client has completed a handshake)"
fi

echo
echo "== CA certificate (public — clients verify against it) =="
if [ -f $STATE_DIR/ca-cert.pem ]; then
    cat $STATE_DIR/ca-cert.pem 2>/dev/null | sed 's/^/  /'
else
    echo "  (ca-cert.pem missing — state not generated yet)"
fi
echo "  Issue a client profile with:"
echo "  docker exec vpndogs-ovpn-inbound entrypoint.sh client-conf <user> > <user>.ovpn"
echo "  Profiles carry no password: the client prompts on connect."

echo
echo "== State volume =="
# The question after a suspected volume loss is "is this the same CA my client's
# profile embeds?". The fingerprint answers it; the modes answer "is the private
# key world-readable".
if [ -d "$STATE_DIR" ]; then
    ls -l "$STATE_DIR" 2>/dev/null | sed 's/^/  /'
    if [ -s "$STATE_DIR/server-cert.pem" ]; then
        openssl x509 -in "$STATE_DIR/server-cert.pem" -noout -subject -dates -fingerprint -sha256 2>/dev/null \
            | sed 's/^/  /'
    fi
    if [ -s "$STATE_DIR/ca-cert.pem" ]; then
        openssl x509 -in "$STATE_DIR/ca-cert.pem" -noout -subject -fingerprint -sha256 2>/dev/null \
            | sed 's/^/  CA: /'
    fi
else
    echo "  ($STATE_DIR missing — state not generated yet)"
fi

echo
echo "== Egress (via the chain) =="
echo "  tun1 sends to socks ${CHAIN_SOCKS_HOST:-vpndogs-router}:${CHAIN_SOCKS_PORT:-1070}"

echo
echo "== Config (secrets redacted) =="
# This output is what users paste into issue trackers. Three things must never
# appear in it: the server private key, the tls-crypt-v2 key (it is embedded in
# every client profile), and any OVPN_USERS password.
env | grep -E '^(OVPN_|VPN_SERVER|CLIENT_|CHAIN_)' | sort \
    | sed 's/^\(OVPN_USERS=\).*/\1<redacted>/' | sed 's/^/  /'
if [ -f $OVPN_DIR/server.conf ]; then
    # server.conf holds paths, not secrets — but the two lines naming secret
    # files are dropped anyway, so this stays safe if that ever changes.
    sed -e 's|^key .*|key <redacted>|' \
        -e 's|^tls-crypt-v2 .*|tls-crypt-v2 <redacted>|' \
        $OVPN_DIR/server.conf | sed 's/^/  /'
fi
echo "  passwords: read from the server env only —"
echo "  docker exec vpndogs-ovpn-inbound sh -c 'printenv OVPN_USERS'"
