#!/usr/bin/env bash
# entrypoint.sh — OpenVPN TCP inbound server for the vpndogs stack.
#
#   entrypoint.sh                       boot: validate -> PKI -> configs -> daemons
#   entrypoint.sh render                print every rendered config (test path)
#   entrypoint.sh client-conf USER      print a ready-to-use client .ovpn
#   entrypoint.sh selftest-cidr A B     exit 0 if CIDR A and CIDR B overlap
set -euo pipefail
umask 077

OVPN_POOL="${OVPN_POOL:-10.10.40.0/24}"
CLIENT_DNS="${CLIENT_DNS:-1.1.1.1}"
CHAIN_SOCKS_HOST="${CHAIN_SOCKS_HOST:-vpndogs-router}"
CHAIN_SOCKS_PORT="${CHAIN_SOCKS_PORT:-1070}"
LISTEN_PORT=1064

# STATE_DIR/OVPN_DIR keep their spec defaults but accept an override so the test
# harness can exercise PKI and auth paths without root. Compose never sets them.
STATE_DIR="${STATE_DIR:-/etc/openvpn/state}"
OVPN_DIR="${OVPN_DIR:-/etc/openvpn}"
USERS_FILE="${USERS_FILE:-$OVPN_DIR/users}"
ROUTER_TABLE=200
TUN_VPN="tun0"     # owned by openvpn
TUN_CHAIN="tun1"   # owned by sing-box

declare -a USERS=()

log() { echo "[entrypoint] $*" >&2; }
fatal() { echo "FATAL: $*" >&2; exit 2; }

# --- env parsing -------------------------------------------------------------

is_ipv4_cidr() {
    local q='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
    [[ "$1" =~ ^$q\.$q\.$q\.$q/(3[0-2]|[12][0-9]|[0-9])$ ]]
}

is_ipv4_addr() {
    local q='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
    [[ "$1" =~ ^$q\.$q\.$q\.$q$ ]]
}

# OVPN_USERS entries are name:password. Container logs get pasted into issue
# trackers, so a fatal names the *name* and never the password: no message here
# echoes an entry that contained a colon.
parse_users() {
    local -a entries=()
    local entry name pass seen_names=" "
    IFS=',' read -r -a entries <<<"${OVPN_USERS:-}"
    for entry in "${entries[@]}"; do
        [[ "$entry" == *:* ]] || fatal "OVPN_USERS entry without ':' — expected name:password, got '$entry' (passwords may contain ':' but not ',')"
        name="${entry%%:*}"
        pass="${entry#*:}"   # first colon only: passwords may contain colons
        [[ -n "$name" ]] || fatal "OVPN_USERS has an entry with an empty name (expected name:password)"
        [[ "$name" =~ ^[A-Za-z0-9_@+-]+$ ]] || fatal "unsupported character in OVPN_USERS name '$name': names may use letters, digits and _ @ + - only"
        [[ -n "$pass" ]] || fatal "OVPN_USERS entry '$name' has an empty password"
        [[ "$seen_names" != *" $name "* ]] || fatal "duplicate OVPN_USERS entry '$name' — one of the two could never log in"
        seen_names="$seen_names$name "
        USERS+=("$name"$'\t'"$pass")
    done
}

validate_env() {
    [[ -n "${OVPN_USERS:-}" ]] || fatal "OVPN_USERS is required (name:password,name2:password2)"
    # Checked on the raw value, not per entry: `read` stops at the first
    # newline, so a newline inside a password would be silently truncated to
    # everything before it and the account would quietly get a different
    # password than the operator intended.
    [[ "${OVPN_USERS}" != *$'\n'* ]] || fatal "OVPN_USERS contains a newline — a password may contain ':' but not a newline"
    [[ -n "${VPN_SERVER_ADDR:-}" ]] || fatal "VPN_SERVER_ADDR is required — the public address clients dial; it becomes the certificate CN and SAN"
    [[ "$CHAIN_SOCKS_PORT" =~ ^[0-9]+$ ]] || fatal "CHAIN_SOCKS_PORT must be a port number, got '$CHAIN_SOCKS_PORT'"
    is_ipv4_cidr "$OVPN_POOL" || fatal "OVPN_POOL is not a valid CIDR, got '$OVPN_POOL'"
    is_ipv4_addr "$CLIENT_DNS" || fatal "CLIENT_DNS is not a valid IPv4 address, got '$CLIENT_DNS'"
    parse_users
}

ip_to_int() {
    local a b c d
    IFS=. read -r a b c d <<<"$1"
    printf '%d\n' "$(( (a << 24) | (b << 16) | (c << 8) | d ))"
}

int_to_ip() {
    local n="$1"
    printf '%d.%d.%d.%d\n' \
        $(( (n >> 24) & 0xFF )) \
        $(( (n >> 16) & 0xFF )) \
        $(( (n >> 8) & 0xFF )) \
        $(( n & 0xFF ))
}

cidr_overlap() { # exit 0 when the two CIDRs share any address
    local a="$1" b="$2" ai bi ma mb diff
    ai="$(ip_to_int "${a%%/*}")"
    bi="$(ip_to_int "${b%%/*}")"
    ma=$(( 0xFFFFFFFF << (32 - ${a##*/}) & 0xFFFFFFFF ))
    mb=$(( 0xFFFFFFFF << (32 - ${b##*/}) & 0xFFFFFFFF ))
    diff=$(( (ai ^ bi) & 0xFFFFFFFF ))
    (( (diff & ma) == 0 || (diff & mb) == 0 ))
}

# Only the branches a task has implemented get a case. An absent branch falls
# through and exits 0, which is what the RED run before validate_env needs.
case "${1:-}" in
    selftest-cidr) shift; cidr_overlap "$@" ;;
    *)             validate_env; log "environment OK (${#USERS[@]} user(s))" ;;
esac