#!/usr/bin/env bash
# test-render.sh — openvpn-server suite.
#   ./scripts/test-render.sh --local   render/validation cases only, no daemon
#   ./scripts/test-render.sh           everything, against $IMG
set -uo pipefail

IMG="${IMAGE:-openvpn-server:latest}"
MODE=docker
[ "${1:-}" = "--local" ] && MODE=local

HERE="$(cd "$(dirname "$0")" && pwd)"
ENTRY="$HERE/entrypoint.sh"
fail=0
LAST_OUT=""

PASS1='alice:s3cret'
PASS2='bob:hunter2'

# One baseline for every case; docker-mode -e flags are appended after it, and
# env applies left to right, so a case's own overrides win.
STATE_DIR_OVERRIDE="/etc/openvpn/state"
FIX_ENV=(OVPN_USERS="alice:$PASS1,bob:$PASS2" VPN_SERVER_ADDR=vpn.example.com)
FIX_DE=()
for kv in "${FIX_ENV[@]}"; do FIX_DE+=(-e "$kv"); done

# run_env KEY=VAL... cmd args... — run the entrypoint subcommand with env
# (FIX_ENV + KEY=VAL args), local or in a --network none container per MODE
run_env() {
    local host_env=("${FIX_ENV[@]}") docker_env=("${FIX_DE[@]}") kv args=()
    for kv in "$@"; do
        if [[ "$kv" == *=* ]]; then
            host_env+=("$kv")
            docker_env+=(-e "$kv")
        else
            args+=("$kv")
        fi
    done
    if [ "$MODE" = local ]; then
        env "${host_env[@]}" bash "$ENTRY" "${args[@]}" 2>&1
    else
        docker run --rm --network none "${docker_env[@]}" \
            --entrypoint /usr/local/bin/entrypoint.sh "$IMG" "${args[@]}" 2>&1
    fi
}

image_run() { docker run --rm "${FIX_DE[@]}" "$@"; }

block() { printf '%s\n' "$2" | awk -v b="# === $1 ===" '$0==b{f=1;next} /^# === /{f=0} f'; }

assert() { # name jq-filter json
    local name="$1" filter="$2" json="$3" res
    if res="$(printf '%s' "$json" | jq -e "$filter" 2>&1)"; then
        echo "$name: PASS"
    else
        echo "$name: FAIL"
        printf '%s\n' "$res" >&2
        fail=1
    fi
}

eq() { local name="$1" got="$2" want="$3"; [ "$got" = "$want" ] && echo "$name: PASS" || { echo "$name: FAIL"; printf 'want:\n%s\n\ngot:\n%s\n' "$want" "$got" >&2; fail=1; }; }
# `--` is load-bearing: a pattern like "-- BEGIN CERTIFICATE --" is otherwise
# swallowed by grep's option parsing and can never match.
has() { local name="$1" text="$2" pat="$3"; printf '%s\n' "$text" | grep -qF -- "$pat" && echo "$name: PASS" || { echo "$name: FAIL"; printf 'expected %q in:\n%s\n' "$pat" "$text" >&2; fail=1; }; }
lacks() { local name="$1" text="$2" pat="$3"; printf '%s\n' "$text" | grep -qF -- "$pat" && { echo "$name: FAIL"; printf 'found %q in:\n%s\n' "$pat" "$text" >&2; fail=1; } || echo "$name: PASS"; }

# run_is name want cmd... — run the command as real argv, compare exit code
run_is() {
    local name="$1" want="$2" rc=0
    shift 2
    set +e; "$@" >/tmp/ovpn-out.$$ 2>&1; rc=$?
    LAST_OUT="$(cat /tmp/ovpn-out.$$)"; rm -f /tmp/ovpn-out.$$ || true
    if [ "$rc" = "$want" ]; then
        echo "$name: PASS (exit $rc)"
    else
        echo "$name: FAIL (exit $rc, want $want)"
        printf '%s\n' "$LAST_OUT" >&2
        fail=1
    fi
}

case_cidr() {
    echo "=== CIDR CASES ==="
    run_is "overlap same /24"      0 run_env selftest-cidr 10.10.40.0/24 10.10.40.5/32
    run_is "overlap /24 vs /16"    0 run_env selftest-cidr 10.10.40.0/24 10.10.0.0/16
    run_is "no overlap"            1 run_env selftest-cidr 10.10.40.0/24 192.168.1.0/24
    run_is "adjacent no overlap"   1 run_env selftest-cidr 10.10.40.0/24 10.10.41.0/24
}

case_validate() {
    echo "=== VALIDATION CASES ==="
    run_is "missing OVPN_USERS" 2 run_env "OVPN_USERS="
    has "missing message names the var" "$LAST_OUT" "OVPN_USERS"
    run_is "entry without colon" 2 run_env "OVPN_USERS=alice"
    run_is "empty username" 2 run_env "OVPN_USERS=:$PASS1"
    run_is "empty password" 2 run_env "OVPN_USERS=alice:"
    run_is "bad username charset" 2 run_env "OVPN_USERS=al ice:$PASS1"
    run_is "duplicate username" 2 run_env "OVPN_USERS=alice:$PASS1,alice:$PASS2"
    has "duplicate message names it" "$LAST_OUT" "alice"
    run_is "comma in password" 2 run_env "OVPN_USERS=alice:a,b"
    run_is "newline in password" 2 run_env "$(printf 'OVPN_USERS=alice:a\nb')"
    # the positive half of Review Focus 1: colons in a password are legal and
    # must survive parsing, not just be rejected when they look wrong.
    # `render`, not a bare boot: the exit-0 contract here is validation, and a
    # bare invocation now goes on to generate state and start daemons.
    run_is "password with colons" 0 run_env "OVPN_USERS=alice:a:b:c" render
    run_is "missing VPN_SERVER_ADDR" 2 run_env "OVPN_USERS=alice:$PASS1" "VPN_SERVER_ADDR="
    run_is "bad OVPN_POOL" 2 run_env "OVPN_USERS=alice:$PASS1" "OVPN_POOL=notacidr"
    run_is "bad OVPN_POOL prefix" 2 run_env "OVPN_USERS=alice:$PASS1" "OVPN_POOL=10.0.0.0/33"
    # /31 and /32 leave no address a client could be handed
    run_is "bad OVPN_POOL prefix high" 2 run_env "OVPN_USERS=alice:$PASS1" "OVPN_POOL=10.0.0.0/31"
    run_is "bad CLIENT_DNS" 2 run_env "OVPN_USERS=alice:$PASS1" "CLIENT_DNS=999.1.1.1"
    run_is "bad CHAIN_SOCKS_PORT" 2 run_env "OVPN_USERS=alice:$PASS1" "CHAIN_SOCKS_PORT=abc"
    run_is "valid config validates" 0 run_env "OVPN_USERS=alice:$PASS1" "OVPN_POOL=10.99.0.0/24" render
    # container logs get pasted into issue trackers; a fatal that echoes a
    # password leaks it. The bad-charset entry carries a distinct password so a
    # match on PASS1 cannot hide a leak.
    run_is "fatal on bad name keeps password" 2 run_env "OVPN_USERS=alice:$PASS1,al ice:hunter3"
    lacks "no password in fatal message" "$LAST_OUT" "hunter3"
}

case_render() {
    echo "=== RENDER CASES ==="
    local out conf sb users
    out="$(run_env render)" || { echo "render: FAIL (rc $?)" >&2; fail=1; return; }
    conf="$(block "server.conf" "$out")"
    sb="$(block "sing-box.json" "$out")"
    users="$(block "users" "$out")"

    has "proto tcp-server"   "$conf" "proto tcp-server"
    has "port 1064"          "$conf" "port 1064"
    has "topology subnet"    "$conf" "topology subnet"
    has "server pool"        "$conf" "server 10.10.40.0 255.255.255.0"
    has "pool persist"       "$conf" "ifconfig-pool-persist /etc/openvpn/state/ipp.txt"
    has "tun-mtu 1500"       "$conf" "tun-mtu 1500"
    has "dh none"            "$conf" "dh none"
    has "tls-crypt-v2 verify" "$conf" "tls-crypt-v2 verify /etc/openvpn/state/tls-crypt-v2.key"
    has "no client certs"    "$conf" "verify-client-cert none"
    has "auth SHA256"        "$conf" "auth SHA256"
    has "auth script"        "$conf" "auth-user-pass-verify /usr/local/bin/auth.sh file"
    has "AEAD ciphers"       "$conf" "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
    has "client-to-client"   "$conf" "client-to-client"
    has "tcp-nodelay"        "$conf" "tcp-nodelay"
    has "persist-key"        "$conf" "persist-key"
    has "persist-tun"        "$conf" "persist-tun"
    has "keepalive"          "$conf" "keepalive 10 60"
    has "explicit-exit"      "$conf" "explicit-exit-notify 1"
    has "drop privs user"    "$conf" "user nobody"
    has "drop privs group"   "$conf" "group nobody"
    has "redirect ipv4+ipv6" "$conf" 'push "redirect-gateway def1 bypass-dhcp ipv6"'
    has "pushed DNS"         "$conf" 'push "dhcp-option DNS 1.1.1.1"'
    has "status file"        "$conf" "status /etc/openvpn/status.log 30"
    has "status version 1"   "$conf" "status-version 1"

    lacks "NO ca directive"          "$conf" "ca "
    lacks "NO compress"               "$conf" "compress"
    lacks "NO mssfix"                 "$conf" "mssfix"
    lacks "NO fragment"               "$conf" "fragment"
    lacks "NO data-ciphers-fallback"  "$conf" "data-ciphers-fallback"
    lacks "NO bare cipher"            "$conf" "cipher "

    has "users alice"  "$users" "alice:$PASS1"
    has "users bob"    "$users" "bob:$PASS2"
    eq  "users in input order" "$users" "alice:$PASS1
bob:$PASS2"

    assert "sb interface_name tun1" '.inbounds[] | select(.type=="tun") | .interface_name == "tun1"' "$sb"
    assert "sb mtu 1500"             '.inbounds[] | select(.type=="tun") | .mtu == 1500' "$sb"
    assert "sb auto_route false"     '.inbounds[] | select(.type=="tun") | .auto_route == false' "$sb"
    assert "sb route final socks"    '.route.final == "chain-out"' "$sb"
    assert "sb socks target"         '.outbounds[] | select(.tag=="chain-out") | .server == "vpndogs-router"' "$sb"
    assert "sb socks port"           '.outbounds[] | select(.tag=="chain-out") | .server_port == 1070' "$sb"
    lacks "sb has no inert direct"  "$sb" "direct-out"

    # the teeth for Task 1's colon-password case: exit code alone could not
    # detect a password silently truncated at the second colon
    local colon; colon="$(run_env "OVPN_USERS=alice:a:b:c" render)"
    has "colon password survives to users file" "$(block "users" "$colon")" "alice:a:b:c"

    # overrides must land in both configs; run_env takes env assignments BEFORE
    # the subcommand, and later assignments win over FIX_ENV
    local ovr; ovr="$(run_env "OVPN_POOL=10.99.0.0/24" "CHAIN_SOCKS_HOST=router2" \
                          "CHAIN_SOCKS_PORT=2080" "CLIENT_DNS=9.9.9.9" render)"
    has "override pool"      "$(block "server.conf" "$ovr")" "server 10.99.0.0 255.255.255.0"
    has "override dns"       "$(block "server.conf" "$ovr")" 'push "dhcp-option DNS 9.9.9.9"'
    has "override persists new pool file path" "$(block "server.conf" "$ovr")" "ifconfig-pool-persist $STATE_DIR_OVERRIDE/ipp.txt"
    assert "override socks host" '.outbounds[] | select(.tag=="chain-out") | .server == "router2"' "$(block "sing-box.json" "$ovr")"
    assert "override socks port" '.outbounds[] | select(.tag=="chain-out") | .server_port == 2080' "$(block "sing-box.json" "$ovr")"
}

case_client() {
    echo "=== CLIENT-CONF CASES ==="
    local ovpn
    ovpn="$(run_env client-conf alice)" || { echo "client-conf: FAIL (rc $?)" >&2; fail=1; return; }
    has "remote host and port" "$ovpn" "remote vpn.example.com 1064"
    has "tcp-client"            "$ovpn" "proto tcp-client"
    has "remote-cert-tls"       "$ovpn" "remote-cert-tls server"
    has "route-ipv6"            "$ovpn" "route-ipv6"
    has "auth-user-pass"        "$ovpn" "auth-user-pass"
    has "auth-nocache"          "$ovpn" "auth-nocache"
    has "inline ca"             "$ovpn" "<ca>"
    has "inline tls-crypt-v2"   "$ovpn" "<tls-crypt-v2>"
    lacks "no password leaked"  "$ovpn" "$PASS1"
    lacks "no client cert"      "$ovpn" "<cert>"
    lacks "no client key"       "$ovpn" "<key>"
    run_is "unknown user exits 2" 2 run_env client-conf nobody
    has "unknown user named"     "$LAST_OUT" "nobody"
}

AUTH="$HERE/auth.sh"

# auth.sh runs on the host too: it is four lines of sh and grep, and shipping a
# password comparison nobody ever executed would be the worst trade in this repo.
case_auth() {
    echo "=== AUTH CASES ==="
    local dir cred; dir="$(mktemp -d)"; cred="$dir/cred"
    printf 'alice:s3cret\nbob:hunter2\ndave:p.*ss\neve:a:b:c\n' > "$dir/users"
    local pair user pass want
    while IFS=' ' read -r user pass want; do
        printf '%s\n%s\n' "$user" "$pass" > "$cred"
        run_is "auth $user / $pass" "$want" env USERS_FILE="$dir/users" sh "$AUTH" "$cred"
    done <<'PAIRS'
alice s3cret 0
alice wrongpw 1
bob hunter2 0
carol whatever 1
dave p.*ss 0
eve a:b:c 0
PAIRS
    printf 'alice\n\n' > "$cred"
    run_is "empty password rejects" 1 env USERS_FILE="$dir/users" sh "$AUTH" "$cred"
    # openvpn writes the credential file without a trailing newline; both
    # shapes have to authenticate
    printf 'alice\ns3cret' > "$cred"
    run_is "no trailing newline accepts" 0 env USERS_FILE="$dir/users" sh "$AUTH" "$cred"
    # Review Focus 2: a newline inside the credential file must fail closed, not
    # partially match. `tr '\n' ':'` joins every line, so the lookup cannot hit.
    printf 'alice\na\nb\n' > "$cred"
    run_is "newline credential rejects" 1 env USERS_FILE="$dir/users" sh "$AUTH" "$cred"
    run_is "no argument rejects" 1 env USERS_FILE="$dir/users" sh "$AUTH"
    run_is "unreadable file rejects" 1 env USERS_FILE="$dir/users" sh "$AUTH" /nonexistent
    rm -rf "$dir"
}

# render_client_conf must inline whatever is really in STATE_DIR, not a marker.
case_client_ca() {
    echo "=== CLIENT-CONF REAL PKI CASES ==="
    local dir; dir="$(mktemp -d)"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
        -keyout "$dir/server-key.pem" -out "$dir/ca-cert.pem" \
        -subj "/CN=test" >/dev/null 2>&1
    printf -- '-----BEGIN OpenVPN Static key V1-----\ndeadbeef\n-----END OpenVPN Static key V1-----\n' \
        > "$dir/tls-crypt-v2.key"
    local ovpn; ovpn="$(run_env "STATE_DIR=$dir" client-conf alice)"
    has "real CA inlined"        "$ovpn" "-----BEGIN CERTIFICATE-----"
    has "real CA body present"   "$ovpn" "$(awk 'NR==2' "$dir/ca-cert.pem")"
    has "real tls-crypt inlined" "$ovpn" "deadbeef"
    rm -rf "$dir"
}

main_cases() { case_cidr; case_validate; case_render; case_client; case_auth; case_client_ca; }

state_case() {
    echo "=== PKI STATE CASES ==="
    local vol="ovpn-state-test-$$"
    docker volume rm -f "$vol" >/dev/null 2>&1 || true
    trap 'docker volume rm -f "$vol" >/dev/null 2>&1 || true' EXIT
    run_is "keys-only first boot" 0 \
        image_run -v "$vol":/etc/openvpn/state -e BOOT_STAGE=keys-only \
            --entrypoint /usr/local/bin/entrypoint.sh "$IMG"
    has "state generated" "$LAST_OUT" "state generated"

    local listing; listing="$(docker run --rm -v "$vol":/etc/openvpn/state \
        --entrypoint /bin/sh "$IMG" -c 'ls /etc/openvpn/state')"
    has "ca-cert.pem present"     "$listing" "ca-cert.pem"
    has "server-cert.pem present" "$listing" "server-cert.pem"
    has "server-key.pem present"  "$listing" "server-key.pem"
    has "tls-crypt-v2.key present" "$listing" "tls-crypt-v2.key"
    lacks "CA KEY IS GONE" "$listing" "ca-key.pem"

    # serverAuth EKU and the SAN are load-bearing, not decoration: without the
    # EKU every handshake is refused, and without the SAN remote-cert-tls fails.
    local cert; cert="$(docker run --rm -v "$vol":/etc/openvpn/state \
        --entrypoint /bin/sh "$IMG" \
        -c 'openssl x509 -in /etc/openvpn/state/server-cert.pem -noout -text')"
    has "server cert has serverAuth EKU" "$cert" "TLS Web Server Authentication"
    has "server cert SAN is the VPN address" "$cert" "DNS:vpn.example.com"

    local fp1 fp2
    fp1="$(docker run --rm -v "$vol":/etc/openvpn/state --entrypoint /bin/sh "$IMG" \
        -c 'cat /etc/openvpn/state/server-cert.pem')"
    run_is "keys-only second boot" 0 \
        image_run -v "$vol":/etc/openvpn/state -e BOOT_STAGE=keys-only "$IMG"
    has "reuse logged" "$LAST_OUT" "reusing existing state"
    fp2="$(docker run --rm -v "$vol":/etc/openvpn/state --entrypoint /bin/sh "$IMG" \
        -c 'cat /etc/openvpn/state/server-cert.pem')"
    eq "certificate identical across boots" "$fp1" "$fp2"

    docker volume rm -f "$vol" >/dev/null 2>&1 || true
}

boot_case() {
    echo "=== BOOT CASES ==="
    local vol="ovpn-boot-test-$$"
    docker volume rm -f "$vol" >/dev/null 2>&1 || true
    trap 'docker volume rm -f "$vol" >/dev/null 2>&1 || true' EXIT
    run_is "live boot" 0 \
        docker run --rm --cap-add NET_ADMIN --device /dev/net/tun \
            -v "$vol":/etc/openvpn/state -e BOOT_STAGE=up-only \
            "${FIX_DE[@]}" \
            --entrypoint /bin/sh "$IMG" -c \
            '/usr/local/bin/entrypoint.sh 2>&1 &&
             ip link show tun0 && ip link show tun1 &&
             pgrep -x openvpn && pgrep -x sing-box &&
             ip rule && ip route show table 200'
    has "tun0 up"      "$LAST_OUT" "tun0"
    has "tun1 up"      "$LAST_OUT" "tun1"
    has "openvpn running"  "$LAST_OUT" "openvpn"
    has "sing-box running" "$LAST_OUT" "sing-box"
    has "policy rule"  "$LAST_OUT" "from 10.10.40.0/24 lookup 200"
    has "default into chain tun" "$LAST_OUT" "default dev tun1"

    # Review Focus 4: decrypted traffic looping back into the netns is a silent
    # black hole, so an overlapping pool must stop the boot.
    run_is "pool overlap fatal" 2 \
        docker run --rm --cap-add NET_ADMIN -e BOOT_STAGE=up-only \
            -e OVPN_POOL=172.17.0.0/16 "${FIX_DE[@]}" "$IMG"
    has "overlap message" "$LAST_OUT" "overlaps"

    docker volume rm -f "$vol" >/dev/null 2>&1 || true
}

boot_cases() { state_case; boot_case; }

[ "$MODE" = local ] && {
    echo "=== LOCAL RENDER TESTS ==="
    main_cases
    exit "$fail"
}

echo "=== DOCKER MODE TESTS ==="
main_cases
boot_cases
exit "$fail"