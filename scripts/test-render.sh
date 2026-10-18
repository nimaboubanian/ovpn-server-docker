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
has() { local name="$1" text="$2" pat="$3"; printf '%s\n' "$text" | grep -qF "$pat" && echo "$name: PASS" || { echo "$name: FAIL"; printf 'expected %q in:\n%s\n' "$pat" "$text" >&2; fail=1; }; }
lacks() { local name="$1" text="$2" pat="$3"; printf '%s\n' "$text" | grep -qF "$pat" && { echo "$name: FAIL"; printf 'found %q in:\n%s\n' "$pat" "$text" >&2; fail=1; } || echo "$name: PASS"; }

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
    # must survive parsing, not just be rejected when they look wrong
    run_is "password with colons" 0 run_env "OVPN_USERS=alice:a:b:c"
    run_is "missing VPN_SERVER_ADDR" 2 run_env "OVPN_USERS=alice:$PASS1" "VPN_SERVER_ADDR="
    run_is "bad OVPN_POOL" 2 run_env "OVPN_USERS=alice:$PASS1" "OVPN_POOL=notacidr"
    run_is "bad OVPN_POOL prefix" 2 run_env "OVPN_USERS=alice:$PASS1" "OVPN_POOL=10.0.0.0/33"
    run_is "bad CLIENT_DNS" 2 run_env "OVPN_USERS=alice:$PASS1" "CLIENT_DNS=999.1.1.1"
    run_is "bad CHAIN_SOCKS_PORT" 2 run_env "OVPN_USERS=alice:$PASS1" "CHAIN_SOCKS_PORT=abc"
    run_is "valid config boots" 0 run_env "OVPN_USERS=alice:$PASS1" "OVPN_POOL=10.99.0.0/24"
    # container logs get pasted into issue trackers; a fatal that echoes a
    # password leaks it. The bad-charset entry carries a distinct password so a
    # match on PASS1 cannot hide a leak.
    run_is "fatal on bad name keeps password" 2 run_env "OVPN_USERS=alice:$PASS1,al ice:hunter3"
    lacks "no password in fatal message" "$LAST_OUT" "hunter3"
}

main_cases() { case_cidr; case_validate; }

[ "$MODE" = local ] && {
    echo "=== LOCAL RENDER TESTS ==="
    main_cases
    exit "$fail"
}

echo "=== DOCKER MODE TESTS ==="
main_cases
exit "$fail"