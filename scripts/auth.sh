#!/bin/sh
# auth-user-pass-verify (via-file): openvpn passes $1, a temp file holding the
# username on line 1 and the password on line 2. Exit 0 accepts, non-zero rejects.
#
# Command substitution first, `tr` second: dropping the trailing newline before
# joining lines keeps the trailing colon out of the lookup, so a credential file
# that ends in a newline (and one that does not) both match.
#
# ponytail: grep -qxF is not a constant-time comparison and reads the whole file.
# Replace with a hashed-password verifier if the threat model ever includes a
# network attacker timing auth.
set -u
USERS_FILE="${USERS_FILE:-/etc/openvpn/users}"
[ $# -eq 1 ] && [ -r "$1" ] || exit 1
cred="$(cat "$1")"
grep -qxF -- "$(printf '%s' "$cred" | tr '\n' ':')" "$USERS_FILE" || exit 1
