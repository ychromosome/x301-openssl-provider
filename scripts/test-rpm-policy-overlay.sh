#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
TEMPLATE=$ROOT/packaging/rpm/opensslcnf-zz-x301.config
ACTIVE=/etc/crypto-policies/local.d/opensslcnf-zz-x301.config
BACKEND=/etc/crypto-policies/back-ends/opensslcnf.config

test -e /run/.containerenv || test -e /.dockerenv || {
    echo 'this test may run only inside a disposable container' >&2
    exit 2
}
command -v update-crypto-policies >/dev/null
test -f "$TEMPLATE"

cleanup() {
    rm -f "$ACTIVE"
    update-crypto-policies --set DEFAULT >/dev/null 2>&1 || :
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$(dirname -- "$ACTIVE")"
rm -f "$ACTIVE"
update-crypto-policies --set DEFAULT >/dev/null
baseline=$(sha256sum "$BACKEND" | awk '{ print $1 }')

# Installing the policy package activates its overlay.
install -pm 0644 "$TEMPLATE" "$ACTIVE"
update-crypto-policies >/dev/null
grep -F 'X301MLKEM1024' "$BACKEND" >/dev/null
if grep -F '?X301/' "$BACKEND" >/dev/null; then
    echo 'policy overlay lists raw X301 as a TLS group' >&2
    exit 1
fi

# Replacing the package payload preserves the active policy.
install -pm 0644 "$TEMPLATE" "$ACTIVE"
update-crypto-policies >/dev/null
grep -F 'X301MLKEM1024' "$BACKEND" >/dev/null

# Removing the policy package removes its effect.
rm -f "$ACTIVE"
update-crypto-policies >/dev/null
test "$(sha256sum "$BACKEND" | awk '{ print $1 }')" = "$baseline"

# Restrictive policies are tested only after the X301 policy is absent.
for policy in EMPTY FIPS; do
    if test -f "/usr/share/crypto-policies/policies/$policy.pol"; then
        update-crypto-policies --set "$policy" >/dev/null
        if grep -F X301 "$BACKEND" >/dev/null; then
            echo "removed overlay changed restrictive policy $policy" >&2
            exit 1
        fi
    fi
done
update-crypto-policies --set DEFAULT >/dev/null

printf '%s\n' \
    'x301_rpm_policy_overlay=PASS install=active upgrade=active remove=clean restrictive=inactive'
