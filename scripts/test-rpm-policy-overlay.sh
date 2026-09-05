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

# The packaged fragment is documentation only. Every named policy remains
# free of the private group while the template is present in the source tree.
test ! -e "$ACTIVE"
for policy in DEFAULT FUTURE FIPS BSI EMPTY; do
    if test -f "/usr/share/crypto-policies/policies/$policy.pol"; then
        update-crypto-policies --set "$policy" >/dev/null
        if grep -F X301 "$BACKEND" >/dev/null; then
            echo "inert X301 template changed policy $policy" >&2
            exit 1
        fi
    fi
done
update-crypto-policies --set DEFAULT >/dev/null
test "$(sha256sum "$BACKEND" | awk '{ print $1 }')" = "$baseline"

printf '%s\n' \
    'x301_rpm_policy_template=PASS transitions=clean'
