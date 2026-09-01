#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
TEMPLATE=$ROOT/packaging/rpm/opensslcnf-x301.config
INSTALLED=/usr/share/x301-openssl-provider/opensslcnf-x301.config
ACTIVE=/etc/crypto-policies/local.d/opensslcnf-zz-x301.config
BACKEND=/etc/crypto-policies/back-ends/opensslcnf.config

test -e /run/.containerenv || {
    echo 'this test may run only inside a disposable container' >&2
    exit 2
}
command -v update-crypto-policies >/dev/null
test -f "$TEMPLATE"

cleanup() {
    rm -f "$ACTIVE" "$INSTALLED"
    update-crypto-policies --set DEFAULT >/dev/null 2>&1 || :
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$(dirname -- "$INSTALLED")" "$(dirname -- "$ACTIVE")"
rm -f "$ACTIVE" "$INSTALLED"
update-crypto-policies --set DEFAULT >/dev/null
baseline=$(sha256sum "$BACKEND" | awk '{ print $1 }')

# Installing or replacing the optional package payload is inert.
install -pm 0644 "$TEMPLATE" "$INSTALLED"
test "$(sha256sum "$BACKEND" | awk '{ print $1 }')" = "$baseline"
install -pm 0644 "$TEMPLATE" "$INSTALLED"
test "$(sha256sum "$BACKEND" | awk '{ print $1 }')" = "$baseline"

# Restrictive policy transitions do not consume the inactive template.
for policy in EMPTY FIPS; do
    if test -f "/usr/share/crypto-policies/policies/$policy.pol"; then
        update-crypto-policies --set "$policy" >/dev/null
        if grep -F X301 "$BACKEND" >/dev/null; then
            echo "inactive template changed restrictive policy $policy" >&2
            exit 1
        fi
    fi
done
update-crypto-policies --set DEFAULT >/dev/null

# Enabling and disabling require an explicit administrator action.
install -pm 0644 "$INSTALLED" "$ACTIVE"
update-crypto-policies >/dev/null
grep -F 'X301MLKEM1024' "$BACKEND" >/dev/null
grep -F '?X301/' "$BACKEND" >/dev/null
rm -f "$ACTIVE"
update-crypto-policies >/dev/null
if grep -F X301 "$BACKEND" >/dev/null; then
    echo 'explicit disable left X301 in the generated policy' >&2
    exit 1
fi

# Removing the optional package payload leaves the selected policy unchanged.
rm -f "$INSTALLED"
test "$(sha256sum "$BACKEND" | awk '{ print $1 }')" = "$baseline"
update-crypto-policies --check >/dev/null

printf '%s\n' \
    'x301_rpm_policy_overlay=PASS install=inactive enable=explicit disable=explicit restrictive=inactive upgrade=inactive remove=clean'
