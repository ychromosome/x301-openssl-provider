#!/bin/sh
set -eu

test -e /run/.containerenv || test -e /.dockerenv || {
    echo 'this test may run only inside a disposable container' >&2
    exit 2
}
test "$(id -u)" -eq 0 || {
    echo 'this container test requires root' >&2
    exit 2
}
test "$#" -eq 1 || {
    echo "usage: $0 RPM_DIRECTORY" >&2
    exit 2
}

RPM_DIR=$1
BACKEND=/etc/crypto-policies/back-ends/opensslcnf.config
ACTIVE=/etc/crypto-policies/local.d/opensslcnf-zz-x301.config
BASE=$(find "$RPM_DIR" -maxdepth 1 -type f \
    -name 'x301-openssl-provider-0*.rpm' -print -quit)
POLICY=$(find "$RPM_DIR" -maxdepth 1 -type f \
    -name 'x301-openssl-provider-policy-*.rpm' -print -quit)

test -n "$BASE" && test -n "$POLICY"
if rpm -q x301-openssl-provider >/dev/null 2>&1; then
    echo 'container already has the X301 package installed' >&2
    exit 2
fi

cleanup() {
    rm -f "$ACTIVE"
    dnf -qy remove x301-openssl-provider-policy \
        x301-openssl-provider >/dev/null 2>&1 || :
    update-crypto-policies --set DEFAULT >/dev/null 2>&1 || :
}
trap cleanup EXIT HUP INT TERM

update-crypto-policies --set DEFAULT >/dev/null
baseline=$(sha256sum "$BACKEND" | cut -d ' ' -f1)

dnf -qy install "$BASE" >/dev/null
test "$(sha256sum "$BACKEND" | cut -d ' ' -f1)" = "$baseline"
test ! -e "$ACTIVE"
openssl list -providers | grep -F x301 >/dev/null

dnf -qy install "$POLICY" >/dev/null
test "$(sha256sum "$BACKEND" | cut -d ' ' -f1)" = "$baseline"
test -f /usr/share/x301-openssl-provider/opensslcnf-x301.config
test ! -e "$ACTIVE"

for policy in EMPTY FIPS; do
    update-crypto-policies --set "$policy" >/dev/null
    if grep -F X301 "$BACKEND" >/dev/null; then
        echo "inactive package changed restrictive policy $policy" >&2
        exit 1
    fi
done
update-crypto-policies --set DEFAULT >/dev/null

install -Dpm 0644 \
    /usr/share/x301-openssl-provider/opensslcnf-x301.config "$ACTIVE"
update-crypto-policies >/dev/null
grep -F X301MLKEM1024 "$BACKEND" >/dev/null
grep -F '?X301/' "$BACKEND" >/dev/null
rm -f "$ACTIVE"
update-crypto-policies >/dev/null
test "$(sha256sum "$BACKEND" | cut -d ' ' -f1)" = "$baseline"

dnf -qy reinstall "$BASE" "$POLICY" >/dev/null
test "$(sha256sum "$BACKEND" | cut -d ' ' -f1)" = "$baseline"
dnf -qy remove x301-openssl-provider-policy \
    x301-openssl-provider >/dev/null
test "$(sha256sum "$BACKEND" | cut -d ' ' -f1)" = "$baseline"
test ! -e /etc/pki/tls/openssl.d/x301-provider.conf
test ! -e /usr/lib64/ossl-modules/x301.so
test ! -e /usr/share/x301-openssl-provider/opensslcnf-x301.config

printf '%s\n' \
    'x301_rpm_install=PASS base=active groups=unchanged enable=explicit disable=explicit restrictive=inactive reinstall=clean remove=clean'
