#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
SPEC=$ROOT/packaging/rpm/x301-openssl-provider.spec
PATCH=$ROOT/packaging/rpm/0001-Build-X301-shim-with-RPM-native-flags.patch

command -v rpmspec >/dev/null
rpmspec -P "$SPEC" >/dev/null

git -C "$ROOT" apply --check --whitespace=error-all "$PATCH"

grep -F '%package policy' "$SPEC" >/dev/null
grep -F '%{_datadir}/%{name}/opensslcnf-x301.config' "$SPEC" >/dev/null
if grep -F '%{_sysconfdir}/crypto-policies/local.d/' "$SPEC" >/dev/null
then
    echo 'base RPM must not install an active crypto-policy overlay' >&2
    exit 1
fi
if sed '/^%changelog/,$d' "$SPEC" \
        | grep -E 'x301-crypto-policy|ssl-ctx-policy-probe' >/dev/null
then
    echo 'obsolete policy controller remains in the spec' >&2
    exit 1
fi

test ! -e "$ROOT/packaging/rpm/x301-crypto-policy"
test ! -e "$ROOT/packaging/rpm/ssl-ctx-policy-probe.c"
test ! -e "$ROOT/packaging/rpm/x301-crypto-policy.8"

printf '%s\n' 'x301_rpm_packaging=PASS provider_auto=1 groups_auto=0'
