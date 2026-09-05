#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
SPEC=$ROOT/packaging/rpm/x301-openssl-provider.spec
PATCH=$ROOT/packaging/rpm/0001-Build-X301-shim-with-RPM-native-flags.patch
RPM_DIR=$ROOT/packaging/rpm

command -v rpmspec >/dev/null
rpmspec -P "$SPEC" >/dev/null

git -C "$ROOT" apply --check --whitespace=error-all "$PATCH"

awk '$1 ~ /^(Source[1-9][0-9]*|Patch[0-9]+):$/ { print $2 }' "$SPEC" \
    | while IFS= read -r source; do
        test -f "$RPM_DIR/$source" || {
            echo "missing local RPM source: $source" >&2
            exit 1
        }
    done

grep -F '%package policy' "$SPEC" >/dev/null
grep -F 'opensslcnf-zz-x301.config.example' "$SPEC" >/dev/null
if sed '/^%changelog/,$d' "$SPEC" \
        | grep -F '%{_sysconfdir}/crypto-policies/local.d/' >/dev/null
then
    echo 'policy package still installs an active crypto-policy overlay' >&2
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

printf '%s\n' 'x301_rpm_packaging=PASS provider_auto=1 policy_template=inert'
