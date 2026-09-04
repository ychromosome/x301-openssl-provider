#!/bin/sh
set -eu

# Timing-leak lane for the final X301 provider module.
# Tool: vendored dudect (provider-tests/x301/third_party/dudect, MIT); method
# Reparaz/Balasch/Verbauwhede, DATE 2017.  Measures EVP derive, raw private
# import and hybrid decapsulation on the loaded module for fixed-vs-random
# input classes and applies dudect's Welch-t verdict.  A positive control must
# be detected in the same run.  Evidence only for the recorded machine; not a
# constant-time proof.  Secret-dependent addresses and branches are covered by
# check-secret-taint.sh, machine-code shape by check-x301-final-codegen.sh.

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
sh "$ROOT/scripts/require-verified-snapshot.sh"

if [ "$#" -ne 3 ]; then
    printf 'usage: %s <openssl-prefix> <provider-modules-dir> <new-evidence-directory>\n' "$0" >&2
    printf '  X301_TIMING_MEASUREMENTS overrides the per-test measurement count (default 200000)\n' >&2
    exit 2
fi
PREFIX=$1
MODULES=$2
EVIDENCE=$3
MEASUREMENTS=${X301_TIMING_MEASUREMENTS:-200000}
case "$MEASUREMENTS" in
    ''|*[!0-9]*) echo "X301_TIMING_MEASUREMENTS must be a positive integer" >&2; exit 2 ;;
esac

for tool in /usr/bin/awk /usr/bin/cp /usr/bin/gcc /usr/bin/mkdir \
        /usr/bin/sha256sum /usr/bin/uname; do
    test -x "$tool" || {
        echo "missing timing-lane tool: $tool" >&2
        exit 127
    }
done
test -f "$PREFIX/include/openssl/evp.h" || {
    echo "not an OpenSSL prefix: $PREFIX" >&2
    exit 2
}
test -f "$MODULES/x301.so" && test ! -L "$MODULES/x301.so" || {
    echo "provider module directory must contain a regular x301.so" >&2
    exit 2
}
test ! -e "$EVIDENCE" || {
    echo "evidence directory already exists: $EVIDENCE" >&2
    exit 2
}
/usr/bin/mkdir -m 700 "$EVIDENCE"
/usr/bin/mkdir -m 700 "$EVIDENCE/modules"
/usr/bin/cp -- "$MODULES/x301.so" "$EVIDENCE/modules/x301.so"

{
    printf 'source_manifest_sha256=%s\n' "$ED301_EXPECTED_SOURCE_MANIFEST_SHA256"
    printf 'module_sha256=%s\n' \
        "$(/usr/bin/sha256sum "$EVIDENCE/modules/x301.so" | /usr/bin/awk '{ print $1 }')"
    for lib in "$PREFIX"/lib/libcrypto.so*; do
        test -f "$lib" || continue
        printf 'libcrypto=%s sha256=%s\n' "$lib" \
            "$(/usr/bin/sha256sum "$lib" | /usr/bin/awk '{ print $1 }')"
    done
    printf 'dudect_h_sha256=%s\n' \
        "$(/usr/bin/sha256sum "$ROOT/provider-tests/x301/third_party/dudect/dudect.h" | /usr/bin/awk '{ print $1 }')"
    printf 'harness_sha256=%s\n' \
        "$(/usr/bin/sha256sum "$ROOT/provider-tests/x301/provider_x301_timing.c" | /usr/bin/awk '{ print $1 }')"
    printf 'measurements_per_test=%s\n' "$MEASUREMENTS"
    printf 'kernel=%s machine=%s\n' "$(/usr/bin/uname -r)" "$(/usr/bin/uname -m)"
    if [ -r /proc/cpuinfo ]; then
        /usr/bin/awk -F': ' '/^model name/ { print "cpu_model=" $2; exit }' /proc/cpuinfo
        /usr/bin/awk -F': ' '/^flags/ { print "cpu_flags=" $2; exit }' /proc/cpuinfo
    fi
    if [ -r /proc/loadavg ]; then
        printf 'loadavg_before=%s\n' "$(/usr/bin/awk '{ print $1, $2, $3 }' /proc/loadavg)"
    fi
    if [ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
        printf 'cpu0_governor=%s\n' "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
    fi
} >"$EVIDENCE/RUN_IDENTITY.txt"

/usr/bin/gcc -std=c11 -O2 -Wall -Wextra -Werror \
    -I"$PREFIX/include" -I"$ROOT/provider-tests/x301" \
    "$ROOT/provider-tests/x301/provider_x301_timing.c" \
    -L"$PREFIX/lib" -Wl,-rpath,"$PREFIX/lib" -lcrypto -lm \
    -o "$EVIDENCE/provider_x301_timing"

status=0
env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES="$EVIDENCE/modules" LD_LIBRARY_PATH="$PREFIX/lib" \
    "$EVIDENCE/provider_x301_timing" "$EVIDENCE/modules" "$MEASUREMENTS" \
    >"$EVIDENCE/provider_x301_timing.log" 2>&1 || status=$?

/usr/bin/awk '/^x301_timing/ || /max_abs_t=/' "$EVIDENCE/provider_x301_timing.log" \
    >"$EVIDENCE/SUMMARY.txt"
if [ -r /proc/loadavg ]; then
    printf 'loadavg_after=%s\n' "$(/usr/bin/awk '{ print $1, $2, $3 }' /proc/loadavg)" \
        >>"$EVIDENCE/RUN_IDENTITY.txt"
fi
sh "$ROOT/scripts/require-verified-snapshot.sh"
cat "$EVIDENCE/SUMMARY.txt"
case "$status" in
    0) printf 'x301_timing_gate=PASS evidence=%s\n' "$EVIDENCE" ;;
    1) printf 'x301_timing_gate=LEAK evidence=%s\n' "$EVIDENCE" >&2 ;;
    3) printf 'x301_timing_gate=INCONCLUSIVE evidence=%s\n' "$EVIDENCE" >&2 ;;
    *) printf 'x301_timing_gate=ERROR status=%s evidence=%s\n' "$status" "$EVIDENCE" >&2 ;;
esac
exit "$status"
