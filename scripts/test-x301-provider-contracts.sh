#!/bin/bash
# Dual-lane X301 H5/T6/T7/T9/T10 provider contract runner.

set -Eeuo pipefail

PATH=/usr/bin:/bin
export PATH LC_ALL=C
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)

if test "$#" -ne 4; then
    printf 'usage: %s <3.5.7-lane-root> <3.5.7-evidence-sha256> <4.0.1-lane-root> <4.0.1-evidence-sha256>\n' \
        "$0" >&2
    exit 2
fi

LANE_357_ROOT=$1
LANE_357_EVIDENCE=$2
LANE_401_ROOT=$3
LANE_401_EVIDENCE=$4

if test -n "${X301_CONTRACT_RESULT_ROOT:-}"; then
    RESULT_ROOT=$X301_CONTRACT_RESULT_ROOT
    test ! -e "$RESULT_ROOT" && test ! -L "$RESULT_ROOT" || {
        printf 'result root already exists: %s\n' "$RESULT_ROOT" >&2
        exit 2
    }
    mkdir -m 700 -- "$RESULT_ROOT"
else
    RESULT_ROOT=$(mktemp -d /tmp/x301-contracts.XXXXXX)
fi
RESULT_ROOT=$(readlink -f -- "$RESULT_ROOT")

record_run_identity() {
    (
        cd "$ROOT"
        find Cargo.toml Cargo.lock \
            crates/ed301-eddsa/Cargo.toml crates/ed301-eddsa/src \
            docs/X301_DRAFT.md docs/X301_CONSTRUCTION_REGISTER.md \
            docs/OPENSSL_PATTERN_DEVIATIONS.md docs/OID_REGISTRY.md \
            provider/Cargo.toml provider/Cargo.lock \
            provider/crates/x301-provider provider-tests/x301 reference/x301 \
            secret-taint/Cargo.toml secret-taint/src \
            scripts/check-secret-taint.sh scripts/check-x301-final-codegen.sh \
            scripts/test-x301-provider-contracts.sh scripts/test-x301-tls.sh \
            scripts/verify-openssl-provider-lane.sh \
            -type f -exec sha256sum {} + | sort -k2
    ) >"$RESULT_ROOT/X301_SOURCE_SHA256SUMS"
    {
        /usr/bin/rustc --version --verbose
        /usr/bin/cargo --version --verbose
        /usr/bin/gcc --version
        /usr/bin/python3 --version
    } >"$RESULT_ROOT/TOOLCHAIN.txt" 2>&1
    {
        printf 'lane\troot\texternal_evidence_sha256\n'
        printf '3.5.7\t%s\t%s\n' "$LANE_357_ROOT" "$LANE_357_EVIDENCE"
        printf '4.0.1\t%s\t%s\n' "$LANE_401_ROOT" "$LANE_401_EVIDENCE"
    } >"$RESULT_ROOT/RUN_INPUTS.tsv"
}

run_lane() {
    local lane=$1
    local lane_root=$2
    local lane_evidence=$3
    local prefix=$lane_root/inst/$lane
    local source=$lane_root/src/openssl-$lane
    local build=$RESULT_ROOT/$lane
    local target=$build/target
    local modules=$build/modules
    local cargo_home=$build/cargo-home
    local data=$source/test/recipes/30-test_evp_data/evppkey_ml_kem_encap_decap.txt
    local mlkem1024_cases

    "$ROOT/scripts/verify-openssl-provider-lane.sh" \
        "$lane_root" "$lane" "$lane_evidence"
    test -x "$prefix/bin/openssl"
    test -x "$source/test/evp_test"
    test -f "$data"
    mkdir -m 700 -p "$target" "$modules" "$cargo_home" "$build/bin"

    printf 'lane=%s\nprefix=%s\nsource=%s\nbuild=%s\n' \
        "$lane" "$prefix" "$source" "$build"
    LD_LIBRARY_PATH="$prefix/lib" "$prefix/bin/openssl" version -a

    (
        cd "$ROOT/provider"
        env -i PATH=/usr/bin:/bin HOME="$build" LC_ALL=C \
            CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$target" \
            CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 \
            CC=/usr/bin/gcc AR=/usr/bin/ar \
            X301_HERMETIC_PROVIDER_BUILD=1 \
            OPENSSL_INCLUDE_DIR="$prefix/include" \
            OPENSSL_LIB_DIR="$prefix/lib" \
            LD_LIBRARY_PATH="$prefix/lib" \
            /usr/bin/cargo build --release --locked --offline \
                -p x301-provider --features tls-x301-mlkem1024
    )
    cp "$target/release/libx301.so" "$modules/x301.so"

    # H5 uses the ordinary signature-only Ed301 module solely to prove that
    # OpenSSL never accepts either algorithm's EVP_PKEY in the other's
    # operation context.  No PKI/TLS/test-only Ed301 feature is enabled.
    (
        cd "$ROOT/provider"
        env -i PATH=/usr/bin:/bin HOME="$build" LC_ALL=C \
            CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$target" \
            CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 \
            CC=/usr/bin/gcc AR=/usr/bin/ar \
            ED301_HERMETIC_PROVIDER_BUILD=1 \
            OPENSSL_INCLUDE_DIR="$prefix/include" \
            OPENSSL_LIB_DIR="$prefix/lib" \
            LD_LIBRARY_PATH="$prefix/lib" \
            /usr/bin/cargo build --release --locked --offline \
                -p ed301-eddsa-provider
    )
    cp "$target/release/libed301_eddsa_draft00.so" \
        "$modules/ed301_eddsa_draft00.so"

    /usr/bin/gcc -std=c11 -Wall -Wextra -Werror \
        -I"$prefix/include" \
        "$ROOT/provider-tests/x301/provider_x301_contract.c" \
        -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" -lcrypto \
        -o "$build/bin/provider_x301_contract"
    /usr/bin/gcc -std=c11 -Wall -Wextra -Werror -pthread \
        -I"$prefix/include" \
        "$ROOT/provider-tests/x301/provider_x301_hybrid_contract.c" \
        -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" -lcrypto \
        -o "$build/bin/provider_x301_hybrid_contract"
    /usr/bin/gcc -std=c11 -Wall -Wextra -Werror \
        -I"$prefix/include" \
        "$ROOT/provider-tests/x301/provider_x301_key_separation.c" \
        -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" -lcrypto \
        -o "$build/bin/provider_x301_key_separation"

    env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
        OPENSSL_MODULES="$modules" LD_LIBRARY_PATH="$prefix/lib" \
        "$build/bin/provider_x301_contract" "$modules" \
        2>&1 | tee "$build/provider_x301_contract.log"
    env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
        OPENSSL_MODULES="$modules" LD_LIBRARY_PATH="$prefix/lib" \
        "$build/bin/provider_x301_hybrid_contract" "$modules" \
        2>&1 | tee "$build/provider_x301_hybrid_contract.log"
    env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
        OPENSSL_MODULES="$modules" LD_LIBRARY_PATH="$prefix/lib" \
        "$build/bin/provider_x301_key_separation" "$modules" \
        2>&1 | tee "$build/provider_x301_key_separation.log"

    # T10: run the normative lane's own ACVP-v42/FIPS-203 EVP data through
    # its commit-exact evp_test executable.  The file contains ML-KEM-1024
    # encapsulation and decapsulation KATs in addition to the lower levels.
    mlkem1024_cases=$(awk '$1 == "Kem" && $2 == "=" && $3 == "ML-KEM-1024" { n++ } END { print n + 0 }' "$data")
    test "$mlkem1024_cases" -ge 1
    printf 't10_mlkem1024_acvp_cases=%s\n' "$mlkem1024_cases" \
        | tee "$build/t10-count.txt"
    env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
        LD_LIBRARY_PATH="$prefix/lib" \
        "$source/test/evp_test" -provider default "$data" \
        2>&1 | tee "$build/t10-openssl-evp-test.log"

    sha256sum "$modules/x301.so" \
        "$modules/ed301_eddsa_draft00.so" \
        "$build/bin/provider_x301_contract" \
        "$build/bin/provider_x301_hybrid_contract" \
        "$build/bin/provider_x301_key_separation" \
        "$data" >"$build/SHA256SUMS"
    printf 'PASS lane=%s lane_evidence_sha256=%s h5=PASS t6=PASS t7=PASS t9=PASS t10=PASS\n' \
        "$lane" "$lane_evidence" \
        | tee "$build/STATUS.txt"
}

record_run_identity
run_lane 3.5.7 "$LANE_357_ROOT" "$LANE_357_EVIDENCE"
run_lane 4.0.1 "$LANE_401_ROOT" "$LANE_401_EVIDENCE"
sha256sum "$RESULT_ROOT/X301_SOURCE_SHA256SUMS" \
    "$RESULT_ROOT/TOOLCHAIN.txt" "$RESULT_ROOT/RUN_INPUTS.tsv" \
    >"$RESULT_ROOT/RUN_IDENTITY_SHA256SUMS"
printf 'PASS X301 provider contracts both_lanes=2 result=%s\n' "$RESULT_ROOT"
