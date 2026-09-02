#!/bin/bash
# Dual-lane X301 T6/T7/T9/T10 provider contract runner.

set -Eeuo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
PATH=/usr/bin:/bin
export PATH LC_ALL=C
sh "$ROOT/scripts/check-rust-build-environment.sh"
sh "$ROOT/scripts/require-verified-snapshot.sh"
CARGO=$($ROOT/scripts/resolve-rust-tool.sh cargo)
RUSTC=$($ROOT/scripts/resolve-rust-tool.sh rustc)
RUST_BIN=$(dirname -- "$CARGO")
umask 077
ORIGINAL_ARGS=("$@")

if test "$#" -ne 4; then
    printf 'usage: %s <3.5.8-lane-root> <3.5.8-evidence-sha256> <4.0.2-lane-root> <4.0.2-evidence-sha256>\n' \
        "$0" >&2
    exit 2
fi

LANE_358_ROOT=$1
LANE_358_EVIDENCE=$2
LANE_402_ROOT=$3
LANE_402_EVIDENCE=$4

/usr/bin/python3 -I -B -O \
    "$ROOT/reference/x301/generate_adversarial_corpus.py" --check

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
mkdir -m 700 -- "$RESULT_ROOT/openssl-lanes"
sh "$ROOT/scripts/materialize-openssl-provider-lane.sh" \
    "$LANE_358_ROOT" 3.5.8 "$LANE_358_EVIDENCE" \
    "$RESULT_ROOT/openssl-lanes/3.5.8"
sh "$ROOT/scripts/materialize-openssl-provider-lane.sh" \
    "$LANE_402_ROOT" 4.0.2 "$LANE_402_EVIDENCE" \
    "$RESULT_ROOT/openssl-lanes/4.0.2"
LANE_358_ROOT=$RESULT_ROOT/openssl-lanes/3.5.8
LANE_402_ROOT=$RESULT_ROOT/openssl-lanes/4.0.2

record_run_identity() {
    mkdir -m 700 -- "$RESULT_ROOT/inputs"
    cp -- "$LANE_358_ROOT/logs/3.5.8/evidence_manifest.sha256" \
        "$RESULT_ROOT/inputs/openssl-3.5.8-evidence-manifest.sha256"
    cp -- "$LANE_402_ROOT/logs/4.0.2/evidence_manifest.sha256" \
        "$RESULT_ROOT/inputs/openssl-4.0.2-evidence-manifest.sha256"
    cp -- "$LANE_358_ROOT/PRIVATE_LANE_SHA256SUMS" \
        "$RESULT_ROOT/inputs/openssl-3.5.8-private-lane.sha256"
    cp -- "$LANE_402_ROOT/PRIVATE_LANE_SHA256SUMS" \
        "$RESULT_ROOT/inputs/openssl-4.0.2-private-lane.sha256"
    test "$(sha256sum "$RESULT_ROOT/inputs/openssl-3.5.8-evidence-manifest.sha256" | awk '{print $1}')" \
        = "$LANE_358_EVIDENCE"
    test "$(sha256sum "$RESULT_ROOT/inputs/openssl-4.0.2-evidence-manifest.sha256" | awk '{print $1}')" \
        = "$LANE_402_EVIDENCE"
    (
        cd "$ROOT"
        find Cargo.toml Cargo.lock \
            crates/ed301-eddsa/Cargo.toml crates/ed301-eddsa/src \
            docs/X301_DRAFT.md docs/X301_CONSTRUCTION_REGISTER.md \
            docs/X301_EXTENDED_ASSURANCE.md \
            docs/OPENSSL_PATTERN_DEVIATIONS.md docs/OID_REGISTRY.md \
            fuzz/Cargo.toml fuzz/Cargo.lock fuzz/fuzz_targets fuzz/corpus \
            provider/Cargo.toml provider/Cargo.lock \
            provider/crates/x301-provider provider-tests/x301 reference/x301 \
            secret-taint/Cargo.toml secret-taint/src \
            scripts/check.sh scripts/check-secret-taint.sh \
            scripts/check-x301-final-codegen.sh scripts/check-x301-long.sh \
            scripts/materialize-openssl-provider-lane.sh \
            scripts/resolve-rust-tool.sh \
            scripts/run-authoritative-gate.sh \
            scripts/run-x301-fuzz.sh \
            scripts/test-x301-provider-contracts.sh scripts/test-x301-tls.sh \
            scripts/verify-openssl-provider-lane.sh \
            scripts/write-cargo-config.py \
            -type f -exec sha256sum {} + | sort -k2
    ) >"$RESULT_ROOT/X301_SOURCE_SHA256SUMS"
    {
        "$RUSTC" --version --verbose
        "$CARGO" --version --verbose
        /usr/bin/gcc --version
        /usr/bin/python3 --version
    } >"$RESULT_ROOT/TOOLCHAIN.txt" 2>&1
    {
        printf 'lane\tevidence_manifest\texternal_evidence_sha256\n'
        printf '3.5.8\tinputs/openssl-3.5.8-evidence-manifest.sha256\t%s\n' \
            "$LANE_358_EVIDENCE"
        printf '4.0.2\tinputs/openssl-4.0.2-evidence-manifest.sha256\t%s\n' \
            "$LANE_402_EVIDENCE"
    } >"$RESULT_ROOT/RUN_INPUTS.tsv"
    {
        printf 'source_mode=%s\n' "${ED301_SOURCE_MODE:-unknown}"
        printf 'source_manifest_sha256=%s\n' \
            "${ED301_EXPECTED_SOURCE_MANIFEST_SHA256:-unknown}"
        printf 'source_commit=%s\n' \
            "${ED301_EXPECTED_GIT_COMMIT:-not-applicable-archive}"
        printf 'argv='
        printf ' %q' "$0" "${ORIGINAL_ARGS[@]}"
        printf '\n'
    } >"$RESULT_ROOT/RUN_IDENTITY.txt"
    {
        printf 'libfuzzer_cargo_fuzz=%s\n' \
            "$(command -v cargo-fuzz 2>/dev/null || printf NOT_INSTALLED)"
        printf 'afl_plus_plus=%s\n' \
            "$(command -v afl-fuzz 2>/dev/null || printf NOT_INSTALLED)"
        printf '%s\n' \
            'selected=structured_sweep_plus_persisted_libfuzzer' \
            'raw_scope=lengths_0_76;all_delete_insert_positions;all_byte_values_at_all_38_positions' \
            'hybrid_scope=lengths_0_1607;all_bits;all_delete_insert_positions' \
            'semantic_seeds=frozen_W1_W6_plus_512_independent_oracle_cases' \
            'coverage_gate=provider_x301_fuzz;seed=301;20000_runs_per_lane;coverage_product_dso;asan_ubsan_harness;separate_f4_product_c_sanitizer' \
            'time_substitution=not_used_complete_defined_sweep_executed'
    } >"$RESULT_ROOT/FUZZING_STRATEGY.txt"
}

run_lane() {
    local lane=$1
    local lane_root=$2
    local lane_evidence=$3
    local prefix=$lane_root/inst/$lane
    local source=$lane_root/src/openssl-$lane
    local build=$RESULT_ROOT/$lane
    local target=$build/target
    local failpoint_target=$build/target-failpoint
    local modules=$build/modules
    local failpoint_modules=$build/modules-failpoint
    local sanitizer_modules=$build/modules-sanitizer
    local sanitizer_target=$build/target-sanitizer
    local taint_modules=$build/modules-taint
    local taint_target=$build/target-taint
    local fuzz_modules=$build/modules-fuzz-coverage
    local fuzz_target=$build/target-fuzz-coverage
    local cargo_home=$build/cargo-home
    local data=$source/test/recipes/30-test_evp_data/evppkey_ml_kem_encap_decap.txt
    local x301_evp_data=$ROOT/provider-tests/x301/openssl_evp_x301.txt
    local x301_evp_config=$ROOT/provider-tests/x301/openssl_evp_x301.cnf
    local mlkem1024_cases

    "$ROOT/scripts/verify-openssl-provider-lane.sh" \
        "$lane_root" "$lane" "$lane_evidence"
    test -x "$prefix/bin/openssl"
    test -x "$source/test/evp_test"
    test -f "$data"
    test -f "$x301_evp_data"
    test -f "$x301_evp_config"
    mkdir -m 700 -p \
        "$target" "$failpoint_target" "$sanitizer_target" "$taint_target" \
        "$fuzz_target" \
        "$modules" "$failpoint_modules" \
        "$sanitizer_modules" "$taint_modules" "$fuzz_modules" \
        "$cargo_home" "$build/bin" \
        "$build/provider-fuzz-corpus" "$build/provider-fuzz-artifacts"
    cp "$ROOT"/fuzz/corpus/provider_x301/* \
        "$build/provider-fuzz-corpus/"

    printf 'lane=%s\nprefix=%s\nsource=%s\nbuild=%s\n' \
        "$lane" "$prefix" "$source" "$build"
    LD_LIBRARY_PATH="$prefix/lib" "$prefix/bin/openssl" version -a

    (
        cd "$ROOT/provider"
        env -i PATH="$RUST_BIN:/usr/bin:/bin" HOME="$build" LC_ALL=C \
            CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$target" \
            CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 \
            RUSTC="$RUSTC" \
            CC=/usr/bin/gcc AR=/usr/bin/ar \
            X301_HERMETIC_PROVIDER_BUILD=1 \
            OPENSSL_INCLUDE_DIR="$prefix/include" \
            OPENSSL_LIB_DIR="$prefix/lib" \
            LD_LIBRARY_PATH="$prefix/lib" \
            "$CARGO" build --release --locked --offline \
                -p x301-provider --features tls-x301-mlkem1024
    )
    cp "$target/release/libx301.so" "$modules/x301.so"

    # M6 uses a separately copied, test-only Rust failpoint artifact.  The
    # ordinary module must remain byte-free of the environment-hook names.
    (
        cd "$ROOT/provider"
        env -i PATH="$RUST_BIN:/usr/bin:/bin" HOME="$build" LC_ALL=C \
            CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$failpoint_target" \
            CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 \
            RUSTC="$RUSTC" \
            CC=/usr/bin/gcc AR=/usr/bin/ar \
            X301_HERMETIC_PROVIDER_BUILD=1 \
            OPENSSL_INCLUDE_DIR="$prefix/include" \
            OPENSSL_LIB_DIR="$prefix/lib" \
            LD_LIBRARY_PATH="$prefix/lib" \
            "$CARGO" build --release --locked --offline \
                -p x301-provider \
                --features tls-x301-mlkem1024,test-failpoint
    )
    cp "$failpoint_target/release/libx301.so" "$failpoint_modules/x301.so"
    if /usr/bin/strings "$modules/x301.so" \
            | grep -E 'X301_PROVIDER_((PANIC|ALLOC)_FAILPOINT|PUBLIC_ALIAS_MASK)' \
                >/dev/null; then
        printf 'ordinary X301 module contains a test failpoint hook\n' >&2
        exit 1
    fi
    /usr/bin/strings "$failpoint_modules/x301.so" \
        | grep -F X301_PROVIDER_PANIC_FAILPOINT >/dev/null
    /usr/bin/strings "$failpoint_modules/x301.so" \
        | grep -F X301_PROVIDER_ALLOC_FAILPOINT >/dev/null
    /usr/bin/strings "$failpoint_modules/x301.so" \
        | grep -F X301_PROVIDER_PUBLIC_ALIAS_MASK >/dev/null

    # F4: test-only C-boundary/hybrid-parser instrumentation in the provider
    # DSO.  Stable rustc supplies no supported whole-crate sanitizer switch;
    # the Rust core is covered independently by Valgrind and T11 taint.
    (
        cd "$ROOT/provider"
        env -i PATH="$RUST_BIN:/usr/bin:/bin" HOME="$build" LC_ALL=C \
            CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$sanitizer_target" \
            CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 \
            RUSTC="$RUSTC" \
            CC=/usr/bin/gcc AR=/usr/bin/ar \
            X301_HERMETIC_PROVIDER_BUILD=1 \
            OPENSSL_INCLUDE_DIR="$prefix/include" \
            OPENSSL_LIB_DIR="$prefix/lib" \
            LD_LIBRARY_PATH="$prefix/lib" \
            "$CARGO" build --release --locked --offline \
                -p x301-provider \
                --features tls-x301-mlkem1024,test-sanitizer
    )
    cp "$sanitizer_target/release/libx301.so" \
        "$sanitizer_modules/x301.so"
    /usr/bin/readelf -d "$sanitizer_modules/x301.so" \
        >"$build/sanitizer-provider.dynamic.txt"
    /usr/bin/nm -D "$sanitizer_modules/x301.so" \
        >"$build/sanitizer-provider.nm.txt"
    grep -E 'NEEDED.*libasan' "$build/sanitizer-provider.dynamic.txt" \
        >/dev/null
    grep -E 'NEEDED.*libubsan' "$build/sanitizer-provider.dynamic.txt" \
        >/dev/null
    grep -E ' U __asan_init' "$build/sanitizer-provider.nm.txt" >/dev/null
    grep -E ' U __ubsan_handle_' "$build/sanitizer-provider.nm.txt" \
        >/dev/null

    (
        cd "$ROOT/provider"
        env -i PATH="$RUST_BIN:/usr/bin:/bin" HOME="$build" LC_ALL=C \
            CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$taint_target" \
            CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 RUSTC="$RUSTC" \
            CC=/usr/bin/gcc AR=/usr/bin/ar \
            ED301_HERMETIC_NATIVE_BUILD=1 \
            X301_HERMETIC_PROVIDER_BUILD=1 \
            OPENSSL_INCLUDE_DIR="$prefix/include" \
            OPENSSL_LIB_DIR="$prefix/lib" LD_LIBRARY_PATH="$prefix/lib" \
            "$CARGO" build --release --locked --offline \
                -p x301-provider \
                --features tls-x301-mlkem1024,secret-taint-instrumentation
    )
    cp "$taint_target/release/libx301.so" "$taint_modules/x301.so"

    # H-04 product-code coverage lane. The final Rust provider crate and both
    # C boundary objects carry sanitizer-coverage counters; the libFuzzer
    # executable supplies their callbacks when it loads this test-only DSO.
    (
        cd "$ROOT/provider"
        env -i PATH="$RUST_BIN:/usr/bin:/bin" HOME="$build" LC_ALL=C \
            CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$fuzz_target" \
            CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 \
            RUSTC="$RUSTC" \
            CC=/usr/bin/clang AR=/usr/bin/ar \
            X301_HERMETIC_PROVIDER_BUILD=1 \
            OPENSSL_INCLUDE_DIR="$prefix/include" \
            OPENSSL_LIB_DIR="$prefix/lib" \
            LD_LIBRARY_PATH="$prefix/lib" \
            "$CARGO" rustc --release --locked --offline \
                -p x301-provider \
                --features tls-x301-mlkem1024,test-fuzz-coverage \
                -- \
                -C passes=sancov-module \
                -C llvm-args=-sanitizer-coverage-level=3 \
                -C llvm-args=-sanitizer-coverage-inline-8bit-counters \
                -C llvm-args=-sanitizer-coverage-pc-table
    )
    cp "$fuzz_target/release/libx301.so" "$fuzz_modules/x301.so"
    /usr/bin/nm -D "$fuzz_modules/x301.so" \
        >"$build/fuzz-provider.nm.txt"
    grep -E ' U __sanitizer_cov_' "$build/fuzz-provider.nm.txt" >/dev/null

    /usr/bin/gcc -std=c11 -Wall -Wextra -Werror -pthread \
        -I"$prefix/include" \
        "$ROOT/provider-tests/x301/provider_x301_contract.c" \
        -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" -lcrypto \
        -o "$build/bin/provider_x301_contract"
    /usr/bin/gcc -std=c11 -Wall -Wextra -Werror -pthread \
        -I"$prefix/include" \
        "$ROOT/provider-tests/x301/provider_x301_hybrid_contract.c" \
        -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" -lcrypto \
        -o "$build/bin/provider_x301_hybrid_contract"
    /usr/bin/gcc -std=c11 -Wall -Wextra -Werror -pthread \
        -I"$prefix/include" \
        "$ROOT/provider-tests/x301/provider_x301_nested_properties.c" \
        -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" -lcrypto \
        -o "$build/bin/provider_x301_nested_properties"
    /usr/bin/gcc -std=c11 -Wall -Wextra -Werror -pthread \
        -I"$prefix/include" \
        "$ROOT/provider-tests/x301/provider_x301_secret_taint.c" \
        "$ROOT/secret-taint/valgrind-client/c/valgrind_client.c" \
        -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" -lcrypto \
        -o "$build/bin/provider_x301_secret_taint"
    for harness in provider_x301_contract provider_x301_hybrid_contract; do
        /usr/bin/gcc -std=c11 -Wall -Wextra -Werror -pthread \
            -fsanitize=address,undefined -fno-sanitize-recover=all \
            -fno-omit-frame-pointer -g \
            -I"$prefix/include" \
            "$ROOT/provider-tests/x301/$harness.c" \
            -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" -lcrypto \
            -o "$build/bin/${harness}_sanitizer"
    done
    /usr/bin/clang -std=c11 -Wall -Wextra -Werror \
        -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g \
        -I"$prefix/include" \
        "$ROOT/provider-tests/x301/provider_x301_fuzz.c" \
        -L"$prefix/lib" -Wl,-rpath,"$prefix/lib" -lcrypto \
        -o "$build/bin/provider_x301_fuzz"

    # Seal every executable input before the first provider or harness use.
    # The same manifest is checked again after all runtime and analyzer lanes.
    (
        cd "$build"
        sha256sum \
            modules/x301.so \
            modules-failpoint/x301.so \
            modules-sanitizer/x301.so \
            modules-taint/x301.so \
            modules-fuzz-coverage/x301.so \
            bin/provider_x301_contract \
            bin/provider_x301_hybrid_contract \
            bin/provider_x301_contract_sanitizer \
            bin/provider_x301_hybrid_contract_sanitizer \
            bin/provider_x301_secret_taint \
            bin/provider_x301_fuzz \
            bin/provider_x301_nested_properties >PREUSE_SHA256SUMS
        sha256sum --strict --quiet -c PREUSE_SHA256SUMS
    )

    env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
        X301_PROVIDER_FAILPOINT_MODE=inert \
        OPENSSL_MODULES="$modules" LD_LIBRARY_PATH="$prefix/lib" \
        "$build/bin/provider_x301_contract" "$modules" \
        2>&1 | tee "$build/provider_x301_contract.log"
    env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
        X301_PROVIDER_FAILPOINT_MODE=active \
        OPENSSL_MODULES="$failpoint_modules" LD_LIBRARY_PATH="$prefix/lib" \
        "$build/bin/provider_x301_contract" "$failpoint_modules" \
        2>&1 | tee "$build/provider_x301_failpoint.log"
    env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
        X301_HYBRID_ALLOC_SWEEP=1 \
        OPENSSL_MODULES="$modules" LD_LIBRARY_PATH="$prefix/lib" \
        "$build/bin/provider_x301_hybrid_contract" "$modules" \
        2>&1 | tee "$build/provider_x301_hybrid_contract.log"
    env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
        OPENSSL_MODULES="$modules" LD_LIBRARY_PATH="$prefix/lib" \
        "$build/bin/provider_x301_nested_properties" "$modules" \
        2>&1 | tee "$build/provider_x301_nested_properties.log"

    # M5/T13 lifecycle memory lane.  In particular, the raw KEYEXCH harness
    # executes four concurrent workers sharing the same immutable EVP_PKEYs;
    # both direct and hybrid contexts must then tear down without an invalid
    # access or a surviving definite/indirect/possible allocation.
    for harness in provider_x301_contract provider_x301_hybrid_contract; do
        env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
            OPENSSL_MODULES="$modules" LD_LIBRARY_PATH="$prefix/lib" \
            /usr/bin/valgrind --tool=memcheck --vgdb=no \
                --error-exitcode=99 --track-origins=yes \
                --undef-value-errors=yes --leak-check=full \
                --errors-for-leak-kinds=definite,indirect,possible --quiet \
                "$build/bin/$harness" "$modules" \
                >"$build/$harness-valgrind.log" 2>&1
    done
    env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
        OPENSSL_MODULES="$modules" LD_LIBRARY_PATH="$prefix/lib" \
        /usr/bin/valgrind --tool=memcheck --vgdb=no \
            --error-exitcode=99 --track-origins=yes \
            --undef-value-errors=yes --leak-check=full \
            --errors-for-leak-kinds=definite,indirect,possible --quiet \
            "$build/bin/provider_x301_nested_properties" "$modules" \
            >"$build/provider_x301_nested_properties-valgrind.log" 2>&1
    env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
        OPENSSL_MODULES="$taint_modules" LD_LIBRARY_PATH="$prefix/lib" \
        /usr/bin/valgrind --tool=memcheck --vgdb=no \
            --error-exitcode=99 --track-origins=yes \
            --undef-value-errors=yes --leak-check=full \
            --errors-for-leak-kinds=definite,indirect,possible --quiet \
            "$build/bin/provider_x301_secret_taint" "$taint_modules" \
            >"$build/provider_x301_secret_taint.log" 2>&1

    # F1-F3: all three provider-entry targets use the frozen W corpus first,
    # followed by the complete, explicitly bounded structured sweep.
    env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
        X301_STRUCTURED_SWEEP=1 \
        OPENSSL_MODULES="$modules" LD_LIBRARY_PATH="$prefix/lib" \
        "$build/bin/provider_x301_contract" "$modules" \
        2>&1 | tee "$build/f1-f3-raw-derive-sweep.log"
    env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
        X301_STRUCTURED_SWEEP=1 \
        OPENSSL_MODULES="$modules" LD_LIBRARY_PATH="$prefix/lib" \
        "$build/bin/provider_x301_hybrid_contract" "$modules" \
        2>&1 | tee "$build/f1-f3-hybrid-parser-sweep.log"

    # F4: repeat every target with ASan+UBSan on both the harness and the C
    # provider boundary.  LeakSanitizer is disabled because OpenSSL owns
    # process/thread globals; leak coverage is supplied by Valgrind instead.
    for harness in provider_x301_contract provider_x301_hybrid_contract; do
        env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
            X301_STRUCTURED_SWEEP=1 \
            OPENSSL_MODULES="$sanitizer_modules" \
            LD_LIBRARY_PATH="$prefix/lib" \
            ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1 \
            UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
            ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer \
            "$build/bin/${harness}_sanitizer" "$sanitizer_modules" \
            2>&1 | tee "$build/f4-${harness}-asan-ubsan.log"
    done

    # H-04: coverage-guided mutation of raw KEYEXCH, hybrid public parsing,
    # decapsulation atomicity and context duplication.  The tracked corpus is
    # copied because the verified source snapshot remains read-only.
    env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
        X301_FUZZ_MODULE_DIR="$fuzz_modules" \
        LD_LIBRARY_PATH="$prefix/lib" \
        ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1 \
        UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
        ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer \
        "$build/bin/provider_x301_fuzz" \
        -runs=20000 -seed=301 -max_len=4096 -timeout=20 \
        -artifact_prefix="$build/provider-fuzz-artifacts/" \
        "$build/provider-fuzz-corpus" \
        2>&1 | tee "$build/h04-provider-libfuzzer.log"
    (
        cd "$build/provider-fuzz-corpus"
        find . -type f -print0 | sort -z | xargs -0 sha256sum
    ) >"$build/provider-fuzz-corpus.sha256"

    # O1/O2: execute the X301 raw-key, pairwise, misuse and exact-derive
    # contracts through the normative lane's unmodified evp_test runner.
    env -i PATH=/usr/bin:/bin LC_ALL=C \
        OPENSSL_MODULES="$modules" LD_LIBRARY_PATH="$prefix/lib" \
        "$source/test/evp_test" -config "$x301_evp_config" \
        "$x301_evp_data" \
        2>&1 | tee "$build/o1-o2-x301-evp-test.log"

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

    mkdir -m 700 -- "$build/inputs"
    cp -- "$data" "$build/inputs/openssl-evp-pkey.txt"
    cp -- "$x301_evp_data" "$build/inputs/openssl-evp-x301.txt"
    cp -- "$x301_evp_config" "$build/inputs/openssl-evp-x301.cnf"
    (
        cd "$build"
        sha256sum --strict --quiet -c PREUSE_SHA256SUMS
        sha256sum \
            modules/x301.so \
            modules-failpoint/x301.so \
            modules-sanitizer/x301.so \
            modules-taint/x301.so \
            modules-fuzz-coverage/x301.so \
            bin/provider_x301_contract \
            bin/provider_x301_hybrid_contract \
            bin/provider_x301_contract_sanitizer \
            bin/provider_x301_hybrid_contract_sanitizer \
            bin/provider_x301_secret_taint \
            bin/provider_x301_fuzz \
            bin/provider_x301_nested_properties \
            PREUSE_SHA256SUMS \
            provider_x301_contract-valgrind.log \
            provider_x301_hybrid_contract-valgrind.log \
            provider_x301_nested_properties-valgrind.log \
            provider_x301_secret_taint.log \
            h04-provider-libfuzzer.log \
            provider-fuzz-corpus.sha256 \
            inputs/openssl-evp-pkey.txt \
            inputs/openssl-evp-x301.txt \
            inputs/openssl-evp-x301.cnf >SHA256SUMS
        sha256sum --strict --quiet -c SHA256SUMS
    )
    printf 'PASS lane=%s lane_evidence_sha256=%s o1=PASS o2=PASS t6=PASS t7=PASS t9=PASS t10=PASS nested_properties=PASS m1_m6=PASS m5_valgrind=PASS provider_taint=PASS f1_f4=PASS h04_libfuzzer=PASS\n' \
        "$lane" "$lane_evidence" \
        | tee "$build/STATUS.txt"
}

record_run_identity
run_lane 3.5.8 "$LANE_358_ROOT" "$LANE_358_EVIDENCE"
run_lane 4.0.2 "$LANE_402_ROOT" "$LANE_402_EVIDENCE"
sh "$ROOT/scripts/verify-openssl-provider-lane.sh" \
    "$LANE_358_ROOT" 3.5.8 "$LANE_358_EVIDENCE"
sh "$ROOT/scripts/verify-openssl-provider-lane.sh" \
    "$LANE_402_ROOT" 4.0.2 "$LANE_402_EVIDENCE"
for lane_root in "$LANE_358_ROOT" "$LANE_402_ROOT"; do
    (cd "$lane_root" && \
        sha256sum --strict --quiet -c PRIVATE_LANE_SHA256SUMS.seal && \
        sha256sum --strict --quiet -c PRIVATE_LANE_SHA256SUMS)
done
(cd "$RESULT_ROOT" && sha256sum \
    X301_SOURCE_SHA256SUMS TOOLCHAIN.txt RUN_INPUTS.tsv RUN_IDENTITY.txt \
    FUZZING_STRATEGY.txt inputs/*.sha256 >RUN_IDENTITY_SHA256SUMS
    sha256sum --strict --quiet -c RUN_IDENTITY_SHA256SUMS)
sh "$ROOT/scripts/require-verified-snapshot.sh"
printf 'PASS X301 provider contracts both_lanes=2 result=%s\n' "$RESULT_ROOT"
