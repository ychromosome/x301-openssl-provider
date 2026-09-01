#!/bin/bash
# Dual-lane and cross-lane X301 TLS robustness runner (T8, R1-R7).
#
# Contract sources: RFC 9846 Sections 4.3.7-4.3.8 and 4.6.1 (TLS 1.3
# NamedGroup, fresh KeyShare, and session tickets), RFC 9954 (hybrid design),
# RFC 10024 Sections 4-5 (ML-KEM-first key-share construction), FIPS 203
# (ML-KEM-1024), and the OpenSSL 3.5.7/4.0.1 s_client/s_server contracts.

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
SS_BIN=
for candidate in /usr/bin/ss /usr/sbin/ss; do
    if test -x "$candidate"; then
        SS_BIN=$candidate
        break
    fi
done
test -n "$SS_BIN" || {
    echo "missing ss readiness tool" >&2
    exit 127
}
KEYSHARE_PARSER=$ROOT/provider-tests/x301/extract_x301_client_keyshare.py
TRACE_INSPECTOR=$ROOT/provider-tests/x301/inspect_x301_tls_trace.py
WIRE_MUTATOR=$ROOT/provider-tests/x301/mutate_x301_tls_keyshare.py
LONG_HANDSHAKES=${X301_TLS_LONG_HANDSHAKES:-0}
SERVER_PID=
SERVER_LOG=
SERVER_PORT=
CLIENT_PORT=
PROXY_PID=
PROXY_LOG=
PUBLIC_ALIAS_MASK=

if test "$#" -ne 4; then
    printf 'usage: %s <3.5.7-lane-root> <3.5.7-evidence-sha256> <4.0.1-lane-root> <4.0.1-evidence-sha256>\n' \
        "$0" >&2
    exit 2
fi

LANE_357_ROOT=$1
LANE_357_EVIDENCE=$2
LANE_401_ROOT=$3
LANE_401_EVIDENCE=$4

if test -n "${X301_TLS_RESULT_ROOT:-}"; then
    RESULT_ROOT=$X301_TLS_RESULT_ROOT
    test ! -e "$RESULT_ROOT" && test ! -L "$RESULT_ROOT" || {
        printf 'result root already exists: %s\n' "$RESULT_ROOT" >&2
        exit 2
    }
    mkdir -m 700 -- "$RESULT_ROOT"
else
    RESULT_ROOT=$(mktemp -d /tmp/x301-tls.XXXXXX)
fi
RESULT_ROOT=$(readlink -f -- "$RESULT_ROOT")
mkdir -m 700 -- "$RESULT_ROOT/openssl-lanes"
sh "$ROOT/scripts/materialize-openssl-provider-lane.sh" \
    "$LANE_357_ROOT" 3.5.7 "$LANE_357_EVIDENCE" \
    "$RESULT_ROOT/openssl-lanes/3.5.7"
sh "$ROOT/scripts/materialize-openssl-provider-lane.sh" \
    "$LANE_401_ROOT" 4.0.1 "$LANE_401_EVIDENCE" \
    "$RESULT_ROOT/openssl-lanes/4.0.1"
LANE_357_ROOT=$RESULT_ROOT/openssl-lanes/3.5.7
LANE_401_ROOT=$RESULT_ROOT/openssl-lanes/4.0.1

record_run_identity() {
    mkdir -m 700 -- "$RESULT_ROOT/inputs"
    cp -- "$LANE_357_ROOT/logs/3.5.7/evidence_manifest.sha256" \
        "$RESULT_ROOT/inputs/openssl-3.5.7-evidence-manifest.sha256"
    cp -- "$LANE_401_ROOT/logs/4.0.1/evidence_manifest.sha256" \
        "$RESULT_ROOT/inputs/openssl-4.0.1-evidence-manifest.sha256"
    cp -- "$LANE_357_ROOT/PRIVATE_LANE_SHA256SUMS" \
        "$RESULT_ROOT/inputs/openssl-3.5.7-private-lane.sha256"
    cp -- "$LANE_401_ROOT/PRIVATE_LANE_SHA256SUMS" \
        "$RESULT_ROOT/inputs/openssl-4.0.1-private-lane.sha256"
    test "$(sha256sum "$RESULT_ROOT/inputs/openssl-3.5.7-evidence-manifest.sha256" | awk '{print $1}')" \
        = "$LANE_357_EVIDENCE"
    test "$(sha256sum "$RESULT_ROOT/inputs/openssl-4.0.1-evidence-manifest.sha256" | awk '{print $1}')" \
        = "$LANE_401_EVIDENCE"
    (
        cd "$ROOT"
        find Cargo.toml Cargo.lock \
            crates/ed301-eddsa/Cargo.toml crates/ed301-eddsa/src \
            docs/X301_DRAFT.md docs/X301_CONSTRUCTION_REGISTER.md \
            docs/X301_EXTENDED_ASSURANCE.md \
            docs/OPENSSL_PATTERN_DEVIATIONS.md docs/OID_REGISTRY.md \
            provider/Cargo.toml provider/Cargo.lock \
            provider/crates/x301-provider provider-tests/x301 reference/x301 \
            secret-taint/Cargo.toml secret-taint/src \
            scripts/check.sh scripts/check-secret-taint.sh \
            scripts/check-x301-final-codegen.sh scripts/check-x301-long.sh \
            scripts/materialize-openssl-provider-lane.sh \
            scripts/resolve-rust-tool.sh \
            scripts/run-authoritative-gate.sh \
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
        printf '3.5.7\tinputs/openssl-3.5.7-evidence-manifest.sha256\t%s\n' \
            "$LANE_357_EVIDENCE"
        printf '4.0.1\tinputs/openssl-4.0.1-evidence-manifest.sha256\t%s\n' \
            "$LANE_401_EVIDENCE"
    } >"$RESULT_ROOT/RUN_INPUTS.tsv"
}

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

case "$LONG_HANDSHAKES" in
    ''|*[!0-9]*) fail "X301_TLS_LONG_HANDSHAKES must be a nonnegative integer" ;;
esac

cleanup_server() {
    if test -n "$PROXY_PID" && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
    fi
    PROXY_PID=
    if test -n "$SERVER_PID" && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    SERVER_PID=
}

trap cleanup_server EXIT INT TERM HUP

require_text() {
    local needle=$1
    local file=$2
    /usr/bin/grep -Fq -- "$needle" "$file" \
        || fail "missing '$needle' in $file"
}

reject_text() {
    local needle=$1
    local file=$2
    if /usr/bin/grep -Fq -- "$needle" "$file"; then
        fail "unexpected '$needle' in $file"
    fi
}

choose_port() {
    /usr/bin/python3 -c \
        'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

start_server() {
    local openssl=$1
    local prefix=$2
    local modules=$3
    local home=$4
    local cert=$5
    local key=$6
    local groups=$7
    local accepts=$8
    local load_x301=$9
    local label=${10}
    local provider_args=(-provider default)
    local attempt
    local server_timeout=45

    cleanup_server
    if test "$load_x301" = yes; then
        provider_args+=(-provider x301)
    fi
    if test "$accepts" -ge 64; then
        server_timeout=300
    fi
    if test "$accepts" -ge 1000; then
        server_timeout=1800
    fi
    SERVER_LOG=$home/$label-server.log

    for attempt in 1 2 3; do
        SERVER_PORT=$(choose_port)
        CLIENT_PORT=$SERVER_PORT
        : >"$SERVER_LOG"
        env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$home" \
            OPENSSL_CONF=/dev/null OPENSSL_MODULES="$modules" \
            X301_PROVIDER_PUBLIC_ALIAS_MASK="$PUBLIC_ALIAS_MASK" \
            LD_LIBRARY_PATH="$prefix/lib" \
            /usr/bin/timeout "$server_timeout" \
            "$openssl" s_server \
                -accept "127.0.0.1:$SERVER_PORT" -tls1_3 \
                -groups "$groups" -cert "$cert" -key "$key" \
                -www -num_tickets 1 -naccept "$accepts" \
                "${provider_args[@]}" >"$SERVER_LOG" 2>&1 &
        SERVER_PID=$!

        for _ in $(/usr/bin/seq 1 100); do
            if "$SS_BIN" -H -ltn "sport = :$SERVER_PORT" \
                    | /usr/bin/grep -q .; then
                return 0
            fi
            if ! kill -0 "$SERVER_PID" 2>/dev/null; then
                wait "$SERVER_PID" 2>/dev/null || true
                SERVER_PID=
                break
            fi
            /usr/bin/sleep 0.05
        done
    done
    fail "server did not listen for $label; see $SERVER_LOG"
}

start_wire_mutator() {
    local home=$1
    local label=$2
    local direction=$3
    local component=$4
    local mode=$5
    local case_index=$6
    local proxy_port

    test -z "$PROXY_PID" || fail "wire mutator is already running"
    proxy_port=$(choose_port)
    PROXY_LOG=$home/$label-proxy.log
    : >"$PROXY_LOG"
    /usr/bin/python3 -u "$WIRE_MUTATOR" \
        --listen-port "$proxy_port" --upstream-port "$SERVER_PORT" \
        --direction "$direction" --component "$component" \
        --mode "$mode" --case-index "$case_index" \
        >"$PROXY_LOG" 2>&1 &
    PROXY_PID=$!
    CLIENT_PORT=$proxy_port

    for _ in $(/usr/bin/seq 1 100); do
        if "$SS_BIN" -H -ltn "sport = :$proxy_port" \
                | /usr/bin/grep -q .; then
            return 0
        fi
        if ! kill -0 "$PROXY_PID" 2>/dev/null; then
            wait "$PROXY_PID" 2>/dev/null || true
            PROXY_PID=
            fail "wire mutator exited before listening; see $PROXY_LOG"
        fi
        /usr/bin/sleep 0.05
    done
    fail "wire mutator did not listen; see $PROXY_LOG"
}

finish_wire_mutator() {
    local status=0

    for _ in $(/usr/bin/seq 1 100); do
        if ! kill -0 "$PROXY_PID" 2>/dev/null; then
            if wait "$PROXY_PID"; then
                status=0
            else
                status=$?
            fi
            PROXY_PID=
            test "$status" -eq 0 \
                || fail "wire mutator failed with status $status; see $PROXY_LOG"
            return 0
        fi
        /usr/bin/sleep 0.05
    done
    fail "wire mutator did not terminate; see $PROXY_LOG"
}

finish_server() {
    local expect_success=$1
    local status=0

    for _ in $(/usr/bin/seq 1 100); do
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            if wait "$SERVER_PID"; then
                status=0
            else
                status=$?
            fi
            SERVER_PID=
            if test "$expect_success" = yes && test "$status" -ne 0; then
                fail "server failed with status $status; see $SERVER_LOG"
            fi
            return 0
        fi
        /usr/bin/sleep 0.05
    done
    fail "server did not terminate after its contracted connection count; see $SERVER_LOG"
}

run_client() {
    local openssl=$1
    local prefix=$2
    local modules=$3
    local home=$4
    local cert=$5
    local groups=$6
    local label=$7
    shift 7

    env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$home" \
        OPENSSL_CONF=/dev/null OPENSSL_MODULES="$modules" \
        X301_PROVIDER_PUBLIC_ALIAS_MASK="$PUBLIC_ALIAS_MASK" \
        LD_LIBRARY_PATH="$prefix/lib" \
        /usr/bin/timeout 30 \
        "$openssl" s_client \
            -connect "127.0.0.1:$CLIENT_PORT" -tls1_3 \
            -groups "$groups" -servername localhost \
            -verify_hostname localhost -verify_return_error \
            -CAfile "$cert" -provider default -provider x301 \
            "$@" <"$home/request.txt" >"$home/$label-client.log" 2>&1
}

field_value() {
    local key=$1
    local file=$2
    /usr/bin/awk -v key="$key" '
        NR == 1 {
            for (i = 1; i <= NF; i++) {
                split($i, field, "=")
                if (field[1] == key) {
                    print field[2]
                    exit
                }
            }
        }
    ' "$file"
}

run_mutation_matrix() {
    local openssl=$1
    local prefix=$2
    local modules=$3
    local home=$4
    local cert=$5
    local key=$6
    local direction=$7
    local component=$8
    local label=$9
    local mutation_dir=$home/r5-$label
    local case_index case_label client_status encrypted plaintext_alerts stage

    mkdir -m 700 -p "$mutation_dir"
    printf 'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n' \
        >"$mutation_dir/request.txt"
    printf 'case\tdirection\tcomponent\tclient_status\tfailure_stage\tencrypted_records\n' \
        >"$mutation_dir/RESULTS.tsv"
    start_server "$openssl" "$prefix" "$modules" "$mutation_dir" \
        "$cert" "$key" X301MLKEM1024 64 yes "$label"
    for case_index in $(/usr/bin/seq 0 63); do
        case_label=$(printf 'case-%02d' "$case_index")
        start_wire_mutator "$mutation_dir" "$case_label" \
            "$direction" "$component" flip "$case_index"
        if run_client "$openssl" "$prefix" "$modules" "$mutation_dir" \
                "$cert" X301MLKEM1024 "$case_label" -brief; then
            fail "$label mutation $case_index unexpectedly completed"
        else
            client_status=$?
        fi
        test "$client_status" -eq 1 \
            || fail "$label mutation $case_index returned $client_status"
        finish_wire_mutator
        require_text "mutated=1 mode=flip direction=$direction" "$PROXY_LOG"
        require_text "component=$component case_index=$case_index" "$PROXY_LOG"
        reject_text 'CONNECTION ESTABLISHED' \
            "$mutation_dir/$case_label-client.log"
        encrypted=$(/usr/bin/awk '
            /^encrypted_records_after_mutation=/ {
                split($1, value, "="); print value[2]; exit
            }
        ' "$PROXY_LOG")
        plaintext_alerts=$(/usr/bin/awk '
            /^encrypted_records_after_mutation=/ {
                split($2, value, "="); print value[2]; exit
            }
        ' "$PROXY_LOG")
        test -n "$encrypted" && test -n "$plaintext_alerts" \
            || fail "$label mutation $case_index has no stage counters"
        if test "$encrypted" -ge 1; then
            require_text 'bad record mac' \
                "$mutation_dir/$case_label-client.log"
            stage=protected-record-auth
        else
            test "$direction" = client && test "$plaintext_alerts" -ge 1 \
                || fail "$label mutation $case_index failed before protected records without a plaintext alert"
            require_text 'alert illegal parameter' \
                "$mutation_dir/$case_label-client.log"
            stage=share-parsing
        fi
        if test "$direction" = server; then
            test "$stage" = protected-record-auth \
                || fail "server ML-KEM mutation $case_index failed too early"
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$case_index" "$direction" "$component" \
            "$client_status" "$stage" "$encrypted" \
            >>"$mutation_dir/RESULTS.tsv"
    done
    finish_server no
    test "$(/usr/bin/awk 'END { print NR - 1 }' \
        "$mutation_dir/RESULTS.tsv")" -eq 64
    (
        cd "$mutation_dir"
        find . -type f ! -name SHA256SUMS -exec sha256sum {} + | sort -k2
    ) >"$mutation_dir/SHA256SUMS"
}

run_foreign_size_negative() {
    local openssl=$1
    local prefix=$2
    local modules=$3
    local home=$4
    local cert=$5
    local key=$6
    local negative_dir=$home/r6-foreign-size
    local client_status

    mkdir -m 700 -p "$negative_dir"
    printf 'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n' \
        >"$negative_dir/request.txt"
    start_server "$openssl" "$prefix" "$modules" "$negative_dir" \
        "$cert" "$key" X301MLKEM1024 1 yes foreign-size
    start_wire_mutator "$negative_dir" foreign-size \
        client mlkem foreign-size 0
    if run_client "$openssl" "$prefix" "$modules" "$negative_dir" \
            "$cert" X301MLKEM1024 foreign-size -brief; then
        fail "1216-byte foreign share unexpectedly completed"
    else
        client_status=$?
    fi
    test "$client_status" -eq 1 \
        || fail "foreign-size client returned $client_status"
    finish_wire_mutator
    finish_server no
    require_text 'mutated=1 mode=foreign-size direction=client' "$PROXY_LOG"
    require_text 'original_length=1606 replacement_length=1216' "$PROXY_LOG"
    require_text 'encrypted_records_after_mutation=0' "$PROXY_LOG"
    require_text 'plaintext_alerts_after_mutation=1' "$PROXY_LOG"
    require_text 'alert illegal parameter' \
        "$negative_dir/foreign-size-client.log"
    reject_text 'CONNECTION ESTABLISHED' \
        "$negative_dir/foreign-size-client.log"
}

run_cross_lane() {
    local client_lane=$1
    local client_root=$2
    local server_lane=$3
    local server_root=$4
    local label=$5
    local client_prefix=$client_root/inst/$client_lane
    local server_prefix=$server_root/inst/$server_lane
    local client_openssl=$client_prefix/bin/openssl
    local server_openssl=$server_prefix/bin/openssl
    local client_modules=$RESULT_ROOT/$client_lane/modules
    local server_modules=$RESULT_ROOT/$server_lane/modules
    local server_cert=$RESULT_ROOT/$server_lane/cert.pem
    local server_key=$RESULT_ROOT/$server_lane/key.pem
    local cross=$RESULT_ROOT/$label

    mkdir -m 700 -p "$cross"
    printf 'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n' \
        >"$cross/request.txt"
    start_server "$server_openssl" "$server_prefix" "$server_modules" \
        "$cross" "$server_cert" "$server_key" \
        X301MLKEM1024 1 yes "$label"
    run_client "$client_openssl" "$client_prefix" "$client_modules" \
        "$cross" "$server_cert" X301MLKEM1024 "$label"
    require_text 'New, TLSv1.3' "$cross/$label-client.log"
    require_text 'Protocol: TLSv1.3' "$cross/$label-client.log"
    require_text 'Negotiated TLS1.3 group: X301MLKEM1024' \
        "$cross/$label-client.log"
    require_text 'Verification: OK' "$cross/$label-client.log"
    finish_server yes
    (
        cd "$cross"
        /usr/bin/sha256sum "$(basename "$cross/$label-client.log")" \
            "$(basename "$SERVER_LOG")" >SHA256SUMS
        /usr/bin/sha256sum --strict --quiet -c SHA256SUMS
    )
    printf 'PASS client=%s server=%s group=X301MLKEM1024\n' \
        "$client_lane" "$server_lane" >"$cross/STATUS.txt"
}

run_long_handshake_lane() {
    local openssl=$1
    local prefix=$2
    local modules=$3
    local parent=$4
    local cert=$5
    local key=$6
    local count=$7
    local long=$parent/l2-long-handshakes
    local iteration

    test "$count" -gt 0 || return 0
    mkdir -m 700 -p "$long"
    printf 'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n' \
        >"$long/request.txt"
    printf 'iteration\tresult\n' >"$long/RESULTS.tsv"

    # L2 full lane: every invocation creates a new process and a new TLS 1.3
    # connection; the server offers only X301MLKEM1024, so success proves a
    # complete fresh hybrid handshake rather than fallback.
    start_server "$openssl" "$prefix" "$modules" "$long" \
        "$cert" "$key" X301MLKEM1024 "$count" yes l2-full
    for iteration in $(/usr/bin/seq 1 "$count"); do
        run_client "$openssl" "$prefix" "$modules" "$long" "$cert" \
            X301MLKEM1024 current -brief
        require_text 'Negotiated TLS1.3 group: X301MLKEM1024' \
            "$long/current-client.log"
        require_text 'Verification: OK' "$long/current-client.log"
        if test "$iteration" -eq 1; then
            cp "$long/current-client.log" "$long/first-client.log"
        fi
        printf '%s\tPASS\n' "$iteration" >>"$long/RESULTS.tsv"
    done
    cp "$long/current-client.log" "$long/last-client.log"
    finish_server yes
    test "$(/usr/bin/awk 'END { print NR - 1 }' "$long/RESULTS.tsv")" \
        -eq "$count"

    # Reduced memory-safety lane: s_client performs the initial connection
    # and five reconnects in one Valgrind process, exercising module reuse,
    # TLS resumption and repeated hybrid key shares without multiplying the
    # already-complete 1,000-connection runtime.
    start_server "$openssl" "$prefix" "$modules" "$long" \
        "$cert" "$key" X301MLKEM1024 6 yes l2-valgrind
    env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$long" \
        OPENSSL_CONF=/dev/null OPENSSL_MODULES="$modules" \
        LD_LIBRARY_PATH="$prefix/lib" \
        /usr/bin/timeout 300 /usr/bin/valgrind --tool=memcheck --vgdb=no \
            --error-exitcode=99 --track-origins=yes \
            --undef-value-errors=yes --leak-check=full \
            --errors-for-leak-kinds=definite,indirect,possible --quiet \
            "$openssl" s_client \
                -connect "127.0.0.1:$CLIENT_PORT" -tls1_3 \
                -groups X301MLKEM1024 -servername localhost \
                -verify_hostname localhost -verify_return_error \
                -CAfile "$cert" -provider default -provider x301 \
                -reconnect -brief <"$long/request.txt" \
                >"$long/valgrind-client.log" 2>&1
    require_text 'Negotiated TLS1.3 group: X301MLKEM1024' \
        "$long/valgrind-client.log"
    require_text 'Verification: OK' "$long/valgrind-client.log"
    finish_server yes

    (
        cd "$long"
        /usr/bin/sha256sum RESULTS.tsv first-client.log last-client.log \
            valgrind-client.log >SHA256SUMS
        /usr/bin/sha256sum --strict --quiet -c SHA256SUMS
    )
    printf 'PASS full_hybrid_handshakes=%s valgrind_connections=6\n' \
        "$count" | tee "$long/STATUS.txt"
}

run_lane() {
    local lane=$1
    local lane_root=$2
    local lane_evidence=$3
    local prefix=$lane_root/inst/$lane
    local openssl=$prefix/bin/openssl
    local build=$RESULT_ROOT/$lane
    local target=$build/target
    local alias_target=$build/target-alias
    local modules=$build/modules
    local alias_modules=$build/modules-alias
    local cargo_home=$build/cargo-home
    local cert=$build/cert.pem
    local key=$build/key.pem
    local first_mlkem resumed_mlkem first_x301 resumed_x301
    local alias_dir alias_label alias_mask client_status

    "$ROOT/scripts/verify-openssl-provider-lane.sh" \
        "$lane_root" "$lane" "$lane_evidence"
    test -x "$openssl" || fail "missing normative OpenSSL $lane executable"
    test -x "$KEYSHARE_PARSER" || fail "missing executable $KEYSHARE_PARSER"
    test -x "$TRACE_INSPECTOR" || fail "missing executable $TRACE_INSPECTOR"
    test -x "$WIRE_MUTATOR" || fail "missing executable $WIRE_MUTATOR"
    mkdir -m 700 -p \
        "$target" "$alias_target" "$modules" "$alias_modules" \
        "$cargo_home" "$build"
    printf 'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n' \
        >"$build/request.txt"

    printf 'lane=%s\nprefix=%s\nbuild=%s\n' "$lane" "$prefix" "$build"
    LD_LIBRARY_PATH="$prefix/lib" "$openssl" version -a \
        >"$build/openssl-version.txt"

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
    ) >"$build/cargo-build.log" 2>&1
    cp "$target/release/libx301.so" "$modules/x301.so"
    /usr/bin/nm -C "$modules/x301.so" >"$build/x301.nm-C.txt"
    require_text 'ed301_eddsa::x301' "$build/x301.nm-C.txt"
    (
        cd "$build"
        /usr/bin/sha256sum modules/x301.so >PREUSE_SHA256SUMS
        /usr/bin/sha256sum --strict --quiet -c PREUSE_SHA256SUMS
    )

    (
        cd "$ROOT/provider"
        env -i PATH="$RUST_BIN:/usr/bin:/bin" HOME="$build" LC_ALL=C \
            CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$alias_target" \
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
    ) >"$build/cargo-build-alias.log" 2>&1
    cp "$alias_target/release/libx301.so" "$alias_modules/x301.so"
    reject_text X301_PROVIDER_PUBLIC_ALIAS_MASK "$modules/x301.so"
    require_text X301_PROVIDER_PUBLIC_ALIAS_MASK "$alias_modules/x301.so"

    env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$build" \
        OPENSSL_CONF=/dev/null LD_LIBRARY_PATH="$prefix/lib" \
        "$openssl" req -x509 -newkey rsa:2048 -nodes -sha256 \
            -subj /CN=localhost -addext subjectAltName=DNS:localhost \
            -keyout "$key" -out "$cert" -days 1 \
            >"$build/certificate-generation.log" 2>&1

    alias_dir=$build/d2-alias
    mkdir -m 700 -- "$alias_dir"
    printf 'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n' \
        >"$alias_dir/request.txt"
    printf 'mask\tclient\tserver\n' >"$alias_dir/RESULTS.tsv"
    for alias_mask in 20 40 60 80 a0 c0 e0; do
        PUBLIC_ALIAS_MASK=$alias_mask
        alias_label=d2-alias-$alias_mask
        start_server "$openssl" "$prefix" "$alias_modules" \
            "$alias_dir" "$cert" "$key" X301MLKEM1024 1 yes \
            "$alias_label"
        run_client "$openssl" "$prefix" "$alias_modules" \
            "$alias_dir" "$cert" X301MLKEM1024 "$alias_label" \
            -msg -msgfile "$alias_dir/$alias_label.msg"
        require_text 'Negotiated TLS1.3 group: X301MLKEM1024' \
            "$alias_dir/$alias_label-client.log"
        "$KEYSHARE_PARSER" "$alias_dir/$alias_label.msg" client \
            | tee "$alias_dir/$alias_label-client-keyshare.txt"
        require_text "x301_unused_bits=0x$alias_mask" \
            "$alias_dir/$alias_label-client-keyshare.txt"
        "$KEYSHARE_PARSER" "$alias_dir/$alias_label.msg" server \
            | tee "$alias_dir/$alias_label-server-keyshare.txt"
        require_text "x301_unused_bits=0x$alias_mask" \
            "$alias_dir/$alias_label-server-keyshare.txt"
        finish_server yes
        printf '%s\tPASS\tPASS\n' "$alias_mask" \
            >>"$alias_dir/RESULTS.tsv"
    done
    PUBLIC_ALIAS_MASK=
    (
        cd "$alias_dir"
        find . -type f ! -name SHA256SUMS -exec sha256sum {} + | sort -k2 \
            >SHA256SUMS
        /usr/bin/sha256sum --strict --quiet -c SHA256SUMS
    )

    # Full hybrid handshake followed by TLS 1.3 ticket resumption.  Both
    # component public values must be newly generated for the new ClientHello.
    start_server "$openssl" "$prefix" "$modules" "$build" "$cert" "$key" \
        X301MLKEM1024 2 yes hybrid
    run_client "$openssl" "$prefix" "$modules" "$build" "$cert" \
        X301MLKEM1024 hybrid-initial \
        -sess_out "$build/session.pem" -ign_eof -nocommands -msg \
        -msgfile "$build/hybrid-initial.msg"
    test -s "$build/session.pem" || fail "initial handshake produced no session"
    require_text 'New, TLSv1.3' "$build/hybrid-initial-client.log"
    require_text 'Protocol: TLSv1.3' "$build/hybrid-initial-client.log"
    require_text 'Negotiated TLS1.3 group: X301MLKEM1024' \
        "$build/hybrid-initial-client.log"
    require_text 'Verification: OK' "$build/hybrid-initial-client.log"
    "$KEYSHARE_PARSER" "$build/hybrid-initial.msg" \
        | tee "$build/hybrid-initial-keyshare.txt"

    run_client "$openssl" "$prefix" "$modules" "$build" "$cert" \
        X301MLKEM1024 hybrid-resumed \
        -sess_in "$build/session.pem" -ign_eof -nocommands -msg \
        -msgfile "$build/hybrid-resumed.msg"
    require_text 'Reused, TLSv1.3' "$build/hybrid-resumed-client.log"
    require_text 'Protocol: TLSv1.3' "$build/hybrid-resumed-client.log"
    require_text 'Negotiated TLS1.3 group: X301MLKEM1024' \
        "$build/hybrid-resumed-client.log"
    require_text 'Verification: OK' "$build/hybrid-resumed-client.log"
    "$KEYSHARE_PARSER" "$build/hybrid-resumed.msg" \
        | tee "$build/hybrid-resumed-keyshare.txt"
    finish_server yes

    first_mlkem=$(field_value mlkem_sha256 "$build/hybrid-initial-keyshare.txt")
    resumed_mlkem=$(field_value mlkem_sha256 "$build/hybrid-resumed-keyshare.txt")
    first_x301=$(field_value x301_sha256 "$build/hybrid-initial-keyshare.txt")
    resumed_x301=$(field_value x301_sha256 "$build/hybrid-resumed-keyshare.txt")
    test -n "$first_mlkem" && test -n "$resumed_mlkem" \
        || fail "missing ML-KEM KeyShare digest"
    test -n "$first_x301" && test -n "$resumed_x301" \
        || fail "missing X301 KeyShare digest"
    test "$first_mlkem" != "$resumed_mlkem" \
        || fail "ML-KEM component was reused across session resumption"
    test "$first_x301" != "$resumed_x301" \
        || fail "X301 component was reused across session resumption"

    # R2: the first ClientHello carries only X25519 while advertising both
    # groups.  The hybrid-only server selects 0xFE2E in HRR, and the second
    # ClientHello must contain one exact 1606-byte hybrid share.
    start_server "$openssl" "$prefix" "$modules" "$build" "$cert" "$key" \
        X301MLKEM1024 1 yes hrr
    run_client "$openssl" "$prefix" "$modules" "$build" "$cert" \
        X25519:X301MLKEM1024 hrr -msg -msgfile "$build/hrr.msg"
    require_text 'Negotiated TLS1.3 group: X301MLKEM1024' \
        "$build/hrr-client.log"
    "$TRACE_INSPECTOR" --hrr "$build/hrr.msg" \
        | tee "$build/hrr-inspection.txt"
    finish_server yes

    # R3: force the 1778-byte ClientHello into <=512-byte TLS records and
    # prove both the record split and the intact 1606-byte inner share.
    start_server "$openssl" "$prefix" "$modules" "$build" "$cert" "$key" \
        X301MLKEM1024 1 yes fragmented
    run_client "$openssl" "$prefix" "$modules" "$build" "$cert" \
        X301MLKEM1024 fragmented -max_send_frag 512 \
        -msg -msgfile "$build/fragmented.msg"
    require_text 'Negotiated TLS1.3 group: X301MLKEM1024' \
        "$build/fragmented-client.log"
    "$TRACE_INSPECTOR" --fragment-max 512 "$build/fragmented.msg" \
        | tee "$build/fragmented-inspection.txt"
    finish_server yes

    # The peer has no x301 provider.  Offering hybrid first and X25519 second
    # must therefore complete using the common RFC 9846 group X25519.
    start_server "$openssl" "$prefix" "$modules" "$build" "$cert" "$key" \
        X25519 1 no fallback
    run_client "$openssl" "$prefix" "$modules" "$build" "$cert" \
        X301MLKEM1024:X25519 fallback -brief
    require_text 'Protocol version: TLSv1.3' "$build/fallback-client.log"
    require_text 'Peer Temp Key: X25519,' "$build/fallback-client.log"
    require_text 'Verification: OK' "$build/fallback-client.log"
    reject_text 'X301MLKEM1024' "$build/fallback-client.log"
    finish_server yes

    # With no common group RFC 9846 requires handshake failure; there must be
    # neither an established connection nor a negotiated-group claim.
    start_server "$openssl" "$prefix" "$modules" "$build" "$cert" "$key" \
        X25519 1 no no-common
    if run_client "$openssl" "$prefix" "$modules" "$build" "$cert" \
            X301MLKEM1024 no-common -brief -msg \
            -msgfile "$build/no-common.msg"; then
        fail "handshake without a common group unexpectedly succeeded"
    else
        client_status=$?
    fi
    test "$client_status" -eq 1 \
        || fail "no-common client exit status is $client_status, expected 1"
    reject_text 'CONNECTION ESTABLISHED' "$build/no-common-client.log"
    reject_text 'Negotiated TLS1.3 group:' "$build/no-common-client.log"
    require_text 'Alert' "$build/no-common.msg"
    finish_server no

    # R5: 64 uniformly distributed deterministic single-bit mutations in
    # each required wire component.  Each reaches protected-record
    # authentication and fails; server-ciphertext cases thereby preserve
    # FIPS 203 implicit rejection rather than becoming an explicit KEM error.
    run_mutation_matrix "$openssl" "$prefix" "$modules" "$build" \
        "$cert" "$key" client mlkem client-mlkem
    run_mutation_matrix "$openssl" "$prefix" "$modules" "$build" \
        "$cert" "$key" client x301 client-x301
    run_mutation_matrix "$openssl" "$prefix" "$modules" "$build" \
        "$cert" "$key" server mlkem server-mlkem

    # R6: retain the X301MLKEM1024 codepoint but shrink the syntactically
    # well-formed KeyShareEntry to X25519MLKEM768's 1216-byte layout.
    run_foreign_size_negative "$openssl" "$prefix" "$modules" "$build" \
        "$cert" "$key"

    run_long_handshake_lane "$openssl" "$prefix" "$modules" "$build" \
        "$cert" "$key" "$LONG_HANDSHAKES"

    (
        cd "$build"
        /usr/bin/sha256sum --strict --quiet -c PREUSE_SHA256SUMS
        /usr/bin/sha256sum \
            modules/x301.so \
            modules-alias/x301.so \
            PREUSE_SHA256SUMS \
            hybrid-initial.msg \
            hybrid-resumed.msg \
            hrr.msg \
            hrr-inspection.txt \
            fragmented.msg \
            fragmented-inspection.txt \
            hybrid-initial-client.log \
            hybrid-resumed-client.log \
            fallback-client.log \
            no-common-client.log \
            r5-client-mlkem/RESULTS.tsv \
            r5-client-mlkem/SHA256SUMS \
            r5-client-x301/RESULTS.tsv \
            r5-client-x301/SHA256SUMS \
            r5-server-mlkem/RESULTS.tsv \
            r5-server-mlkem/SHA256SUMS \
            r6-foreign-size/foreign-size-client.log \
            r6-foreign-size/foreign-size-proxy.log >SHA256SUMS
        /usr/bin/sha256sum \
            d2-alias/RESULTS.tsv d2-alias/SHA256SUMS >>SHA256SUMS
    )
    if test "$LONG_HANDSHAKES" -gt 0; then
        (
            cd "$build"
            /usr/bin/sha256sum \
                l2-long-handshakes/STATUS.txt \
                l2-long-handshakes/SHA256SUMS \
                l2-long-handshakes/l2-full-server.log \
                l2-long-handshakes/l2-valgrind-server.log \
                >>SHA256SUMS
        )
    fi
    (cd "$build" && /usr/bin/sha256sum --strict --quiet -c SHA256SUMS)
    printf '%s\n' \
        "PASS lane=$lane lane_evidence_sha256=$lane_evidence t8_hybrid=PASS r2_hrr=PASS r3_fragmentation=PASS" \
        'r4_fallback=PASS r4_no_common=PASS r5_client_mlkem=64/64 r5_client_x301=64/64' \
        "r5_server_mlkem=64/64 r6_foreign_size=PASS r7_resumption=PASS r7_fresh_mlkem=PASS r7_fresh_x301=PASS d2_aliases=7/7 l2_full_handshakes=$LONG_HANDSHAKES" \
        | tee "$build/STATUS.txt"
}

record_run_identity
run_lane 3.5.7 "$LANE_357_ROOT" "$LANE_357_EVIDENCE"
run_lane 4.0.1 "$LANE_401_ROOT" "$LANE_401_EVIDENCE"
run_cross_lane 3.5.7 "$LANE_357_ROOT" 4.0.1 "$LANE_401_ROOT" \
    cross-357-client-401-server
run_cross_lane 4.0.1 "$LANE_401_ROOT" 3.5.7 "$LANE_357_ROOT" \
    cross-401-client-357-server
sh "$ROOT/scripts/verify-openssl-provider-lane.sh" \
    "$LANE_357_ROOT" 3.5.7 "$LANE_357_EVIDENCE"
sh "$ROOT/scripts/verify-openssl-provider-lane.sh" \
    "$LANE_401_ROOT" 4.0.1 "$LANE_401_EVIDENCE"
for lane_root in "$LANE_357_ROOT" "$LANE_401_ROOT"; do
    (cd "$lane_root" && \
        sha256sum --strict --quiet -c PRIVATE_LANE_SHA256SUMS.seal && \
        sha256sum --strict --quiet -c PRIVATE_LANE_SHA256SUMS)
done
(cd "$RESULT_ROOT" && sha256sum \
    X301_SOURCE_SHA256SUMS TOOLCHAIN.txt RUN_INPUTS.tsv inputs/*.sha256 \
    >RUN_IDENTITY_SHA256SUMS
    sha256sum --strict --quiet -c RUN_IDENTITY_SHA256SUMS)
sh "$ROOT/scripts/require-verified-snapshot.sh"
printf 'PASS X301 TLS R1-R7 both_lanes=2 cross_lanes=2 result=%s\n' "$RESULT_ROOT" \
    | tee "$RESULT_ROOT/STATUS.txt"
