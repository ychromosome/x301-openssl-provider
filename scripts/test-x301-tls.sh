#!/bin/bash
# Dual-lane X301 T8 CLI contract runner.
#
# Contract sources: RFC 9846 Sections 4.3.7-4.3.8 and 4.6.1 (TLS 1.3
# NamedGroup, fresh KeyShare, and session tickets), RFC 9954 (hybrid design),
# RFC 10024 Sections 4-5 (ML-KEM-first key-share construction), FIPS 203
# (ML-KEM-1024), and the OpenSSL 3.5.7/4.0.1 s_client/s_server contracts.

set -Eeuo pipefail

PATH=/usr/bin:/bin
export PATH LC_ALL=C
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
KEYSHARE_PARSER=$ROOT/provider-tests/x301/extract_x301_client_keyshare.py
WIRE_MUTATOR=$ROOT/provider-tests/x301/mutate_x301_mlkem_server_ciphertext.py
SERVER_PID=
SERVER_LOG=
SERVER_PORT=
CLIENT_PORT=
PROXY_PID=
PROXY_LOG=

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

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

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

    cleanup_server
    if test "$load_x301" = yes; then
        provider_args+=(-provider x301)
    fi
    SERVER_LOG=$home/$label-server.log

    for attempt in 1 2 3; do
        SERVER_PORT=$(choose_port)
        CLIENT_PORT=$SERVER_PORT
        : >"$SERVER_LOG"
        env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$home" \
            OPENSSL_CONF=/dev/null OPENSSL_MODULES="$modules" \
            LD_LIBRARY_PATH="$prefix/lib" \
            /usr/bin/timeout 45 \
            "$openssl" s_server \
                -accept "127.0.0.1:$SERVER_PORT" -tls1_3 \
                -groups "$groups" -cert "$cert" -key "$key" \
                -www -num_tickets 1 -naccept "$accepts" \
                "${provider_args[@]}" >"$SERVER_LOG" 2>&1 &
        SERVER_PID=$!

        for _ in $(/usr/bin/seq 1 100); do
            if /usr/sbin/ss -H -ltn "sport = :$SERVER_PORT" \
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
    local proxy_port

    test -z "$PROXY_PID" || fail "wire mutator is already running"
    proxy_port=$(choose_port)
    PROXY_LOG=$home/mlkem-wire-mutation-proxy.log
    : >"$PROXY_LOG"
    /usr/bin/python3 -u "$WIRE_MUTATOR" \
        --listen-port "$proxy_port" --upstream-port "$SERVER_PORT" \
        >"$PROXY_LOG" 2>&1 &
    PROXY_PID=$!
    CLIENT_PORT=$proxy_port

    for _ in $(/usr/bin/seq 1 100); do
        if /usr/sbin/ss -H -ltn "sport = :$proxy_port" \
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

run_lane() {
    local lane=$1
    local lane_root=$2
    local lane_evidence=$3
    local prefix=$lane_root/inst/$lane
    local openssl=$prefix/bin/openssl
    local build=$RESULT_ROOT/$lane
    local target=$build/target
    local modules=$build/modules
    local cargo_home=$build/cargo-home
    local cert=$build/cert.pem
    local key=$build/key.pem
    local first_mlkem resumed_mlkem first_x301 resumed_x301
    local client_status

    "$ROOT/scripts/verify-openssl-provider-lane.sh" \
        "$lane_root" "$lane" "$lane_evidence"
    test -x "$openssl" || fail "missing normative OpenSSL $lane executable"
    test -x "$KEYSHARE_PARSER" || fail "missing executable $KEYSHARE_PARSER"
    test -x "$WIRE_MUTATOR" || fail "missing executable $WIRE_MUTATOR"
    mkdir -m 700 -p "$target" "$modules" "$cargo_home" "$build"
    printf 'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n' \
        >"$build/request.txt"

    printf 'lane=%s\nprefix=%s\nbuild=%s\n' "$lane" "$prefix" "$build"
    LD_LIBRARY_PATH="$prefix/lib" "$openssl" version -a \
        >"$build/openssl-version.txt"

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
    ) >"$build/cargo-build.log" 2>&1
    cp "$target/release/libx301.so" "$modules/x301.so"
    /usr/bin/nm -C "$modules/x301.so" >"$build/x301.nm-C.txt"
    require_text 'ed301_eddsa::x301' "$build/x301.nm-C.txt"

    env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$build" \
        OPENSSL_CONF=/dev/null LD_LIBRARY_PATH="$prefix/lib" \
        "$openssl" req -x509 -newkey rsa:2048 -nodes -sha256 \
            -subj /CN=localhost -addext subjectAltName=DNS:localhost \
            -keyout "$key" -out "$cert" -days 1 \
            >"$build/certificate-generation.log" 2>&1

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

    # T9 wire proof: flip one bit only in the ML-KEM ciphertext portion of the
    # ServerHello KeyShare.  FIPS 203 implicit rejection must remain internal:
    # the ServerHello is accepted, then the mismatched TLS handshake key causes
    # failure while decrypting the protected post-ServerHello flight.
    start_server "$openssl" "$prefix" "$modules" "$build" "$cert" "$key" \
        X301MLKEM1024 1 yes mlkem-wire-mutation
    start_wire_mutator "$build"
    if run_client "$openssl" "$prefix" "$modules" "$build" "$cert" \
            X301MLKEM1024 mlkem-wire-mutation -brief -msg \
            -msgfile "$build/mlkem-wire-mutation.msg"; then
        fail "ML-KEM ciphertext mutation unexpectedly completed a handshake"
    else
        client_status=$?
    fi
    test "$client_status" -eq 1 \
        || fail "ML-KEM mutation client status is $client_status, expected 1"
    finish_wire_mutator
    finish_server no
    require_text 'mutated=1 group=0xfe2e key_exchange_length=1606 component=mlkem' \
        "$build/mlkem-wire-mutation-proxy.log"
    require_text 'encrypted_records_after_mutation=' \
        "$build/mlkem-wire-mutation-proxy.log"
    require_text 'bad record mac' "$build/mlkem-wire-mutation-client.log"
    reject_text 'CONNECTION ESTABLISHED' "$build/mlkem-wire-mutation-client.log"
    reject_text 'Negotiated TLS1.3 group:' "$build/mlkem-wire-mutation-client.log"

    /usr/bin/sha256sum \
        "$modules/x301.so" \
        "$build/hybrid-initial.msg" \
        "$build/hybrid-resumed.msg" \
        "$build/hybrid-initial-client.log" \
        "$build/hybrid-resumed-client.log" \
        "$build/fallback-client.log" \
        "$build/no-common-client.log" \
        "$build/mlkem-wire-mutation-client.log" \
        "$build/mlkem-wire-mutation-proxy.log" >"$build/SHA256SUMS"
    printf '%s\n' \
        "PASS lane=$lane lane_evidence_sha256=$lane_evidence t8_hybrid=PASS t8_resumption=PASS" \
        't8_fresh_mlkem=PASS t8_fresh_x301=PASS t8_fallback=PASS t8_no_common=PASS' \
        't9_mlkem_wire_implicit_rejection=PASS' \
        | tee "$build/STATUS.txt"
}

record_run_identity
run_lane 3.5.7 "$LANE_357_ROOT" "$LANE_357_EVIDENCE"
run_lane 4.0.1 "$LANE_401_ROOT" "$LANE_401_EVIDENCE"
sha256sum "$RESULT_ROOT/X301_SOURCE_SHA256SUMS" \
    "$RESULT_ROOT/TOOLCHAIN.txt" "$RESULT_ROOT/RUN_INPUTS.tsv" \
    >"$RESULT_ROOT/RUN_IDENTITY_SHA256SUMS"
printf 'PASS X301 T8 both_lanes=2 result=%s\n' "$RESULT_ROOT" \
    | tee "$RESULT_ROOT/STATUS.txt"
