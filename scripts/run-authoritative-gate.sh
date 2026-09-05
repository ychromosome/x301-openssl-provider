#!/usr/bin/env -S -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C X301_LAUNCH_STAGE=clean /bin/sh
set -eu

if [ "${X301_LAUNCH_STAGE:-}" != clean ]; then
    exec /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent LC_ALL=C \
        X301_LAUNCH_STAGE=clean /bin/sh "$0" "$@"
fi
unset X301_LAUNCH_STAGE

PATH=/usr/bin:/bin
HOME=/nonexistent
LC_ALL=C
export PATH HOME LC_ALL
umask 077

ROOT=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")/.." && /bin/pwd -P)

usage() {
    echo "usage: $0 archive <manifest-sha256> <gate> [gate-arguments...]" >&2
    echo "       $0 git <manifest-sha256> <commit> verify-source-tree" >&2
    exit 2
}

[ "$#" -ge 3 ] || usage
MODE=$1
MANIFEST_DIGEST=$2
shift 2

[ "${#MANIFEST_DIGEST}" -eq 64 ] || usage
case "$MANIFEST_DIGEST" in *[!0-9a-f]*) usage ;; esac

ED301_HERMETIC_LAUNCH=1
ED301_SOURCE_MODE=$MODE
ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$MANIFEST_DIGEST
export ED301_HERMETIC_LAUNCH ED301_SOURCE_MODE
export ED301_EXPECTED_SOURCE_MANIFEST_SHA256

case "$MODE" in
    archive)
        ED301_VERIFIED_SNAPSHOT=1
        export ED301_VERIFIED_SNAPSHOT
        ;;
    git)
        [ "$#" -eq 2 ] || usage
        ED301_EXPECTED_GIT_COMMIT=$1
        [ "${#ED301_EXPECTED_GIT_COMMIT}" -eq 40 ] || usage
        case "$ED301_EXPECTED_GIT_COMMIT" in *[!0-9a-f]*) usage ;; esac
        export ED301_EXPECTED_GIT_COMMIT
        shift
        [ "$1" = verify-source-tree ] || usage
        ;;
    *) usage ;;
esac

GATE=$1
shift
TARGET_SHELL=/bin/sh
case "$GATE" in
    environment-check)
        TARGET=$ROOT/scripts/check-rust-build-environment.sh
        ;;
    verify-source-tree)
        TARGET=$ROOT/scripts/verify-source-tree.sh
        ;;
    check)
        TARGET=$ROOT/scripts/check.sh
        ;;
    check-downstream)
        TARGET=$ROOT/scripts/check-downstream.sh
        ;;
    check-secret-taint)
        TARGET=$ROOT/scripts/check-secret-taint.sh
        ;;
    check-x301-long)
        TARGET=$ROOT/scripts/check-x301-long.sh
        ;;
    check-x301-final-codegen)
        TARGET=$ROOT/scripts/check-x301-final-codegen.sh
        ;;
    check-x301-timing)
        if [ "${1:-}" = --measurements ] && [ "$#" -ge 2 ]; then
            X301_TIMING_MEASUREMENTS=$2
            export X301_TIMING_MEASUREMENTS
            shift 2
        fi
        TARGET=$ROOT/scripts/check-x301-timing.sh
        ;;
    run-x301-fuzz)
        while [ "$#" -ge 2 ]; do
            case "$1" in
                --target-dir)
                    X301_FUZZ_TARGET_DIR=$2
                    export X301_FUZZ_TARGET_DIR
                    ;;
                --corpus-dir)
                    X301_FUZZ_CORPUS_DIR=$2
                    export X301_FUZZ_CORPUS_DIR
                    ;;
                --artifact-dir)
                    X301_FUZZ_ARTIFACT_DIR=$2
                    export X301_FUZZ_ARTIFACT_DIR
                    ;;
                *) break ;;
            esac
            shift 2
        done
        TARGET=$ROOT/scripts/run-x301-fuzz.sh
        ;;
    build-openssl-provider-lane)
        TARGET=$ROOT/scripts/build-openssl-provider-lane.sh
        TARGET_SHELL=/bin/bash
        ;;
    verify-openssl-provider-lane)
        TARGET=$ROOT/scripts/verify-openssl-provider-lane.sh
        ;;
    test-x301-provider-contracts)
        if [ "${1:-}" = --result-root ] && [ "$#" -ge 2 ]; then
            X301_CONTRACT_RESULT_ROOT=$2
            export X301_CONTRACT_RESULT_ROOT
            shift 2
        fi
        TARGET=$ROOT/scripts/test-x301-provider-contracts.sh
        TARGET_SHELL=/bin/bash
        ;;
    test-x301-tls)
        while [ "$#" -ge 2 ]; do
            case "$1" in
                --long-handshakes)
                    X301_TLS_LONG_HANDSHAKES=$2
                    export X301_TLS_LONG_HANDSHAKES
                    ;;
                --result-root)
                    X301_TLS_RESULT_ROOT=$2
                    export X301_TLS_RESULT_ROOT
                    ;;
                *) break ;;
            esac
            shift 2
        done
        TARGET=$ROOT/scripts/test-x301-tls.sh
        TARGET_SHELL=/bin/bash
        ;;
    *) usage ;;
esac

if [ "$TARGET_SHELL" = /bin/bash ]; then
    exec /bin/bash --noprofile --norc "$TARGET" "$@"
fi
exec /bin/sh "$TARGET" "$@"
