#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNS=40000
SEED=301

sh "$ROOT_DIR/scripts/check-rust-build-environment.sh"
sh "$ROOT_DIR/scripts/require-verified-snapshot.sh"

while test "$#" -gt 0; do
    case "$1" in
        --runs)
            test "$#" -ge 2 || { echo "missing value for --runs" >&2; exit 2; }
            RUNS=$2
            shift 2
            ;;
        *)
            echo "usage: $0 [--runs COUNT]" >&2
            exit 2
            ;;
    esac
done

case "$RUNS" in
    ''|*[!0-9]*) echo "run count must be a non-negative integer" >&2; exit 2 ;;
esac

CARGO=$($SCRIPT_DIR/resolve-rust-tool.sh cargo)
RUSTC=$($SCRIPT_DIR/resolve-rust-tool.sh rustc)
RUST_BIN=$(dirname -- "$CARGO")
HOST=$($RUSTC --version --verbose | sed -n 's/^host: //p')
test -n "$HOST" || {
    echo "cannot determine rustc host target" >&2
    exit 1
}
TARGET_DIR=${X301_FUZZ_TARGET_DIR:-/tmp/ed301/x301-fuzz-target}
CORPUS_DIR=${X301_FUZZ_CORPUS_DIR:-/tmp/ed301/x301-fuzz-corpus}
ARTIFACT_DIR=${X301_FUZZ_ARTIFACT_DIR:-/tmp/ed301/x301-fuzz-artifacts}
ENV_ROOT=$(mktemp -d /tmp/x301-fuzz-env.XXXXXX)
CARGO_HOME_DIR=$ENV_ROOT/cargo-home
HOME_DIR=$ENV_ROOT/home
cleanup() {
    rm -rf -- "$ENV_ROOT"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$TARGET_DIR" "$CORPUS_DIR" "$ARTIFACT_DIR" \
    "$CARGO_HOME_DIR" "$HOME_DIR"
/usr/bin/python3 -I -B "$ROOT_DIR/scripts/write-cargo-config.py" \
    "$CARGO_HOME_DIR/config.toml" "$ROOT_DIR/vendor"
for seed in "$ROOT_DIR"/fuzz/corpus/x301_core/*; do
    test -f "$seed" || continue
    test -e "$CORPUS_DIR/$(basename -- "$seed")" \
        || cp "$seed" "$CORPUS_DIR/$(basename -- "$seed")"
done

echo "cargo=$($CARGO --version)"
echo "rustc=$($RUSTC --version)"
echo "target=$HOST"
echo "runs=$RUNS"
echo "seed=$SEED"
echo "corpus=$CORPUS_DIR"

(
    cd /
    env -i PATH="$RUST_BIN:/usr/bin:/bin" HOME="$HOME_DIR" LC_ALL=C \
        CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$TARGET_DIR" \
        CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
        CC=/usr/bin/gcc CXX=/usr/bin/g++ AR=/usr/bin/ar RUSTC="$RUSTC" \
        RUSTFLAGS='-C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=3 -C llvm-args=-sanitizer-coverage-inline-8bit-counters -C llvm-args=-sanitizer-coverage-pc-table' \
        "$CARGO" build \
        --offline \
        --manifest-path "$ROOT_DIR/fuzz/Cargo.toml" \
        --bin x301_core \
        --release \
        --target "$HOST"
)

env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    "$TARGET_DIR/$HOST/release/x301_core" \
    -runs="$RUNS" \
    -seed="$SEED" \
    -max_len=76 \
    -timeout=20 \
    -artifact_prefix="$ARTIFACT_DIR/" \
    "$CORPUS_DIR"

sh "$ROOT_DIR/scripts/require-verified-snapshot.sh"
