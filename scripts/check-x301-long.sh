#!/bin/sh
# Separate L1 gate: RFC-7748-shaped one-million X301 iterations.

set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
sh "$ROOT/scripts/require-verified-snapshot.sh"
sh "$ROOT/scripts/check-rust-build-environment.sh"
case "$ROOT" in
    *"'"*) echo "source snapshot path may not contain an apostrophe" >&2; exit 2 ;;
esac

WORK=$(mktemp -d /tmp/ed301-x301-long.XXXXXX)
HOME_DIR=$WORK/home
CARGO_HOME_DIR=$WORK/cargo-home
TARGET_DIR=$WORK/target
mkdir -m 700 "$HOME_DIR" "$CARGO_HOME_DIR" "$TARGET_DIR"
{
    printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' \
        '' '[source.vendored-sources]'
    printf "directory = '%s'\n" "$ROOT/vendor"
    printf '%s\n' '' '[net]' 'offline = true'
} >"$CARGO_HOME_DIR/config.toml"
chmod 600 "$CARGO_HOME_DIR/config.toml"
cleanup() {
    rm -rf -- "$WORK"
}
trap cleanup EXIT HUP INT TERM

/usr/bin/python3 -I -B -O "$ROOT/reference/x301/x301_reference.py" \
    verify-long-iteration \
    --path "$ROOT/reference/x301/x301-long-iteration.json"

(cd / && env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" LC_ALL=C \
    CARGO_HOME="$CARGO_HOME_DIR" CARGO_TARGET_DIR="$TARGET_DIR" \
    CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 CCACHE_DISABLE=1 \
    /usr/bin/cargo test --manifest-path "$ROOT/Cargo.toml" \
        --locked --offline --release --workspace --features x301 \
        x301_tests::rfc_style_iteration_result_is_frozen_at_one_million \
        -- --ignored --exact)

sh "$ROOT/scripts/require-verified-snapshot.sh"
printf 'x301_long_gate=PASS iterations=1000000\n'
