#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
for tool in cp ln mkfifo mktemp tar; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing source-gate regression tool: $tool" >&2
        exit 127
    }
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/ed301-source-gate-test.XXXXXX")
cleanup() {
    rm -rf -- "$TMP"
}
trap cleanup EXIT HUP INT TERM

BASE=$TMP/base
mkdir -p "$BASE"
(
    cd "$ROOT"
    {
        printf '%s\n' SOURCE_MANIFEST.sha256
        awk '{ print substr($0, 67) }' SOURCE_MANIFEST.sha256
    } | tar -cf "$TMP/source.tar" -T -
)
tar -xf "$TMP/source.tar" -C "$BASE"
chmod -R u+w "$BASE"
EXPECTED=$(sha256sum "$BASE/SOURCE_MANIFEST.sha256" | awk '{ print $1 }')

ED301_SOURCE_MODE=archive \
ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$BASE/scripts/verify-source-tree.sh" >/dev/null

new_case() {
    CASE=$TMP/case-$1
    mkdir -p "$CASE"
    cp -a "$BASE/." "$CASE/"
    chmod -R u+w "$CASE"
}

install_build_sentinel() {
    manifest=$CASE/crates/ed301-eddsa/Cargo.toml
    sentinel=$CASE/crates/ed301-eddsa/cargo-was-reached
    sed 's/^build = false$/build = "build.rs"/' "$manifest" \
        >"$manifest.new"
    mv "$manifest.new" "$manifest"
    printf '%s\n' \
        'fn main() {' \
        '    std::fs::write(' \
        '        concat!(env!("CARGO_MANIFEST_DIR"), "/cargo-was-reached"),' \
        '        b"cargo reached\\n",' \
        '    ).unwrap();' \
        '}' >"$CASE/crates/ed301-eddsa/build.rs"
}

must_reject() {
    label=$1
    shift
    if "$@" >"$TMP/$label.log" 2>&1; then
        echo "source gate accepted malicious case: $label" >&2
        exit 1
    fi
}

must_reject missing-anchor-verifier env \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256= \
    sh "$BASE/scripts/verify-source-tree.sh"
grep -Fqx \
    'ED301_EXPECTED_SOURCE_MANIFEST_SHA256 must be an external lowercase SHA-256' \
    "$TMP/missing-anchor-verifier.log"

new_case missing-anchor-callers
install_build_sentinel
SENTINEL=$CASE/crates/ed301-eddsa/cargo-was-reached
for gate in scripts/check.sh scripts/check-downstream.sh \
        scripts/check-secret-taint.sh; do
    label="missing-anchor-$(basename "$gate")"
    rm -f "$SENTINEL"
    must_reject "$label" env \
        ED301_SOURCE_MODE=archive \
        ED301_VERIFIED_SNAPSHOT=1 \
        ED301_EXPECTED_SOURCE_MANIFEST_SHA256= \
        sh "$CASE/$gate"
    grep -Fqx 'verified snapshot requires an external manifest digest' \
        "$TMP/$label.log"
    if [ -e "$SENTINEL" ]; then
        echo "$gate ran an actual Rust build script without an anchor" >&2
        exit 1
    fi
done

new_case build-script
printf '%s\n' 'fn main() { panic!("must not execute"); }' \
    >"$CASE/crates/ed301-eddsa/build.rs"
must_reject build-script env ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

for kind in tests examples benches; do
    new_case "$kind"
    mkdir -p "$CASE/crates/ed301-eddsa/$kind"
    printf '%s\n' '#![allow(dead_code)]' \
        >"$CASE/crates/ed301-eddsa/$kind/unlisted.rs"
    must_reject "$kind" env \
        ED301_SOURCE_MODE=archive \
        ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
        sh "$CASE/scripts/verify-source-tree.sh"
done

new_case symlink
ln -s README.md "$CASE/unlisted-link"
must_reject symlink env ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case reserved-target-symlink
ln -s README.md "$CASE/target"
must_reject reserved-target-symlink env \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case reserved-target-file
printf '%s\n' 'not a build directory' >"$CASE/target"
must_reject reserved-target-file env \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case reserved-target-directory
mkdir "$CASE/target"
printf '%s\n' 'untrusted prior artifact' >"$CASE/target/injected"
must_reject reserved-target-directory env \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case fifo
mkfifo "$CASE/unlisted-fifo"
must_reject fifo env ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case empty-directory
mkdir "$CASE/unlisted-directory"
must_reject empty-directory env \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case missing-file
rm "$CASE/README.md"
must_reject missing-file env \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case altered-manifest
printf '%s\n' '# attacker-controlled replacement' \
    >>"$CASE/SOURCE_MANIFEST.sha256"
must_reject altered-manifest env \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
    sh "$CASE/scripts/verify-source-tree.sh"

new_case caller-order
install_build_sentinel
SENTINEL=$CASE/crates/ed301-eddsa/cargo-was-reached
for gate in scripts/check.sh scripts/check-downstream.sh \
        scripts/check-secret-taint.sh; do
    rm -f "$SENTINEL"
    must_reject "caller-$(basename "$gate")" env \
        ED301_SOURCE_MODE=archive \
        ED301_VERIFIED_SNAPSHOT=1 \
        ED301_EXPECTED_SOURCE_MANIFEST_SHA256=$EXPECTED \
        sh "$CASE/$gate"
    if [ -e "$SENTINEL" ]; then
        echo "$gate ran an actual Rust build script before rejection" >&2
        exit 1
    fi
done

printf 'source_tree_gate_regressions=PASS cases=19\n'
