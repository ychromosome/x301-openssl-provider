#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
if [ "$#" -ne 1 ]; then
    printf 'usage: %s <fresh-output.bundle>\n' "$0" >&2
    exit 2
fi
OUT=$1
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || {
    printf 'output already exists: %s\n' "$OUT" >&2
    exit 2
}

# The source archive remains the build input. This companion carries the
# audited HEAD and its complete reachable parent chain for ancestry checks.
git -C "$ROOT" diff --quiet
git -C "$ROOT" diff --cached --quiet
git -C "$ROOT" bundle create "$OUT" HEAD
git -C "$ROOT" bundle verify "$OUT"
sha256sum "$(readlink -f -- "$OUT")" >"$OUT.sha256"
printf 'head=%s\n' "$(git -C "$ROOT" rev-parse HEAD)"
printf 'tree=%s\n' "$(git -C "$ROOT" rev-parse HEAD^{tree})"
