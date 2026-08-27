#!/bin/sh
set -eu

if test "$#" -ne 1; then
    echo "usage: $0 <tool>" >&2
    exit 2
fi

tool=$1
candidate=$(command -v "$tool" 2>/dev/null || true)
test -n "$candidate" && test -x "$candidate" || {
    echo "missing Rust tool in PATH: $tool" >&2
    exit 127
}

resolved=$(readlink -f -- "$candidate")
rustup_candidate=$(command -v rustup 2>/dev/null || true)
rustup_resolved=
if test -n "$rustup_candidate" && test -x "$rustup_candidate"; then
    rustup_resolved=$(readlink -f -- "$rustup_candidate")
fi
rustup_proxy=
if test "$(basename -- "$resolved")" = rustup; then
    rustup_proxy=$resolved
elif test -n "$rustup_resolved" && test "$resolved" -ef "$rustup_resolved"; then
    rustup_proxy=$rustup_resolved
fi
if test -n "$rustup_proxy"; then
    # The resolved shim target is the rustup executable itself.  Invoke that
    # absolute path before the caller enters its empty HOME/PATH environment.
    resolved=$($rustup_proxy which "$tool")
fi

test -x "$resolved" || {
    echo "resolved Rust tool is not executable: $resolved" >&2
    exit 127
}
printf '%s\n' "$resolved"
