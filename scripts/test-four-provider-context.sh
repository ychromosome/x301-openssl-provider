#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

test "$#" -eq 2 || {
    echo "usage: $0 OPENSSL_PREFIX MODULE_DIRECTORY" >&2
    exit 2
}

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
PREFIX=$(readlink -f -- "$1")
MODULES=$(readlink -f -- "$2")
if [ -f "$PREFIX/libssl.so" ]; then
    LIBDIR=$PREFIX
elif [ -f "$PREFIX/lib/libssl.so" ]; then
    LIBDIR=$PREFIX/lib
else
    LIBDIR=$PREFIX/lib64
fi
test -f "$LIBDIR/libssl.so" && test -d "$PREFIX/include"

WORK=$(mktemp -d /tmp/x301-four-provider.XXXXXX)
trap 'rm -rf -- "$WORK"' EXIT HUP INT TERM

/usr/bin/gcc -std=c11 -Wall -Wextra -Werror \
    -I"$PREFIX/include" \
    "$ROOT/integration/four-provider-context.c" \
    -L"$LIBDIR" -Wl,-rpath,"$LIBDIR" -lssl -lcrypto \
    -o "$WORK/four-provider-context"

env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES="$MODULES" LD_LIBRARY_PATH="$LIBDIR" \
    "$WORK/four-provider-context" "$MODULES"
env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES="$MODULES" LD_LIBRARY_PATH="$LIBDIR" \
    /usr/bin/valgrind --quiet --error-exitcode=99 --leak-check=full \
        --errors-for-leak-kinds=definite,indirect,possible \
        "$WORK/four-provider-context" "$MODULES"
