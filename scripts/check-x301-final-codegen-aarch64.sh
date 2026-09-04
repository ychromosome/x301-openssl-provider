#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH LC_ALL=C

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
sh "$ROOT/scripts/check-rust-build-environment.sh"
sh "$ROOT/scripts/require-verified-snapshot.sh"
if [ "$#" -ne 2 ]; then
    echo "usage: $0 <x301-provider.so> <new-evidence-directory>" >&2
    exit 2
fi
MODULE=$1
EVIDENCE=$2
for tool in awk cp find grep mkdir nm objdump readelf sha256sum sort tee \
        xargs; do
    test -x "/usr/bin/$tool" || {
        echo "missing AArch64 codegen tool: /usr/bin/$tool" >&2
        exit 127
    }
done
test -f "$MODULE" && test ! -L "$MODULE"
test ! -e "$EVIDENCE" && test ! -L "$EVIDENCE"
mkdir -m 700 "$EVIDENCE"
SOURCE_SHA256=$(sha256sum "$MODULE" | awk '{ print $1 }')
cp -- "$MODULE" "$EVIDENCE/provider-module.so"
MODULE=$EVIDENCE/provider-module.so

readelf -h "$MODULE" >"$EVIDENCE/elf-header.txt"
grep -Eq 'Type:[[:space:]]+DYN \(Shared object file\)$' \
    "$EVIDENCE/elf-header.txt"
grep -Eq 'Machine:[[:space:]]+AArch64$' "$EVIDENCE/elf-header.txt"
readelf -S "$MODULE" >"$EVIDENCE/elf-sections.txt"
grep -Eq '[[:space:]]\.symtab[[:space:]]+SYMTAB[[:space:]]' \
    "$EVIDENCE/elf-sections.txt"
objdump -d -C --no-show-raw-insn --disassemble-zeroes --wide "$MODULE" \
    >"$EVIDENCE/provider.objdump"
nm -C --defined-only "$MODULE" >"$EVIDENCE/provider.nm"
objdump --version >"$EVIDENCE/objdump-version.txt"
SUMMARY=$EVIDENCE/summary.txt
: >"$SUMMARY"

extract_symbol() {
    symbol=$1
    output=$2
    count=$(awk -v symbol="$symbol" '
        function canonical(name) {
            if (substr(name, 1, 1) == "<") {
                sub(/^</, "", name)
                sub(/>::/, "::", name)
            }
            return name
        }
        /^[[:space:]]*[[:xdigit:]]+ <.*>:/ {
            name = $0
            sub(/^[^<]*</, "", name)
            sub(/>:[[:space:]]*$/, "", name)
            if (canonical(name) == symbol)
                count++
        }
        END { print count + 0 }
    ' "$EVIDENCE/provider.objdump")
    test "$count" -eq 1 || {
        echo "expected one AArch64 symbol $symbol, found $count" >&2
        exit 1
    }
    awk -v symbol="$symbol" '
        function canonical(name) {
            if (substr(name, 1, 1) == "<") {
                sub(/^</, "", name)
                sub(/>::/, "::", name)
            }
            return name
        }
        /^[[:space:]]*[[:xdigit:]]+ <.*>:/ {
            name = $0
            sub(/^[^<]*</, "", name)
            sub(/>:[[:space:]]*$/, "", name)
            active = canonical(name) == symbol
        }
        active { print }
    ' "$EVIDENCE/provider.objdump" >"$output"
    test -s "$output"
}

forbidden_straight_line() {
    awk '
        /^[[:space:]]*[[:xdigit:]]+:/ {
            mnemonic = $2
            if (mnemonic ~ /^b\./ || mnemonic == "b" ||
                    mnemonic == "bl" || mnemonic == "blr" ||
                    mnemonic == "br" || mnemonic == "cbz" ||
                    mnemonic == "cbnz" || mnemonic == "tbz" ||
                    mnemonic == "tbnz" || mnemonic == "udiv" ||
                    mnemonic == "sdiv" || mnemonic == "brk" ||
                    mnemonic == "hlt" || mnemonic == "udf") {
                print
                bad = 1
            }
        }
        END { exit bad ? 0 : 1 }
    ' "$1"
}

check_straight_line() {
    label=$1
    symbol=$2
    require_subtract=$3
    output=$EVIDENCE/$label.asm
    extract_symbol "$symbol" "$output"
    if forbidden_straight_line "$output"; then
        echo "forbidden AArch64 control flow in $symbol" >&2
        exit 1
    fi
    if awk '
        /^[[:space:]]*[[:xdigit:]]+:/ &&
                $0 ~ /\[[^]]*,[[:space:]]*(x|w)[0-9]+/ {
            print
            bad = 1
        }
        END { exit bad ? 0 : 1 }
    ' "$output"; then
        echo "indexed AArch64 memory in $symbol" >&2
        exit 1
    fi
    selects=$(awk '
        /^[[:space:]]*[[:xdigit:]]+:/ &&
                $2 ~ /^(csel|csinc|csinv|csneg|cset|csetm|cinc|cinv|cneg)$/ {
            count++
        }
        END { print count + 0 }
    ' "$output")
    subtracts=$(awk '
        /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^(subs|sbc|sbcs)$/ { count++ }
        END { print count + 0 }
    ' "$output")
    test "$selects" -gt 0
    if [ "$require_subtract" = yes ]; then
        test "$subtracts" -gt 0
    fi
    printf 'PASS aarch64_symbol=%s conditional_select=%s subtract=%s branches=0 calls=0 indexed_memory=0\n' \
        "$symbol" "$selects" "$subtracts" | tee -a "$SUMMARY"
}

check_straight_line point_add_affine \
    'ed301_eddsa::edwards::EdwardsPoint::add_affine' yes
check_straight_line point_double \
    'ed301_eddsa::edwards::EdwardsPoint::double' yes
check_straight_line affine_select \
    'ed301_eddsa::edwards::AffineNielsPoint::conditional_select' no

BASEPOINT_SELECT=$EVIDENCE/basepoint_select.asm
extract_symbol 'ed301_eddsa::edwards::select_basepoint' "$BASEPOINT_SELECT"
if awk '
    /^[[:space:]]*[[:xdigit:]]+:/ {
        mnemonic = $2
        if (mnemonic ~ /^b\./ || mnemonic == "b" || mnemonic == "blr" ||
                mnemonic == "br" || mnemonic == "cbz" ||
                mnemonic == "cbnz" || mnemonic == "tbz" ||
                mnemonic == "tbnz" || mnemonic == "udiv" ||
                mnemonic == "sdiv" || mnemonic == "brk" ||
                mnemonic == "hlt" || mnemonic == "udf" ||
                (mnemonic == "bl" &&
                 $0 !~ /<ed301_eddsa::edwards::AffineNielsPoint::conditional_select>$/)) {
            print
            bad = 1
        }
    }
    END { exit bad ? 0 : 1 }
' "$BASEPOINT_SELECT"; then
    echo "forbidden AArch64 basepoint-selection control flow" >&2
    exit 1
fi
basepoint_calls=$(awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 == "bl" { count++ }
    END { print count + 0 }
' "$BASEPOINT_SELECT")
test "$basepoint_calls" -eq 9
if awk '
    /^[[:space:]]*[[:xdigit:]]+:/ &&
            $0 ~ /\[[^]]*,[[:space:]]*(x|w)[0-9]+/ {
        print
        bad = 1
    }
    END { exit bad ? 0 : 1 }
' "$BASEPOINT_SELECT"; then
    echo "indexed AArch64 memory in basepoint selection" >&2
    exit 1
fi
printf 'PASS aarch64_basepoint_select fixed_select_calls=%s branches=0 indexed_memory=0\n' \
    "$basepoint_calls" | tee -a "$SUMMARY"

LADDER=$EVIDENCE/x301-ladder.asm
extract_symbol 'ed301_eddsa::x301::ladder' "$LADDER"
if awk '
    /^[[:space:]]*[[:xdigit:]]+:/ &&
            ($2 == "udiv" || $2 == "sdiv" || $2 == "brk" ||
             $2 == "hlt" || $2 == "udf" || $2 == "bl" ||
             $2 == "blr" || $2 == "br") { print; bad = 1 }
    END { exit bad ? 0 : 1 }
' "$LADDER"; then
    echo "forbidden instruction or call in AArch64 ladder" >&2
    exit 1
fi
ladder_branches=$(awk '
    /^[[:space:]]*[[:xdigit:]]+:/ &&
            ($2 ~ /^b\./ || $2 == "cbz" || $2 == "cbnz" ||
             $2 == "tbz" || $2 == "tbnz") { count++ }
    END { print count + 0 }
' "$LADDER")
ladder_selects=$(awk '
    /^[[:space:]]*[[:xdigit:]]+:/ &&
            $2 ~ /^(csel|csinc|csinv|csneg|cset|csetm|cinc|cinv|cneg)$/ {
        count++
    }
    END { print count + 0 }
' "$LADDER")
test "$ladder_branches" -gt 0
test "$ladder_branches" -le 2
test "$ladder_selects" -ge 20
printf 'PASS x301_aarch64_ladder conditional_branches=%s conditional_select=%s calls=0\n' \
    "$ladder_branches" "$ladder_selects" | tee -a "$SUMMARY"

NEGATIVE=$EVIDENCE/negative-control.asm
printf '0: b.ne 0\n' >"$NEGATIVE"
if ! forbidden_straight_line "$NEGATIVE" >/dev/null; then
    echo "AArch64 X301 checker negative control failed" >&2
    exit 1
fi
printf 'PASS aarch64_negative_control=conditional-branch-rejected\n' \
    | tee -a "$SUMMARY"
(cd "$EVIDENCE" && \
    find . -type f ! -name SHA256SUMS -print0 \
        | sort -z | xargs -0 sha256sum >SHA256SUMS && \
    sha256sum --strict --quiet -c SHA256SUMS)
printf 'PASS x301_final_codegen_aarch64 module_sha256=%s evidence=%s\n' \
    "$SOURCE_SHA256" "$EVIDENCE"
