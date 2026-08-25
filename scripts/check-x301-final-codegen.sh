#!/bin/sh
set -eu

# Final-binary X301 ladder and fixed-base key-generation gate.
# Sources: RFC 7748 Section 5 fixed Montgomery ladder; X301 decisions D2-D4;
# the repository constant-time contract.  This gate is intentionally tied to
# the reviewed x86-64 Rust lowering and must be rerun after every toolchain
# change.  Dynamic secret-address/control-flow coverage remains the job of
# check-secret-taint.sh; this script binds the actual provider machine code.

PATH=/usr/bin:/bin
export PATH LC_ALL=C

if [ "$#" -ne 2 ]; then
    printf 'usage: %s <x301-provider.so> <new-evidence-directory>\n' "$0" >&2
    exit 2
fi
MODULE=$1
EVIDENCE=$2

for tool in /usr/bin/awk /usr/bin/gawk /usr/bin/grep /usr/bin/mkdir \
        /usr/bin/nm /usr/bin/objdump /usr/bin/readelf /usr/bin/sha256sum; do
    test -x "$tool" || {
        echo "missing codegen tool: $tool" >&2
        exit 127
    }
done
test -f "$MODULE" && test ! -L "$MODULE" || {
    echo "module must be a regular non-symlink file" >&2
    exit 2
}
test ! -e "$EVIDENCE" || {
    echo "evidence directory already exists: $EVIDENCE" >&2
    exit 2
}
/usr/bin/mkdir -m 700 "$EVIDENCE"

/usr/bin/readelf -h "$MODULE" >"$EVIDENCE/elf-header.txt"
/usr/bin/grep -Eq 'Type:[[:space:]]+DYN \(Shared object file\)$' \
    "$EVIDENCE/elf-header.txt"
/usr/bin/grep -Eq \
    'Machine:[[:space:]]+Advanced Micro Devices X86-64$' \
    "$EVIDENCE/elf-header.txt"
/usr/bin/readelf -S "$MODULE" >"$EVIDENCE/elf-sections.txt"
/usr/bin/grep -Eq '[[:space:]]\.symtab[[:space:]]+SYMTAB[[:space:]]' \
    "$EVIDENCE/elf-sections.txt"

DUMP=$EVIDENCE/provider.objdump
X301=$EVIDENCE/x301.asm
LADDER=$EVIDENCE/x301-ladder.asm
LOOP=$EVIDENCE/x301-ladder-loop.asm
PUBLIC=$EVIDENCE/x301-public-from-secret.asm
BASE_SELECT=$EVIDENCE/x301-basepoint-select.asm
AFFINE_SELECT=$EVIDENCE/x301-affine-select.asm
COMB=$EVIDENCE/x301-prepared-comb.asm
COMB_DIGITS=$EVIDENCE/x301-prepared-comb-digits.asm
SUMMARY=$EVIDENCE/summary.txt
/usr/bin/objdump -d -C --no-show-raw-insn --disassemble-zeroes --wide \
    "$MODULE" >"$DUMP"
/usr/bin/nm -C --defined-only "$MODULE" >"$EVIDENCE/provider.nm"
: >"$SUMMARY"

extract_symbol() {
    symbol=$1
    output=$2
    count=$(/usr/bin/awk -v symbol="$symbol" '
        /^[[:space:]]*[[:xdigit:]]+ <.*>:/ &&
                index($0, "<" symbol ">:") != 0 { count++ }
        END { print count + 0 }
    ' "$DUMP")
    test "$count" -eq 1 || {
        printf 'expected one symbol %s, found %s\n' "$symbol" "$count" >&2
        exit 1
    }
    /usr/bin/awk -v symbol="$symbol" '
        /^[[:space:]]*[[:xdigit:]]+ <.*>:/ {
            active = index($0, "<" symbol ">:") != 0
        }
        active { print }
    ' "$DUMP" >"$output"
    test -s "$output"
}

forbidden_straight_line() {
    /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ {
            mnemonic = $2
            if ((mnemonic ~ /^j/ && mnemonic !~ /^jmpq?$/) ||
                    mnemonic ~ /^loop/ || mnemonic ~ /^div/ ||
                    mnemonic ~ /^idiv/ || mnemonic == "ud2" ||
                    mnemonic == "int3") {
                print
                bad = 1
            }
        }
        END { exit bad ? 0 : 1 }
    ' "$1"
}

extract_symbol 'ed301_eddsa::x301::x301' "$X301"
extract_symbol 'ed301_eddsa::x301::ladder' "$LADDER"

# Reject variable-time arithmetic and traps anywhere in the X301 function.
# Public decode/failure branches and the fixed safegcd loops are recorded but
# deliberately not misrepresented as branch-free.
if /usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ &&
            ($2 ~ /^loop/ || $2 ~ /^div/ || $2 ~ /^idiv/ ||
             $2 == "ud2" || $2 == "int3") { print; bad = 1 }
    END { exit bad ? 0 : 1 }
' "$X301"; then
    echo "forbidden instruction in final X301 function" >&2
    exit 1
fi
/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^j/ { print }
' "$X301" >"$EVIDENCE/x301-all-branches.txt"

# Locate the named ladder loop from the public fixed counter value 300 through
# its first backward conditional edge. Keeping the symbol named makes the
# final-binary gate independent of the compiler's inlining budget.
/usr/bin/gawk '
    /^[[:space:]]*[[:xdigit:]]+:/ {
        address = $1
        sub(/:$/, "", address)
        if (index($0, "$0x12c,%") != 0)
            active = 1
        if (active)
            print
        if (active && $2 ~ /^j/ && $2 !~ /^jmpq?$/ &&
                $3 ~ /^[[:xdigit:]]+$/ &&
                strtonum("0x" $3) < strtonum("0x" address))
            exit
    }
' "$LADDER" >"$LOOP"
test -s "$LOOP"

branches=$(/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^j/ { count++ }
    END { print count + 0 }
' "$LOOP")
test "$branches" -eq 1 || {
    echo "ladder loop contains non-fixed conditional control flow" >&2
    exit 1
}
/usr/bin/grep -Eq \
    '^[[:space:]]*[[:xdigit:]]+:[[:space:]]+jb[[:space:]]+[[:xdigit:]]+' \
    "$LOOP" || {
    echo "reviewed fixed 301-round loop edge changed" >&2
    exit 1
}
if /usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ &&
            ($2 ~ /^loop/ || $2 ~ /^div/ || $2 ~ /^idiv/ ||
             $2 == "ud2" || $2 == "int3" || $2 ~ /^jmp/) {
        print
        bad = 1
    }
    END { exit bad ? 0 : 1 }
' "$LOOP"; then
    echo "forbidden ladder-loop instruction" >&2
    exit 1
fi

cmov=$(/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^cmov/ { count++ }
    END { print count + 0 }
' "$LOOP")
test "$cmov" -ge 40 || {
    echo "constant-time swap/select lowering changed" >&2
    exit 1
}

# Exactly one indexed read is permitted: the scalar byte selected by the
# public fixed loop counter. Valgrind T11 independently proves its address is
# defined when the scalar contents are tainted.
/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $0 ~ /\([^)]*,[^)]*\)/ &&
            $2 !~ /^lea/ && index($0, "nop") == 0 { print }
' "$LOOP" >"$EVIDENCE/x301-indexed-memory.txt"
test "$(/usr/bin/awk 'END { print NR + 0 }' \
        "$EVIDENCE/x301-indexed-memory.txt")" -eq 1
/usr/bin/grep -Eq 'movzbl[[:space:]]+[^,]*\(%rsp,%rcx,1\),%ecx$' \
    "$EVIDENCE/x301-indexed-memory.txt" || \
/usr/bin/grep -Eq 'movzbl[[:space:]]+\(%r[a-z0-9]+,%rcx,1\),%ecx$' \
    "$EVIDENCE/x301-indexed-memory.txt"

# The inlined ladder may call only the existing shared field backend.
/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^call/ {
        line = $0
        sub(/^.*</, "", line)
        sub(/>.*/, "", line)
        print line
    }
' "$LOOP" >"$EVIDENCE/x301-ladder-calls.txt"
test "$(/usr/bin/grep -c '^ed301_eddsa::field_5x64::reduce_wide$' \
        "$EVIDENCE/x301-ladder-calls.txt")" -eq 10
test "$(/usr/bin/grep -c '^ed301_eddsa::field_5x64::square_wide$' \
        "$EVIDENCE/x301-ladder-calls.txt")" -eq 4
test "$(/usr/bin/awk 'END { print NR + 0 }' \
        "$EVIDENCE/x301-ladder-calls.txt")" -eq 14

for entry in \
        'field-reduce:ed301_eddsa::field_5x64::reduce_wide' \
        'field-square:ed301_eddsa::field_5x64::square_wide'; do
    label=${entry%%:*}
    symbol=${entry#*:}
    section=$EVIDENCE/$label.asm
    extract_symbol "$symbol" "$section"
    if forbidden_straight_line "$section"; then
        echo "shared field primitive is no longer branch-free: $symbol" >&2
        exit 1
    fi
done

# K1: X301 public-key derivation reuses the existing constant-time Edwards
# fixed-base machinery.  Thin LTO inlines the two radix-16 loops into
# public_from_secret(), while leaving both selectors as named leaves.  The
# selectors must remain straight-line and must never address their tables by
# a secret digit.  The caller may branch only for public length, fixed loop
# counters, declassified impossible-fault predicates and unwind cleanup;
# check-secret-taint.sh independently binds those classifications.
extract_symbol 'ed301_eddsa::x301::public_from_secret' "$PUBLIC"
extract_symbol 'ed301_eddsa::edwards::select_basepoint' "$BASE_SELECT"
extract_symbol \
    '<ed301_eddsa::edwards::AffineNielsPoint>::conditional_select' \
    "$AFFINE_SELECT"

for section in "$BASE_SELECT" "$AFFINE_SELECT"; do
    if forbidden_straight_line "$section"; then
        echo "fixed-base selector contains conditional control flow" >&2
        exit 1
    fi
    if /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ && $0 ~ /\([^)]*,[^)]*\)/ &&
                $2 !~ /^lea/ && $2 !~ /^nop/ { print; bad = 1 }
        END { exit bad ? 0 : 1 }
    ' "$section"; then
        echo "fixed-base selector contains indexed memory" >&2
        exit 1
    fi
done

if /usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ &&
            ($2 ~ /^loop/ || $2 ~ /^div/ || $2 ~ /^idiv/ ||
             $2 == "ud2" || $2 == "int3") { print; bad = 1 }
    END { exit bad ? 0 : 1 }
' "$PUBLIC"; then
    echo "forbidden instruction in final X301 key-generation function" >&2
    exit 1
fi

base_select_calls=$(/usr/bin/grep -c \
    'call.*<ed301_eddsa::edwards::select_basepoint>' "$PUBLIC")
affine_add_calls=$(/usr/bin/grep -c \
    'call.*<<ed301_eddsa::edwards::EdwardsPoint>::add_affine>' "$PUBLIC")
double_calls=$(/usr/bin/grep -c \
    'call.*<<ed301_eddsa::edwards::EdwardsPoint>::double>' "$PUBLIC")
invert_calls=$(/usr/bin/grep -c \
    'call.*<<ed301_eddsa::field_5x64::Fe301>::invert>' "$PUBLIC")
test "$base_select_calls" -eq 2
test "$affine_add_calls" -eq 2
test "$double_calls" -eq 4
test "$invert_calls" -eq 1

# Both mixed-add loops are controlled by the same public bound (74 decimal).
# Secret digits are read with those public loop indices and passed by value to
# the full-scan selector; no digit is used to address the basepoint table.
test "$(/usr/bin/grep -c 'cmp[[:space:]]\+\$0x4a,' "$PUBLIC")" -eq 2
/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^j/ { print }
' "$PUBLIC" >"$EVIDENCE/x301-public-from-secret-branches.txt"
/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $0 ~ /\([^)]*,[^)]*\)/ &&
            $2 !~ /^lea/ { print }
' "$PUBLIC" >"$EVIDENCE/x301-public-from-secret-indexed-memory.txt"

printf 'PASS x301_keygen=fixed-base base_select_sites=%s affine_add_sites=%s double_sites=%s inversion_sites=%s\n' \
    "$base_select_calls" "$affine_add_calls" "$double_calls" "$invert_calls" \
    | tee -a "$SUMMARY"

# Prepared derive uses regular signed five-bit comb recoding. The only
# conditional edges are fixed public loop counters: 304 recoding steps, 16
# full-scan table entries, 61 comb rows, and the normal/unwind zeroization
# loops. Secret-taint independently verifies that the scalar cannot influence
# branch decisions or addresses.
extract_symbol \
    '<ed301_eddsa::edwards::EdwardsPoint>::scalar_mul_x301_comb' "$COMB"
extract_symbol 'ed301_eddsa::edwards::x301_regular_signed_digits' \
    "$COMB_DIGITS"
for section in "$COMB" "$COMB_DIGITS"; do
    if /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ &&
                ($2 ~ /^loop/ || $2 ~ /^div/ || $2 ~ /^idiv/ ||
                 $2 == "ud2" || $2 == "int3" || $2 ~ /^jmp/) {
            print
            bad = 1
        }
        END { exit bad ? 0 : 1 }
    ' "$section"; then
        echo "forbidden prepared-comb instruction" >&2
        exit 1
    fi
done
test "$(/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^j/ { count++ }
    END { print count + 0 }
' "$COMB_DIGITS")" -eq 1
/usr/bin/grep -Eq \
    'cmp[[:space:]]+\$0x130,%rbp' "$COMB_DIGITS"
test "$(/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^j/ { count++ }
    END { print count + 0 }
' "$COMB")" -eq 4
test "$(/usr/bin/grep -c 'cmp[[:space:]]\+\$0x10,%rdi' "$COMB")" -eq 1
test "$(/usr/bin/grep -c 'cmp[[:space:]]\+\$0x131,' "$COMB")" -eq 2
test "$(/usr/bin/grep -c 'mov[[:space:]]\+\$0x3d,%eax' "$COMB")" -eq 1
/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^j/ { print }
' "$COMB" >"$EVIDENCE/x301-prepared-comb-branches.txt"
/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $0 ~ /\([^)]*,[^)]*\)/ &&
            $2 !~ /^lea/ && index($0, "nop") == 0 { print }
' "$COMB" >"$EVIDENCE/x301-prepared-comb-indexed-memory.txt"
test "$(/usr/bin/awk 'END { print NR + 0 }' \
        "$EVIDENCE/x301-prepared-comb-indexed-memory.txt")" -eq 7
printf '%s\n' \
    'PASS x301_prepared_comb=regular-signed width=5 rows=61 table_scan=16' \
    'PASS x301_prepared_comb_secret_taint_gate=required' | tee -a "$SUMMARY"

# Checker negative control: a synthetic conditional edge must be rejected.
NEGATIVE=$EVIDENCE/negative-control.asm
/usr/bin/awk '{ print } END { print "deadbeef: jne deadbeef" }' \
    "$EVIDENCE/field-reduce.asm" >"$NEGATIVE"
if ! forbidden_straight_line "$NEGATIVE" >/dev/null; then
    echo "codegen checker negative control failed" >&2
    exit 1
fi

printf 'PASS x301_ladder_rounds=301 loop_branches=1 cmov=%s indexed_reads=1\n' \
    "$cmov" | tee -a "$SUMMARY"
printf '%s\n' \
    'PASS field_backend=ed301_eddsa::field_5x64 branch_free=1' \
    'PASS negative_control=conditional-edge-rejected' | tee -a "$SUMMARY"
/usr/bin/sha256sum "$MODULE" "$DUMP" "$X301" "$LADDER" "$LOOP" "$PUBLIC" \
    "$BASE_SELECT" "$AFFINE_SELECT" "$COMB" "$COMB_DIGITS" "$SUMMARY" \
    >"$EVIDENCE/SHA256SUMS"
printf 'PASS x301_final_codegen module_sha256=%s evidence=%s\n' \
    "$(/usr/bin/sha256sum "$MODULE" | /usr/bin/awk '{ print $1 }')" \
    "$EVIDENCE"
