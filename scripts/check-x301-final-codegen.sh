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

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
sh "$ROOT/scripts/check-rust-build-environment.sh"
sh "$ROOT/scripts/require-verified-snapshot.sh"

if [ "$#" -ne 2 ]; then
    printf 'usage: %s <x301-provider.so> <new-evidence-directory>\n' "$0" >&2
    exit 2
fi
MODULE=$1
EVIDENCE=$2

for tool in /usr/bin/awk /usr/bin/cp /usr/bin/find \
        /usr/bin/grep /usr/bin/mkdir /usr/bin/nm /usr/bin/objdump \
        /usr/bin/readelf /usr/bin/sha256sum /usr/bin/sort /usr/bin/xargs; do
    test -x "$tool" || {
        echo "missing codegen tool: $tool" >&2
        exit 127
    }
done
test -f "$MODULE" && test ! -L "$MODULE" || {
    echo "module must be a regular non-symlink file" >&2
    exit 2
}
if /usr/bin/readelf -h "$MODULE" \
        | /usr/bin/grep -Eq 'Machine:[[:space:]]+AArch64$'; then
    exec "$ROOT/scripts/check-x301-final-codegen-aarch64.sh" \
        "$MODULE" "$EVIDENCE"
fi
test -x /usr/bin/gawk || {
    echo "missing codegen tool: /usr/bin/gawk" >&2
    exit 127
}
test ! -e "$EVIDENCE" || {
    echo "evidence directory already exists: $EVIDENCE" >&2
    exit 2
}
/usr/bin/mkdir -m 700 "$EVIDENCE"
SOURCE_MODULE_SHA256=$(/usr/bin/sha256sum "$MODULE" | /usr/bin/awk '{ print $1 }')
/usr/bin/cp -- "$MODULE" "$EVIDENCE/provider-module.so"
MODULE=$EVIDENCE/provider-module.so
test "$SOURCE_MODULE_SHA256" = \
    "$(/usr/bin/sha256sum "$MODULE" | /usr/bin/awk '{ print $1 }')"

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
PUBLIC_MAP=$EVIDENCE/x301-public-map.asm
BASE_SELECT=$EVIDENCE/x301-basepoint-select.asm
AFFINE_SELECT=$EVIDENCE/x301-affine-select.asm
POINT_AFFINE_ADD=$EVIDENCE/x301-point-add-affine.asm
POINT_DOUBLE=$EVIDENCE/x301-point-double.asm
SUMMARY=$EVIDENCE/summary.txt
PUBLIC_CALLS=$EVIDENCE/x301-public-from-secret-calls.txt
PUBLIC_MAP_CALLS=$EVIDENCE/x301-public-map-calls.txt
/usr/bin/objdump -d -C --no-show-raw-insn --disassemble-zeroes --wide \
    "$MODULE" >"$DUMP"
/usr/bin/nm -S -C --defined-only "$MODULE" >"$EVIDENCE/provider.nm"
: >"$SUMMARY"

count_symbol() {
    input=$1
    symbol=$2
    /usr/bin/awk -v symbol="$symbol" '
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
    ' "$input"
}

clip_symbol_extent() {
    input=$1
    output=$2
    start=$3
    size=$4
    /usr/bin/gawk -v start="$start" -v size="$size" '
        BEGIN {
            first = strtonum("0x" start)
            end = first + strtonum("0x" size)
            if (end <= first)
                exit 2
        }
        /^[[:space:]]*[[:xdigit:]]+:/ {
            address = strtonum("0x" $1)
            if (address < first || address >= end)
                next
        }
        { print }
    ' "$input" >"$output"
}

extract_symbol() {
    symbol=$1
    output=$2
    raw=$output.raw
    count=$(count_symbol "$DUMP" "$symbol")
    test "$count" -eq 1 || {
        printf 'expected one symbol %s, found %s\n' "$symbol" "$count" >&2
        exit 1
    }
    /usr/bin/awk -v symbol="$symbol" '
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
    ' "$DUMP" >"$raw"
    # objdump also emits alignment bytes after the ELF function's extent,
    # including after non-returning unwind calls. Never omit an in-range trap.
    extent=$(/usr/bin/awk -v symbol="$symbol" '
        function canonical(name) {
            if (substr(name, 1, 1) == "<") {
                sub(/^</, "", name)
                sub(/>::/, "::", name)
            }
            return name
        }
        $1 ~ /^[[:xdigit:]]+$/ && $2 ~ /^[[:xdigit:]]+$/ && $3 ~ /^[tT]$/ {
            address = $1
            size = $2
            name = $0
            sub(/^[[:space:]]*[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+/, "", name)
            if (canonical(name) == symbol)
                print address, size
        }
    ' "$EVIDENCE/provider.nm")
    set -- $extent
    test "$#" -eq 2 || {
        echo "missing or ambiguous ELF function extent: $symbol" >&2
        exit 1
    }
    clip_symbol_extent "$raw" "$output" "$1" "$2"
    test -s "$output"
}

extract_call_targets() {
    input=$1
    output=$2
    /usr/bin/awk '
        function canonical(name) {
            if (substr(name, 1, 1) == "<") {
                sub(/^</, "", name)
                sub(/>::/, "::", name)
            }
            return name
        }
        /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^call/ && $0 ~ /<.*>$/ {
            name = $0
            sub(/^[^<]*</, "", name)
            sub(/>[[:space:]]*$/, "", name)
            print canonical(name)
        }
    ' "$input" >"$output"
}

# rustc 1.91 emits legacy demangled method names while current rustc emits
# v0 names with an angle-bracketed inherent-impl type.  Both must resolve to
# the same exact canonical symbol; partial and suffix matches remain rejected.
MANGLE_FIXTURE=$EVIDENCE/symbol-mangling-fixture.txt
printf '%s\n' \
    '0000000000000000 <ed301_eddsa::edwards::EdwardsPoint::double>:' \
    '0000000000000001 <<ed301_eddsa::edwards::EdwardsPoint>::double>:' \
    >"$MANGLE_FIXTURE"
test "$(count_symbol "$MANGLE_FIXTURE" \
    'ed301_eddsa::edwards::EdwardsPoint::double')" -eq 2

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

PADDING_OK_RAW=$EVIDENCE/terminal-padding-ok.raw
PADDING_OK=$EVIDENCE/terminal-padding-ok.asm
printf '0: ret\n1: int3\n2: int3\n' >"$PADDING_OK_RAW"
clip_symbol_extent "$PADDING_OK_RAW" "$PADDING_OK" 0 1
if /usr/bin/grep -q int3 "$PADDING_OK"; then
    echo "terminal padding was not removed" >&2
    exit 1
fi
PADDING_BAD_RAW=$EVIDENCE/terminal-padding-bad.raw
PADDING_BAD=$EVIDENCE/terminal-padding-bad.asm
printf '0: int3\n1: ret\n' >"$PADDING_BAD_RAW"
clip_symbol_extent "$PADDING_BAD_RAW" "$PADDING_BAD" 0 2
if ! forbidden_straight_line "$PADDING_BAD" >/dev/null; then
    echo "internal trap padding was accepted" >&2
    exit 1
fi
printf '0: ret\n1: int3\n' >"$PADDING_BAD_RAW"
clip_symbol_extent "$PADDING_BAD_RAW" "$PADDING_BAD" 0 2
if ! forbidden_straight_line "$PADDING_BAD" >/dev/null; then
    echo "in-range trap after ret was accepted" >&2
    exit 1
fi
printf '0: call 8 <_Unwind_Resume>\n5: int3\n' >"$PADDING_OK_RAW"
clip_symbol_extent "$PADDING_OK_RAW" "$PADDING_OK" 0 5
if /usr/bin/grep -q int3 "$PADDING_OK"; then
    echo "out-of-range unwind padding was not removed" >&2
    exit 1
fi
printf 'PASS terminal_padding=outside-elf-function-only\n' | tee -a "$SUMMARY"

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

# D3 folds the fixed top-one bit into initialization and the two low-zero bits
# into finalization. Locate the remaining public loop (bits 299 through 2)
# from its sole backward edge. LLVM uses either a 300 -> 2 counter or a
# one-biased 301 -> 3 counter; both address scalar bits 299 down through 2.
extract_ladder_loop() {
    /usr/bin/gawk '
    /^[[:space:]]*[[:xdigit:]]+:/ {
        address = $1
        sub(/:$/, "", address)
        seen[address] = NR
        if ($2 ~ /^j/) {
            branches++
            if ($2 == "ja" && $3 in seen &&
                    strtonum("0x" $3) < strtonum("0x" address)) {
                first = seen[$3]
                last = NR
            }
        }
    }
    { lines[NR] = $0 }
    END {
        if (branches != 1 || !first)
            exit 1
        start = first - 1
        while (start > 0 && lines[start] ~ /[[:space:]]nop[a-z]*([[:space:]]|$)/)
            start--
        if (!start || lines[start] !~ /mov[[:space:]]+\$0x12[cd],%e[a-z0-9]+$/)
            exit 1
        for (i = start; i <= last; i++)
            print lines[i]
    }
    ' "$1" >"$2"
}
extract_ladder_loop "$LADDER" "$LOOP"
test -s "$LOOP"
COUNTER_BAD=$EVIDENCE/negative-counter.raw
COUNTER_OUT=$EVIDENCE/negative-counter.asm
printf '0: mov $0x12d,%%ecx\n5: mov $0x12e,%%eax\na: dec %%rax\nd: cmp $0x3,%%rax\n11: ja a\n' \
    >"$COUNTER_BAD"
if extract_ladder_loop "$COUNTER_BAD" "$COUNTER_OUT"; then
    echo "incorrect loop bound matched an earlier field constant" >&2
    exit 1
fi
if head -1 "$LOOP" | grep -q '\$0x12c,'; then
    grep -Eq 'cmp[[:space:]]+\$0x2,%rax$' "$LOOP"
    grep -Eq 'lea[[:space:]]+-0x1\(%rcx\),%rax$' "$LOOP"
    counter_shape=300-to-2
else
    grep -Eq 'cmp[[:space:]]+\$0x3,%rax$' "$LOOP"
    grep -Eq 'add[[:space:]]+\$0xfffffffffffffffe,%rax$' "$LOOP"
    grep -Eq 'dec[[:space:]]+%rax$' "$LOOP"
    counter_shape=301-to-3
fi

branches=$(/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^j/ { count++ }
    END { print count + 0 }
' "$LOOP")
test "$branches" -eq 1 || {
    echo "ladder loop contains non-fixed conditional control flow" >&2
    exit 1
}
/usr/bin/grep -Eq \
    '^[[:space:]]*[[:xdigit:]]+:[[:space:]]+ja[[:space:]]+[[:xdigit:]]+' \
    "$LOOP" || {
    echo "reviewed fixed bits-299-through-2 loop edge changed" >&2
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
# One ladder swap selects four five-limb coordinates, so its required
# lowering accounts for 20 cmovs. Additional cmovs belong to field correction
# and may legitimately disappear when an arithmetic operation is removed.
test "$cmov" -ge 20 || {
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
/usr/bin/grep -Eq \
    'movzbl[[:space:]]+[^,]*\(%r[a-z0-9]+,%r[a-z0-9]+,1\),%e[a-z0-9]+$' \
    "$EVIDENCE/x301-indexed-memory.txt"

# The ladder may either retain the reviewed 10 reduction and four squaring
# calls or inline that complete field closure.  In the latter case the checks
# above inspect the arithmetic inside the fixed loop itself.
/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^call/ {
        line = $0
        sub(/^.*</, "", line)
        sub(/>.*/, "", line)
        print line
    }
' "$LOOP" >"$EVIDENCE/x301-ladder-calls.txt"
ladder_calls=$(/usr/bin/awk 'END { print NR + 0 }' \
    "$EVIDENCE/x301-ladder-calls.txt")
case "$ladder_calls" in
    0)
        ladder_field_shape=fully-inlined
        ;;
    14)
        test "$(/usr/bin/grep -c '^ed301_eddsa::field_5x64::reduce_wide$' \
                "$EVIDENCE/x301-ladder-calls.txt")" -eq 10
        test "$(/usr/bin/grep -c '^ed301_eddsa::field_5x64::square_wide$' \
                "$EVIDENCE/x301-ladder-calls.txt")" -eq 4
        ladder_field_shape=named-leaves
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
        ;;
    *)
        echo "unexpected X301 ladder call closure: $ladder_calls" >&2
        exit 1
        ;;
esac

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
    'ed301_eddsa::edwards::AffineNielsPoint::conditional_select' \
    "$AFFINE_SELECT"
extract_symbol \
    'ed301_eddsa::edwards::EdwardsPoint::add_affine' \
    "$POINT_AFFINE_ADD"
extract_symbol \
    'ed301_eddsa::edwards::EdwardsPoint::double' \
    "$POINT_DOUBLE"

for section in "$BASE_SELECT" "$AFFINE_SELECT"; do
    if forbidden_straight_line "$section"; then
        echo "fixed-base selector contains conditional control flow" >&2
        exit 1
    fi
    if /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ && $0 ~ /\([^)]*,[^)]*\)/ &&
                $2 !~ /^lea/ && $0 !~ /[[:space:]]nop[a-z]*[[:space:]]/ {
            print
            bad = 1
        }
        END { exit bad ? 0 : 1 }
    ' "$section"; then
        echo "fixed-base selector contains indexed memory" >&2
        exit 1
    fi
done

for section in "$POINT_AFFINE_ADD" "$POINT_DOUBLE"; do
    if forbidden_straight_line "$section"; then
        echo "fixed-base Edwards arithmetic contains conditional control flow" >&2
        exit 1
    fi
    if /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^call/ { print; bad = 1 }
        END { exit bad ? 0 : 1 }
    ' "$section"; then
        echo "fixed-base Edwards arithmetic contains a call" >&2
        exit 1
    fi
    if /usr/bin/awk '
        /^[[:space:]]*[[:xdigit:]]+:/ && $0 ~ /\([^)]*,[^)]*\)/ &&
                $2 !~ /^lea/ && $0 !~ /[[:space:]]nop[a-z]*[[:space:]]/ {
            print
            bad = 1
        }
        END { exit bad ? 0 : 1 }
    ' "$section"; then
        echo "fixed-base Edwards arithmetic contains indexed memory" >&2
        exit 1
    fi
done

affine_cmov=$(/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^cmov/ { count++ }
    END { print count + 0 }
' "$POINT_AFFINE_ADD")
double_cmov=$(/usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ && $2 ~ /^cmov/ { count++ }
    END { print count + 0 }
' "$POINT_DOUBLE")
# Each formula has one small-constant multiply. Its proven no-underflow fold
# omits one five-word selection; all remaining field corrections still apply.
test "$affine_cmov" -eq 25
test "$double_cmov" -eq 35
printf 'PASS x301_fixed_base_edwards add_affine_cmov=%s double_cmov=%s branch_free=1 indexed_memory=0 calls=0\n' \
    "$affine_cmov" "$double_cmov" | tee -a "$SUMMARY"

if /usr/bin/awk '
    /^[[:space:]]*[[:xdigit:]]+:/ &&
            ($2 ~ /^loop/ || $2 ~ /^div/ || $2 ~ /^idiv/ ||
             $2 == "ud2" || $2 == "int3") { print; bad = 1 }
    END { exit bad ? 0 : 1 }
' "$PUBLIC"; then
    echo "forbidden instruction in final X301 key-generation function" >&2
    exit 1
fi

extract_call_targets "$PUBLIC" "$PUBLIC_CALLS"
base_select_calls=$(/usr/bin/grep -Fxc \
    'ed301_eddsa::edwards::select_basepoint' "$PUBLIC_CALLS")
affine_add_calls=$(/usr/bin/grep -Fxc \
    'ed301_eddsa::edwards::EdwardsPoint::add_affine' "$PUBLIC_CALLS")
double_calls=$(/usr/bin/grep -Fxc \
    'ed301_eddsa::edwards::EdwardsPoint::double' "$PUBLIC_CALLS")
invert_calls=$(/usr/bin/awk '
    $0 == "ed301_eddsa::field_5x64::Fe301::invert" { count++ }
    END { print count + 0 }
' "$PUBLIC_CALLS")
map_calls=$(/usr/bin/awk '
    $0 == "ed301_eddsa::edwards::EdwardsPoint::montgomery_u_public_artifact" {
        count++
    }
    END { print count + 0 }
' "$PUBLIC_CALLS")
test "$base_select_calls" -eq 2
test "$affine_add_calls" -eq 2
test "$double_calls" -eq 4
case "$invert_calls:$map_calls" in
    1:0)
        ;;
    0:1)
        extract_symbol \
            'ed301_eddsa::edwards::EdwardsPoint::montgomery_u_public_artifact' \
            "$PUBLIC_MAP"
        if /usr/bin/awk '
            /^[[:space:]]*[[:xdigit:]]+:/ &&
                    ($2 ~ /^loop/ || $2 ~ /^div/ || $2 ~ /^idiv/ ||
                     $2 == "ud2" || $2 == "int3") { print; bad = 1 }
            END { exit bad ? 0 : 1 }
        ' "$PUBLIC_MAP"; then
            echo "forbidden instruction in X301 public mapping" >&2
            exit 1
        fi
        extract_call_targets "$PUBLIC_MAP" "$PUBLIC_MAP_CALLS"
        test "$(/usr/bin/awk '
            $0 == "ed301_eddsa::field_5x64::Fe301::invert" { count++ }
            END { print count + 0 }
        ' "$PUBLIC_MAP_CALLS")" -eq 1
        ;;
    *)
        echo "unexpected X301 public-key inversion closure" >&2
        exit 1
        ;;
esac

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
    "$base_select_calls" "$affine_add_calls" "$double_calls" 1 \
    | tee -a "$SUMMARY"

# Checker negative control: a synthetic conditional edge must be rejected.
NEGATIVE=$EVIDENCE/negative-control.asm
/usr/bin/awk '{ print } END { print "deadbeef: jne deadbeef" }' \
    "$BASE_SELECT" >"$NEGATIVE"
if ! forbidden_straight_line "$NEGATIVE" >/dev/null; then
    echo "codegen checker negative control failed" >&2
    exit 1
fi

printf 'PASS x301_ladder_rounds=301 variable_rounds=298 fixed_doublings=3 loop_branches=1 cmov=%s indexed_reads=1 counter=%s\n' \
    "$cmov" "$counter_shape" | tee -a "$SUMMARY"
printf '%s\n' \
    "PASS field_backend=ed301_eddsa::field_5x64 branch_free=1 ladder_shape=$ladder_field_shape" \
    'PASS negative_control=conditional-edge-rejected' | tee -a "$SUMMARY"
(cd "$EVIDENCE" && \
    /usr/bin/find . -type f ! -name SHA256SUMS -printf '%P\0' \
        | /usr/bin/sort -z \
        | /usr/bin/xargs -0 /usr/bin/sha256sum >SHA256SUMS && \
    /usr/bin/sha256sum --strict --quiet -c SHA256SUMS)
printf 'PASS x301_final_codegen module_sha256=%s evidence=%s\n' \
    "$SOURCE_MODULE_SHA256" \
    "$EVIDENCE"
