#!/bin/bash
set -Eeuo pipefail

PATH=/usr/bin:/bin
export PATH LC_ALL=C
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
if (( $# < 7 || $# > 8 )); then
    printf 'usage: %s <3.5.8|4.0.2> <sealed-lane-root> <lane-evidence-sha256> <provider-modules> <source-manifest> <cpu> <fresh-output-dir> [repetitions]\n' "$0" >&2
    exit 2
fi

LANE=$1
LANE_ROOT=$(readlink -f -- "$2")
LANE_EVIDENCE_SHA256=$3
MODULE_SOURCE=$(readlink -f -- "$4")
SOURCE_MANIFEST=$(readlink -f -- "$5")
CPU=$6
OUTPUT=$7
REPETITIONS=${8:-5}
case "$LANE" in
    3.5.8|4.0.2) ;;
    *) printf 'unsupported OpenSSL lane: %s\n' "$LANE" >&2; exit 2 ;;
esac
case "$CPU:$REPETITIONS" in
    *[!0-9:]*|:*|*:0) printf 'cpu and repetitions must be positive integers\n' >&2; exit 2 ;;
esac
if [[ ${X301_COMPARATIVE_PINNED:-0} != 1 ]]; then
    exec env X301_COMPARATIVE_PINNED=1 taskset -c "$CPU" "$0" "$@"
fi
unset X301_COMPARATIVE_PINNED

"$ROOT/scripts/verify-openssl-provider-lane.sh" \
    "$LANE_ROOT" "$LANE" "$LANE_EVIDENCE_SHA256"
PREFIX=$LANE_ROOT/inst/$LANE
LANE_MANIFEST=$LANE_ROOT/logs/$LANE/evidence_manifest.sha256

[[ ! -e $OUTPUT && ! -L $OUTPUT ]] || {
    printf 'output directory must not exist: %s\n' "$OUTPUT" >&2
    exit 2
}
mkdir -m 700 -- "$OUTPUT"
OUTPUT=$(readlink -f -- "$OUTPUT")
INPUTS=$OUTPUT/inputs
MODULES=$INPUTS/modules
mkdir -m 700 -p -- "$INPUTS" "$MODULES" "$OUTPUT/logs"

OPENSSL=$PREFIX/bin/openssl
if [[ -d $PREFIX/lib64 ]]; then LIBDIR=$PREFIX/lib64; else LIBDIR=$PREFIX/lib; fi
for input in "$OPENSSL" "$SOURCE_MANIFEST" "$LANE_MANIFEST" \
        "$ROOT/performance/x301_bench.c" \
        "$ROOT/performance/signature_bench.c" \
        "$ROOT/performance/summarize_comparative.py" \
        "$ROOT/scripts/run-x301-comparative-benchmark.sh"; do
    [[ -f $input && ! -L $input ]] || {
        printf 'missing regular input: %s\n' "$input" >&2
        exit 2
    }
done
for directory in "$MODULE_SOURCE" "$LIBDIR" "$PREFIX/include/openssl"; do
    [[ -d $directory && ! -L $directory ]] || {
        printf 'missing input directory: %s\n' "$directory" >&2
        exit 2
    }
done
(cd "$ROOT" && sha256sum --strict --quiet -c "$SOURCE_MANIFEST")

ARTIFACTS=$OUTPUT/artifacts.tsv
printf 'label\tsha256\tpath\n' >"$ARTIFACTS"
record_copy() {
    local label=$1 source=$2 destination=$3 digest

    [[ -f $source && ! -L $source ]] || return 1
    mkdir -m 700 -p -- "$(dirname -- "$INPUTS/$destination")"
    cp -- "$source" "$INPUTS/$destination"
    digest=$(sha256sum "$source" | awk '{print $1}')
    test "$digest" = "$(sha256sum "$INPUTS/$destination" | awk '{print $1}')"
    printf '%s\t%s\tinputs/%s\n' "$label" "$digest" "$destination" \
        >>"$ARTIFACTS"
}

record_copy benchmark-runner \
    "$ROOT/scripts/run-x301-comparative-benchmark.sh" comparative-runner.sh
record_copy lane-verifier \
    "$ROOT/scripts/verify-openssl-provider-lane.sh" lane-verifier.sh
record_copy x301-benchmark-source \
    "$ROOT/performance/x301_bench.c" x301_bench.c
record_copy signature-benchmark-source \
    "$ROOT/performance/signature_bench.c" signature_bench.c
record_copy comparative-summarizer \
    "$ROOT/performance/summarize_comparative.py" summarize_comparative.py
record_copy source-manifest "$SOURCE_MANIFEST" source-manifest.sha256
record_copy lane-evidence-manifest "$LANE_MANIFEST" lane-evidence-manifest.sha256
record_copy compiler "$(readlink -f -- /usr/bin/cc)" compiler
record_copy openssl-binary "$(readlink -f -- "$OPENSSL")" openssl

library_count=0
while IFS= read -r library; do
    library_count=$((library_count + 1))
    record_copy openssl-library "$library" \
        "libraries/$library_count-$(basename "$library")"
done < <(find "$LIBDIR" -maxdepth 1 -type f \
    \( -name 'libcrypto.so*' -o -name 'libssl.so*' \) -print | sort)
(( library_count > 0 )) || {
    printf 'no OpenSSL shared libraries found\n' >&2
    exit 2
}

module_count=0
while IFS= read -r module; do
    module_count=$((module_count + 1))
    record_copy provider-module "$module" "modules/$(basename "$module")"
done < <(find "$MODULE_SOURCE" -maxdepth 1 -type f -name '*.so*' -print | sort)
(( module_count >= 2 )) || {
    printf 'X301 and Ed301 provider modules are required\n' >&2
    exit 2
}

(
    cd "$PREFIX/include"
    find openssl -type f -print0 | sort -z | xargs -0 sha256sum
) >"$INPUTS/openssl-headers.sha256"
printf 'openssl-header-manifest\t%s\tinputs/openssl-headers.sha256\n' \
    "$(sha256sum "$INPUTS/openssl-headers.sha256" | awk '{print $1}')" \
    >>"$ARTIFACTS"

XBENCH=$INPUTS/x301_bench
SBENCH=$INPUTS/signature_bench
/usr/bin/cc -O3 -Wall -Wextra -Werror -std=c11 \
    -I"$PREFIX/include" "$ROOT/performance/x301_bench.c" \
    -L"$LIBDIR" -Wl,-rpath,"$LIBDIR" -lcrypto -o "$XBENCH"
/usr/bin/cc -O3 -Wall -Wextra -Werror -std=c11 \
    -I"$PREFIX/include" "$ROOT/performance/signature_bench.c" \
    -L"$LIBDIR" -Wl,-rpath,"$LIBDIR" -lcrypto -o "$SBENCH"
"$XBENCH" --self-test >"$INPUTS/x301-benchmark-self-test.txt"
printf '%s\n' \
    'cc -O3 -Wall -Wextra -Werror -std=c11' \
    '  -I${OPENSSL_PREFIX}/include performance/x301_bench.c' \
    '  -L${OPENSSL_LIBDIR} -Wl,-rpath,${OPENSSL_LIBDIR} -lcrypto' \
    'cc -O3 -Wall -Wextra -Werror -std=c11' \
    '  -I${OPENSSL_PREFIX}/include performance/signature_bench.c' \
    '  -L${OPENSSL_LIBDIR} -Wl,-rpath,${OPENSSL_LIBDIR} -lcrypto' \
    >"$INPUTS/BUILD_COMMANDS.txt"
for generated in x301_bench signature_bench x301-benchmark-self-test.txt \
        BUILD_COMMANDS.txt; do
    printf 'generated-input\t%s\tinputs/%s\n' \
        "$(sha256sum "$INPUTS/$generated" | awk '{print $1}')" "$generated" \
        >>"$ARTIFACTS"
done

awk -F '\t' 'NR > 1 { print $2 "  " $3 }' "$ARTIFACTS" \
    >"$OUTPUT/INPUT_SHA256SUMS"
(cd "$OUTPUT" && sha256sum --strict --quiet -c INPUT_SHA256SUMS)
: >"$OUTPUT/PROVENANCE_COMPLETE"

{
    printf 'format=x301-comparative-benchmark-v1\n'
    printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'lane=%s\nrepetitions=%s\ncpu=%s\n' "$LANE" "$REPETITIONS" "$CPU"
    printf 'lane_evidence_sha256=%s\n' "$LANE_EVIDENCE_SHA256"
    printf 'affinity=%s\n' "$(taskset -pc $$ | sed 's/^[^:]*: //')"
    printf 'cpu_model=%s\n' "$(sed -n '/^model name[[:space:]]*: / { s/^model name[[:space:]]*: //; p; q; }' /proc/cpuinfo)"
    printf 'kernel=%s\n' "$(uname -srvmo)"
    printf 'loadavg_start=%s\n' "$(sed -n '1p' /proc/loadavg)"
    governor=/sys/devices/system/cpu/cpu"$CPU"/cpufreq/scaling_governor
    printf 'governor=%s\n' "$(if [[ -r $governor ]]; then sed -n '1p' "$governor"; else printf unavailable; fi)"
    "$OPENSSL" version -a
    /usr/bin/cc --version
} >"$OUTPUT/environment.txt" 2>&1

printf 'lane\tcategory\toperation\talgorithm\trun\tcount\tmean_ns\n' \
    >"$OUTPUT/raw.tsv"
run_case() {
    local category=$1 operation=$2 algorithm=$3 run=$4 count=$5
    local properties=- module_arg=- provider=- bytes=0 binary=$XBENCH
    local tag log mean

    case "$category:$algorithm" in
        kex:X25519) bytes=32 ;;
        kex:X448) bytes=56 ;;
        kex:X301) bytes=38; properties=provider=x301; module_arg=$MODULES ;;
        kem:X301MLKEM1024) properties=provider=x301; module_arg=$MODULES ;;
        signature:ED25519|signature:ED448) binary=$SBENCH ;;
    esac
    tag=$(printf '%s-%s-%s-%s' "$category" "$operation" "$algorithm" "$run" \
        | tr -c 'A-Za-z0-9._-' '_')
    log=$OUTPUT/logs/$tag.log
    if [[ $category == signature ]]; then
        env LD_LIBRARY_PATH="$LIBDIR" "$binary" "$operation" "$algorithm" \
            "$properties" "$module_arg" "$provider" "$count" >"$log" 2>&1
    else
        env LD_LIBRARY_PATH="$LIBDIR" "$binary" "$operation" "$algorithm" \
            "$properties" "$module_arg" "$bytes" "$count" >"$log" 2>&1
    fi
    mean=$(sed -n 's/.* mean_ns=\([0-9.]*\).*/\1/p' "$log")
    [[ $mean =~ ^[0-9]+([.][0-9]+)?$ ]] || {
        printf 'missing result in %s\n' "$log" >&2
        exit 1
    }
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$LANE" "$category" \
        "$operation" "$algorithm" "$run" "$count" "$mean" \
        >>"$OUTPUT/raw.tsv"
}

for ((run = 1; run <= REPETITIONS; run++)); do
    if (( run % 2 == 1 )); then
        kexes=(X25519 X448 X301)
        kems=(ML-KEM-1024 X25519MLKEM768 X448MLKEM1024 X301MLKEM1024)
        signatures=(ED25519 ED448)
    else
        kexes=(X301 X448 X25519)
        kems=(X301MLKEM1024 X448MLKEM1024 X25519MLKEM768 ML-KEM-1024)
        signatures=(ED448 ED25519)
    fi
    for algorithm in "${kexes[@]}"; do
        run_case kex keygen "$algorithm" "$run" 1500
        run_case kex derive-setup "$algorithm" "$run" 1500
        run_case kex derive-first "$algorithm" "$run" 1500
        run_case kex derive-second "$algorithm" "$run" 600
        run_case kex derive-steady "$algorithm" "$run" 1500
    done
    for algorithm in "${kems[@]}"; do
        run_case kem kem-keygen "$algorithm" "$run" 400
        run_case kem encaps "$algorithm" "$run" 500
        run_case kem decaps "$algorithm" "$run" 700
    done
    for algorithm in "${signatures[@]}"; do
        run_case signature keygen "$algorithm" "$run" 1000
        run_case signature sign "$algorithm" "$run" 2500
        run_case signature verify "$algorithm" "$run" 2500
    done
done

/usr/bin/python3 "$ROOT/performance/summarize_comparative.py" "$OUTPUT" \
    | tee "$OUTPUT/SUMMARY.txt"
printf 'loadavg_end=%s\n' "$(sed -n '1p' /proc/loadavg)" \
    >>"$OUTPUT/environment.txt"
(cd "$OUTPUT" && sha256sum --strict --quiet -c INPUT_SHA256SUMS)
(
    cd "$OUTPUT"
    find . -type f ! -name RESULT_SHA256SUMS -print0 \
        | sort -z | xargs -0 sha256sum >RESULT_SHA256SUMS
    sha256sum --strict --quiet -c RESULT_SHA256SUMS
)
printf 'PASS comparative benchmark lane=%s result=%s\n' "$LANE" "$OUTPUT"
