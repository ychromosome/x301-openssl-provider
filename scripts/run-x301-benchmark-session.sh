#!/bin/bash
set -Eeuo pipefail

PATH=/usr/bin:/bin
export PATH LC_ALL=C
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
if (( $# < 6 || $# > 7 )); then
    printf 'usage: %s <keygen|derive-setup|derive-first|derive-second|derive-steady|kem-keygen|encaps|decaps> <openssl-prefix> <baseline-modules> <candidate-modules> <cpu> <fresh-output-dir> [count]\n' "$0" >&2
    exit 2
fi

OPERATION=$1
PREFIX=$(readlink -f -- "$2")
BASELINE=$(readlink -f -- "$3")
CANDIDATE=$(readlink -f -- "$4")
CPU=$5
OUTPUT=$6
COUNT=${7:-}
case "$OPERATION" in
    keygen) COUNT=${COUNT:-2000}; CONTROL=X25519; CONTROL_BYTES=32 ;;
    derive-setup|derive-first|derive-second|derive-steady)
        COUNT=${COUNT:-4000}; CONTROL=X25519; CONTROL_BYTES=32 ;;
    kem-keygen|encaps|decaps)
        COUNT=${COUNT:-1000}; CONTROL=ML-KEM-1024; CONTROL_BYTES=0 ;;
    *) printf 'unsupported operation: %s\n' "$OPERATION" >&2; exit 2 ;;
esac
case "$CPU:$COUNT" in
    *[!0-9:]*|:*) printf 'cpu and count must be non-negative integers\n' >&2; exit 2 ;;
esac

if [[ ${X301_BENCH_PINNED:-0} != 1 ]]; then
    exec env X301_BENCH_PINNED=1 taskset -c "$CPU" "$0" "$@"
fi
[[ ! -e $OUTPUT && ! -L $OUTPUT ]] || {
    printf 'output directory must not exist: %s\n' "$OUTPUT" >&2
    exit 2
}
mkdir -m 700 -- "$OUTPUT"
OUTPUT=$(readlink -f -- "$OUTPUT")

OPENSSL=$PREFIX/bin/openssl
if [[ -d $PREFIX/lib64 ]]; then LIBDIR=$PREFIX/lib64; else LIBDIR=$PREFIX/lib; fi
for required in "$OPENSSL" "$ROOT/performance/x301_bench.c" \
        "$ROOT/performance/summarize.py"; do
    [[ -f $required && ! -L $required ]] || {
        printf 'missing regular input: %s\n' "$required" >&2; exit 2;
    }
done
for directory in "$BASELINE" "$CANDIDATE" "$LIBDIR"; do
    [[ -d $directory ]] || {
        printf 'missing directory: %s\n' "$directory" >&2; exit 2;
    }
done
for target in "$BASELINE/x301.so" "$CANDIDATE/x301.so"; do
    [[ -f $target && ! -L $target ]] || {
        printf 'missing regular X301 provider: %s\n' "$target" >&2
        exit 2
    }
done

BENCH=$OUTPUT/x301_bench
/usr/bin/cc -O3 -Wall -Wextra -Werror -std=c11 \
    -I"$PREFIX/include" "$ROOT/performance/x301_bench.c" \
    -L"$LIBDIR" -Wl,-rpath,"$LIBDIR" -lcrypto -o "$BENCH"
"$BENCH" --self-test >"$OUTPUT/benchmark-self-test.txt"
printf '%s\n' \
    'cc -O3 -Wall -Wextra -Werror -std=c11 -I${OPENSSL_PREFIX}/include' \
    '  performance/x301_bench.c -L${OPENSSL_LIBDIR}' \
    '  -Wl,-rpath,${OPENSSL_LIBDIR} -lcrypto -o x301_bench' \
    >"$OUTPUT/benchmark-build-command.txt"

CANDIDATE_SOURCE_MANIFEST=${ED301_CANDIDATE_SOURCE_MANIFEST:-MISSING}
if [[ -f $CANDIDATE_SOURCE_MANIFEST && ! -L $CANDIDATE_SOURCE_MANIFEST ]]; then
    (cd "$ROOT" && sha256sum --strict --quiet -c "$CANDIDATE_SOURCE_MANIFEST")
fi

{
    printf 'format=x301-benchmark-session-v1\n'
    printf 'timestamp_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'operation=%s\ncount=%s\ncpu=%s\n' "$OPERATION" "$COUNT" "$CPU"
    printf 'affinity=%s\n' "$(taskset -pc $$ | sed 's/^[^:]*: //')"
    printf 'hostname=%s\n' "$(hostname)"
    printf 'kernel=%s\n' "$(uname -srvmo)"
    printf 'cpu_model=%s\n' "$(sed -n '/^model name[[:space:]]*: / {
        s/^model name[[:space:]]*: //
        p
        q
    }' /proc/cpuinfo)"
    printf 'loadavg=%s\n' "$(sed -n '1p' /proc/loadavg)"
    governor=/sys/devices/system/cpu/cpu"$CPU"/cpufreq/scaling_governor
    turbo=/sys/devices/system/cpu/intel_pstate/no_turbo
    printf 'governor=%s\n' "$(if [[ -r $governor ]]; then sed -n '1p' "$governor"; else printf unavailable; fi)"
    printf 'intel_no_turbo=%s\n' "$(if [[ -r $turbo ]]; then sed -n '1p' "$turbo"; else printf unavailable; fi)"
    printf 'openssl_prefix=%s\nbaseline_modules=%s\ncandidate_modules=%s\n' \
        "$PREFIX" "$BASELINE" "$CANDIDATE"
} >"$OUTPUT/session.env"

INPUTS=$OUTPUT/inputs
mkdir -m 700 -- "$INPUTS"
copy_artifact() {
    label=$1
    source=$2
    destination=$3
    if [[ -f $source ]]; then
        cp -- "$source" "$INPUTS/$destination"
        source_digest=$(sha256sum "$source" | awk '{print $1}')
        copied_digest=$(sha256sum "$INPUTS/$destination" | awk '{print $1}')
        [[ $source_digest == "$copied_digest" ]] || return 1
        printf '%s\t%s\tinputs/%s\n' "$label" "$copied_digest" "$destination"
        return 0
    fi
    printf '%s\tMISSING\tinputs/%s\n' "$label" "$destination"
    return 1
}

provenance_ok=1
{
    printf 'label\tsha256\tpath\n'
    copy_artifact benchmark-source "$ROOT/performance/x301_bench.c" \
        benchmark-source.c || provenance_ok=0
    copy_artifact benchmark-runner "$ROOT/scripts/run-x301-benchmark-session.sh" \
        benchmark-runner.sh || provenance_ok=0
    copy_artifact benchmark-summarizer "$ROOT/performance/summarize.py" \
        benchmark-summarizer.py || provenance_ok=0
    copy_artifact benchmark-build-command "$OUTPUT/benchmark-build-command.txt" \
        benchmark-build-command.txt || provenance_ok=0
    copy_artifact benchmark-self-test "$OUTPUT/benchmark-self-test.txt" \
        benchmark-self-test.txt || provenance_ok=0
    copy_artifact benchmark-compiler "$(readlink -f -- /usr/bin/cc)" \
        benchmark-compiler || provenance_ok=0
    copy_artifact benchmark-binary "$BENCH" benchmark-binary || provenance_ok=0
    copy_artifact openssl-binary "$(readlink -f -- "$OPENSSL")" \
        openssl-binary || provenance_ok=0
    library_count=0
    while IFS= read -r artifact; do
        library_count=$((library_count + 1))
        copy_artifact openssl-library "$artifact" \
            "openssl-library-$library_count-$(basename "$artifact")" \
            || provenance_ok=0
    done < <(find "$LIBDIR" -maxdepth 1 -type f \( -name 'libcrypto.so*' -o -name 'libssl.so*' \) -print | sort)
    (( library_count > 0 )) || provenance_ok=0
    copy_artifact baseline-target-provider "$BASELINE/x301.so" \
        baseline-target-x301.so || provenance_ok=0
    copy_artifact candidate-target-provider "$CANDIDATE/x301.so" \
        candidate-target-x301.so || provenance_ok=0
    baseline_provider_count=0
    while IFS= read -r artifact; do
        baseline_provider_count=$((baseline_provider_count + 1))
        copy_artifact baseline-support-provider "$artifact" \
            "baseline-support-$baseline_provider_count-$(basename "$artifact")" \
            || provenance_ok=0
    done < <(find "$BASELINE" -maxdepth 1 -type f -name '*.so*' \
        ! -name 'x301.so' -print | sort)
    candidate_provider_count=0
    while IFS= read -r artifact; do
        candidate_provider_count=$((candidate_provider_count + 1))
        copy_artifact candidate-support-provider "$artifact" \
            "candidate-support-$candidate_provider_count-$(basename "$artifact")" \
            || provenance_ok=0
    done < <(find "$CANDIDATE" -maxdepth 1 -type f -name '*.so*' \
        ! -name 'x301.so' -print | sort)
    copy_artifact baseline-source-manifest \
        "${ED301_BASELINE_SOURCE_MANIFEST:-MISSING}" \
        baseline-source-manifest.sha256 || provenance_ok=0
    copy_artifact candidate-source-manifest "$CANDIDATE_SOURCE_MANIFEST" \
        candidate-source-manifest.sha256 || provenance_ok=0
    copy_artifact lane-evidence-manifest \
        "${ED301_LANE_EVIDENCE_MANIFEST:-MISSING}" \
        lane-evidence-manifest.sha256 || provenance_ok=0
} >"$OUTPUT/artifacts.tsv"
awk -F '\t' 'NR > 1 && $2 ~ /^[0-9a-f]{64}$/ { print $2 "  " $3 }' \
    "$OUTPUT/artifacts.tsv" >"$OUTPUT/INPUT_SHA256SUMS"
if ! (cd "$OUTPUT" && sha256sum --strict --quiet -c INPUT_SHA256SUMS); then
    provenance_ok=0
fi
if (( provenance_ok == 1 )); then : >"$OUTPUT/PROVENANCE_COMPLETE"; fi
(cd "$OUTPUT" && sha256sum session.env artifacts.tsv >session.sha256
    sha256sum --strict --quiet -c session.sha256)
artifact_manifest_sha256=$(sha256sum "$OUTPUT/artifacts.tsv" | awk '{print $1}')
affinity=$(taskset -pc $$ | sed 's/^[^:]*: //')

printf 'sequence\ttimestamp_utc\tpid\taffinity\tloadavg\tphase\tround\tposition\tvariant\talgorithm\tstatus\tmean_ns\targv\tlog\tartifacts_sha256\n' >"$OUTPUT/runs.tsv"
printf 'sequence\ttimestamp_utc\tpid\tpsr\tstat\tpcpu\tcomm\n' >"$OUTPUT/processes.tsv"
sequence=0

run_one() {
    phase=$1 round=$2 position=$3 variant=$4 algorithm=$5 properties=$6 modules=$7 bytes=$8 count=$9
    sequence=$((sequence + 1))
    tag=$(printf '%04d-%s-%s' "$sequence" "$variant" "$algorithm" | tr -c 'A-Za-z0-9._-' '_')
    log=$OUTPUT/$tag.log
    argv_file=$OUTPUT/$tag.argv
    printf '%q ' "$BENCH" "$phase" "$algorithm" "$properties" "$modules" "$bytes" "$count" >"$argv_file"
    printf '\n' >>"$argv_file"
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    loadavg=$(sed -n '1p' /proc/loadavg)
    ps -eo pid=,psr=,stat=,pcpu=,comm= | awk -v seq="$sequence" -v now="$timestamp" \
        '{print seq "\t" now "\t" $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5}' \
        >>"$OUTPUT/processes.tsv"
    env LD_LIBRARY_PATH="$LIBDIR" "$BENCH" "$phase" "$algorithm" \
        "$properties" "$modules" "$bytes" "$count" >"$log" 2>&1 &
    pid=$!
    status=0
    wait "$pid" || status=$?
    mean_ns=$(sed -n 's/.* mean_ns=\([0-9.]*\).*/\1/p' "$log")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$sequence" "$timestamp" "$pid" "$affinity" "$loadavg" "$phase" \
        "$round" "$position" "$variant" "$algorithm" "$status" "$mean_ns" \
        "$(basename "$argv_file")" "$(basename "$log")" "$artifact_manifest_sha256" \
        >>"$OUTPUT/runs.tsv"
    (( status == 0 )) || return "$status"
}

if [[ $OPERATION == keygen || $OPERATION == derive-setup \
        || $OPERATION == derive-first || $OPERATION == derive-second \
        || $OPERATION == derive-steady ]]; then
    TARGET_ALGORITHM=X301; TARGET_PROPERTIES=provider=x301; TARGET_BYTES=38
else
    TARGET_ALGORITHM=X301MLKEM1024; TARGET_PROPERTIES=provider=x301; TARGET_BYTES=0
fi
round=1
while (( round <= 4 )); do
    run_one "$OPERATION" "$round" pre control-pre "$CONTROL" - - "$CONTROL_BYTES" "$COUNT"
    run_one "$OPERATION" "$round" A1 baseline "$TARGET_ALGORITHM" "$TARGET_PROPERTIES" "$BASELINE" "$TARGET_BYTES" "$COUNT"
    run_one "$OPERATION" "$round" B1 candidate "$TARGET_ALGORITHM" "$TARGET_PROPERTIES" "$CANDIDATE" "$TARGET_BYTES" "$COUNT"
    run_one "$OPERATION" "$round" B2 candidate "$TARGET_ALGORITHM" "$TARGET_PROPERTIES" "$CANDIDATE" "$TARGET_BYTES" "$COUNT"
    run_one "$OPERATION" "$round" A2 baseline "$TARGET_ALGORITHM" "$TARGET_PROPERTIES" "$BASELINE" "$TARGET_BYTES" "$COUNT"
    run_one "$OPERATION" "$round" post control-post "$CONTROL" - - "$CONTROL_BYTES" "$COUNT"
    round=$((round + 1))
done

printf 'variant\tstatus\tinstructions\tcallgrind_file\n' >"$OUTPUT/ir.tsv"
for variant in baseline candidate; do
    if [[ $variant == baseline ]]; then modules=$BASELINE; else modules=$CANDIDATE; fi
    callgrind=$OUTPUT/callgrind.$variant.out
    log=$OUTPUT/callgrind.$variant.log
    status=0
    env LD_LIBRARY_PATH="$LIBDIR" valgrind --quiet --tool=callgrind \
        --instr-atstart=no --callgrind-out-file="$callgrind" \
        "$BENCH" "$OPERATION" "$TARGET_ALGORITHM" "$TARGET_PROPERTIES" \
        "$modules" "$TARGET_BYTES" 1 >"$log" 2>&1 || status=$?
    instructions=$(callgrind_annotate --inclusive=yes --auto=no "$callgrind" \
        | awk '
            !found && /PROGRAM TOTALS/ {
                gsub(/,/, "", $1)
                value = $1
                found = 1
            }
            END {
                if (!found)
                    exit 1
                print value
            }
        ')
    printf '%s\t%s\t%s\t%s\n' "$variant" "$status" "$instructions" "$(basename "$callgrind")" >>"$OUTPUT/ir.tsv"
done

/usr/bin/python3 "$ROOT/performance/summarize.py" "$OUTPUT" | tee "$OUTPUT/SUMMARY.txt"
(
    cd "$OUTPUT"
    find . -type f ! -name RESULT_SHA256SUMS -print0 \
        | sort -z | xargs -0 sha256sum >RESULT_SHA256SUMS
    sha256sum --strict --quiet -c RESULT_SHA256SUMS
)
