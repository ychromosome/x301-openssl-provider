# Performance measurement

`scripts/run-x301-benchmark-session.sh` runs one operation in four pinned ABBA
rounds. Each timed value comes from a fresh process; X25519 or ML-KEM-1024 is
measured before and after every round as a load/frequency control. The session
also records exact binaries and manifests, affinity, CPU state, load, process
snapshots and one deterministic Callgrind count per tested variant.

For key exchange, four timings are retained for longitudinal compatibility.
Each derive timing measures only the named call; setup happens outside the
timer:

- `derive-setup`: fresh public-key import, context creation, derive init and
  peer setup; no derivation;
- `derive-first`: the first 301-bit ladder derive;
- `derive-second`: a second derive on the same context;
- `derive-steady`: a third derive on the same context.

Cold one-shot latency is `derive-setup + derive-first`. All three derive calls
use the same ladder; second and steady measurements detect unintended
state-dependent behaviour and ordinary warm-cache effects. Historical
preparation break-even fields, where present in old result artifacts, are not
claims about the current provider.

A number is a local reference unless all of these hold:

- baseline and candidate are paired in the same ABBA session;
- `PROVENANCE_COMPLETE` exists and all recorded hashes verify;
- the control-median drift is at most 3%;
- both deterministic instruction counts exist and agree in direction;
- correctness, constant-time and final-binary codegen gates pass separately.

Only then may a repeatable slowdown over 3% be classified automatically as a
performance finding. Absolute values and cross-session comparisons never meet
that rule by themselves.

`scripts/run-x301-comparative-benchmark.sh` measures the current X301,
X301MLKEM1024 and Ed301 artifacts beside OpenSSL's X25519, X448, ML-KEM and
EdDSA controls. It copies and hashes the runner, sources, compiler, OpenSSL
libraries, provider modules, source manifest, lane manifest, raw logs and
derived table. Before creating an output directory it verifies the selected
OpenSSL prefix against the externally sealed lane root and digest.
`PROVENANCE_COMPLETE` is created only after all copied inputs verify, and the
complete result uses relative checksum paths.

Example:

```text
ED301_BASELINE_SOURCE_MANIFEST=/path/baseline/SOURCE_MANIFEST.sha256
ED301_CANDIDATE_SOURCE_MANIFEST=/path/candidate/SOURCE_MANIFEST.sha256
ED301_LANE_EVIDENCE_MANIFEST=/path/lane/EVIDENCE_MANIFEST.sha256
scripts/run-x301-benchmark-session.sh derive-first /path/openssl-prefix \
    /path/baseline-modules /path/candidate-modules 2 /tmp/x301-derive-session

scripts/run-x301-comparative-benchmark.sh 3.5.8 /path/sealed-lane \
    <lane-evidence-sha256> /path/provider-modules SOURCE_MANIFEST.sha256 \
    2 /tmp/x301-comparative
```
