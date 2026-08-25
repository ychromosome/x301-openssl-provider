# Performance measurement

`scripts/run-x301-benchmark-session.sh` runs one operation in four pinned ABBA
rounds. Each timed value comes from a fresh process; X25519 or ML-KEM-1024 is
measured before and after every round as a load/frequency control. The session
also records exact binaries and manifests, affinity, CPU state, load, process
snapshots and one deterministic Callgrind count per tested variant.

A number is a local reference unless all of these hold:

- baseline and candidate are paired in the same ABBA session;
- `PROVENANCE_COMPLETE` exists and all recorded hashes verify;
- the control-median drift is at most 3%;
- both deterministic instruction counts exist and agree in direction;
- correctness, constant-time and final-binary codegen gates pass separately.

Only then may a repeatable slowdown over 3% be classified automatically as a
performance finding. Absolute values and cross-session comparisons never meet
that rule by themselves.

Example:

```text
ED301_BASELINE_SOURCE_MANIFEST=/path/baseline/SOURCE_MANIFEST.sha256
ED301_CANDIDATE_SOURCE_MANIFEST=/path/candidate/SOURCE_MANIFEST.sha256
ED301_LANE_EVIDENCE_MANIFEST=/path/lane/EVIDENCE_MANIFEST.sha256
scripts/run-x301-benchmark-session.sh derive /path/openssl-prefix \
    /path/baseline-modules /path/candidate-modules 2 /tmp/x301-derive-session
```
