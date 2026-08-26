# Status

Date: 2026-08-27

## Components

| Component | State | Remaining decision |
|---|---|---|
| Ed301-EdDSA | Frozen draft-00 contract and experimental provider | Full-scope deep scan and release decision |
| X301 | Implementation-frozen experimental candidate | Deep scan and release decision |
| X301MLKEM1024 | Implementation-frozen private-use integration | Deep scan; no standards allocation claimed |

X301 is additive: it reuses the ED301 field backend but has a distinct key
domain and does not change Ed301-EdDSA bytes or verification semantics.

## Completed local gates

- Core tests in both feature states and release profiles.
- Frozen KATs, 1,000 deterministic properties, 10,000 independent Python
  differentials and the separate one-million-iteration reproduction.
- Ten sealed Valgrind secret-taint cases covering Ed301 public/sign and X301
  keygen/ladder/prepared derive, each in defined and tainted form.
- Final-provider disassembly gates on both lanes, including the prepared comb.
- Dual-lane KEYMGMT/KEYEXCH, raw-key, failure, sanitizer, Valgrind and ML-KEM
  integration contracts.
- TLS 1.3 normal, HRR, fragmentation, mutation, resumption and cross-lane
  interoperability matrices for X301MLKEM1024.

These are local development results, not independent reproduction.

Independent performance and security rereviews were repaired before freeze.
Codex Security Standard scan `2965ac81-9427-4d71-b4cc-0e1dda702370` reviewed
the pre-freeze working tree rooted at revision `c4ea771` and confirmed no
product finding. Its evidence follow-ups are closed separately by the RAND,
snapshot, artifact-identity and codegen-gate changes in this freeze commit.

## Current performance baseline

Preliminary medians on one Ryzen 9 5950X host after the lazy ladder and fixed
clamped-bit schedule, using OpenSSL 3.5.7:

| Operation | X301 | X25519 control | Ratio |
|---|---:|---:|---:|
| Key generation | 36.64 us | 23.59 us | 1.55x |
| Setup plus first derive | 60.5 us | 24.6 us | 2.46x |
| Second derive, including table build | 118.09 us | 23.61 us | 5.00x |
| Prepared steady derive | 33.46 us | 23.61 us | 1.42x |

Key generation and prepared steady derive meet the owner-set 1.56x ceiling.
Cold derive does not. Its current result is accepted for the implementation
freeze. It improved from about 93--94 us to about 60.5 us; the
latest steps reduced the raw first derive from 75.08 to 58.78 us. The second
call deliberately exposes the one-time 1,920-byte public-peer table build
instead of hiding it in warm-up.
These values are local engineering measurements, not portable guarantees.
Only the provenance-bound procedures in `docs/PERFORMANCE_MEASUREMENT.md`
may support an acceptance decision.

## Toolchain boundary

The manifests require Rust 1.91 or newer because runtime field subtraction
uses `u64::borrowing_sub`. Canonical local evidence used Fedora rustc 1.97.1.
Constant-time and codegen conclusions apply only to each recorded compiler,
profile, architecture and final binary.

## Open gates

- Fresh full-repository deep security scan.
- AArch64 final-binary codegen and timing evidence.
- Coverage-guided fuzzing and additional platform lanes.
- Final identifier/standardization decisions, including any IANA allocation.
- Production-readiness and release review.

No production, universal constant-time, complete-zeroization, standards or
release claim is made.
