# Status

Date: 2026-08-25

## Components

| Component | State | Remaining decision |
|---|---|---|
| Ed301-EdDSA | Frozen draft-00 contract and experimental provider | Full-scope deep scan and release decision |
| X301 | Implemented, performance-tuned, pre-freeze | Independent review of the latest remediation and owner freeze |
| X301MLKEM1024 | Implemented as private-use TLS integration | Re-review after X301 remediation; no standards allocation claimed |

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

## Current performance baseline

Medians on one Ryzen 9 5950X host, measured separately on both OpenSSL lanes:

| Operation | OpenSSL 3.5.7 | OpenSSL 4.0.1 |
|---|---:|---:|
| X301 key generation | 36.97 us | 36.68 us |
| Prepared X301 derive | 35.48 us | 35.70 us |
| X25519 prepared derive control | 23.48 us | 23.89 us |
| X301/X25519 prepared ratio | 1.511x | 1.496x |
| One-shot X301 setup plus first derive | 93.28 us | 93.43 us |
| Hybrid key generation | 73.87 us | 73.19 us |
| Hybrid encapsulation | 146.04 us | 145.75 us |
| Hybrid decapsulation | 120.02 us | 119.70 us |

Key generation uses the existing constant-time fixed-base table. Repeated
main-curve derive uses a public-peer comb after two untimed warm-up calls;
first-use and twist inputs retain the ladder. The measured repeated-derive
ratio meets the owner-set 1.56x ceiling without moving table construction into
the one-shot measurement. These are local reference values, not portable
guarantees. A 3% regression classification is valid only for the
paired, provenance-bound procedure in `docs/PERFORMANCE_MEASUREMENT.md`.

## Toolchain boundary

The manifests require Rust 1.91 or newer because runtime field subtraction
uses `u64::borrowing_sub`. Canonical local evidence used Fedora rustc 1.97.1.
Constant-time and codegen conclusions apply only to each recorded compiler,
profile, architecture and final binary.

## Open gates

- Independent re-review of the security and performance remediation.
- Fresh full-repository deep security scan.
- AArch64 final-binary codegen and timing evidence.
- Coverage-guided fuzzing and additional platform lanes.
- Final identifier/standardization decisions, including any IANA allocation.
- Production-readiness and release review.

No production, universal constant-time, complete-zeroization, standards or
release claim is made.
