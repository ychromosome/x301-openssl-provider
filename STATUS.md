# Status

Date: 2026-08-27

| Component | State |
|---|---|
| Ed301-EdDSA | Experimental integration dependency |
| X301 | Experimental review candidate |
| MLKEM1024X301 | Experimental private-use TLS integration |

The current work removes the automatic prepared-peer accelerator, corrects
the ML-KEM-first group name, publishes the complete retained curve-search
evidence, makes the runners portable across packaged Rust and rustup layouts,
and lets the child library context select OpenSSL's ML-KEM implementation.
Every X301 derive now uses one ladder implementation.

The checked-in curve provenance reproduces the recorded search through
`c=50687` and the first recorded qualifying candidate at `c=44730`. It is an
after-the-fact publication, not a pre-search public commitment or an external
audit.

## Required before another candidate freeze

- complete core, provider, TLS, taint, codegen and benchmark reruns on the
  final source bytes;
- coverage-guided TLS wire-state fuzzing beyond the persisted core and
  provider-boundary targets;
- final-binary constant-time evidence on x86-64 and AArch64;
- an independent implementation and interoperability run; and
- identifier/standardization and release-governance decisions.

`0xFE2E` remains a test-only Private Use NamedGroup. No production, FIPS,
standardization, universal constant-time or complete-zeroization claim is
made.
