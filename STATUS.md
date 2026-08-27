# Status

Date: 2026-08-27

| Component | State |
| --- | --- |
| Ed301-EdDSA | Experimental integration dependency |
| X301 | Experimental review candidate |
| MLKEM1024X301 | Experimental private-use TLS integration |

Before a candidate freeze, the final source bytes still require:

- complete core, provider, TLS, taint, codegen, and benchmark reruns;
- coverage-guided TLS wire-state fuzzing;
- final-binary constant-time review on x86-64 and AArch64;
- independent implementation and interoperability; and
- identifier, standardization, and release-governance decisions.

The curve-search evidence is after-the-fact provenance, not a pre-search
commitment or independent audit. NamedGroup `0xFE2E` remains test-only.
