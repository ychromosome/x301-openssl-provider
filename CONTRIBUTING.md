# Contributing

This is an experimental cryptographic implementation candidate. Small,
reviewable issues and pull requests are welcome, but no contribution should
expand its claims or silently change the draft-00 byte contract.

Before proposing a change:

1. read `README.md`, `STATUS.md`, `ZEROIZATION_AND_CT_BOUNDARY.md`, the
   applicable draft under `docs/`, and the immutable inputs under
   `inputs/round4/`;
2. preserve Ed301-EdDSA's context-free one-shot API and the documented X301
   and hybrid encodings unless a new incompatible profile is proposed;
3. keep Ed301 and X301 key domains separate;
4. update tests and provenance for every behavioral change;
5. regenerate `SOURCE_MANIFEST.sha256`; and
6. run `sh scripts/check.sh` and, where Valgrind is available,
   `sh scripts/check-secret-taint.sh`.

Changes to X301 parsing or arithmetic also run
`scripts/run-x301-fuzz.sh --runs 40000`. The fast GitHub workflow repeats the
core and bounded fuzz gates; it does not replace the dual OpenSSL-lane, TLS,
Valgrind or final-codegen matrices.

Changes to X301 or MLKEM1024X301 additionally require the dual-lane provider
and TLS entry points in `docs/X301_EXTENDED_ASSURANCE.md`.  Run
`scripts/check-x301-long.sh` when the ladder, field use, clamping, basepoint or
frozen long vector changes; it is deliberately excluded from an ordinary
developer test loop.

Do not submit production-readiness, audit, constant-time-completion,
zeroization-completion or standards claims without corresponding independent
evidence.
