# Contributing

Changes MUST preserve the documented Ed301, X301, and hybrid wire contracts
unless they introduce an explicitly incompatible profile. Ed301 and X301 keys
MUST remain separate.

Before submitting a change:

1. Read `README.md`, `STATUS.md`, `ZEROIZATION_AND_CT_BOUNDARY.md`, the
   applicable draft, and `inputs/round4/`.
2. Add independent expected values for behavioral changes.
3. Regenerate `SOURCE_MANIFEST.sha256`.
4. Run `scripts/check.sh` and the affected provider, TLS, fuzz, taint, and
   final-codegen gates.

X301 parsing or arithmetic changes require:

```sh
scripts/run-x301-fuzz.sh --runs 40000
```

Ladder, field, clamp, basepoint, or long-vector changes also require:

```sh
scripts/check-x301-long.sh
```

Repository text MUST retain only unique normative requirements, formats,
security rationale, reproducible commands, provenance, user instructions,
known limits, and open questions. Duplicate status prose, review history,
test diaries, self-assessment, and obvious code comments MUST be deleted.

Do not claim production readiness, completed audit, universal constant-time
behavior, complete zeroization, or standards status without independent
evidence for the exact source and binaries.
