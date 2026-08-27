# X301 coverage-guided fuzzing

`x301_core` covers strict decoding, arbitrary lengths, clamping aliases,
basepoint equivalence and Diffie-Hellman commutativity. It uses the upstream
Rust Fuzz `libfuzzer-sys` crate as test-only infrastructure; product code and
dependencies are unchanged.

Run a bounded local gate with:

```sh
scripts/run-x301-fuzz.sh --runs 40000
```

The script records tool identities, preserves the evolving corpus outside the
source tree and fails on a panic or libFuzzer crash. The dual-lane provider
runner separately builds `provider_x301_fuzz.c` with libFuzzer, ASan and UBSan;
that target exercises raw X301 FFI, hybrid public-key parsing, decapsulation
output atomicity and context duplication.

This is assurance evidence, not a production-readiness or universal memory-
safety claim.
