# X301 extended test lane

This lane supplements T1-T13. It adapts Wycheproof and OpenSSL test
categories, not X25519/X448 expected bytes.

## Entry points

```sh
python3 -I -B -O reference/x301/generate_adversarial_corpus.py --check
python3 -I -B -O reference/x301/test_x301_reference.py

scripts/run-authoritative-gate.sh archive SOURCE_MANIFEST_SHA256 \
  test-x301-provider-contracts \
    OPENSSL_3_5_8_ROOT OPENSSL_3_5_8_EVIDENCE_SHA256 \
    OPENSSL_4_0_2_ROOT OPENSSL_4_0_2_EVIDENCE_SHA256

scripts/run-authoritative-gate.sh archive SOURCE_MANIFEST_SHA256 test-x301-tls \
  OPENSSL_3_5_8_ROOT OPENSSL_3_5_8_EVIDENCE_SHA256 \
  OPENSSL_4_0_2_ROOT OPENSSL_4_0_2_EVIDENCE_SHA256

scripts/run-authoritative-gate.sh archive SOURCE_MANIFEST_SHA256 \
  test-x301-tls --long-handshakes 1000 \
  OPENSSL_3_5_8_ROOT OPENSSL_3_5_8_EVIDENCE_SHA256 \
  OPENSSL_4_0_2_ROOT OPENSSL_4_0_2_EVIDENCE_SHA256
```

`scripts/check.sh`, `scripts/check-secret-taint.sh`, and
`scripts/check-x301-long.sh` require an externally anchored read-only source
snapshot.

## Required coverage

| Family | Cases |
| --- | --- |
| W1-W6 | order-2/order-4 main/twist points, large-order twist inputs, D2 aliases and reductions, clamp, zero-octet, length, and type boundaries; 560 generated cases |
| O1-O2 | native `evp_test` KAT, pairwise, missing-peer, and wrong-peer cases |
| P1-P4 | 1,000 deterministic commutativity, birational, clamp, and canonical-output cases |
| M1-M6 | peer replacement, repeat derive, `dupctx`, re-init, fresh local context, concurrency, allocation failure, and panic |
| R1-R7 | cross-lane TLS, HRR, fragmentation, fallback, wire mutations, foreign-size rejection, resumption, and fresh shares |
| F1-F4 | persisted core/provider libFuzzer targets and the 55,100-case structured provider sweep per lane |
| L1-L2 | one-million iteration vector and 1,000 complete hybrid handshakes per lane |

The structured sweep covers raw lengths 0-76, all deletion and insertion
positions, every byte value at every position of a valid 38-byte key, hybrid
lengths 0-1607, every bit of valid 1,606-byte shares, and all hybrid deletion
and insertion positions. It does not prove arbitrary-input safety.

## Fuzz boundary

`fuzz/fuzz_targets/x301_core.rs` covers length, D2 decoding, aliases,
basepoint equivalence, and DH commutativity.
`provider-tests/x301/provider_x301_fuzz.c` covers raw KEYEXCH, hybrid parsing,
output atomicity, and context duplication.

The provider target uses a fixed seed and 20,000 mutations per OpenSSL lane.
The C boundary also runs under ASan and UBSan. A separate Valgrind lane taints
provider-owned X301 and hybrid shared-secret buffers. Corpora under
`fuzz/corpus/` are tracked; crashes and evolving corpora remain outside the
verified tree.

TLS wire-state coverage-guided fuzzing and AArch64 runs remain open.

## Result identity

A result MUST record the source-manifest digest, toolchains, OpenSSL lane
digests, module hashes, commands, and logs. Git-backed runs also record the
commit; archive runs use the external manifest digest as their source
identity. Historical PASS logs or an unanchored worktree do not establish the
current source.
