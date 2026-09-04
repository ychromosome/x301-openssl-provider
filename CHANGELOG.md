# Changelog

## Unreleased

- X301 key generation now draws from one provider-owned `CTR-DRBG` instance
  (fetched under the child-context policy, seeded through the core entropy
  upcall, locked) instead of `RAND_priv_bytes_ex()` on the child context, and
  the per-operation `OPENSSL_thread_stop_ex(child)` calls are gone. No
  per-thread state remains on the child context, so provider unload while
  worker threads live needs no thread stop. X301 keygen throughput at 16
  threads improves about 3.7x and the hybrid KEM round trip about 35%. This
  is registered as exception X-RAND-INSTANCE to construction rule E4. The
  warm instance keeps the implementation selected at first key generation
  across later property-policy changes, as libcrypto's own DRBGs do; only a
  fresh library context re-evaluates the policy. New T7 lifecycle,
  DRBG-policy fail-closed and warm-instance tests.
- X301 public inputs now require 38 bytes, clear bits 301-303, and subtract
  `p` once when necessary. Imports store and export the canonical coordinate.
  Post-ladder all-zero rejection is unchanged.
- Added X301 KEYMGMT/KEYEXCH and the private-use TLS 1.3 group
  `X301MLKEM1024`. ML-KEM-1024 is fetched through OpenSSL EVP. Shares and
  secrets are concatenated ML-KEM first; the project adds no hybrid KDF.
- X301 key generation uses the existing constant-time Ed301 fixed-base table
  and a one-inversion projective Edwards-to-Montgomery map. The previous
  generic basepoint ladder remains a differential test reference.
- Removed automatic prepared-peer acceleration. Every derive uses the same
  Montgomery ladder.
- Added independent Python vectors, dual OpenSSL 3.5.8/4.0.2 provider and TLS
  matrices, persisted fuzz targets, secret-taint tests, and final-binary
  codegen gates.
- Removed the bundled Ed301-EdDSA-draft-00 provider. Its `.301.3` OID remains
  frozen; the canonical Ed301-EdDSA-v1 provider uses `.301.4` in its own
  repository. X301 remains `.301.2`.
