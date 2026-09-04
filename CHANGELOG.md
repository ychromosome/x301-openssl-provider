# Changelog

## Unreleased

- X301 key generation uses one locked provider-owned `CTR-DRBG`, seeded by
  the child library context's primary DRBG. This removes per-operation
  `OPENSSL_thread_stop_ex(child)` calls and child-context thread-local state.
  The local instance and lifecycle remain registered as exception
  X-RAND-INSTANCE to construction rule E4. The hybrid artifact disables
  child-local provider fallback. Without application-context ML-KEM-1024,
  raw X301 remains available and the hybrid group is not advertised.
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
