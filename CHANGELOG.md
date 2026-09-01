# Changelog

## Unreleased

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
- Added independent Python vectors, dual OpenSSL 3.5.7/4.0.1 provider and TLS
  matrices, persisted fuzz targets, secret-taint tests, and final-binary
  codegen gates.
- Ed301-EdDSA uses OID `1.3.6.1.4.1.66282.301.3`. The retired
  Ed301-Sig-v1 identity remains `.301.1`; X301 remains `.301.2`.
