# Provider status

The repository builds two experimental provider families:

| Build | Module | Surface |
|---|---|---|
| Ed301 | `ed301_eddsa_draft00.so` | `KEYMGMT`, `SIGNATURE` |
| X301 raw | `x301-raw.so` | `KEYMGMT`, `KEYEXCH` |
| X301 hybrid feature | `x301.so` | raw X301 plus private-use `MLKEM1024X301` |

OpenSSL ABI majors 3 and 4 are accepted. The normative test lanes are 3.5.7
and 4.0.1.

## X301

- private, public and shared values are exactly 38 bytes;
- key generation uses `RAND_priv_bytes_ex()` in the provider child context;
- public generation uses the existing constant-time Ed301 fixed-base path;
- derive always uses the same fixed-schedule Montgomery ladder;
- peer encodings must be canonical and all-zero results are rejected; and
- Ed301 and X301 key objects are not interchangeable.

## MLKEM1024X301

The project implements no ML-KEM arithmetic. It fetches `ML-KEM-1024` through
EVP in the child library context with a null property query, so the
application's provider/property policy selects the implementation.

| Value | Encoding | Length |
|---|---|---:|
| Client share | ML-KEM key || X301 public | 1606 |
| Server share | ML-KEM ciphertext || X301 public | 1606 |
| Shared secret | ML-KEM secret || X301 secret | 70 |

The OpenSSL hybrid security-bits field is 256; the component profile is
ML-KEM-1024/X301 = 256/149 bits. NamedGroup `0xFE2E` is Private Use and
test-only.

## Open gates

The final-source matrices and persisted core/provider fuzz targets must still
be rerun on the final bytes. TLS wire-state fuzzing, AArch64 codegen/timing,
independent interoperability, standardization and release review remain open.
No production, FIPS or standards claim is made.
