# Provider status

The repository builds two distinct experimental provider families:

| Build | Installed module | Surface |
|---|---|---|
| Ed301 provider | `ed301_eddsa_draft00.so` | Ed301 `KEYMGMT` and `SIGNATURE` |
| X301 default features | `x301-raw.so` | X301 `KEYMGMT`/`KEYEXCH` only |
| X301 with `tls-x301-mlkem1024` | `x301.so` | Raw X301 plus the private-use X301MLKEM1024 TLS group |

Cargo names both X301 build outputs `libx301.so`; packaging and evidence must
rename the raw-only artifact to `x301-raw.so`. The authoritative integration
matrix always builds the explicit hybrid feature and records it as `x301.so`.

Ed301 and X301 share field arithmetic but never share keys. The ordinary
Ed301 module exposes no TLS capability, OID alias, encoder or decoder.
Optional Ed301 PKI and private-use TLS proof modules remain separately named,
disabled-by-default test artifacts.

## ABI and review lanes

Runtime compatibility is gated only on the ABI major used to build the module:
OpenSSL 3 or OpenSSL 4. Minor and patch versions are not rejected. This is a
compatibility policy, not evidence that every minor release has been tested.

The reproducible provider matrix targets exactly:

- OpenSSL 3.5.7; and
- OpenSSL 4.0.1.

Each lane is built from a pinned release tarball and accepted only with an
externally recorded evidence-manifest digest. One module is built per ABI
major. X301MLKEM1024 additionally requires `ML-KEM-1024` to be fetchable from
OpenSSL's default provider; its operations fail closed when that optional
algorithm is unavailable. Raw X301 has no ML-KEM dependency.

## X301 contract

- Raw private and public keys are exactly 38 bytes.
- Key generation obtains its seed from `RAND_priv_bytes_ex()` in a child
  `OSSL_LIB_CTX`; it has no operating-system RNG fallback.
- The clamped scalar is reduced modulo `L` and multiplied through the existing
  constant-time Edwards fixed-base table. The result is mapped directly with
  `u=(Z+Y)/(Z-Y)`, using one field inversion.
- Public-key generation is byte-identical to the retained 301-bit
  Montgomery-ladder reference over the frozen boundaries and 10,000
  independent differential cases.
- Peer inputs require canonical 38-byte u encodings. Derivation uses the fixed
  301-bit ladder schedule and rejects an all-zero shared secret.
- X301 keys cannot be imported as Ed301 signing keys, or vice versa.

The fixed-base optimization adds no unsafe Rust, assembly, CPU dispatch,
second field backend, dependency or wire-format change. The public
cryptographic core retains `#![forbid(unsafe_code)]`; native pointers remain
inside the existing provider FFI boundary.

## X301MLKEM1024 contract

ML-KEM-1024 is fetched from OpenSSL's default provider. This repository does
not implement ML-KEM and adds no combiner KDF.

| Value | Encoding | Length |
|---|---|---:|
| Client share | ML-KEM encapsulation key || X301 public key | 1606 bytes |
| Server share | ML-KEM ciphertext || X301 public key | 1606 bytes |
| Shared secret | ML-KEM secret || X301 secret | 70 bytes |

Every parser requires the exact component and total lengths. An X301 all-zero
result fails the whole group. ML-KEM implicit rejection remains OpenSSL-owned;
a modified ciphertext is detected by the TLS Finished check rather than being
converted into a project-specific explicit KEM error.

The TLS NamedGroup `0xFE2E` is private-use, test-only and not an IANA
allocation. No standalone hybrid wire format or production profile is
claimed.

## Ed301 signature boundary

The Ed301 signature module retains OpenSSL's documented one-shot PureEdDSA
behavior:

- NULL-key DigestSign/DigestVerify reinitialization retains a matching bound
  key;
- invalid modes and parameters fail closed;
- verification returns `1` for acceptance, `0` for signature invalidity and a
  negative value for operational failure; and
- key generation uses the same application-linked private RAND boundary.

These contracts are regression-tested against OpenSSL's Ed25519 behavior on
both review lanes.

## Assurance matrix

The current local matrix covers:

- core KATs, boundaries, small-order cases and independent differentials;
- provider load/unload, key import/export, duplication, concurrency and
  failure injection;
- ASan/UBSan, Valgrind and finite structured input sweeps;
- OpenSSL ML-KEM ACVP integration;
- TLS normal, HRR, fragmentation, mutation, resumption and cross-lane cases;
- secret-taint lanes for Ed301 and X301; and
- final-binary branch, table-selection and ladder-shape checks.

All authoritative runs start from a caller-authenticated, read-only source
snapshot and recheck it after execution. Generated modules and harnesses are
sealed before first use and rechecked afterward.

## Performance snapshot

Preliminary local medians on the Ryzen 9 5950X development host after the lazy
ladder and fixed clamped-bit schedule:

| OpenSSL | X301 keygen | Cold setup + first | Prepared steady | X25519 cold |
|---|---:|---:|---:|---:|
| 3.5.7 | 36.64 us | 61.55 us | 33.46 us | 24.79 us |

The old ladder key-generation path measured about 97.4 us. The cold derive
target of at most 1.56x X25519 is not met: the current ratio is about 2.48x.
Prepared steady derive is about 1.42x X25519. Measurements are local
engineering evidence, not portable guarantees or security evidence.

## Remaining gates

The full-repository deep scan, AArch64 codegen/timing, coverage-guided fuzzing,
identifier standardization and production/release review remain open. The
current cold-derive result is accepted for this implementation freeze. No
production, FIPS, standards, universal constant-time or complete-zeroization
claim is made.
