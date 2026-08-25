# Provider status

The repository builds two distinct experimental provider modules:

| Module | Surface |
|---|---|
| `ed301_eddsa_draft00.so` | Ed301 `KEYMGMT` and `SIGNATURE` |
| `x301.so` | X301 `KEYMGMT`/`KEYEXCH` and the private-use X301MLKEM1024 TLS group |

Ed301 and X301 share field arithmetic but never share keys. The ordinary
Ed301 module exposes no TLS capability, OID alias, encoder or decoder.
Optional Ed301 PKI and private-use TLS proof modules remain separately named,
disabled-by-default test artifacts.

## Supported review lanes

The provider matrix targets exactly:

- OpenSSL 3.5.7; and
- OpenSSL 4.0.1.

Each lane is built from a pinned release tarball and accepted only with an
externally recorded evidence-manifest digest. One module is built per OpenSSL
ABI major; patch-version string equality is not required.

## X301 contract

- Raw private and public keys are exactly 38 bytes.
- Key generation obtains its seed from `RAND_priv_bytes_ex()` in a child
  `OSSL_LIB_CTX`; it has no operating-system RNG fallback.
- The clamped scalar is reduced modulo `L` and multiplied through the existing
  constant-time Edwards fixed-base table. The result is mapped directly with
  `u=(Z+Y)/(Z-Y)`, using one field inversion.
- Public-key generation is byte-identical to the retained 301-round
  Montgomery-ladder reference over the frozen boundaries and 10,000
  independent differential cases.
- Peer inputs require canonical 38-byte u encodings. Derivation uses the fixed
  301-round ladder and rejects an all-zero shared secret.
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

Local medians on the Ryzen 9 5950X development host:

| OpenSSL | X301 keygen | Prepared derive | Hybrid keygen | Hybrid encaps | Hybrid decaps |
|---|---:|---:|---:|---:|---:|
| 3.5.7 | 36.98 us | 90.53 us | 73.87 us | 146.04 us | 120.02 us |
| 4.0.1 | 36.60 us | 90.89 us | 73.19 us | 145.75 us | 119.70 us |

The old ladder key-generation path measured about 97.4 us. Prepared derive
remains the canonical ladder and was not changed. Measurements are local
regression evidence, not portable guarantees or security evidence.

## Remaining gates

Independent X301 security/performance reviews, the full-repository deep scan,
AArch64 codegen/timing, coverage-guided fuzzing, identifier standardization and
production/release review remain open. No production, FIPS, standards,
universal constant-time or complete-zeroization claim is made.
