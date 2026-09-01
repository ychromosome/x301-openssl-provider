# X301 OpenSSL Provider

This repository contains experimental implementations of:

- X301 `KEYMGMT` and `KEYEXCH`; and
- the private-use TLS 1.3 group `X301MLKEM1024`.

The source is not approved for production use. NamedGroup `0xFE2E` is
test-only and is not an IANA allocation. Remaining gates are listed in
`STATUS.md`.

## Contracts

X301 private keys, public keys, and shared secrets are 38 bytes. External
public inputs clear bits 301-303 and reduce once modulo
`p = 2^301 - 2^99 + 947`. Stored and exported public keys are canonical.
Derivation rejects an all-zero result.

Ed301 and X301 use separate key types and keys. X301 reuses the safe-Rust
5x64 field backend derived from the Ed301 curve work, but this repository
builds no Ed301 signature provider. Every derive uses the same Montgomery
ladder.

X301MLKEM1024 fetches `ML-KEM-1024` through EVP in the provider child library
context. This repository contains no ML-KEM implementation or hybrid KDF.

| Value | Layout | Bytes |
| --- | --- | ---: |
| Client share | ML-KEM key || X301 public | 1606 |
| Server share | ML-KEM ciphertext || X301 public | 1606 |
| Shared secret | ML-KEM secret || X301 secret | 70 |

The normative profile is `docs/X301_DRAFT.md`. Local construction choices and
OpenSSL deviations are in `docs/X301_CONSTRUCTION_REGISTER.md` and
`docs/OPENSSL_PATTERN_DEVIATIONS.md`.

## Modules and OpenSSL lanes

| Build | Module | Operations |
| --- | --- | --- |
| X301 raw | `x301-raw.so` | `KEYMGMT`, `KEYEXCH` |
| X301 hybrid | `x301.so` | X301 plus `X301MLKEM1024` |

Modules accept the OpenSSL ABI major used at build time: 3 or 4. The tested
reference lanes are 3.5.8 and 4.0.2.

## Verification

Authoritative gates require a caller-authenticated, read-only snapshot:

```sh
scripts/run-authoritative-gate.sh archive <trusted-sha256> check
```

The launcher removes inherited startup and tool-control variables before the
gate shell starts. Calling an underlying gate script directly does not produce
authoritative evidence. The host kernel, dynamic loader, and outer process
starter remain trusted.

Provider and TLS matrices:

```sh
scripts/run-authoritative-gate.sh archive <trusted-sha256> \
  test-x301-provider-contracts \
    /trusted/openssl-3.5.8-lane <3.5.8-evidence-sha256> \
    /trusted/openssl-4.0.2-lane <4.0.2-evidence-sha256>

scripts/run-authoritative-gate.sh archive <trusted-sha256> test-x301-tls \
    /trusted/openssl-3.5.8-lane <3.5.8-evidence-sha256> \
    /trusted/openssl-4.0.2-lane <4.0.2-evidence-sha256>
```

`scripts/check-x301-long.sh` runs the million-iteration vector.
`docs/PERFORMANCE_MEASUREMENT.md` defines benchmark provenance.

## Source map

- `crates/ed301-eddsa/src/x301.rs`: X301 core.
- `provider/crates/x301-provider/`: X301 and hybrid provider.
- `provider-tests/x301/`: EVP, hybrid, TLS, fuzz, and generated vectors.
- `reference/x301/`: independent variable-time Python oracle.
- `evidence/curve-provenance/`: retained curve-search and verification files.
- `ZEROIZATION_AND_CT_BOUNDARY.md`: secret-handling limits.

## License

Apache-2.0. Vendored dependencies retain their own licenses.
