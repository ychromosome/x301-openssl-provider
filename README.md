# X301 OpenSSL Provider

Experimental implementations of:

- **X301**, a 38-byte XDH profile over the frozen ED301 curve; and
- **MLKEM1024X301**, a private-use TLS 1.3 hybrid group that combines X301
  with OpenSSL's ML-KEM-1024 implementation.

The repository also contains the Ed301-EdDSA core and signature provider from
which X301 reuses field arithmetic and test infrastructure. Ed301 and X301 use
separate key types and keys.

This is reviewable experimental source, not production cryptography. The TLS
NamedGroup `0xFE2E` is test-only and is not an IANA allocation.

## Current status

| Component | Status |
|---|---|
| Ed301-EdDSA | Frozen draft-00 byte contract; integration candidate |
| X301 | Experimental review candidate |
| MLKEM1024X301 | Experimental private-use integration |

None of the three components is released or approved for production use.
There is no IANA allocation or organizationally independent X301
implementation. See `STATUS.md` for the remaining gates.

## Design boundaries

- X301 uses the existing safe-Rust 5x64 ED301 field backend.
- X301 public keys and shared secrets are 38-byte little-endian u-coordinates.
- Key generation uses OpenSSL's application-linked private RAND path.
- Derivation rejects non-canonical peer keys and an all-zero shared secret.
- Every derive uses the same RFC-7748-shaped ladder; there is no implicit
  repeated-peer accelerator.
- MLKEM1024X301 obtains ML-KEM-1024 through EVP using the child library
  context's provider and property policy. The project contains no ML-KEM
  implementation and no hybrid KDF.
- Hybrid values are concatenated ML-KEM first, following the documented TLS
  hybrid pattern; the public name follows that component order.

The complete byte and provider contracts are in `docs/X301_DRAFT.md`.
Construction choices and deviations are recorded in
`docs/X301_CONSTRUCTION_REGISTER.md` and
`docs/OPENSSL_PATTERN_DEVIATIONS.md`.

## Source verification

Authoritative gates require a caller-authenticated, read-only source snapshot.
The manifest inside an archive is not its own trust anchor.

```sh
ED301_SOURCE_MODE=archive \
ED301_VERIFIED_SNAPSHOT=1 \
ED301_EXPECTED_SOURCE_MANIFEST_SHA256=<trusted-sha256> \
    sh scripts/check.sh
```

The same environment is required by the downstream, secret-taint and
provider gates. Git mode additionally requires an externally authenticated
commit and is not accepted as an authoritative archive build.

## OpenSSL matrices

Build sealed lanes from the pinned OpenSSL 3.5.7 and 4.0.1 releases, then run:

```sh
scripts/test-x301-provider-contracts.sh \
    /trusted/openssl-3.5.7-lane <3.5.7-evidence-sha256> \
    /trusted/openssl-4.0.1-lane <4.0.1-evidence-sha256>

scripts/test-x301-tls.sh \
    /trusted/openssl-3.5.7-lane <3.5.7-evidence-sha256> \
    /trusted/openssl-4.0.1-lane <4.0.1-evidence-sha256>
```

The million-iteration X301 reproduction is separate from the ordinary loop:

```sh
scripts/check-x301-long.sh
```

Set `X301_TLS_LONG_HANDSHAKES=1000` for the separate long TLS lane. Detailed
coverage is listed in `docs/X301_EXTENDED_ASSURANCE.md`.

Pinned ABBA performance sessions and their provenance requirements are defined
in `docs/PERFORMANCE_MEASUREMENT.md`.

## Repository map

- `crates/ed301-eddsa/src/x301.rs`: X301 core.
- `provider/crates/x301-provider/`: OpenSSL X301 and hybrid provider.
- `provider-tests/x301/`: independent oracle and frozen vectors.
- `fuzz/`: persisted coverage-guided core/provider seed corpora and Rust
  target.
- `docs/X301_DRAFT.md`: protocol and encoding contract.
- `docs/OID_REGISTRY.md`: private OID and TLS codepoint registry.
- `evidence/curve-provenance/`: manifest-bound curve search and verification
  evidence, including all 355 worker results.
- `ZEROIZATION_AND_CT_BOUNDARY.md`: secret-handling and constant-time limits.

## License

Apache-2.0. Vendored dependencies retain their own licenses.
