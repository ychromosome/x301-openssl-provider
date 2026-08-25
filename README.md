# Ed301, X301 and X301MLKEM1024

This repository contains three related experimental components over ED301:

- `Ed301-EdDSA-draft-00`, implemented as a `no_std` Rust core and an optional
  OpenSSL signature provider;
- `X301`, exposed through a distinct OpenSSL `KEYMGMT`/`KEYEXCH`; and
- `X301MLKEM1024`, an opt-in private-use TLS 1.3 group that delegates
  ML-KEM-1024 to OpenSSL's default provider.

The components share field arithmetic but use separate key domains.  Start
with `inputs/round4/ED301-EdDSA-draft.md` for the signature byte contract,
`docs/X301_DRAFT.md` for X301 and the hybrid construction, and
`PROVIDER_STATUS.md` for the assurance boundary.

The cryptographic Rust core is:

- `no_std`
- safe Rust
- context-free one-shot signing and verification
- locked, vendored and offline builds
- draft vectors and edge cases included

## Test

Authoritative gates run only from a caller-created, read-only source snapshot.
The caller must authenticate the enclosing archive and pass the expected
manifest digest explicitly:

```sh
ED301_SOURCE_MODE=archive \
ED301_VERIFIED_SNAPSHOT=1 \
ED301_EXPECTED_SOURCE_MANIFEST_SHA256=<trusted-sha256> \
    sh scripts/check.sh
```

The same three variables are required by `scripts/check-downstream.sh`,
`scripts/check-secret-taint.sh`, and `scripts/test-provider.sh`. The manifest
inside an unauthenticated archive is not its own trust anchor. Git mode exists
only as a source-verification primitive and additionally requires an external
exact commit; authoritative build gates do not accept it.

## Experimental OpenSSL provider

The ordinary Ed301-EdDSA provider module is signature-only. OpenSSL must first
be built into a sealed lane from a pinned public release tarball. The
externally recorded digest of that lane's evidence manifest is then an input
to the provider gate:

```sh
scripts/build-openssl-provider-lane.sh 3.5.7 /trusted/upstream /private/lane-root
scripts/test-provider.sh /private/lane-root 3.5.7 <trusted-evidence-manifest-sha256>
```

Repeat with `4.0.1` for OpenSSL 4. The ordinary module exposes only `KEYMGMT`
and `SIGNATURE`: no OID alias, encoder, decoder, PKI registration, or TLS
capability. PKI encoders and the private-use TLS proof are separately named,
disabled-by-default test artifacts whose registry setup belongs to the host
harness.

The optional PKI integration uses the internally assigned Adiumentum OID
`1.3.6.1.4.1.66282.301.3` for this exact Ed301-EdDSA key/signature profile.
This private-enterprise allocation is not a standards or IANA TLS
registration. See `docs/OID_REGISTRY.md` for the allocation and immutability
rules.

The provider is an integration candidate, not a release.  See
`PROVIDER_STATUS.md`.

## Experimental X301 integration

The local X301 integration adds a distinct raw `X301` KEYMGMT/KEYEXCH and an
opt-in `X301MLKEM1024` TLS 1.3 group. The latter delegates ML-KEM-1024 entirely
to OpenSSL's default provider and supplies no standalone hybrid format or KDF.
Its project contract is `docs/X301_DRAFT.md`; the additive Wycheproof/OpenSSL
taxonomy, structured-sweep and long-running lane is documented in
`docs/X301_EXTENDED_ASSURANCE.md`.

After authenticating sealed OpenSSL 3.5.7 and 4.0.1 lanes, run the dual-lane
provider and TLS matrices with the lane roots and their external evidence
digests:

```sh
scripts/test-x301-provider-contracts.sh \
    /trusted/openssl-3.5.7-lane <3.5.7-evidence-sha256> \
    /trusted/openssl-4.0.1-lane <4.0.1-evidence-sha256>
scripts/test-x301-tls.sh \
    /trusted/openssl-3.5.7-lane <3.5.7-evidence-sha256> \
    /trusted/openssl-4.0.1-lane <4.0.1-evidence-sha256>
```

Set `X301_TLS_LONG_HANDSHAKES=1000` for the separate L2 handshake lane.  From
the same authenticated read-only source snapshot, run
`scripts/check-x301-long.sh` for L1's one-million iteration reproduction.

The private NamedGroup `0xFE2E` is test-only and not an IANA allocation.
X301/X301MLKEM1024 remain experimental assurance candidates, not production
cryptography.

## Status

- **Ed301-EdDSA:** frozen draft-00 byte contract; integration candidate;
  another full-scope deep scan remains pending.
- **X301:** pre-freeze integration candidate; independent security and
  performance review remain pending.
- **X301MLKEM1024:** private-use assurance candidate; independent security and
  performance review remain pending; no IANA allocation is claimed.

None of these components is production-ready.

See `STATUS.md` and `ZEROIZATION_AND_CT_BOUNDARY.md` for the current assurance
boundary.

## License

Apache-2.0. Vendored dependencies retain their own licenses.
