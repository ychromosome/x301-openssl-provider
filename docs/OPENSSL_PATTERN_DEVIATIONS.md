# X301 OpenSSL pattern decisions

The controlling contract is `X301_DRAFT.md`. RFC 7748, RFC 9846, RFC 9954,
RFC 10024, FIPS 203 and the tested OpenSSL provider interfaces supply the
patterns below.

| ID | Decision | Enforcement |
| --- | --- | --- |
| X-D2 | Require 38 input bytes, clear bits 301--303 and subtract `p` once when needed. Store and export only the canonical coordinate. | Core, provider and TLS boundary vectors cover `p-1`, `p`, `p+1`, the 301-bit maximum, all seven high-bit aliases and lengths 37/39. |
| X-D4 | Reject an all-zero shared secret in direct KEYEXCH and TLS use. | Independent low-order vectors and direct EVP tests cover both key directions and hybrid failure propagation. |
| X-H1 | `X301MLKEM1024` uses X-family naming while retaining ML-KEM-first client share, server share and shared secret layouts. | Tests reject the retired name and bind exact 1606/1606/70-byte layouts plus boundary mutations. |
| X-H3 | Preserve FIPS 203 implicit rejection. A successful ML-KEM decapsulation is not converted into a provider error; later TLS authentication detects a mismatched secret. | Direct implicit-rejection and server-wire mutation tests. |
| X-E5 | The hybrid is a TLS group adapter, not a standalone hybrid-KEM profile. | No non-TLS OID, codec, persistence or KDF surface is exposed. |
| X-H5 | Ed301 and X301 keys are distinct types. This repository contains no Ed301 signature provider; cross-type checks belong to the joint integration lane with the canonical Ed301-v1 provider. | Shared four-component integration test; no seed-conversion API exists. |
| X-W2 | Accept canonical large-order twist inputs and reject only a resulting all-zero secret. | Frozen twist vectors and twist-order evidence. |
| X-M1 | A second valid `EVP_PKEY_derive_set_peer` replaces the first peer. | M1/M2 provider tests. |
| X-M4 | `EVP_PKEY_derive_init` clears peer state; changing the local key uses a new context. | Provider context lifecycle tests. |
| X-O2 | Native `evp_test` covers representable derive failures; malformed raw-key lengths remain C-EVP boundary cases. | Unmodified `evp_test` data plus exact 0/37/39-byte C tests. |
