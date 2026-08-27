# OpenSSL pattern decisions and deviations

Date: 2026-08-24; X301 additions: 2026-08-25

This register records which OpenSSL Ed25519/Ed448 test patterns are adopted
for the optional Ed301 PKI integration and where the draft-00 byte contract
deliberately differs.  OpenSSL test sources are structural precedents, not
normative Ed301 encodings.  The Ed301 draft and provider byte/API contracts
remain authoritative.

Local comparison sources:

- `test/endecode_test.c`
- `test/evp_extra_test.c`
- `test/x509_req_test.c`
- `test/x509_test.c`
- `test/verify_extra_test.c`
- `providers/implementations/keymgmt/ecx_kmgmt.c`
- `providers/implementations/signature/eddsa_sig.c`

## Serialization and decoder matrix

| ID | Decision and contract source | Enforcement |
| --- | --- | --- |
| D1 | Adopt the OpenSSL encoder/decoder round-trip pattern. The provider contract requires PKCS#8 and SPKI DER -> PEM -> DER to remain byte-identical. | `provider-tests/provider_serialization.c` tests both structures. |
| D2 | The project-owned complete-buffer boundary accepts exactly one DER object. One trailing octet is an error for both PKCS#8 and SPKI. | Both forms have explicit `DER + 1` rejection tests. |
| D3 | Adopt the truncation categories from `endecode_test.c`, specialized to the fixed Ed301 layouts. Empty input, every tag/length/value boundary, and the final short value reject. | Boundary tables in `provider_serialization.c`. |
| D4 | Follow the parameterless ECX AlgorithmIdentifier pattern. Encoders emit absent parameters; decoders reject `NULL` and every explicit parameter type. | Exact encoder bytes plus PKCS#8/SPKI parameter-negative tests. |
| D5 | The assigned Ed301 OID must be byte-exact and must map to the no-digest SIGID. Historical Ed301-Sig-v1, X301, and other OIDs are foreign. | Serialization OID negatives and the host-registry assertions in `provider_pki.c`. |
| D6 | **Deliberate deviation:** draft-00 accepts only PKCS#8 `PrivateKeyInfo` version 0. RFC 5958 `OneAsymmetricKey` version 1, with or without embedded public key, is rejected. The seed uniquely derives the public key and KEYMGMT validates that relation, so accepting a second embedded copy adds mismatch policy without a draft requirement. Revisit only if a later Ed301 PKI profile normatively adopts OneAsymmetricKey. | Explicit version-1 and canonical embedded-public-key rejection tests. No mismatch-acceptance path exists. |
| D7 | The draft fixes the seed at 38 bytes. The nested private-key OCTET STRING accepts neither 37 nor 39 bytes. | Independently constructed, internally consistent DER objects carry actual 37- and 39-byte seeds in `provider_serialization.c`; both reject. |

The ordinary and PKI artifacts deliberately expose no generic private-key
decoder.  The private-use TLS test artifact exposes only the transactional
SPKI DER decoder required for wire certificates.  Direct encrypted PKCS#8 is
not a provider-encoder feature; generic application-side wrapping is outside
this optional profile.

## PKI matrix

| ID | Decision and contract source | Enforcement |
| --- | --- | --- |
| P1 | Adopt the public X.509 round-trip pattern: a self-signed Ed301 CA certificate is DER-reparsed and verified. | `provider-tests/provider_pki.c`. |
| P2 | The optional all-Ed301 profile supports a direct Ed301 CA -> Ed301 leaf chain through `X509_STORE`. | Strict profile and store verification test. |
| P3 | Mixed-algorithm interoperability is supported through generic OpenSSL X.509 validation in both directions: classic P-256 ECDSA CA -> Ed301 leaf, and Ed301 CA -> classic P-256 ECDSA leaf. Such certificates intentionally fail the all-Ed301 profile predicate where their signature algorithm or SPKI is classic. | Two public-API chain tests; no ASN.1 byte mutation. |
| P4 | Adopt the signed-TBS integrity pattern. A serial-number mutation through `X509_set_serialNumber()` after signing must invalidate verification. | Focused semantic TBS mutation test. |
| P5 | An Ed301 CSR must sign and verify, survive DER and PEM reparsing, retain exact SPKI/signature identifiers, and reject signature/SPKI mutations. | CSR matrix in `provider_pki.c`. |
| P6 | **Not supported in draft-00:** no Ed301 CRL-signing or OCSP-response profile is claimed. Their object identifiers, responder authorization, freshness and extension policies are not defined by the signature draft. Revisit only with a separate PKI profile and permanent identifiers; do not infer support merely because generic EVP signing could be wired to those containers. | Register-only negative scope decision; no synthetic CRL/OCSP test. |

## SIGNATURE decisions reserved by the same register

| ID | Decision and contract source | Enforcement |
| --- | --- | --- |
| S6 | Ed301-EdDSA draft-00 is pure-only. `OSSL_SIGNATURE_PARAM_CONTEXT_STRING`, including a non-empty context, is rejected rather than ignored; no Ed301ctx instance is defined. This deliberately differs from Ed448 and Ed25519ctx patterns in OpenSSL 4.0 `eddsa_sig.c`. | Existing `provider_signature.c` context rejection tests. |
| S7 | Ed301-EdDSA draft-00 has one fixed pure instance. `OSSL_SIGNATURE_PARAM_INSTANCE`, prehash mode, external digest selection and streaming/prehashed signing are rejected rather than reinterpreted. This deliberately omits the Ed25519ph/Ed448ph instance family. | Existing pure-only, instance, digest, prehash and streaming rejection tests. |

## KEYMGMT decisions reserved by the same register

| ID | Decision and contract source | Enforcement |
| --- | --- | --- |
| K6 | Ed301 public-key import validates canonical encoding and prime-subgroup membership before an `EVP_PKEY` can materialize. Invalid torsion and mixed-order inputs therefore reject at the `EVP_PKEY_fromdata` API boundary; they are not retained as deferred-invalid objects for a later `EVP_PKEY_public_check`. This is deliberately stricter and more fail-closed than the deferred-check shape used by some ECX fixtures. | Existing invalid-point and mixed-order `fromdata` rejection tests; valid keys additionally pass `EVP_PKEY_check` and `EVP_PKEY_public_check`. |
| K7 | An imported private seed derives one unique Ed301 public key. If an import supplies both components, seed/public equality is checked atomically and a mismatch never materializes as an `EVP_PKEY`; no partially replaced key is observable. | Existing mismatched-pair and atomic-import rejection tests; valid complete keys additionally pass `EVP_PKEY_check` and `EVP_PKEY_pairwise_check`. |

## Lifecycle and failpoint decisions reserved by the same register

| ID | Decision and contract source | Enforcement |
| --- | --- | --- |
| L6 | Use real provider-owned failure boundaries only. The `provider_hardening` signature-duplicate failpoint and the `provider_rand` generate-failure path are retained. No product hook is added merely to simulate host RAND installation failure, `pthread` failure, or allocation inside OpenSSL PKI containers, because those operations are not provider-owned. Revisit only if a combined PKI-plus-failpoint provider is deliberately built and reviewed. | Existing hardening and RAND failure tests; host-owned failures remain outside the product failpoint surface. |

## X301 and MLKEM1024X301 decisions

The controlling full contract is `X301_DRAFT.md`. RFC 7748, RFC 9846,
RFC 9954, RFC 10024, FIPS 203 and the OpenSSL 3.5.7/4.0.1 provider manuals are
normative for the patterns named below; the ED301-specific choices remain
experimental.

| ID | Decision and contract source | Enforcement |
| --- | --- | --- |
| X-D2 | X301 uses RFC-7748-shaped input acceptance: require 38 bytes, clear bits 301-303, and subtract `p` once when needed. Stored and exported coordinates remain canonical. | Independent T3 vectors and Rust/provider/TLS boundaries cover `p-1`, `p`, `p+1`, the 301-bit maximum, all seven high-bit aliases, canonical export and lengths 37/39. |
| X-D4 | RFC 7748's all-zero recommendation is mandatory for both direct KEYEXCH and TLS use, translating the X25519/X448 requirement in RFC 9846 Section 7.4.2. Failure returns no partial output. | Independent T4 derives canonical u encodings `0`, `1` and `p-1`; direct EVP tests reject all three atomically in both KAT directions, and the hybrid test propagates the all-zero failure. |
| X-H1 | MLKEM1024X301 follows RFC 9954's general ordered-component naming convention: ML-KEM bytes precede X301 bytes in the name, client share, server share and shared secret. The historical `X25519MLKEM768` naming exception is deliberately not copied. | The old `X301MLKEM1024` name is rejected; exact 1606/1606/70-byte layouts, 1605/1607 totals, and delete/insert mutations at offset 1568 are tested. |
| X-H3 | FIPS 203 implicit rejection remains OpenSSL-owned. A successful OpenSSL decapsulation that yields the implicit-rejection secret is not converted into a provider error. The resulting TLS traffic-key mismatch aborts record authentication; TLS 1.3 does not guarantee that the first observable failure is `Finished`. Actual EVP errors, X301 all-zero and length failures abort the whole group immediately. | Direct deterministic implicit-rejection test plus a real server-wire ciphertext mutation; the latter fails at the first protected server record without an explicit KEM error or accepted handshake. |
| X-E5 | OpenSSL `TLS-GROUP` with `is-kem=1` requires libssl to fetch KEYMGMT/KEM and call EVP encapsulation/decapsulation. MLKEM1024X301 therefore has a technically ordinary EVP-fetchable adapter. **This is not a standalone hybrid-KEM profile:** no non-TLS OID, KDF, persistence, codec or compatibility commitment is defined. | EVP fetch/dispatch and complete dual-lane TLS tests enforce the minimal surface; review MUST reject any extra standalone surface. |
| X-H5 | Ed301 and X301 use distinct key types. Cross-supplying their `EVP_PKEY` objects fails; no provider seed-conversion path exists. Deliberate application reuse of the same raw bytes is separately forbidden because type checks cannot detect it. RFC 9846 Section 4.3.8 additionally forbids local KeyShare reuse across connections. | Cross-type EVP negatives, independent key generation and fresh key shares across resumption are tested. |
| X-W2 | X301 accepts canonical large-order twist inputs, as the RFC 7748 XDH model requires. Twist membership is not treated as malformed input; only a resulting all-zero secret is rejected. | Independent W2 Legendre classification, frozen twist vectors and the existing twist-order evidence distinguish accepted large-order twist inputs from the low-order all-zero case. |
| X-M1 | Calling `EVP_PKEY_derive_set_peer` a second time with a valid X301 peer replaces the previous peer. | M1 sets two distinct peers and proves byte-exact output for the last peer; M2 then proves that repeated derives do not consume this state. |
| X-M4 | `EVP_PKEY_derive_init` resets peer state. A local-key change uses a fresh `EVP_PKEY_CTX`, because OpenSSL exposes no public in-place local-key replacement API. | M4 proves that neither boundary retains an earlier peer and that each context works after an explicit new `set_peer`. |
| X-O2 | OpenSSL's native `evp_test` grammar can express a missing peer and a wrong peer type as operation failures, but malformed raw-key lengths fail while the named key fixture is parsed, before a `Derive` stanza and its `Result` expectation exist. The OpenSSL-format data file therefore carries the representable negatives unchanged; raw lengths 0, 37 and 39 remain C-EVP boundary cases rather than being disguised as nonstandard data-file syntax. | `provider-tests/x301/openssl_evp_x301.txt` runs the representable O1/O2 cases through the unmodified 3.5.7/4.0.1 `evp_test`; `provider_x301_contract.c` enforces every raw-length failure and output atomicity on both lanes. |

## Review rule

Every future OpenSSL or Rust toolchain update must preserve the decisions
above.  A new container form or PKI object class is a profile change, not a
test-only compatibility tweak, and requires a new dated register entry plus
positive and negative vectors.
