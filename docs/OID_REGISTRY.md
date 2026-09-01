# ED301 OID registry

The [IANA Private Enterprise Numbers registry](https://www.iana.org/assignments/enterprise-numbers/)
assigns number `66282` to Adiumentum GmbH. The ED301 project uses the subtree
`1.3.6.1.4.1.66282.301`.

| OID | Assignment | State |
| --- | --- | --- |
| `1.3.6.1.4.1.66282.301.1` | Ed301-Sig-v1 | Historical and retired; never reassign |
| `1.3.6.1.4.1.66282.301.2` | X301 | Existing assignment; unchanged |
| `1.3.6.1.4.1.66282.301.3` | Ed301-EdDSA key and signature algorithm | Active experimental assignment |

The `.301.3` OID binds the exact manifest-defined Ed301-EdDSA byte profile,
not merely the current draft label. It is used without
`AlgorithmIdentifier` parameters for both the key algorithm in SPKI/PKCS#8
and the signature algorithm in CSR and certificate objects. The fixed
encodings contain a 38-byte raw public key, a 38-byte private seed and a
76-byte signature. The canonical DER sizes are 58 bytes for SPKI and 62 bytes
for PKCS#8.

An incompatible change to the algorithm semantics or wire encoding requires
a new OID. In particular, the retired `.301.1` identity must never be reused,
even though it was not deployed as an official public provider.

## TLS private-use identifiers

TLS NamedGroup values are not OIDs. The following assignment is recorded here
only to keep the same collision and non-reuse discipline:

| Codepoint | Assignment | Date | State and rationale |
| --- | --- | --- | --- |
| `0xFE2E` | X301MLKEM1024 TLS 1.3 NamedGroup | 2026-08-25 | Active experimental private use. Required for the in-project OpenSSL 3.5.7/4.0.1 handshake matrix; never present as an IANA or public-interoperability claim. ML-KEM-first layouts are fixed by `X301_DRAFT.md`. |

RFC 9846 Section 4.3.7 records `0xFE00` through `0xFEFF` as the ECDHE
private-use range. The value can therefore collide with unrelated private
deployments. It MUST NOT leave an explicitly coordinated test environment and
MUST never be silently reassigned. A future public registration requires a
new standards and registry review; it does not inherit `0xFE2E`.

This private-enterprise allocation does not constitute an IANA TLS
SignatureScheme registration, an interoperability standard or a production
readiness claim. TLS test codepoint `0xFE84` remains a separate private-use,
nonregistrable SignatureScheme identifier and is not derived from this OID or
from the `0xFE2E` NamedGroup assignment.
