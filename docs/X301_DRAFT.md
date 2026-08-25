# X301 and X301MLKEM1024 experimental profile

Status: project draft, 2026-08-25. This document is not an IETF or NIST
standard and does not assign a public TLS codepoint. The words MUST, MUST NOT,
SHOULD and MAY describe the frozen ED301 project profile only.

The governing design rule is simplicity: X301 is an RFC-7748-shaped use of
the already reviewed ED301 field, and X301MLKEM1024 is TLS wiring around X301
and OpenSSL's ML-KEM-1024. Neither construction creates a second field engine,
an ML-KEM implementation, a combiner KDF, or a standalone hybrid protocol.

## 1. Sources and authority

| Subject | Standard or contract source | Local use |
| --- | --- | --- |
| Montgomery conversion, ladder and XDH API pattern | [RFC 7748 Sections 4-6](https://www.rfc-editor.org/rfc/rfc7748.html) | D1-D4, scalar/u processing, all-zero check |
| TLS 1.3 group negotiation and key schedule | [RFC 9846 Sections 4.3.7, 4.3.8, 7.1 and 7.4](https://www.rfc-editor.org/info/rfc9846/) | NamedGroup/private-use range, fresh KeyShare values, raw asymmetric secret and the TLS KDF |
| Hybrid TLS construction | [RFC 9954](https://www.rfc-editor.org/rfc/rfc9954.html) | Concatenated component shares and secrets; failure as one group |
| Registered X25519/ML-KEM instance | [RFC 10024 Sections 4-5](https://www.rfc-editor.org/rfc/rfc10024.html) | ML-KEM-first ordering and role-dependent share layout |
| ML-KEM-1024 | [FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) | Algorithms, sizes and implicit rejection; implementation is OpenSSL-owned |
| Provider TLS group and KEM surface | OpenSSL `provider-base(7)`, `provider-keymgmt(7)`, `provider-kem(7)`, `EVP_PKEY_encapsulate(3)` and `EVP_PKEY_decapsulate(3)` in exactly 3.5.7 and 4.0.1 | The technically EVP-fetchable adapter that libssl requires |
| ED301 parameters and EdDSA byte contract | `../inputs/round4/ED301-EdDSA-draft.md` and `../inputs/round4/upstream/ed301-v1/ed301-v1.json` | Frozen curve input only; the Ed301-EdDSA contract is unchanged |

RFC 9846 obsoletes RFC 8446 and is the controlling base TLS 1.3 source. Its
section numbering differs: Supported Groups and Key Share are Sections 4.3.7
and 4.3.8. RFC 10024 is the published successor used here for the previously
drafted X25519MLKEM768 pattern. If an implementation comment names an older
TLS RFC or IETF draft for history, it MUST also name RFC 9846 or RFC 10024,
respectively, as the controlling published source.

The only project-specific choices are enumerated in
`X301_CONSTRUCTION_REGISTER.md` and `OPENSSL_PATTERN_DEVIATIONS.md`. An
unregistered local cryptographic transform is forbidden.

## 2. Scope and non-goals

The provider profile has exactly two additions:

1. `X301`, a provider KEYMGMT/KEYEXCH algorithm with 38-byte raw private,
   public and derived-secret values.
2. `X301MLKEM1024`, a TLS 1.3 hybrid group advertised through OpenSSL's
   `TLS-GROUP` capability.

ML-KEM-1024 MUST be fetched through EVP from the OpenSSL default provider in
the normative 3.5.7 and 4.0.1 lanes. The project MUST NOT implement, vendor,
partially reproduce, or expose project-owned ML-KEM arithmetic.

OpenSSL requires a `TLS-GROUP` with `is-kem=1` to name provider KEYMGMT and KEM
operations that libssl fetches through EVP. Consequently, the hybrid adapter
MUST be technically fetchable through ordinary EVP; hiding it behind a
TLS-only private entry point would violate the OpenSSL contract. That adapter
exists solely so libssl can execute the group. It is **not** a promise of a
standalone hybrid-KEM protocol: this profile defines no non-TLS KDF, OID,
persistent hybrid-key encoding, generic ciphertext format, application
workflow, or compatibility commitment outside TLS. A future standalone use
requires a dated register entry, a documented need and a combiner definition
following SP 800-56C practice before code is written.

## 3. ED301 and Montgomery parameters

All arithmetic is over

```text
p = 2^301 - 2^99 + 947
  = 4074071952668972172536891376818756322102936787331872501272280264883462485411972664015193011.
```

The source curve is the twisted Edwards curve

```text
a*x^2 + y^2 = 1 + d*x^2*y^2,
a = 2086388329,
d = 301.
```

The curve-evidence archive reports the orders

```text
#E(F_p)       = 4*q,
q             = 1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403,
#E_twist(F_p) = 4*q_twist,
q_twist       = 1018517988167243043134222844204689080525734196323118960177517235683197019236556497968262103.
```

The archive reports both large factors as prime; `q` is 300 bits and
`q_twist` is 299 bits. Section 8 records the evidence paths and the current
materialization gate. This integration draft does not promote that external
report into a freshly verified result.

Following RFC 7748 Section 4, define the Montgomery curve

```text
B*v^2 = u^3 + A*u^2 + u,
A = 2*(a+d)/(a-d) mod p,
B = 4/(a-d) mod p,
A24 = (A-2)/4 mod p.
```

The resulting constants are

```text
A   = 1337125101468798294423667083008487580371440947467333579746761624815927501631542793281919359
B   = 2102386304867639485174889802292078795702081870378430469358638547115457185184343208357597462
A24 = 1352799263534442616740139614956810975618594433699801520254760472424847496760878864324278092
```

The existing Ed301 basepoint encoding is

```text
6bf73f755a0c80653ce83fcf6d6ff7d7f347b1929224ac67552273419e6cf2c8a88a02d38898
```

and its derived canonical Montgomery u-coordinate is

```text
5ba6f0f4ccc6ff5f018a2496fe165eb7d1893949fe3d05f79c12d2bd99952cd42d2ae9546308.
```

These constants are independently recomputed by
`../reference/x301/x301_reference.py`; product code MUST NOT be the source of
their expected values.

## 4. D1: birational correspondence

For a nonexceptional Edwards point `(x,y)`, the forward map is

```text
u = (1+y)/(1-y)
v = u/x.
```

The inverse map is

```text
x = u/v
y = (u-1)/(u+1).
```

Substitution in the two curve equations yields the `A` and `B` formulas in
Section 3. The exceptional points are part of the definition:

| Edwards point | Montgomery point |
| --- | --- |
| `(0,1)`, the identity | point at infinity; no affine u encoding |
| `(0,-1)`, order 2 | `(u,v)=(0,0)` |

The independent oracle implements complete Edwards addition and a separate
Montgomery group law through the isomorphic Weierstrass equation
`Y^2=X^3+A*B*X^2+B^2*X`. It checks both exceptional cases, both inverse maps,
and the homomorphism `phi(P+Q)=phi(P)+phi(Q)` for 256 deterministic
SHAKE256-derived pairs spanning the prime subgroup and all four torsion
cosets. This test demonstrates the implemented formulas; the algebraic
substitution is the proof obligation.

The maps are defined over `F_p` and extend to an isomorphism of the smooth
projective curves. Consequently the Montgomery model has the same point
count, Frobenius trace, endomorphism algebra and CM field as the frozen
Edwards model; its quadratic twist has the corresponding twist order. This is
why the order, twist and CM evidence in Section 8 applies to X301 without a
second curve search or point count. The statement is model invariance, not a
claim that the selected historical evidence has been independently rerun here.

## 5. X301 byte and scalar contract

### 5.1 D2: strict u encoding

An X301 u-coordinate is exactly 38 octets, little-endian. This profile chooses
strict canonical decoding:

- lengths other than 38 MUST fail;
- bits 301, 302 and 303 MUST each be zero;
- the decoded integer MUST be less than `p`;
- input MUST NOT be masked or reduced modulo `p`;
- output is the unique 38-byte encoding of an integer in `[0,p)`.

Thus `u=p`, `u=p+1`, every reserved-bit case and lengths 37/39 fail at decode.
This deliberately differs from X25519's tolerant RFC 7748 decoder. The reason
is the existing ED301 canonical-encoding discipline and the smaller attack
surface of one representation per value; the departure is registered as
`X-D2`.

### 5.2 D3: clamping

The raw private input is exactly 38 octets. Before the ladder, the
implementation MUST perform only these fixed bit operations:

```text
scalar[0]  &= 0xfc       # clear bits 0 and 1 for cofactor 4
scalar[37] &= 0x0f       # clear bits 300 through 303 temporarily
scalar[37] |= 0x10       # set bit 300
```

Equivalently, the low two bits are zero, bit 300 is one, and bits 301-303 are
zero. The original bytes are not interpreted as a reduced integer before
clamping.

No special raw-scalar or `4*q_twist` rejection is defined. RFC 7748 provides
no such preprocessing, and it would be a project-owned rule. If the clamped
scalar annihilates a supplied x-line, the ordinary D4 all-zero rule rejects
the result.

### 5.3 Ladder and output

The product implementation MUST use the RFC 7748 Section 5 Montgomery ladder
for exactly bits 300 down through 0 with `A24=(A-2)/4`. It MUST reuse the
existing Ed301 5x64 `mul`, `square`, reduction and constant-time selection
domain. A ladder swap may only apply that same selection to the two existing
states; it MUST NOT add a second field representation, reducer, independent
selector or variable-time product path.

The ladder returns the affine value `x_2/z_2`. Inversion, encoding and every
error path MUST use the existing secret-ownership and zeroization rules.

### 5.4 D4: contributory behaviour

After a successful ladder, the implementation MUST compare all 38 output
octets with zero without secret-dependent control flow. An all-zero value MUST
return an error and MUST NOT release a result. This mandatory rule translates
the strict policy in RFC 9846 Section 7.4.2, which requires all-zero rejection
for X25519/X448, even though RFC 7748 alone describes the check as a
recommendation. Both direct X301 KEYEXCH and the hybrid group apply it.

No curve-membership test is performed on the peer u-coordinate. Therefore the
twist order and its 299-bit prime factor are a security requirement, not an
incidental curve property.

## 6. X301 provider contract and key separation

`X301` is a distinct provider algorithm and key type. Its raw private key,
public key and derived secret are each 38 octets. KEYMGMT and KEYEXCH follow
the OpenSSL provider contracts in both normative lanes. A length query with a
NULL output buffer returns 38. Derivation without a peer, with a foreign key
type, or with a 0/37/39-byte raw key fails without partial output.

Key generation obtains 38 random octets through the same provider RAND route
as existing key generation and then applies D3. Derivation is deterministic
and MUST NOT consume RAND.

RFC 9846 Section 4.3.8 forbids reusing a KeyShare value across connections.
Every TLS connection, including one that performs session resumption with an
asymmetric share, MUST generate fresh X301 and ML-KEM key-share material.
Receiving code remains interoperable with a peer that reuses a share, as RFC
9846 requires; local generation never does so.

Ed301 signing and X301 exchange share curve arithmetic but not key objects or
seed lifecycle. An Ed301 `EVP_PKEY` MUST fail when supplied to X301 KEYEXCH,
and an X301 `EVP_PKEY` MUST fail in an Ed301 signature context. The profile
also forbids an application from importing the same 38 raw octets for both
algorithms; type separation cannot detect deliberate caller-side byte reuse,
so this remains an explicit protocol rule as well as a cross-type API test.

## 7. X301MLKEM1024 TLS group

### 7.1 H1/H2: exact layout

The ordering follows X25519MLKEM768 in RFC 10024, including its ML-KEM-first
choice. It MUST NOT copy the historically different SecP/ML-KEM ordering.

| Value | Exact construction | Size |
| --- | --- | ---: |
| Client key share | ML-KEM-1024 encapsulation key `ek` || X301 public u | `1568 + 38 = 1606` bytes |
| Server key share | ML-KEM-1024 ciphertext `ct` || X301 public u | `1568 + 38 = 1606` bytes |
| Hybrid shared secret | ML-KEM shared secret || X301 shared secret | `32 + 38 = 70` bytes |

The first component always starts at offset zero; the X301 component starts
at offset 1568. A parser MUST require the exact total and component sizes.
Deletion or insertion of one byte immediately before or after the component
boundary, and total sizes 1605/1607, MUST fail. No parser may infer or accept
alternate ordering.

The 70-byte concatenation is passed unchanged to the RFC 9846 Section 7.1 TLS
1.3 key schedule. The adapter MUST NOT hash, label, extract, expand or
otherwise combine it.

### 7.2 E1/E3: component ownership

ML-KEM key generation, encapsulation and decapsulation are performed only by
the FIPS-203 ML-KEM implementation fetched from the OpenSSL default provider.
The ED301 provider owns no ML-KEM symbol or intermediate step. X301 is the
project-owned KEYEXCH component described in Sections 3-6. The adapter only
parses fixed lengths, invokes both components and concatenates their outputs.

### 7.3 H3: atomic failure and implicit rejection

Wrong length, an OpenSSL ML-KEM operation error, an X301 parse error or an
X301 all-zero result fails the whole group. No component secret or partial
output may escape.

FIPS 203 implicit rejection is not converted into a new explicit error. If
OpenSSL successfully decapsulates a modified ciphertext to its implicit
rejection secret, the adapter treats that as the OpenSSL-defined result. The
client and server then derive different TLS traffic keys. The handshake MUST
not be accepted, but TLS 1.3 does not promise that the first observable failure
is `Finished`: authentication of the first protected server record can fail
earlier. The adapter MUST NOT try to recognize or reinterpret the implicit-
rejection secret or turn it into a component-specific alert.

### 7.4 H4: private-use identifier

The experimental NamedGroup codepoint is `0xFE2E`, from the `0xFE00` through
`0xFEFF` ECDHE private-use range recorded by RFC 9846 Section 4.3.7.
`OID_REGISTRY.md` records the name, date and rationale. The value is
nonregistrable test infrastructure, may collide with other private uses, and
MUST NOT be advertised as an IANA allocation or public interoperability claim.

### 7.5 H5: hybrid key separation

The X301 secret in a group instance is generated independently of its ML-KEM
key material and every Ed301 signing seed. Neither component may derive the
other. A group context is not an Ed301 signature context and accepts no
Ed301 key object.

## 8. Materialized c44730 curve and twist evidence

The minimal selected final evidence is materialized at
`../evidence/curve-freeze/`. Its `README.md` defines the selection and its
provenance boundary; `UPSTREAM_SELECTED_SHA256SUMS` fixes the twelve selected
upstream files. The mathematical evidence used by this draft is limited to:

- `parameter/ed301-v1.json`;
- `rohresultate/audit_c44730_full_reproducibility_pari.txt`;
- `rohresultate/audit_c44730_security_parameters_pari.txt`;
- `rohresultate/c44730_q_qtwist_primality_security_pari.txt`;
- `rohresultate/c44730_q_twist_ecpp_independent_python.txt` and
  `zertifikate/c44730_q_twist_ecpp_internal.pari`;
- `rohresultate/c44730_q_twist_nminus1_bls_independent_python.txt` and
  `zertifikate/c44730_q_twist_nminus1_bls_internal.pari`.

The two included reports provide historical context only. Their links to
omitted scripts, older `phase_a` outputs, rejected candidates and historical
signature/X301 profiles are not evidence or normative input for this draft.
In particular, this profile does not inherit the historical special
annihilating-twist-scalar rejection; Sections 5.2 and 5.4 remain controlling.

The selected parameter JSON and the full/focused PARI outputs agree exactly
on `p`, Edwards `a,d`, Montgomery `A,B,A24_minus`, `N=4q`,
`N_twist=4q_twist`, and the main/twist prime factors stated in Section 3. The
recorded full and focused audits end in `audit_pass=1`; the selected twist
ECPP and N-1/BLS Python-verifier outputs end in
`independent_certificate_valid=1` and
`independent_N_minus_1_certificate_valid=1`, respectively.

The selected arithmetic records additionally report

```text
Frobenius discriminant = -12137149071563589304614945125775576912493244030482643957703903238011574008842143168751612044
fundamental CM discriminant = -3034287267890897326153736281443894228123311007620660989425975809502893502210535792187903011
```

The latter has 301 bits and is neither a small-CM special case nor associated
with `j=0` or `j=1728` in the selected report. These values are invariant
under the D1 model change. They remain recorded evidence, subject to the
provenance boundary below, rather than a fresh computation by this integration.

This is value agreement, **not byte identity with the Ed301-EdDSA freeze**.
The freeze-associated Git identifier
`0c48294893e9b7ec46109de51c3a04829befb39f` is not a file SHA-256. The current
EdDSA input `../inputs/round4/upstream/ed301-v1/ed301-v1.json` hashes to
`23cb60255848176320d8938cb1856d469eb91455868da4078526dfb26ef6806f`;
the selected evidence JSON hashes to
`a9d66a001b2ef7c46a90cde447e64740b6eae024f6923e71dd504c13e5a4d27d`.
Their materialized diff consists of two metadata-wording changes (`status`
and `field.formal_primality_proof`); the checked cryptographic values and
encodings match.

The checkout-local materialization and hash gate is therefore closed for this
selected subset. The subset omits the original upstream manifests,
reproduction document and verifier scripts, so it does not by itself prove a
complete upstream tree, source-commit identity, from-scratch reproducibility
or organizationally independent external review. Those are separate
provenance and assurance claims.

## 9. Independent vectors

`../reference/x301/x301_reference.py` is a standard-library-only,
variable-time oracle. It imports neither Rust/product code nor provider output.
`../reference/x301/x301-test-vectors.json` freezes:

- four T1 scalar/u KATs, including basepoint cases independently cross-checked
  through complete Edwards scalar multiplication, and exact clamped bytes;
- T2 results after 1 and 1,000 RFC-shaped iterations;
- separate T3 strict-canonical boundary cases;
- the independently derived complete T4 affine x-line corpus;
- the SHA-256, first record and last record of a canonical 10,000-case T5
  scalar/basepoint/DH stream.

The T4 derivation uses the rational two-torsion polynomial
`u*(u^2+A*u+1)` and the doubling numerator `(u^2-1)^2`. The quadratic
factor's discriminant is nonsquare, so `u=0` is the only rational order-2
x-line. The order-4 x-lines are `u=1` on the main curve and `u=-1=p-1` on
the twist. The identity has no affine u encoding. Thus the unique canonical
rejection encodings are 0, 1 and `p-1`.

The oracle is test-only, variable-time and MUST NOT process production
secrets.

## 10. Acceptance matrix

The integration is accepted only against the exact source and binary gates
named below.  Passing them does not change the experimental status or create
a standards-conformance claim:

| Contract | Required evidence | Current status |
| --- | --- | --- |
| D1 | algebra, exceptional points, 256 deterministic round trips/homomorphisms | PASS in the independent Python oracle |
| T1 | fixed scalar/u/basepoint KATs and random DH agreement | PASS: four fixed KATs and the T5 DH stream |
| T2 | frozen results after 1 and 1,000 iterations | PASS byte-for-byte in Python and Rust |
| T3 | `p`, `p+1`, bits 301-303, length 37/39 | PASS in Python, Rust and EVP boundaries |
| T4 | all main/twist order-1/2/4 x-lines and rejection | PASS: independently derived `u=0,1,p-1`; direct EVP rejects all three in both KAT directions |
| T5 | at least 10,000 independent differential cases | PASS; canonical digest `257711151f37d9011cbf42123901ae914b77e461db7edb80ee85405e4b97d076` |
| T6 | KEYEXCH/KEYMGMT EVP matrix in 3.5.7 and 4.0.1 | PASS on both exact lanes |
| T7 | deterministic derive and poisoned-RAND split | PASS on both exact lanes |
| T8 | TLS 1.3 handshake, fresh resumption shares and unsupported-peer outcome | PASS on both exact lanes, including fresh component digests across resumption, fallback and no-common-group failure |
| T9 | ML-KEM mutation, all-zero X301 and boundary mutations | PASS on both exact lanes; wire mutation fails protected-record authentication without an explicit KEM error |
| T10 | OpenSSL-owned ML-KEM Encaps/Decaps KAT | PASS: 35 ML-KEM-1024 cases/105 checks on 3.5.7 and 36 cases/108 checks on 4.0.1 |
| T11 | fifth taint case `x301-derive`, preserving the existing four | Pending the commit-bound, read-only archive gate |
| T12 | ladder/cswap/field disassembly gate | PASS on both final provider modules: 301 rounds, one fixed loop edge, 64 `cmov`, one public-index scalar read |
| T13 | scalar, ladder-state and shared-secret zeroization | PASS for the named-owner boundary; all six dual-lane provider Valgrind runs are clean |

The current core run has 44 default-feature tests and 53 `x301` tests in both
debug and release, plus the separately executed ignored 10,000-case test. The
independent oracle has 10 tests. Each OpenSSL lane has 10 raw-X301, 16 hybrid
and 8 key-separation harness checks in addition to its native ML-KEM data.
`fmt`, `clippy -D warnings`, rustdoc, both feature states, GCC `-fanalyzer`,
Clang static analysis, final codegen and the materialized twist evidence in
Section 8 pass. T11 remains the sole acceptance item not yet bound to a
committed, read-only archive.

## 11. Simplicity and implementation limits

The product X301 ladder, encoding and clamping target remains under 400 source
lines excluding tests. The provider hybrid adapter target remains under 600
source lines excluding tests. The reproducible metric is nonblank,
non-comment source lines: X301 counts only the production portion before its
test module; the hybrid count is `hybrid_kem.c` plus all lines conditional on
`X301_ENABLE_HYBRID_MLKEM1024` in `provider_shim.c`. Physical formatting and
contract comments are reported separately and are never hidden. Exceeding the
source-line target is a review finding requiring a written reason, not a
license to add mechanisms.

Every new product source file and public function MUST name its controlling
RFC, FIPS or OpenSSL contract in its source comment. The X301 implementation
must share the existing 5x64 field, parser/failure patterns, RAND route,
secret ownership and test infrastructure. A duplicated field path, ML-KEM
implementation, combiner, RNG, persistent hybrid format or standalone API
profile is a defect.

The measured production counts are:

| Surface | Physical lines | Nonblank, non-comment source lines | Budget |
| --- | ---: | ---: | ---: |
| X301 core before its test-only section | 264 | 160 | under 400 |
| `hybrid_kem.c` | 583 | 516 | |
| hybrid-only blocks in `provider_shim.c` | 81 | 80 | |
| Hybrid total | 664 | 596 | under 600 source lines |

The physical total is reported rather than hidden: 68 lines are required
source citations, contract comments, and spacing. The implementation budget
uses the stated reproducible nonblank/non-comment metric so documentation
mandated by this profile does not penalize the simpler implementation. Both
figures MUST be recomputed whenever either product file changes.
