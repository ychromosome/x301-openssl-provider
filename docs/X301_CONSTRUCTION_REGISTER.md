# X301 construction and simplicity register

Date: 2026-08-25. Controlling sources are listed in `X301_DRAFT.md`. Every
local cryptographic transform MUST have a row here before implementation.

## Build-versus-buy decisions

| ID | Decision | Controlling source | Required disposition |
| --- | --- | --- | --- |
| E1 | ML-KEM-1024 is OpenSSL-owned | FIPS 203; OpenSSL EVP ML-KEM contract | Fetch through EVP in the provider child library context, under that context's property policy, in both normative lanes. No Rust crate, vendored implementation, copied substep or project-owned ML-KEM symbol. |
| E2 | X301 is not a second field engine | RFC 7748 ladder pattern; frozen Ed301 5x64 field | Reuse the existing limbs, multiplication, squaring, reduction and constant-time selection. A second backend, reducer, limb representation or swap implementation is forbidden. Private types may encode proven intermediate bounds. |
| E3 | The hybrid is concatenation, not a combiner construction | RFC 9954; RFC 10024 Sections 4-5; RFC 9846 Section 7.1 | Concatenate component shares and secrets. TLS 1.3 performs the only KDF. No project hash, extract, expand or label. |
| E4 | No new RNG route | OpenSSL provider RAND contract; existing provider keygen contract | Generate private material through provider RAND. Fixed-key derive consumes no RAND. |
| E5 | TLS group plus required fetchable adapter, no standalone profile | OpenSSL `TLS-GROUP` with `is-kem=1`, provider KEYMGMT/KEM contracts | Expose the EVP-fetchable operations libssl requires. Define no non-TLS KDF, OID, persistence, ciphertext profile or compatibility promise. |

E1-E5 are mandatory.

## Registered project choices

| ID | Local choice | Standard anchor | Why the local choice is necessary and minimal | Frozen evidence |
| --- | --- | --- | --- | --- |
| X-PARAM | Translate the frozen ED301 `(a,d)` curve to Montgomery `(A,B)` and derive the base u-coordinate | RFC 7748 Section 4 | RFC 7748 supplies the algebraic pattern but cannot name ED301 parameters. Formulas, exceptional points and homomorphism are all explicit; there is no new curve search. | `X301_DRAFT.md` Sections 3-4; independent D1 oracle |
| X-D2 | Accept exactly 38 bytes, clear bits 301-303, and subtract `p` once when needed; store and export only the canonical result | RFC 7748 Sections 5-6 field-element decoding pattern | X301 has a 301-bit field in a 304-bit encoding. Masking followed by one subtraction covers every input without a general reducer. | T3 fixture and `OPENSSL_PATTERN_DEVIATIONS.md` `X-D2` |
| X-D3 | Clear bits 0-1, set bit 300, clear bits 301-303 | RFC 7748 Section 5 scalar-decoding pattern, translated to cofactor 4 and a 301-bit field | The exact bit positions are specific to ED301. No scalar reduction or extra rejection is added. | Four T1 clamping KATs |
| X-D4 | Make the all-zero shared-secret check mandatory for direct KEYEXCH and TLS | RFC 7748 Section 6 recommendation; RFC 9846 Section 7.4.2 mandate for X25519/X448 | One fail-closed translation prevents silent non-contributory exchange and avoids separate direct/TLS behavior. | Independent T4 corpus plus direct EVP rejection of `0`, `1` and `p-1` in both key directions |
| X-BASE | Use the u-coordinate obtained by mapping the frozen Ed301 basepoint | RFC 7748 Section 4 mapping pattern | Preserves the reviewed prime-order generator rather than searching or inventing a second point. | Independent parameter derivation and T1/T2 fixture |
| X-K1 | Derive local X301 public keys through the existing constant-time Edwards radix-16 fixed-base table, then map projectively with `u=(Z+Y)/(Z-Y)` | RFC 7748 Sections 4 and 6; the already registered X-BASE birational equivalence | This removes the generic 301-round basepoint ladder while retaining the same clamped scalar, point, bytes and field backend. Because the base point has order `L`, direct multiplication by the clamped integer equals multiplication by its residue modulo `L`; the explicit reduction is omitted. | Nine independent scalar boundaries compare direct and reduced fixed-base results; byte-identical KATs, 10,000-case ladder/Python differential, dedicated taint case and final-binary fixed-base selector gate |
| X-LAZY | Represent reduced ladder values below `2p` and immediate linear intermediates below `4p`; canonicalize at input decoding, inversion and output encoding | Existing Ed301 5x64 limbs, product/reduction code and RFC 7748 ladder schedule | The private `Fe301Lazy` and `Fe301LazyLinear` types make the bounds explicit while reusing the sole field backend. This removes repeated final subtractions without a new reducer, dependency, unsafe code or architecture path. | 10,000 field differential cases, X301 KAT/differential corpus, secret-taint and final-provider codegen gates on both lanes |
| X-CLAMP-SCHEDULE | Fold fixed scalar bits 300=1 and 1=0, 0=0 into ladder initialization and finalization | RFC 7748 ladder invariant; frozen D3 clamping | The implementation still performs 301 doublings but needs full differential-addition rounds only for variable bits 299 through 2. The scalar-independent schedule removes three known-result differential additions. | Frozen KATs, 1,000 properties, 10,000 Python differentials, taint and exact final-binary loop-shape gate |
| X-A24-SCALE | Scale both projective doubling outputs by `q=a-d=2086388028`, using `A24=d/(a-d)=301/q` | RFC 7748 projective-coordinate freedom; frozen ED301 `a,d` | Replaces one dense field-constant multiplication per doubling with products by two public 32-bit constants. `q*AA` is reused in both outputs; the common nonzero scale leaves `X/Z` unchanged. | Parameter identity, field differential corpus, full X301 oracle corpus, taint and final-provider codegen |
| X-H1 | Order all three hybrid values ML-KEM first and name the group `MLKEM1024X301` | RFC 9954 ordered-component convention; RFC 10024 Sections 4-5 | The public name and every concatenation use the same component order. The historical `X25519MLKEM768` naming exception is not copied into a new private-use group. | H1/H2 name rejection, 1606/1606/70-byte size, offset-1568 delete/insert and parser tests |
| X-H4 | Assign experimental NamedGroup `0xFE2E` | RFC 9846 Section 4.3.7 ECDHE private-use range | A private identifier is required for in-project handshakes. It is explicitly nonpublic and nonregistrable. | `OID_REGISTRY.md` |
| X-TEST | Use named SHAKE256 domains to generate deterministic oracle cases | FIPS 202 SHAKE256; test-only reproducibility pattern | Avoids platform RNG drift and a huge checked-in corpus. SHAKE output is not protocol input generated by product code. | T5 canonical-stream digest, first and last records |
| X-W2 | Accept canonical large-order Montgomery-twist u-coordinates and reject only contributory all-zero results | RFC 7748 Sections 5-6; the frozen ED301 twist-order evidence cited by `X301_DRAFT.md` | An XDH ladder intentionally does not perform curve-membership validation. Adding such validation would create a different protocol and discard the twist-security model. | Eight independently classified twist vectors, including the low-order rejection boundary, pass through the Python, Rust and EVP lanes |
| X-M1 | A second successful `set_peer` replaces the first peer; it does not merge state or reject reuse | OpenSSL provider-keyexch state model | This is the smallest useful context-reuse rule and matches assignment semantics in the provider state. An invalid replacement still fails without producing output. | EVP M1 test sets two distinct independent-reference peers and proves that the second peer determines the result |
| X-M4 | Re-running `derive_init` clears the peer. OpenSSL binds the local key when `EVP_PKEY_CTX` is created, so changing the local key requires a new context, which also starts without a peer | OpenSSL `EVP_PKEY_CTX_new_from_pkey` and provider-keyexch contracts | There is no public EVP API for replacing the bound local key in place. Explicit reinitialization and fresh-context semantics prevent stale peer material from crossing either supported reuse boundary. | EVP M4 test proves failure without a newly set peer after both re-init and creation with a different private key |

No other project-owned cryptographic transform is registered.

RFC 9846 Section 4.3.8 directly requires locally generated KeyShare values to
be fresh for every connection. MLKEM1024X301 inherits that rule, including on
session resumption; this is not a project-specific construction.

## Forbidden additions

The implementation MUST NOT add:

- a second X301 field backend, reducer, limb representation, or selector;
- a twist-order scalar blacklist beyond D3 clamping and D4 all-zero rejection;
- project-owned ML-KEM arithmetic or KAT logic;
- a hybrid hash, HKDF, label, RNG, OID, persistent key format, or generic
  protocol;
- Ed301/X301 key conversion or shared key objects; or
- duplicate parsers, secret owners, error plumbing, or lane scripts where the
  existing contract applies.

## Review trigger

Any new dependency, public operation, file format, hash invocation, random
source, field primitive or component reordering requires a dated row before
implementation. If no RFC, FIPS, IETF publication or OpenSSL contract can be
named, the proposed code is local construction and MUST either be justified
here or deleted.
