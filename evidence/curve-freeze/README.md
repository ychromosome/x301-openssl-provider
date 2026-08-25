# Selected final c44730 curve evidence

Date of integration selection: 2026-08-25.

This directory materializes the minimal final c44730 evidence selected for the
X301 curve/twist review. It is an evidence subset, not a complete copy of the
historical `ed301_technischer_abschluss` tree, not a standards publication and
not a production approval. The current X301 contract is
`../../docs/X301_DRAFT.md`; protocol statements in the historical reports do
not override it.

## Selected evidence and its role

| Selected files | Evidentiary role |
| --- | --- |
| `parameter/ed301-v1.json` | Machine-readable final c44730 curve, group, twist, Montgomery and basepoint values. |
| `rohresultate/audit_c44730_full_reproducibility_pari.txt` | Recorded PARI/GP 2.17.3 run with direct curve/twist counts, factorizations, group structures, parameter derivation, ECPP validation, security checks and terminal `audit_pass=1`. |
| `rohresultate/audit_c44730_security_parameters_pari.txt` | Recorded focused recomputation in the same PARI tool lane, with terminal `audit_pass=1`. |
| `rohresultate/c44730_q_qtwist_primality_security_pari.txt` | Recorded fresh validation of the main and twist prime certificates and the `q-1`/`q_twist-1` factorizations. |
| `zertifikate/c44730_q_twist_ecpp_internal.pari` and `rohresultate/c44730_q_twist_ecpp_independent_python.txt` | Twist-prime ECPP certificate plus recorded separate Python verifier result `independent_certificate_valid=1`. |
| `zertifikate/c44730_q_twist_nminus1_bls_internal.pari` and `rohresultate/c44730_q_twist_nminus1_bls_independent_python.txt` | Twist-prime N-1/BLS certificate plus recorded separate Python verifier result `independent_N_minus_1_certificate_valid=1`. |
| `berichte/KURVENBERICHT_ED301.md` and `berichte/TECHNISCHER_ABSCHLUSS.md` | Historical narrative and interpretation of the final c44730 results. They are context, not the current X301 byte contract. |
| `LICENSE` and `LICENSE_SCOPE.md` | License text and the original technical-tree license boundary. |

The reports contain links to files that were not selected, including scripts,
older `phase_a` outputs, broader test suites and specifications. Such links do
not enlarge this evidence subset. In particular, rejected/earlier candidate
work and omitted `phase_a_*` files are not evidence for the current X301
decision. Historical X301 rules mentioned in the reports, including a special
annihilating-twist-scalar rejection, are also nonnormative here.

## Integrity

`UPSTREAM_SELECTED_SHA256SUMS` pins the twelve selected upstream files exactly
as received in this integration checkout. It deliberately excludes this local
README and the checksum list itself. Verify it from this directory with:

```sh
sha256sum -c UPSTREAM_SELECTED_SHA256SUMS
```

This verifies checkout-local bytes only. It does not prove that the subset is
a complete upstream tree or recreate an omitted upstream manifest.

## Reconciliation with the Ed301-EdDSA freeze

The Ed301 blind-oracle provenance records freeze commit
`0c48294893e9b7ec46109de51c3a04829befb39f`. That Git commit identifier is
not a SHA-256 digest of either parameter JSON and does not establish byte
identity for this evidence subset.

The two materialized parameter files have different SHA-256 digests:

| File | SHA-256 |
| --- | --- |
| `../../inputs/round4/upstream/ed301-v1/ed301-v1.json` | `23cb60255848176320d8938cb1856d469eb91455868da4078526dfb26ef6806f` |
| `parameter/ed301-v1.json` | `a9d66a001b2ef7c46a90cde447e64740b6eae024f6923e71dd504c13e5a4d27d` |

They are therefore **not byte-identical**. A direct diff of the materialized
files shows two textual metadata changes: the top-level `status` string and
the wording of `field.formal_primality_proof`. All other JSON lines match.
Fieldwise comparison additionally confirmed equality of these cryptographic
values:

| Values checked equal | Exact value or reference |
| --- | --- |
| `p` | `4074071952668972172536891376818756322102936787331872501272280264883462485411972664015193011` |
| Edwards `a`, `d` | `2086388329`, `301` |
| `N=4q` | `4074071952668972172536891376818756322102936789371269161834491587034136893877719336157337612` |
| `q` | `1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403` |
| `N_twist=4q_twist` | `4074071952668972172536891376818756322102936785292475840710068942732788076946225991873048412` |
| `q_twist` | `1018517988167243043134222844204689080525734196323118960177517235683197019236556497968262103` |
| Montgomery `A`, `B`, `A24_minus` | Equal in both JSON files and in the full PARI result. |
| Compressed Edwards basepoint | `6bf73f755a0c80653ce83fcf6d6ff7d7f347b1929224ac67552273419e6cf2c8a88a02d38898` |
| Little-endian Montgomery base u | `5ba6f0f4ccc6ff5f018a2496fe165eb7d1893949fe3d05f79c12d2bd99952cd42d2ae9546308` |

The full and focused PARI outputs agree with the selected JSON for `p`, `a`,
`d`, `A`, `B`, `A24_minus`, `N`, `q`, `N_twist` and `q_twist`; the checked
relations `N=4q`, `N_twist=4q_twist` and `N+N_twist=2p+2` also hold exactly.

## Provenance and reproducibility boundary

The integration handoff identifies these bytes as a selection from the final
c44730 technical evidence tree. This subset does not contain that tree's
original `SOURCE_SHA256SUMS`, `SHA256SUMS`, reproduction document or verifier
scripts. Consequently, this directory alone cannot prove the original source
commit/path, completeness of the upstream package or a from-scratch rerun.
The two included Python files are recorded verifier outputs, not the verifier
programs. Their certificate inputs are present, but rerunning those exact
checks requires recovering and separately authenticating the omitted scripts.

What is closed here is the narrower checkout-local gate: the selected final
artifacts are present, hashed and internally value-consistent with the current
Ed301 curve parameters. External organizational independence, complete
upstream provenance and full reproducibility remain separate assurance claims.
