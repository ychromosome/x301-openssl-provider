# Independent X301 reference

`x301_reference.py` is a variable-time test oracle. It imports no product
implementation and uses only Python's standard library. Its sources are RFC
7748 Sections 4 through 6, the ED301-v1 parameters named in
`../../inputs/round4/ED301-EdDSA-draft.md`, and the complete algebra in
`../../docs/X301_DRAFT.md`.

The oracle has six deliberately separate jobs:

1. T1 produces fixed scalar/u KATs, cross-checks basepoint results through
   complete Edwards scalar multiplication, and records exact D3 clamping bytes.
2. D1 evaluates complete twisted-Edwards addition and a Montgomery group law
   through the associated Weierstrass model, then checks deterministic random
   round trips and homomorphisms.
3. T2 applies the RFC 7748 iteration-test state update and freezes the results
   after one and 1,000 iterations.
4. T3 separates strict noncanonical, reserved-bit and wrong-length failures.
5. T4 derives all rational order-2 and order-4 x-lines algebraically and
   classifies the order-4 lines between the main curve and the twist by their
   quadratic characters. The identity has no affine u encoding.
6. T5 streams 10,000 deterministic key-generation/basepoint/DH cases. The
   fixture freezes the SHA-256 of the canonical TSV stream plus its first and
   last records; it does not store a redundant multi-megabyte copy.

Run the complete standard-library test:

```sh
python3 -I -B -O reference/x301/test_x301_reference.py
```

Validate a frozen fixture, including recomputation of all 10,000 T5 records:

```sh
python3 -I -B -O reference/x301/x301_reference.py verify-vectors \
  --path reference/x301/x301-test-vectors.json
```

Stream the T5 records for a differential consumer:

```sh
python3 -I -B -O reference/x301/x301_reference.py emit-corpus --count 10000
```

The oracle is not constant-time and MUST NOT process production secrets.
The frozen values are computed by this independent module, never read from
the Rust core, provider, handshake logs or historical X301 code.

Evidence checks use explicit `if ...: raise EvidenceError` control flow, not
Python `assert`, so `PYTHONOPTIMIZE=1` cannot remove them. The regression suite
contains negative controls that mutate a derived Montgomery constant and a
frozen iteration vector and requires both mutations to fail.
