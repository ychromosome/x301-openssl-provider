# Independent X301 reference

`x301_reference.py` is a variable-time, standard-library-only test oracle. It
uses RFC 7748 Sections 4-6, the parameters in
`../../inputs/round4/ED301-EdDSA-draft.md`, and `../../docs/X301_DRAFT.md`. It
imports no product code or output and MUST NOT process production secrets.

It provides:

- T1 scalar/u/basepoint KATs and exact clamped bytes;
- D1 Edwards/Montgomery round trips and homomorphisms;
- T2 results after 1, 1,000, and separately 1,000,000 iterations;
- T3 alias, reduction, and length boundaries;
- T4 algebraically derived order-2/order-4 x-lines; and
- a deterministic 10,000-case T5 key-generation and DH stream.

Run the reference tests and frozen-vector check:

```sh
python3 -I -B -O reference/x301/test_x301_reference.py
python3 -I -B -O reference/x301/x301_reference.py verify-vectors \
  --path reference/x301/x301-test-vectors.json
```

Run the separate long vector:

```sh
python3 -I -B -O reference/x301/x301_reference.py verify-long-iteration \
  --path reference/x301/x301-long-iteration.json
```

Generate the long fixture or stream T5 records:

```sh
python3 -I -B -O reference/x301/x301_reference.py emit-long-iteration \
  --count 1000000
python3 -I -B -O reference/x301/x301_reference.py emit-corpus --count 10000
```

Evidence checks use explicit exceptions rather than `assert`, so Python
optimization cannot remove them. Negative controls mutate a Montgomery
constant and an iteration vector and require both checks to fail.
