# X301 small-a24 isomorphism analysis

Date: 2026-08-25. Disposition: analysis only; no parameter or byte-contract
change is authorized by this document.

## Frozen model

For the frozen twisted Edwards coefficients `a=2086388329`, `d=301` over
`p=2^301-2^99+947`, the documented birational map gives

```
A = 2(a+d)/(a-d) mod p
B = 4/(a-d) mod p
u = (1+y)/(1-y)
```

The resulting Montgomery coefficient is

```
A = 1337125101468798294423667083008487580371440947467333579746761624815927501631542793281919359
```

and the ladder constant used by X301 is

```
(A-2)/4 mod p =
1352799263534442616740139614956810975618594433699801520254760472424847496760878864324278092
```

Its least-absolute residue has 300 bits. The alternative ladder convention
`(A+2)/4` differs by one and is also 300 bits.

## Isomorphism constraint

Write the normalized Montgomery model as

```
B v^2 = u^3 + A u^2 + u.
```

Under a scaling `u=r*u'`, `v=s*v'`, normalization of both the cubic and
linear coefficients requires `r^2=1`. Thus a normalized Montgomery
isomorphism can change `A` only to `A` or `-A`; it cannot choose an arbitrary
small coefficient. Both corresponding `a24` residues have 300-bit
least-absolute representatives.

There is no second rational 2-torsion origin which could supply another
normalized Montgomery model: `A^2-4` is a quadratic non-residue modulo `p`.
The curve therefore has only the rational point `(0,0)` of order two in this
model. Allowing a non-normalized coefficient merely moves the same large
constant into another multiplication; it does not remove it.

## Contract and performance consequence

A genuinely different Montgomery coordinate would change the frozen base
coordinate, every X301 public key, every shared secret, all KATs and the TLS
group's wire bytes. It would be a new X301 byte contract, not an internal
optimization. The possible saving is only the roughly one full constant
multiplication per ladder round identified in the performance brief; it does
not justify reopening a frozen interoperable encoding.

Recommendation: retain the present model and `a24`. Revisit only before a new
and explicitly incompatible X301 profile is frozen; do not alter the current
provider.
