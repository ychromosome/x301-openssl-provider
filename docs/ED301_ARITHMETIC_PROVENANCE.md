# Ed301 arithmetic provenance

The X301 field backend derives from Ed301 commit
`eaebfe5048757c3daa2e257e9a74175ca3fe1d4c`.

`scripts/check-ed301-arithmetic-provenance.py` compares the following function
bodies and inline attributes byte for byte against that exact checkout:

- `EdwardsPoint::{add, add_affine, double}`;
- `multiply_wide`, `multiply_five_by_u32`,
  `reduce_wide`, `reduce_wide_unreduced`, and
  `accumulate_fold`;
- `MODULUS_TIMES_TWO`;
- the shared `Fe301Lazy` and `Fe301LazyLinear` methods.

X301-only lazy methods, decoding, ladder, conditional swap, zeroization and
protocol code are outside this comparison. Updating the Ed301 pin requires
the full X301 arithmetic, long-vector, taint and codegen gates.

Two local adaptations dated 2026-09-05 are checked against their own source
hashes, not claimed byte-identical to Ed301:

- `reduce_small_product_unreduced` omits an unreachable underflow correction.
  With `T=x*c`, `x<4p`, `c<2^32`, write `T=L+H*2^301`.
  Then `H<2^34`, `L+H*2^99<2^320`, and `H*947<2^44`.
  The exact subtraction gives `L+H*(2^99-947)>=0` and
  `L+H*(2^99-947)<2^301+2^133<2p`.
- `square_wide` follows OpenSSL `crypto/bn/bn_sqr.c:bn_sqr_normal`:
  cross products once, doubling, then diagonals. It retains 15 word products
  and the complete 320-bit input domain. Each row accumulator fits u128;
  the nonnegative cross terms and diagonals sum to `x^2<2^640`.

The exact-width test uses `crypto-bigint::U320::widening_mul`; small-fold
endpoints and full lazy-domain tests use the separate Montgomery oracle.
Both adaptations require the same functional, taint, final-codegen and
long-vector gates. No second field backend is introduced.
