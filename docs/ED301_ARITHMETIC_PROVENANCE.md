# Ed301 arithmetic provenance

The X301 fixed-base path uses the runtime Edwards formulas and wide-field
helpers from Ed301 commit
`eaebfe5048757c3daa2e257e9a74175ca3fe1d4c`.

`scripts/check-ed301-arithmetic-provenance.py` compares the following function
bodies and inline attributes byte for byte against that exact checkout:

- `EdwardsPoint::{add, add_affine, double}`;
- `multiply_wide`, `multiply_five_by_u32`, `reduce_small_product_unreduced`,
  `square_wide`, `reduce_wide`, `reduce_wide_unreduced`, and
  `accumulate_fold`;
- `MODULUS_TIMES_TWO`;
- the shared `Fe301Lazy` and `Fe301LazyLinear` methods.

X301-only lazy methods, decoding, ladder, conditional swap, zeroization and
protocol code are outside this comparison. Updating the Ed301 pin requires
the full X301 arithmetic, long-vector, taint and codegen gates.
