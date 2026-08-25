# Arithmetic implementation register

This register records deliberately local arithmetic code whose rationale can
become stale as compilers and libraries change. Revisit every entry whenever
the canonical Fedora Rust toolchain changes.

| Area | Current implementation | Why it exists | Permanent evidence |
| --- | --- | --- | --- |
| Runtime field borrow | Safe `u64::borrowing_sub` chain | Replaces the larger Hacker's-Delight expansion after Rust 1.97.1 lowered every reviewed final-provider use site to branchless SBB/CMOV code. The expansion originally repaired a real secret-dependent `overflowing_sub` lowering under older compilers. | Full core differential/KAT tests, four core taint cases, EVP-provider taint, and `scripts/check-final-provider-codegen.sh` on each OpenSSL-lane module. |
| Compile-time field borrow | Local Hacker's-Delight identity | `u64::borrowing_sub` is not const-stable. This path constructs public immutable tables and is not executed on secrets at runtime. | Table reconstruction and field differential tests. |
| Field wide reduction | Positive `high * (2^99 - 947)` MAC fold | Exploits the fixed pseudo-Mersenne modulus while removing borrow-heavy work. | Montgomery differential oracle, reachable one-hot/boundary/random cases, taint and final codegen gate. |
| Scalar wide reduction | Natural 304+304 split and fixed `2^304 mod L` | Reuses constant-time `crypto-bigint` Montgomery operations and removes the ten-word Horner loop. | Independently reproduced radix, block-boundary/all-one-hot/random division-oracle tests, taint and final codegen gate. |

## X301 arithmetic constraint

Date: 2026-08-25. Source: RFC 7748 Sections 4-6 and the frozen ED301 field
contract. This section records required reuse and the evidence expected from
each implementation; it does not turn passing local tests into a production
claim.

| Area | Required implementation | Why no separate implementation is permitted | Required permanent evidence |
| --- | --- | --- | --- |
| X301 field operations | Use the existing Ed301 5x64 field type for addition, subtraction, multiplication, squaring, reduction, inversion and constant-time selection. The prepared comb's internal `a=1` point coordinates remain values of this same type; they are not a second limb representation or reducer. | E2: a second field representation, reducer or constant-time selector would be unstandardized duplicate cryptography. | T5 differential corpus, ladder and prepared-derive taint, and final-provider codegen on both OpenSSL lanes. |
| X301 Montgomery ladder | A 301-round RFC-7748-shaped ladder with `A24=(A-2)/4`, retained as the reference, first-use and twist/exceptional path. | RFC 7748 supplies the mechanism; ED301 contributes only fixed parameters and bit count. | T1/T2/T4/T5, taint and disassembly gates. |
| Prepared X301 derive | Public-peer fixed-base comb: `Q=4P`, masked odd representative of `k/4`, 305 regular signed digits, width 5, 61 rows and a full scan of 16 entries per row. The private point model scales `X,T` by `45677`, uses `d/a`, and preserves `Y,Z` and Montgomery u. | Removes repeated ladder work without changing accepted inputs, wire bytes, the field backend or the twist fallback. Simpler measured candidates missed the owner-set 1.56-times-X25519 target. | Nine interval/boundary scalars, 559-case adversarial matrix, 10,000 independent Python cases, `x301-derive-prepared` taint, exact final-binary recoder/table-scan gate, provider duplicate/reinit tests and paired dual-lane benchmarks. |
| Edwards/Montgomery conversion | General conversion remains test-only. X301 key generation alone maps the existing constant-time fixed-base result directly as `u=(Z+Y)/(Z-Y)`, with one existing field inversion and no affine Edwards encode/decode cycle. | K1 removes an entire 301-round basepoint ladder without adding arithmetic. The clamped scalar cannot be zero modulo `L`; the release path therefore needs no exceptional identity branch. | Nine independent reduction boundaries, 10,000-case ladder/Python differential, `x301-keygen` taint and final-provider fixed-base codegen gate on both lanes. |
| Twist-scalar edge | Do not add a special raw-key or `4*q_twist` rejection. Use exact clamping and mandatory all-zero output rejection. | No RFC source exists for an additional scalar blacklist; D4 already supplies contributory failure. | D3 clamping KATs and complete T4 corpus. |

The independent Python reference is deliberately variable-time test code and
is not an alternate production arithmetic path.

The final codegen gate is intentionally compiler-specific. Passing it under one
compiler is not a promise about another compiler, architecture, build profile,
or future inlining decision.
