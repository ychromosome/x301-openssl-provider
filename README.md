# X301 core review step

This first review commit contains the experimental X301 Rust core, its
independent Python reference and vectors, frozen inputs, curve evidence,
vendored dependencies and portable test sources. The existing Ed301
draft-00 compatibility core is preserved unchanged; it is not the separate
Ed301-v1 provider. Ed301 and X301 keys must remain separate.

The next commit adds the complete X301 and X301MLKEM1024 OpenSSL provider,
integration, packaging, authoritative gates and final user documentation.
No wire format is changed by this history condensation. The complete
development history remains on `provider-experiment` at commit
`569dc4ff10e0e5e19d106cbe490d2a5aaeac935e`.

The root Cargo workspace is independently buildable with locked, vendored,
offline dependencies. Its unit-test configurations are debug and release,
each with default features, `sign-self-verify`, `x301`, and
`x301,sign-self-verify`. The X301-only no-default-features build is separate.
Release overflow checks remain enabled for owned code; the existing
crypto-bigint 0.7.5 exception and profile guard are preserved unchanged.

These intermediate unit checks are not the final authoritative integration
gate. This is a research and review candidate, not a production release,
completed audit or universal constant-time or zeroization claim.

Apache-2.0; vendored dependencies retain their original licenses and notices.
