# Fuzz-only dependency provenance

The entries below are unmodified extractions of official crates.io archives.
They complete the test-only libFuzzer dependency closure and are not linked
into the provider or public cryptographic crate.

| Crate | Version | crates.io archive SHA-256 | License |
| --- | --- | --- | --- |
| `arbitrary` | 1.4.2 | `c3d036a3c4ab069c7b410a2ce876bd74808d2d0888a82667669f8e783a898bf1` | MIT OR Apache-2.0 |
| `getrandom` | 0.4.3 | `300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099` | MIT OR Apache-2.0 |
| `jobserver` | 0.1.35 | `1c00acbd29eabad4a2392fa0e921c874934dbbf4194312ad20f04a0ed67a3cb3` | MIT OR Apache-2.0 |
| `libfuzzer-sys` | 0.4.13 | `a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2` | (MIT OR Apache-2.0) AND NCSA |
| `r-efi` | 6.0.0 | `f8dcc9c7d52a811697d2151c701e0d08956f92b0e24136cf4cf27b57a6a0d9bf` | MIT OR Apache-2.0 OR LGPL-2.1-or-later |

The repository source manifest authenticates every extracted file. Updating a
crate requires recording the new archive hash and rerunning the fuzz and
license gates.
