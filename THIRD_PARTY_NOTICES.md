# Third-party notices

The Rust crate uses exactly pinned crates from crates.io. Their original
license files, Cargo metadata and `.cargo-checksum.json` files are preserved in
the vendored dependency tree supplied to reviewers.

The direct dependencies declare:

- `crypto-bigint 0.7.5`: Apache-2.0 OR MIT
- `shake 0.1.0`: MIT OR Apache-2.0
- `zeroize 1.9.0`: Apache-2.0 OR MIT
- test-only `serde_json 1.0.150`: MIT OR Apache-2.0
- provider build dependency `cc 1.2.66`: MIT OR Apache-2.0

`provider-tests/x301/third_party/dudect/dudect.h` is dudect by Oscar Reparaz
(MIT, https://github.com/oreparaz/dudect, commit
`dc269651fb2567e46755cfb2a13d3875592968b5`); its license file and provenance
sit beside it. It is compiled only into the test-only timing harness and is
not part of any provider module or package.

Transitive packages retain their own notices and terms. The project license
does not relicense third-party code, standards or imported provenance inputs.
The local `cpufeatures 0.3.0` HWCAP-mask correction is documented under that
package and remains under its Apache-2.0 OR MIT license.
