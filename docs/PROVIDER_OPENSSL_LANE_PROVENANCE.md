# Public OpenSSL lane evidence contract

`scripts/build-openssl-provider-lane.sh` consumes only a caller-staged
public release
tarball. It performs no clone, network fetch, private-fork lookup, packaging,
or release operation. The only accepted lanes are:

| lane | release name | public source URL | shared-library major |
|---|---|---|---|
| 3.5.8 | openssl-3.5.8 | https://www.openssl.org/source/openssl-3.5.8.tar.gz | 3 |
| 4.0.2 | openssl-4.0.2 | https://www.openssl.org/source/openssl-4.0.2.tar.gz | 4 |

The builder also pins the full SHA-256 digest of each accepted release
tarball: `a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2`
for 3.5.8 and
`736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8`
for 4.0.2. Both the sidecar value and the tarball bytes must match the
corresponding pinned value.

The URL is provenance metadata only. The helper does not fetch it; the
tarball and its `.sha256` sidecar must already exist in the supplied upstream
directory. The builder copies both inputs through no-follow file descriptors
into its private lane root before authentication. Hashing, layout validation,
extraction, and final evidence use only those private copies. The checksum
sidecar must name exactly the selected tarball, contain the pinned digest, and
pass a strict `sha256sum -c` check. The tar listing must contain one
top-level `openssl-<version>/` tree, no absolute or `..` member, and
`VERSION.dat`.

A release tarball has no verifiable Git object database. Consequently
`source_commit` and `source_tree` are explicitly
`NOT_AVAILABLE_FROM_RELEASE_TARBALL`; the lane seal does not infer a commit or
tree from the release name. `authenticated_git_tag` is recorded as
`NOT_VERIFIED_FROM_RELEASE_TARBALL`.

This lane verifies the pinned SHA-256 values but does not perform an OpenPGP
identity check. A separately authenticated OpenSSL signing-key/PGP check is
therefore an explicit provenance gate for any release use beyond this test
campaign.

## Required per-lane artifacts

Under the lane root, `logs/<version>/` contains:

- `builder_inputs.sha256` and `builder_identity.tsv`, binding the builder,
  input stager, and this provenance document before and after the build;
- `staged_inputs.log` and `staged_inputs_recheck.log`, recording the private
  input copy and its post-extraction verification;
- `toolchain_identity.tsv` and `build_environment.tsv`, recording executable
  paths/versions, OS/kernel/architecture, and relevant inherited variables;
- `tarball.sha256`, `tarball_checksum.sha256`, and `source_identity.tsv`;
- `source_manifest_pristine.sha256` and its `.seal`, made immediately after
  extraction plus the explicit `VERSION.dat` check, and before `Configure`;
- `source_manifest_post.sha256`, `source_change.tsv`, and the source file
  lists used by the post-build check;
- `linker_selection.tsv`, recording the selected `-L<lane>/lib` and
  `-Wl,-rpath,<lane>/lib` arguments;
- `openssl_modules_pre.tsv` (the explicit empty-prefix pre-state) and
  `openssl_modules_post.sha256`, covering the installed OpenSSL
  `lib/ossl-modules/*.so` files;
- `artifact_hashes.sha256`, covering the CLI, both shared libraries, the
  dereferenced contents at their unversioned symlink paths, and installed
  OpenSSL module DSOs; `library_symlinks.tsv` separately binds the link targets;
- `runtime_binding.ldd` and `runtime_binding.readelf`, produced under a clean
  environment and proving that the CLI
  `libcrypto` and `libssl` DSOs resolve under the exact selected prefix and
  that the only RPATH/RUNPATH is that prefix's `lib/`;
- `lane_identity.seal`, the machine-readable release/header/library/loader
  identity record; and
- `prefix_manifest.sha256`, `prefix_inventory.tsv`, and
  `prefix_symlinks.tsv`, which bind every installed regular file, directory,
  and symlink and reject special objects or links escaping the prefix; and
- `evidence_manifest.sha256` and its seal, hashing every preceding executable
  step's log and exit file plus the identity, provenance, source, loader, and
  artifact records. The manifest intentionally excludes its own log/exit, its
  subsequent verification step, and the final lane-status transition to avoid
  a self-referential hash. The final outer snapshot must bind those remaining
  files.

Every executable step has a sibling `<step>.exit` and captured stdout/stderr.
`LANE <version> OK` is written only after the evidence manifest is complete.
Any failed manifest, version, loader, linker, or hash check records
`LANE <version> FAILED` and a nonzero `lane_status.exit`; no later command can
overwrite it with `OK`.

The lane consumer does not trust the directory name or an unbound version
label. Before executing the lane CLI or linking any provider artifact it
requires the exact lane root, version, and an evidence-manifest SHA-256
supplied by the outer controller. `scripts/verify-openssl-provider-lane.sh`
then rechecks the complete prefix inventory, regular-file hashes, symlink
containment, release identity, and evidence chain.

Consumers copy the installed prefix, evidence logs, and required native test
files into their private result root and verify that copy before compilation
or execution. All include, library, loader, CLI, `evp_test`, and cross-lane
paths then use the private copy. The external lane is not used again.

The source manifest is a content/presence seal for all regular files present
after extraction and the version check. OpenSSL's in-tree build may add
generated files, so the
post-build check requires every pre-existing regular file to remain byte
identical and records added regular-file paths in `source_change.tsv`; it does
not falsely call the entire post-build directory pristine.

## Provider-module and sanitizer boundary

The OpenSSL lane helper builds no project provider. The X301 acceptance runner
separately records ordinary, failpoint, sanitizer and fuzz-coverage module
hashes before and after use. ASan/UBSan covers the C provider and hybrid
boundaries; Valgrind covers the linked Rust/FFI paths. Neither lane sanitizes
the OpenSSL shared libraries or establishes a general memory-safety claim.

No lane result should be promoted beyond public OpenSSL 3.5.8/4.0.2 tarball,
build, and runtime identity verified under this evidence contract.
