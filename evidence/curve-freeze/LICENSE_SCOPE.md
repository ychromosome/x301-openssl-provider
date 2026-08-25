# ED301 technical-tree license scope

Copyright 2026 Martin Wolf and ED301 contributors.

## Apache-2.0 project work

Unless an individual file states otherwise, copyrightable project-authored
content inside this `ed301_technischer_abschluss` directory is licensed under
the Apache License, Version 2.0 (`Apache-2.0`). The complete license text is in
`LICENSE`.

This scope includes, to the extent it is project-authored and copyrightable,
the source and countercheck implementations, tests, scripts, manifests,
package metadata, technical specifications, project-created vectors and
technical documentation in this tree. Both Node.js countercheck packages
therefore declare `Apache-2.0` in their respective `package.json` files. Their
`private` setting and their not-for-production status are unchanged.

The license statement does not claim copyright in mathematical facts,
formulae, parameter values or algorithms as such. It also does not assert that
the included cryptographic material is standardized, approved, secure or fit
for production.

## Separately supplied and third-party material

This directory license does not relicense separately authored or third-party
works. Such material remains subject to its own notices and terms. Recorded
tool output, certificates and imported evidence are covered only to the extent
that a copyrightable portion was project-authored; no rights are claimed in
tool-authored, third-party or separately supplied portions. References to RFC,
NIST, OpenSSL or other external publications and projects do not incorporate
those works into the Apache-2.0 project work.

The three provenance inputs named through parent-relative paths in
`SOURCE_SHA256SUMS` are outside this directory. Their inclusion in a review
bundle is for provenance and reproducibility and does not, by itself, place
them under this directory's Apache-2.0 grant. Any notices or usage terms carried
by those artifacts remain controlling.

Historical or retired status does not remove a project-authored file from the
license grant. The separate current-review boundary for `Ed301-Sig-v1` and
`X301-v1` is defined in `SIGNATURE_STATUS.md`; it is a technical scope rule,
not a claim about third-party rights.
