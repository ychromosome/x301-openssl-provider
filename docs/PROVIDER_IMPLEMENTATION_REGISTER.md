# Provider implementation register

This register records deliberately local provider infrastructure whose
rationale can become stale as stable Rust changes. Revisit every entry when
the canonical Fedora Rust toolchain changes.

| Area | Current implementation | Why it exists | Replacement trigger | Permanent evidence |
| --- | --- | --- | --- | --- |
| Fallibly allocated shared state | Local immutable `Shared<T>` with atomic reference counting and last-owner destruction | Provider allocation failure must return an OpenSSL error instead of aborting. Stable `Arc::try_new` still requires the unstable `allocator_api` feature. | Replace with `Arc::try_new` once it is stable and preserves the fail-closed allocation contract. | Rust clone/drop/reference-count tests; provider duplicate/free/unload tests; allocation-failpoint and Valgrind lanes. |
| Fallible owned allocation | Local `try_box`/`try_box_at` over the global allocator | Stable `Box::try_new` still requires the unstable `allocator_api` feature. The helper also gives every externally reachable allocation site a deterministic test failpoint. | Replace the allocation core with stable `Box::try_new`; retain only the named test-failpoint wrapper if still needed. | Sized and zero-sized Rust tests; every named site exercised through the provider hardening harness; ordinary-module inert-control test. |

## X301 provider additions

Date: 2026-08-25. Sources: OpenSSL 3.5.7 and 4.0.1
`provider-keymgmt(7)`, `provider-keyexch(7)`, `provider-kem(7)` and
`provider-base(7)` TLS-GROUP contracts; FIPS 203; RFC 9846; RFC 10024. These
are implementation constraints, not a completed-lane claim.

| Area | Required implementation | Why it exists | Replacement or deletion trigger | Required permanent evidence |
| --- | --- | --- | --- | --- |
| X301 KEYMGMT/KEYEXCH | Add a distinct X301 key type and 38-byte derive surface by sharing existing provider context, fixed-length import/export, error and secret-owner patterns. | OpenSSL KEYEXCH is the requested direct X301 API. Key-type separation enforces H5 at the EVP-object boundary. | Delete copied infrastructure; retain only X301-specific dispatch and lengths. | T6/T7 in both lanes, cross-type Ed301/X301 negatives, lifecycle and zeroization tests. |
| X301MLKEM1024 libssl adapter | Expose the KEYMGMT/KEM operations named by a `TLS-GROUP` capability with `is-kem=1`; they are technically fetchable by ordinary EVP because that is how libssl invokes the group. | Mandatory OpenSSL architecture, not a promise of a standalone hybrid-KEM protocol. | Delete any non-TLS OID, persistence, KDF, codec or application profile. If OpenSSL later offers a smaller standard TLS-only contract, reassess and prefer it. | EVP fetch/dispatch test plus T8/T9 in both exact lanes. |
| ML-KEM-1024 component | Fetch ML-KEM-1024 from the OpenSSL default provider and call its EVP keygen/encaps/decaps operations. | E1: FIPS 203 cryptography remains OpenSSL-owned. | Any project-owned ML-KEM symbol, crate, vendored code or copied substep is a removal finding. | Provider provenance/fetch assertion and T10 integration KAT in both lanes. |
| Hybrid layout | Parse and emit exactly 1568-byte ML-KEM component followed by 38-byte X301 component; concatenate 32-byte ML-KEM secret followed by 38-byte X301 secret. | RFC 10024's X25519MLKEM768 ordering and H1/H2. | Delete alternate ordering, length inference and any hash/KDF. | H2 +/-1 boundary matrix and 1606/1606/70 assertions. |
| Random generation | Route X301 key generation through existing provider RAND; let OpenSSL default-provider ML-KEM use its own standard RNG path. Derive/decaps with fixed keys must not call X301 RAND. | E4 and the existing poisoned-RAND assurance pattern. | Delete any hybrid or X301-specific RNG abstraction. | T7 poisoned-RAND split and complete handshake. |
| Hybrid secrets and failures | Reuse existing fallible allocation, no-partial-output, zeroization and drop ownership. Preserve OpenSSL ML-KEM implicit rejection verbatim. | H3/T13 without a parallel secret lifecycle. | Delete copied owners or code that detects/rewrites an implicit-rejection secret. | T9, allocation failures, taint, drop/zeroization and protected-record authentication failure after a wire mutation. |
| Nested default-provider use | Use the provider Child `OSSL_LIB_CTX` for ML-KEM fetches and require the application/default-provider configuration to make `provider=default` available. Capability discovery stays side-effect free; absent ML-KEM makes hybrid key generation/import fail cleanly. | External providers must not cast the core context; ML-KEM must remain OpenSSL-owned. | Prefer a smaller standard core upcall if OpenSSL later provides one. Do not add a parallel RNG or auto-load policy. | Default-present provenance/fetch tests and isolated default-absent failure test. |
| Child-context thread lifecycle | Temporary nested EVP contexts are freed first; `OPENSSL_thread_stop_ex(child)` then releases only the invoking thread's Child-LIBCTX handlers. Refcounted returned `EVP_PKEY` objects remain live. | OpenSSL cannot clear another thread's Child-LIBCTX state at teardown. The explicit stop permits a worker that has finished provider operations to exit after main-thread teardown. | Revisit only if OpenSSL publishes a provider-owned all-thread teardown primitive. | Cross-thread teardown regression first performs OpenSSL's required worker-side stop for the application-owned host context; Valgrind then independently detects any stale provider-child handler. Repeated returned-key use and dual-lane TLS are also required. |

Any replacement must retain fallible allocation, zeroizing destruction of
rejected secret values, the ordinary/test-artifact separation, and the full
provider lifecycle contract. It therefore requires both normative OpenSSL
lanes, the hardening and load/unload matrices, and the secret-taint lane.
