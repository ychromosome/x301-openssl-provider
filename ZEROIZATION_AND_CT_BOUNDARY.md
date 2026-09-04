# Zeroization and constant-time boundary

## Named secret owners

RAII owners clear these Ed301 values on return, error, and panic unwinding:

- seed and expanded seed;
- pruned and reduced secret scalar;
- nonce prefix, deterministic nonce, response term, and response buffer.

X301 owners clear the raw scalar, ladder state, projective output, and returned
38-byte shared secret. The provider clears its raw derive buffer, key-generation
seed buffer, and the temporary 70-byte `ML-KEM-SS || X301-SS` value on every
exit after creation. The provider contract has a separate Valgrind artifact
that marks these shared-secret paths undefined before they cross the FFI
boundary.

These guarantees cover named source-level owners only. Rust and LLVM may copy
field, scalar, point, stack, register, spill, or ABI values. The project makes
no every-copy or forensic stack-remanence claim.

Destructors do not run with `panic=abort`. The core and provider reject that
panic strategy. Release gates record `panic=unwind` on the actual compiler
invocations and exercise unwinding through secret owners. They do not inspect
freed stack memory.

## Constant-time boundary

The public Rust core forbids unsafe code. Secret fixed-base multiplication
uses fixed radix-16 digits and scans all eight table entries. X301 uses a fixed
301-doubling schedule. Runtime field correction crosses the reviewed
`CtAssign`/`cmov` boundary. Wide reduction and scalar reduction use fixed loop
counts.

Public Ed301 verification uses variable-time wNAF/Straus recoding and public
table indices. Point decoding uses a fixed public exponent and verifies its
candidate. The independent Python oracle is variable-time and MUST NOT process
production secrets.

Source structure is not a constant-time proof. Secret-taint and disassembly
gates bind one compiler, architecture, profile, and final binary. A compiler,
target, profile, inlining, or arithmetic change MUST rerun those gates.

The current final-binary policy is defined for x86-64. AArch64 disassembly,
timing, and cache evidence remains open.

## Provider FFI and shared state

Provider keys and contexts share immutable expanded-signing and
prepared-verification objects through a fallibly allocated atomic owner.
Public-only objects cannot retain the signing scalar or nonce prefix. The last
reference runs the existing secret destructors.

Raw pointers, allocation, and explicit `Send`/`Sync` implementations remain
inside the provider FFI boundary. Reference increments are relaxed; decrements
are release operations followed by an acquire fence before final destruction.
Reference-count overflow aborts. This boundary requires allocation-failure,
duplicate/free, concurrency, load/unload, and Valgrind tests.

The ordinary signing provider follows the EdDSA signing path without a second
verification. Feature `sign-self-verify` adds that fault check. The selected
build MUST be recorded because the feature changes fault detection, not wire
bytes.

## RAND and child contexts

Provider key generation draws its 38 octets from a provider-owned DRBG: one
`CTR-DRBG` instance fetched under the child `OSSL_LIB_CTX` provider and
property policy, instantiated without a parent so that it is seeded through
the core `get_user_entropy` upcall from the application context's seed source,
and locked for concurrent callers. The provider never calls
`RAND_priv_bytes_ex()` on the child context, so no per-thread DRBG and no
thread-exit handler is created on the child context and no thread has to call
`OPENSSL_thread_stop_ex()` for it. The instance is uninstantiated and freed in
provider teardown before the child context. Cross-thread teardown tests in
both harnesses keep workers alive across provider and host-context teardown;
under Valgrind a provider with child-context thread state fails them with an
invalid read at worker exit.

## Build boundary

The top-level release profile MUST keep Ed301 overflow checks enabled,
`crypto-bigint` overflow checks disabled, `panic=unwind`, optimization level
3, one codegen unit, and debug assertions disabled. Cargo profiles are not
transitive. Every consuming product MUST repeat the override and inspect its
own final binary.

Open work: exact-revision full-source security review, multi-architecture
timing and cache tests, fault injection, and a decision on stricter non-`Copy`
secret arithmetic. Production keys MUST NOT be used before those gates close.
