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

The final-binary policy has separate x86-64 and AArch64 rules. Timing receipts
remain machine-specific; cache evidence remains open.

## Provider FFI and ownership

Raw X301 keys and exchange contexts own separate zeroizing private-scalar
copies. Public-only keys contain no private scalar. Duplication clones these
owners; exchange reinitialization replaces the private copy and clears the peer.

Hybrid keys own an X301 key and an OpenSSL `EVP_PKEY` for ML-KEM. Hybrid KEM
contexts borrow that key; OpenSSL MUST keep it alive for the operation.
The provider build disables Ed301 signature features.

## RAND and child contexts

Provider key generation draws 38 octets from one locked provider-owned
`CTR-DRBG`, seeded by `RAND_get0_primary(child)`. The primary uses the child
context's seed source, which reads from the operating system; application
`rand.seed` and `seed_strict` settings are not inherited by the child context.
Instantiation fails if the selected DRBG cannot obtain entropy from that
parent. No child-context thread-local DRBG or thread-exit handler is created.
The instance is freed before the child context. Cross-thread teardown tests
and their Valgrind negative control cover stale thread state.

The hybrid provider disables child-local fallback before fetching ML-KEM.
Without an allowed application-context ML-KEM-1024 implementation, raw X301
remains available but no hybrid TLS group is advertised and hybrid operations
fail. This prevents a child-local default provider from creating ML-KEM RAND
thread state.

## Build boundary

The top-level release profile MUST keep Ed301 overflow checks enabled,
`crypto-bigint` overflow checks disabled, `panic=unwind`, optimization level
3, one codegen unit, and debug assertions disabled. Cargo profiles are not
transitive. Every consuming product MUST repeat the override and inspect its
own final binary.

Open work: exact-revision full-source security review, cache-timing tests,
fault injection, and a decision on stricter non-`Copy` secret arithmetic.
Timing remains machine-bound evidence, not a proof. Production keys MUST NOT
be used before those gates close.
