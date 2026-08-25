//! Rust implementation candidate for `Ed301-EdDSA-draft-00`, with an optional
//! additive X301 key-exchange core following the RFC 7748 ladder pattern.
//!
//! The default build implements only the context-free, one-shot Ed301 byte
//! contract bound by the Round-4 source manifest. The `x301` feature does not
//! alter that contract or permit Ed301/X301 key reuse. This remains review
//! software, not a production or standards-conformance claim.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(not(panic = "unwind"))]
compile_error!("ed301-eddsa requires panic=unwind so named secret owners are dropped");

mod edwards;
mod field;
mod field_5x64;
pub mod parameters;
mod scalar;
mod secret;
mod secret_taint;
pub mod signature;
mod signature_hash;
#[cfg(test)]
mod test_support;
#[cfg(feature = "x301")]
pub mod x301;

pub use signature::{
    ExpandedSigningKey, Signature, SignatureError, SigningKey, VerifyingKey, sign,
    validate_public_key, verify,
};

#[cfg(test)]
mod vector_tests;
#[cfg(all(test, feature = "x301"))]
mod x301_tests;
