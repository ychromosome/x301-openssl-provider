//! Rust implementation candidate for `Ed301-EdDSA-draft-00`, with an optional
//! additive X301 key-exchange core following the RFC 7748 ladder pattern.
//!
//! Feature `signature` implements the context-free, one-shot Ed301 byte
//! contract. Feature `x301` supplies the separate key-exchange core. Neither
//! feature permits Ed301/X301 key reuse.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(not(panic = "unwind"))]
compile_error!("ed301-eddsa requires panic=unwind so named secret owners are dropped");

mod edwards;
mod field;
mod field_5x64;
pub mod parameters;
#[cfg(feature = "signature")]
mod scalar;
mod secret;
mod secret_taint;
#[cfg(feature = "signature")]
pub mod signature;
#[cfg(feature = "signature")]
mod signature_hash;
#[cfg(test)]
mod test_support;
#[cfg(feature = "x301")]
pub mod x301;

#[cfg(feature = "signature")]
pub use signature::{
    ExpandedSigningKey, Signature, SignatureError, SigningKey, VerifyingKey, sign,
    validate_public_key, verify,
};

#[cfg(all(test, feature = "signature"))]
mod vector_tests;
#[cfg(all(test, feature = "x301"))]
mod x301_tests;
