//! Loadable OpenSSL provider adapter for experimental X301 operations.
//!
//! The base module exposes raw key management and key exchange. The optional
//! `tls-x301-mlkem1024` artifact adds only the `KEYMGMT` and `KEM` substrate
//! that stock OpenSSL requires for a provider-defined TLS KEM group. Although
//! those operations are unavoidably EVP-fetchable, they are not a supported
//! standalone hybrid-KEM profile. The module exposes no signature, persistent
//! key format, combiner KDF, or raw-X301 TLS group.
//!
//! Sources: OpenSSL provider(7), provider-keymgmt(7), provider-keyexch(7),
//! provider-kem(7), provider-base(7) TLS-GROUP, RFC 9846, RFC 9954, RFC
//! 10024, FIPS 203, and RFC 7748.

#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(panic = "unwind"))]
compile_error!("the X301 OpenSSL provider requires panic=unwind at its FFI boundary");

use core::ffi::{c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

mod x301_ffi;

unsafe extern "C" {
    fn x301_shim_init(
        handle: *const c_void,
        input_dispatch: *const c_void,
        output_dispatch: *mut *const c_void,
        provider_context: *mut *mut c_void,
        rust_api: *const c_void,
    ) -> c_int;
}

/// OpenSSL provider entry point.
///
/// # Safety
///
/// All pointers must satisfy OpenSSL's `OSSL_provider_init` contract. Rust
/// panics are caught before they can cross the C ABI boundary.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn OSSL_provider_init(
    handle: *const c_void,
    input_dispatch: *const c_void,
    output_dispatch: *mut *const c_void,
    provider_context: *mut *mut c_void,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || input_dispatch.is_null()
            || output_dispatch.is_null()
            || provider_context.is_null()
        {
            return 0;
        }

        // SAFETY: Null pointers were rejected above. OpenSSL owns the core
        // objects; the C shim validates the complete callback-table contract.
        unsafe {
            x301_shim_init(
                handle,
                input_dispatch,
                output_dispatch,
                provider_context,
                (&raw const x301_ffi::RUST_API).cast(),
            )
        }
    }))
    .unwrap_or(0)
}
