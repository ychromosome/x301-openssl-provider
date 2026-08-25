//! Rust-owned X301 provider keys and exchange contexts.
//!
//! Sources: the `ed301_eddsa::x301` RFC-7748-pattern byte contract and the
//! OpenSSL provider-keymgmt(7), provider-keyexch(7), and RAND contracts. Key
//! generation performs exactly one provider-supplied random fill.

use core::ffi::{c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};

use crypto_bigint::CtEq;
use ed301_eddsa::x301::{
    PUBLIC_BYTES, SECRET_BYTES, SHARED_BYTES, public_from_secret, shared_secret,
    validate_public_encoding,
};
use zeroize::Zeroize;

/// Function table consumed by the C provider shim.
#[repr(C)]
pub(crate) struct X301RustApi {
    abi_version: u32,
    struct_size: usize,
    secret_bytes: usize,
    public_bytes: usize,
    shared_bytes: usize,
    key_new: extern "C" fn() -> *mut c_void,
    key_free: unsafe extern "C" fn(*mut c_void),
    key_import: unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize) -> c_int,
    key_set_encoded_public: unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int,
    key_generate: unsafe extern "C" fn(
        Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int>,
        *mut c_void,
    ) -> *mut c_void,
    key_duplicate: unsafe extern "C" fn(*const c_void, c_int, c_int) -> *mut c_void,
    key_has: unsafe extern "C" fn(*const c_void, c_int, c_int) -> c_int,
    key_validate: unsafe extern "C" fn(*const c_void, c_int, c_int) -> c_int,
    key_match: unsafe extern "C" fn(*const c_void, *const c_void, c_int, c_int) -> c_int,
    key_get_private: unsafe extern "C" fn(*const c_void, *mut u8, usize) -> c_int,
    key_get_public: unsafe extern "C" fn(*const c_void, *mut u8, usize) -> c_int,
    exchange_new: extern "C" fn() -> *mut c_void,
    exchange_free: unsafe extern "C" fn(*mut c_void),
    exchange_duplicate: unsafe extern "C" fn(*const c_void) -> *mut c_void,
    exchange_init: unsafe extern "C" fn(*mut c_void, *const c_void) -> c_int,
    exchange_set_peer: unsafe extern "C" fn(*mut c_void, *const c_void) -> c_int,
    exchange_derive: unsafe extern "C" fn(*const c_void, *mut u8, usize) -> c_int,
    cleanse: unsafe extern "C" fn(*mut u8, usize),
}

pub(crate) static RUST_API: X301RustApi = X301RustApi {
    abi_version: 1,
    struct_size: core::mem::size_of::<X301RustApi>(),
    secret_bytes: SECRET_BYTES,
    public_bytes: PUBLIC_BYTES,
    shared_bytes: SHARED_BYTES,
    key_new,
    key_free,
    key_import,
    key_set_encoded_public,
    key_generate,
    key_duplicate,
    key_has,
    key_validate,
    key_match,
    key_get_private,
    key_get_public,
    exchange_new,
    exchange_free,
    exchange_duplicate,
    exchange_init,
    exchange_set_peer,
    exchange_derive,
    cleanse,
};

struct SecretBytes([u8; SECRET_BYTES]);

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Zeroize for SecretBytes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Default)]
struct X301Key {
    private: Option<SecretBytes>,
    public: Option<[u8; PUBLIC_BYTES]>,
}

#[derive(Clone, Default)]
struct X301Exchange {
    private: Option<SecretBytes>,
    peer_public: Option<[u8; PUBLIC_BYTES]>,
}

#[cfg(feature = "test-failpoint")]
fn hit_panic_failpoint(name: &str) {
    match std::env::var("X301_PROVIDER_PANIC_FAILPOINT") {
        Ok(value) if value == name => panic!("injected X301 provider panic in {name}"),
        _ => {}
    }
}

#[cfg(not(feature = "test-failpoint"))]
#[inline(always)]
fn hit_panic_failpoint(_name: &str) {}

#[cfg(feature = "test-failpoint")]
fn hit_alloc_failpoint(name: &str) -> bool {
    matches!(
        std::env::var("X301_PROVIDER_ALLOC_FAILPOINT"),
        Ok(value) if value == name
    )
}

#[cfg(not(feature = "test-failpoint"))]
#[inline(always)]
fn hit_alloc_failpoint(_name: &str) -> bool {
    false
}

fn try_box<T>(value: T) -> Option<Box<T>> {
    let layout = std::alloc::Layout::new::<T>();
    if layout.size() == 0 {
        let pointer = core::ptr::NonNull::<T>::dangling().as_ptr();
        // SAFETY: An aligned dangling pointer is valid storage for a ZST.
        unsafe { core::ptr::write(pointer, value) };
        // SAFETY: `Box` accepts an aligned dangling pointer for a ZST.
        return Some(unsafe { Box::from_raw(pointer) });
    }
    // SAFETY: `layout` is the exact, non-zero layout of `T`.
    let pointer = unsafe { std::alloc::alloc(layout) }.cast::<T>();
    if pointer.is_null() {
        drop(value);
        return None;
    }
    // SAFETY: The fresh allocation is aligned, writable, and uniquely owned.
    unsafe { core::ptr::write(pointer, value) };
    // SAFETY: `pointer` now contains one initialized `T` with Box's layout.
    Some(unsafe { Box::from_raw(pointer) })
}

fn try_box_at<T>(site: &str, value: T) -> Option<Box<T>> {
    if hit_alloc_failpoint(site) {
        drop(value);
        return None;
    }
    try_box(value)
}

fn ffi_int(operation: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(0)
}

fn ffi_pointer(operation: impl FnOnce() -> *mut c_void) -> *mut c_void {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(core::ptr::null_mut())
}

extern "C" fn key_new() -> *mut c_void {
    ffi_pointer(|| {
        hit_panic_failpoint("key_new");
        try_box_at("key_new", X301Key::default())
            .map_or(core::ptr::null_mut(), |key| Box::into_raw(key).cast())
    })
}

unsafe extern "C" fn key_free(key: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !key.is_null() {
            // SAFETY: Each pointer returned by this module is freed once.
            drop(unsafe { Box::from_raw(key.cast::<X301Key>()) });
        }
    }));
}

unsafe extern "C" fn key_import(
    key: *mut c_void,
    private: *const u8,
    private_len: usize,
    public: *const u8,
    public_len: usize,
) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("key_import");
        // SAFETY: C passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<X301Key>().as_mut() }) else {
            return 0;
        };
        // SAFETY: Present C buffers remain readable for this call.
        let Some(raw_private) = (unsafe { read_optional_secret(private, private_len) }) else {
            return 0;
        };
        // SAFETY: Same contract as the private input.
        let Some(raw_public) = (unsafe { read_optional_exact(public, public_len) }) else {
            return 0;
        };
        if raw_private.is_none() && raw_public.is_none() {
            return 0;
        }

        let derived_public = match raw_private.as_ref() {
            Some(secret) => match public_from_secret(&secret.0) {
                Ok(value) => Some(value),
                Err(_) => return 0,
            },
            None => None,
        };
        if let Some(public) = raw_public.as_ref() {
            if validate_public_encoding(public).is_err() {
                return 0;
            }
            if let Some(derived) = derived_public.as_ref()
                && !bytes_equal(derived, public)
            {
                return 0;
            }
        }

        let replacement = X301Key {
            private: raw_private,
            public: derived_public.or(raw_public),
        };
        *key = replacement;
        1
    })
}

unsafe extern "C" fn key_set_encoded_public(
    key: *mut c_void,
    public: *const u8,
    public_len: usize,
) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("key_set_encoded_public");
        // SAFETY: C passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<X301Key>().as_mut() }) else {
            return 0;
        };
        // SAFETY: The C buffer remains readable for this call.
        let Some(Some(public)) = (unsafe { read_optional_exact(public, public_len) }) else {
            return 0;
        };
        if validate_public_encoding(&public).is_err() {
            return 0;
        }
        if let Some(existing) = key.public.as_ref()
            && !bytes_equal(existing, &public)
        {
            return 0;
        }
        key.public = Some(public);
        1
    })
}

unsafe extern "C" fn key_generate(
    fill_random: Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int>,
    callback_context: *mut c_void,
) -> *mut c_void {
    ffi_pointer(|| {
        hit_panic_failpoint("key_generate");
        let Some(fill_random) = fill_random else {
            return core::ptr::null_mut();
        };
        let mut secret = SecretBytes([0_u8; SECRET_BYTES]);
        // SAFETY: The caller supplied the callback. `secret` is a live,
        // writable, Rust-owned zeroizing buffer for this single call and is
        // exactly `SECRET_BYTES` bytes long.
        if unsafe { fill_random(callback_context, secret.0.as_mut_ptr(), SECRET_BYTES) } != 1 {
            return core::ptr::null_mut();
        }
        let Ok(public) = public_from_secret(&secret.0) else {
            return core::ptr::null_mut();
        };
        let key = X301Key {
            private: Some(secret),
            public: Some(public),
        };
        try_box_at("key_generate", key)
            .map_or(core::ptr::null_mut(), |key| Box::into_raw(key).cast())
    })
}

unsafe extern "C" fn key_duplicate(
    source: *const c_void,
    include_private: c_int,
    include_public: c_int,
) -> *mut c_void {
    ffi_pointer(|| {
        hit_panic_failpoint("key_duplicate");
        // SAFETY: C passes a live Rust-owned key object.
        let Some(source) = (unsafe { source.cast::<X301Key>().as_ref() }) else {
            return core::ptr::null_mut();
        };
        let private = (include_private != 0)
            .then(|| source.private.clone())
            .flatten();
        let public = (include_public != 0).then_some(source.public).flatten();
        try_box_at("key_duplicate", X301Key { private, public })
            .map_or(core::ptr::null_mut(), |key| Box::into_raw(key).cast())
    })
}

unsafe extern "C" fn key_has(
    key: *const c_void,
    require_private: c_int,
    require_public: c_int,
) -> c_int {
    ffi_int(|| {
        // SAFETY: C passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<X301Key>().as_ref() }) else {
            return 0;
        };
        i32::from(
            (require_private == 0 || key.private.is_some())
                && (require_public == 0 || key.public.is_some()),
        )
    })
}

unsafe extern "C" fn key_validate(
    key: *const c_void,
    validate_private: c_int,
    validate_public: c_int,
) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("key_validate");
        // SAFETY: C passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<X301Key>().as_ref() }) else {
            return 0;
        };
        let derived = if validate_private != 0 {
            let Some(private) = key.private.as_ref() else {
                return 0;
            };
            match public_from_secret(&private.0) {
                Ok(value) => Some(value),
                Err(_) => return 0,
            }
        } else {
            None
        };
        if validate_public != 0 {
            let Some(public) = key.public.as_ref() else {
                return 0;
            };
            if validate_public_encoding(public).is_err() {
                return 0;
            }
            if let Some(derived) = derived.as_ref()
                && !bytes_equal(derived, public)
            {
                return 0;
            }
        }
        1
    })
}

unsafe extern "C" fn key_match(
    first: *const c_void,
    second: *const c_void,
    match_private: c_int,
    match_public: c_int,
) -> c_int {
    ffi_int(|| {
        // SAFETY: C passes two live Rust-owned key objects.
        let (Some(first), Some(second)) = (unsafe { first.cast::<X301Key>().as_ref() }, unsafe {
            second.cast::<X301Key>().as_ref()
        }) else {
            return 0;
        };
        if match_private != 0 {
            let (Some(first), Some(second)) = (first.private.as_ref(), second.private.as_ref())
            else {
                return 0;
            };
            if !bytes_equal(&first.0, &second.0) {
                return 0;
            }
        }
        if match_public != 0 {
            let (Some(first), Some(second)) = (first.public.as_ref(), second.public.as_ref())
            else {
                return 0;
            };
            if !bytes_equal(first, second) {
                return 0;
            }
        }
        1
    })
}

unsafe extern "C" fn key_get_private(
    key: *const c_void,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    ffi_int(|| {
        // SAFETY: C passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<X301Key>().as_ref() }) else {
            return 0;
        };
        let Some(private) = key.private.as_ref() else {
            return 0;
        };
        // SAFETY: C supplies `output_len` writable bytes.
        i32::from(unsafe { write_exact(output, output_len, &private.0) })
    })
}

unsafe extern "C" fn key_get_public(
    key: *const c_void,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    ffi_int(|| {
        // SAFETY: C passes a live Rust-owned key object.
        let Some(key) = (unsafe { key.cast::<X301Key>().as_ref() }) else {
            return 0;
        };
        let Some(public) = key.public.as_ref() else {
            return 0;
        };
        // SAFETY: C supplies `output_len` writable bytes.
        i32::from(unsafe { write_exact(output, output_len, public) })
    })
}

extern "C" fn exchange_new() -> *mut c_void {
    ffi_pointer(|| {
        hit_panic_failpoint("exchange_new");
        try_box_at("exchange_new", X301Exchange::default())
            .map_or(core::ptr::null_mut(), |value| Box::into_raw(value).cast())
    })
}

unsafe extern "C" fn exchange_free(exchange: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !exchange.is_null() {
            // SAFETY: Each pointer returned by this module is freed once.
            drop(unsafe { Box::from_raw(exchange.cast::<X301Exchange>()) });
        }
    }));
}

unsafe extern "C" fn exchange_duplicate(source: *const c_void) -> *mut c_void {
    ffi_pointer(|| {
        hit_panic_failpoint("exchange_duplicate");
        // SAFETY: C passes a live Rust-owned exchange object.
        let Some(source) = (unsafe { source.cast::<X301Exchange>().as_ref() }) else {
            return core::ptr::null_mut();
        };
        try_box_at("exchange_duplicate", source.clone())
            .map_or(core::ptr::null_mut(), |value| Box::into_raw(value).cast())
    })
}

unsafe extern "C" fn exchange_init(exchange: *mut c_void, key: *const c_void) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("exchange_init");
        // SAFETY: C passes live Rust-owned exchange and key objects.
        let (Some(exchange), Some(key)) = (
            unsafe { exchange.cast::<X301Exchange>().as_mut() },
            unsafe { key.cast::<X301Key>().as_ref() },
        ) else {
            return 0;
        };
        let Some(private) = key.private.clone() else {
            return 0;
        };
        *exchange = X301Exchange {
            private: Some(private),
            peer_public: None,
        };
        1
    })
}

unsafe extern "C" fn exchange_set_peer(exchange: *mut c_void, peer: *const c_void) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("exchange_set_peer");
        // SAFETY: C passes live Rust-owned exchange and key objects.
        let (Some(exchange), Some(peer)) = (
            unsafe { exchange.cast::<X301Exchange>().as_mut() },
            unsafe { peer.cast::<X301Key>().as_ref() },
        ) else {
            return 0;
        };
        if exchange.private.is_none() {
            return 0;
        }
        let Some(public) = peer.public else {
            return 0;
        };
        if validate_public_encoding(&public).is_err() {
            return 0;
        }
        exchange.peer_public = Some(public);
        1
    })
}

unsafe extern "C" fn exchange_derive(
    exchange: *const c_void,
    output: *mut u8,
    output_len: usize,
) -> c_int {
    ffi_int(|| {
        hit_panic_failpoint("exchange_derive");
        // SAFETY: C passes a live Rust-owned exchange object.
        let Some(exchange) = (unsafe { exchange.cast::<X301Exchange>().as_ref() }) else {
            return 0;
        };
        let (Some(private), Some(peer_public)) =
            (exchange.private.as_ref(), exchange.peer_public.as_ref())
        else {
            return 0;
        };
        let Ok(shared) = shared_secret(&private.0, peer_public) else {
            return 0;
        };
        // SAFETY: C supplies `output_len` writable bytes.
        i32::from(unsafe { write_exact(output, output_len, shared.as_bytes()) })
    })
}

unsafe extern "C" fn cleanse(buffer: *mut u8, length: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if length != 0 && !buffer.is_null() {
            // SAFETY: C owns this writable temporary buffer.
            unsafe { core::slice::from_raw_parts_mut(buffer, length) }.zeroize();
        }
    }));
}

fn bytes_equal<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    left.ct_eq(right).to_bool()
}

unsafe fn read_optional_exact(
    input: *const u8,
    input_len: usize,
) -> Option<Option<[u8; PUBLIC_BYTES]>> {
    if input.is_null() && input_len == 0 {
        return Some(None);
    }
    if input.is_null() || input_len != PUBLIC_BYTES {
        return None;
    }
    let mut output = [0_u8; PUBLIC_BYTES];
    // SAFETY: The caller guarantees `input_len` readable bytes.
    unsafe { core::ptr::copy_nonoverlapping(input, output.as_mut_ptr(), PUBLIC_BYTES) };
    Some(Some(output))
}

unsafe fn read_optional_secret(input: *const u8, input_len: usize) -> Option<Option<SecretBytes>> {
    if input.is_null() && input_len == 0 {
        return Some(None);
    }
    if input.is_null() || input_len != SECRET_BYTES {
        return None;
    }
    let mut output = SecretBytes([0_u8; SECRET_BYTES]);
    // SAFETY: The caller guarantees `input_len` readable bytes. The first
    // Rust-owned copy is already protected by `SecretBytes::drop`.
    unsafe { core::ptr::copy_nonoverlapping(input, output.0.as_mut_ptr(), SECRET_BYTES) };
    Some(Some(output))
}

unsafe fn write_exact<const N: usize>(output: *mut u8, output_len: usize, value: &[u8; N]) -> bool {
    if output.is_null() || output_len < N {
        return false;
    }
    // SAFETY: The caller guarantees `output_len` writable bytes.
    unsafe { core::ptr::copy_nonoverlapping(value.as_ptr(), output, N) };
    true
}
