//! X301 raw Diffie-Hellman primitive over the ED301 field core.
//!
//! The construction follows the Montgomery ladder of RFC 7748 sections 4-6,
//! translated by the X301 draft decisions D1-D4: the ED301 birational
//! Montgomery form, strict canonical 38-byte decoding, cofactor-four scalar
//! clamping, and mandatory all-zero rejection.  This module contains no KDF,
//! RNG, key reuse, peer point validation, or independent field arithmetic.

use crypto_bigint::Choice;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    edwards::{EdwardsPoint, X301PreparedComb},
    field_5x64::Fe301,
    parameters::{FIELD_BITS, FIELD_BYTES},
    scalar::Scalar,
    secret::{Secret, secret},
    secret_taint::declassify,
};

/// Exact byte length of an X301 scalar, public key, and raw shared secret.
///
/// Source: RFC 7748 section 5's fixed-width little-endian interface, with the
/// width translated to the 301-bit ED301 field by X301 decision D2.
pub const X301_BYTES: usize = FIELD_BYTES;

/// Exact byte length of a raw X301 private scalar input.
///
/// Source: RFC 7748 section 5's fixed-width scalar interface, translated to
/// the 301-bit ED301 field by X301 decision D3.
pub const SECRET_BYTES: usize = X301_BYTES;

/// Exact byte length of a canonical X301 public coordinate.
///
/// Source: RFC 7748 section 5 and the strict X301 decision D2 encoding.
pub const PUBLIC_BYTES: usize = X301_BYTES;

/// Exact byte length of a raw X301 shared secret.
///
/// Source: RFC 7748 section 6; the result is one fixed-width `u` coordinate.
pub const SHARED_BYTES: usize = X301_BYTES;

/// Canonical little-endian Montgomery `u` coordinate of the ED301 base point.
///
/// Source: the D1 birational map from the frozen ED301 base point and the
/// RFC 7748 section 5 basepoint-multiplication pattern.
pub const BASE_U_BYTES: [u8; X301_BYTES] = [
    0x5b, 0xa6, 0xf0, 0xf4, 0xcc, 0xc6, 0xff, 0x5f, 0x01, 0x8a, 0x24, 0x96, 0xfe, 0x16, 0x5e, 0xb7,
    0xd1, 0x89, 0x39, 0x49, 0xfe, 0x3d, 0x05, 0xf7, 0x9c, 0x12, 0xd2, 0xbd, 0x99, 0x95, 0x2c, 0xd4,
    0x2d, 0x2a, 0xe9, 0x54, 0x63, 0x08,
];

// `(A - 2) / 4` for the D1 Montgomery form.  This is the RFC 7748 section 5
// `a24` convention used by `z2 = E * (AA + a24 * E)`.
const A24_MINUS: Fe301 = Fe301::from_canonical_words([
    0x09f4_8544_0646_b74c,
    0x15ed_71ca_8cd4_4f2f,
    0x3a5e_a817_22d2_2255,
    0x137b_ab9f_5cdc_1fc8,
    0x0000_0aa0_2936_2ba3,
]);

/// Failure from the strict X301 byte contract.
///
/// Source: RFC 7748 sections 5-6, narrowed by X301 decisions D2 and D4.  The
/// enum deliberately has no secret-value rejection variant: every 38-byte
/// scalar is accepted and clamped exactly once under D3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X301Error {
    /// The scalar is not exactly 38 bytes.
    InvalidSecretLength,
    /// The encoded peer coordinate is not exactly 38 bytes.
    InvalidPublicLength,
    /// The coordinate is not the unique 38-byte encoding of a value below `p`.
    NonCanonicalPublic,
    /// The completed ladder produced the all-zero shared secret.
    AllZeroSharedSecret,
}

/// Zeroizing owner of one raw X301 shared secret.
///
/// Source: RFC 7748 section 6 defines the raw coordinate; the ownership and
/// no-implicit-KDF boundary follows the OpenSSL provider derive contract. The
/// value is deliberately neither `Copy` nor `Clone` and is erased on drop.
pub struct SharedSecret(Secret<[u8; SHARED_BYTES]>);

/// Public peer state prepared for repeated X301 derivation.
///
/// Main-curve peers use a constant-time fixed-base comb.  Twist and
/// exceptional Montgomery coordinates retain the RFC-7748 ladder.  The
/// choice depends only on the public peer encoding and changes neither the
/// accepted input set nor the shared-secret byte contract.
#[derive(Clone)]
pub struct PreparedX301Peer {
    inner: PreparedPeerInner,
}

#[derive(Clone)]
// The public table is the payload being cached. Indirection would add an
// allocator requirement to the no_std core without reducing that payload.
#[allow(clippy::large_enum_variant)]
enum PreparedPeerInner {
    MainCurve(X301PreparedComb),
    Montgomery(Fe301),
}

impl Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SharedSecret {}

impl SharedSecret {
    /// Borrow the exact raw bytes for immediate protocol or provider use.
    ///
    /// Source: RFC 7748 section 6. The caller must preserve secret ownership
    /// when copying these bytes and must not treat them as a public artifact.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARED_BYTES] {
        &self.0
    }
}

/// Apply the strict raw X301 function.
///
/// This is the RFC 7748 section 5 ladder with the D1 X301 parameters. `secret`
/// is clamped according to D3. `u_bytes` is decoded strictly according to D2;
/// unlike X25519, the three unused high bits are not masked and values at or
/// above `p` are rejected.  Every canonical input runs all 301 rounds.  D4
/// then rejects an all-zero result as required for TLS key exchange by RFC
/// 9846 section 7.4.2.
pub fn x301(secret_bytes: &[u8], u_bytes: &[u8]) -> Result<SharedSecret, X301Error> {
    let secret_bytes: &[u8; X301_BYTES] = secret_bytes
        .try_into()
        .map_err(|_| X301Error::InvalidSecretLength)?;
    let u = decode_public(u_bytes)?;
    let scalar = clamp_scalar(secret_bytes);
    let projective = ladder(&scalar, u);
    finalize(projective)
}

/// Derive the canonical X301 public key for one raw 38-byte scalar.
///
/// Source: the RFC 7748 section 6 Diffie-Hellman construction, using the D1
/// X301 base coordinate and D3 scalar clamping.
pub fn public_from_secret(secret: &[u8]) -> Result<[u8; X301_BYTES], X301Error> {
    let secret: &[u8; X301_BYTES] = secret
        .try_into()
        .map_err(|_| X301Error::InvalidSecretLength)?;
    let clamped = clamp_scalar(secret);
    let reduced = Scalar::reduce_pruned_le(&clamped);

    // Let L be the odd prime subgroup order. A clamped k is in
    // [2^300, 2^301) and k = 0 (mod 4). The only multiples of L in this
    // interval are 2L and 3L; because L = 3 (mod 4), their residues are 2
    // and 1. Also 4L >= 2^301. Hence no clamped k is 0 modulo L.
    #[cfg(debug_assertions)]
    debug_assert!(!reduced.is_zero().to_bool());

    EdwardsPoint::scalar_mul_base(&reduced)
        .montgomery_u_public_artifact()
        .map_err(|_| X301Error::AllZeroSharedSecret)
}

/// Derive a raw X301 shared secret from a scalar and peer public key.
///
/// Source: RFC 7748 section 6 and RFC 9846 section 7.4.2.  The returned raw
/// coordinate has no internal KDF; D4 rejects all zero before it is returned.
pub fn shared_secret(secret: &[u8], peer_public: &[u8]) -> Result<SharedSecret, X301Error> {
    x301(secret, peer_public)
}

/// Prepare one public peer for repeated constant-time X301 derivation.
///
/// Preparation is allowed to depend on the public coordinate.  Main-curve
/// points are mapped to the birationally equivalent Edwards form and receive
/// a fixed-base comb table; twist and exceptional inputs retain the ladder.
pub fn prepare_peer(peer_public: &[u8]) -> Result<PreparedX301Peer, X301Error> {
    let u = decode_public(peer_public)?;
    let inner = edwards_from_montgomery_u(u).map_or(PreparedPeerInner::Montgomery(u), |point| {
        PreparedPeerInner::MainCurve(point.prepare_x301_comb())
    });
    Ok(PreparedX301Peer { inner })
}

/// Derive a shared secret from a previously prepared public peer.
///
/// The scalar schedule and all table accesses remain constant-time.  The
/// public main-curve/twist classification performed by [`prepare_peer`] is
/// the only path distinction.
pub fn shared_secret_prepared(
    secret_bytes: &[u8],
    peer: &PreparedX301Peer,
) -> Result<SharedSecret, X301Error> {
    let secret_bytes: &[u8; X301_BYTES] = secret_bytes
        .try_into()
        .map_err(|_| X301Error::InvalidSecretLength)?;
    let scalar = clamp_scalar(secret_bytes);
    match &peer.inner {
        PreparedPeerInner::MainCurve(table) => {
            let point = secret(EdwardsPoint::scalar_mul_x301_comb(&scalar, table));
            let (x, z) = point.montgomery_projective();
            finalize(secret(ProjectiveOutput { x, z }))
        }
        PreparedPeerInner::Montgomery(u) => finalize(ladder(&scalar, *u)),
    }
}

/// Validate only the strict canonical encoding of an X301 public coordinate.
///
/// Source: RFC 7748 section 5's little-endian field encoding, intentionally
/// narrowed by D2.  Main-curve and twist coordinates are both accepted here;
/// D4 low-order rejection occurs only after the complete ladder.
pub fn validate_public_encoding(public: &[u8]) -> Result<(), X301Error> {
    decode_public(public).map(|_| ())
}

fn decode_public(public: &[u8]) -> Result<Fe301, X301Error> {
    let bytes: &[u8; X301_BYTES] = public
        .try_into()
        .map_err(|_| X301Error::InvalidPublicLength)?;
    Fe301::from_canonical_bytes(bytes)
        .into_option_copied()
        .ok_or(X301Error::NonCanonicalPublic)
}

fn edwards_from_montgomery_u(u: Fe301) -> Option<EdwardsPoint> {
    // D1 inverse map: y = (u - 1) / (u + 1).  The sign of x is irrelevant
    // because P and -P produce the same Montgomery u after scalar multiply.
    let denominator = u.add(Fe301::ONE);
    let inverse = denominator.invert();
    let mut present = inverse.is_some();
    declassify(&mut present);
    if !present.to_bool() {
        return None;
    }
    let y = u.sub(Fe301::ONE).mul(inverse.to_inner_unchecked());
    let encoded = y.to_canonical_bytes();
    EdwardsPoint::decode(&encoded).ok()
}

fn clamp_scalar(input: &[u8; X301_BYTES]) -> Secret<[u8; X301_BYTES]> {
    let mut scalar = secret(*input);
    scalar[0] &= 0xfc;
    scalar[X301_BYTES - 1] = (scalar[X301_BYTES - 1] & 0x0f) | 0x10;
    scalar
}

struct LadderState {
    x1: Fe301,
    x2: Fe301,
    z2: Fe301,
    x3: Fe301,
    z3: Fe301,
}

impl LadderState {
    fn new(u: Fe301) -> Self {
        Self {
            x1: u,
            x2: Fe301::ONE,
            z2: Fe301::ZERO,
            x3: u,
            z3: Fe301::ONE,
        }
    }

    #[inline(always)]
    fn conditional_swap(&mut self, choice: Choice) {
        Fe301::conditional_swap(&mut self.x2, &mut self.x3, choice);
        Fe301::conditional_swap(&mut self.z2, &mut self.z3, choice);
    }
}

impl Zeroize for LadderState {
    fn zeroize(&mut self) {
        self.x1.zeroize();
        self.x2.zeroize();
        self.z2.zeroize();
        self.x3.zeroize();
        self.z3.zeroize();
    }
}

struct ProjectiveOutput {
    x: Fe301,
    z: Fe301,
}

impl Zeroize for ProjectiveOutput {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.z.zeroize();
    }
}

#[inline(never)]
fn ladder(scalar: &[u8; X301_BYTES], u: Fe301) -> Secret<ProjectiveOutput> {
    let mut state = secret(LadderState::new(u));
    let mut swap = Choice::FALSE;

    for bit_index in (0..FIELD_BITS).rev() {
        let bit = Choice::from_u8_lsb(scalar[bit_index >> 3] >> (bit_index & 7));
        state.conditional_swap(swap.xor(bit));
        swap = bit;

        let a = state.x2.add(state.z2);
        let aa = a.square();
        let b = state.x2.sub(state.z2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = state.x3.add(state.z3);
        let d = state.x3.sub(state.z3);
        let da = d.mul(a);
        let cb = c.mul(b);

        state.x3 = da.add(cb).square();
        state.z3 = state.x1.mul(da.sub(cb).square());
        state.x2 = aa.mul(bb);
        state.z2 = e.mul(aa.add(A24_MINUS.mul(e)));
    }

    state.conditional_swap(swap);
    secret(ProjectiveOutput {
        x: state.x2,
        z: state.z2,
    })
}

fn finalize(projective: Secret<ProjectiveOutput>) -> Result<SharedSecret, X301Error> {
    let mut accepted = projective.z.is_zero().not();
    let inverse = secret(projective.z.invert().to_inner_unchecked());
    let affine = secret(projective.x.mul(*inverse));
    accepted = accepted.and(affine.is_zero().not());
    let output = secret(affine.to_canonical_bytes());

    // RFC 7748 allows the all-zero check; RFC 9846 requires TLS to abort.
    // Expose the result predicate only after the full ladder and finalization.
    declassify(&mut accepted);
    if !accepted.to_bool() {
        return Err(X301Error::AllZeroSharedSecret);
    }

    // The raw result remains secret-tainted and inside its zeroizing owner.
    // `public_from_secret` alone copies and declassifies a public artifact.
    Ok(SharedSecret(output))
}

#[cfg(test)]
pub(crate) fn clamped_scalar_for_test(input: &[u8; X301_BYTES]) -> [u8; X301_BYTES] {
    *clamp_scalar(input)
}

#[cfg(test)]
pub(crate) fn montgomery_a_for_test() -> Fe301 {
    A24_MINUS.mul_small(4).add(Fe301::from_u64(2))
}

#[cfg(test)]
pub(crate) fn public_from_secret_ladder_for_test(
    secret: &[u8],
) -> Result<[u8; X301_BYTES], X301Error> {
    let output = x301(secret, &BASE_U_BYTES)?;
    let mut public = *output.as_bytes();
    declassify(&mut public);
    Ok(public)
}

#[cfg(test)]
mod ownership_tests {
    use super::*;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn every_named_x301_secret_owner_zeroizes_on_drop() {
        assert_zeroize_on_drop::<Secret<[u8; SECRET_BYTES]>>();
        assert_zeroize_on_drop::<Secret<LadderState>>();
        assert_zeroize_on_drop::<Secret<ProjectiveOutput>>();
        assert_zeroize_on_drop::<SharedSecret>();
        assert!(core::mem::needs_drop::<Secret<LadderState>>());
        assert!(core::mem::needs_drop::<Secret<ProjectiveOutput>>());
        assert!(core::mem::needs_drop::<SharedSecret>());
    }
}
