#!/usr/bin/env python3
"""Independent, variable-time X301 mathematics and vector generator.

Sources: RFC 7748 Sections 4-6 for the Montgomery/XDH pattern and the
iteration-test construction; the ED301-v1 parameters stated in
``inputs/round4/ED301-EdDSA-draft.md``; the curve-evidence paths recorded in
``docs/X301_DRAFT.md`` Section 8; and the algebraic Edwards/Montgomery change
of variables in Sections 3-5 of that draft. Reproducible SHAKE256 test domains
are registered as ``X-TEST`` in ``docs/X301_CONSTRUCTION_REGISTER.md``.

This module deliberately imports no Rust crate, provider output, historical
X301 implementation, or generated vector.  It is test-only and unsuitable for
secret values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional


FIELD_BYTES = 38
FIELD_BITS = 301
P = 2**301 - 2**99 + 947
EDWARDS_A = 2_086_388_329
EDWARDS_D = 301
COFACTOR = 4
Q = int(
    "1018517988167243043134222844204689080525734197342817290458622896758534223469429834039334403"
)
Q_TWIST = int(
    "1018517988167243043134222844204689080525734196323118960177517235683197019236556497968262103"
)
BASEPOINT_ENCODING = bytes.fromhex(
    "6bf73f755a0c80653ce83fcf6d6ff7d7f347b1929224ac67552273419e6cf2c8a88a02d38898"
)


def inverse(value: int) -> int:
    """Return an inverse in F_p, rejecting zero."""

    value %= P
    if value == 0:
        raise ZeroDivisionError("zero has no inverse")
    return pow(value, -1, P)


def legendre(value: int) -> int:
    """Return -1, 0, or 1 for the quadratic character in F_p."""

    symbol = pow(value % P, (P - 1) // 2, P)
    return -1 if symbol == P - 1 else symbol


def sqrt_mod(value: int) -> int:
    """Return one square root in F_p; p is 3 modulo 4."""

    value %= P
    root = pow(value, (P + 1) // 4, P)
    if root * root % P != value:
        raise ValueError("nonsquare")
    return root


# Twisted Edwards: a*x^2 + y^2 = 1 + d*x^2*y^2.
EdwardsPoint = tuple[int, int]
MontgomeryPoint = Optional[tuple[int, int]]
IDENTITY: EdwardsPoint = (0, 1)
ORDER_TWO: EdwardsPoint = (0, P - 1)


def edwards_is_on_curve(point: EdwardsPoint) -> bool:
    x, y = point
    return (
        EDWARDS_A * x * x + y * y - 1 - EDWARDS_D * x * x * y * y
    ) % P == 0


def edwards_neg(point: EdwardsPoint) -> EdwardsPoint:
    x, y = point
    return (-x % P, y)


def edwards_add(left: EdwardsPoint, right: EdwardsPoint) -> EdwardsPoint:
    """Complete affine Edwards addition; variable-time test arithmetic."""

    x1, y1 = left
    x2, y2 = right
    product = EDWARDS_D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + y1 * x2) * inverse(1 + product) % P
    y3 = (y1 * y2 - EDWARDS_A * x1 * x2) * inverse(1 - product) % P
    result = (x3, y3)
    if not edwards_is_on_curve(result):
        raise ArithmeticError("Edwards addition left the curve")
    return result


def edwards_scalar_mul(scalar: int, point: EdwardsPoint) -> EdwardsPoint:
    """Variable-time double-and-add used only by the independent oracle."""

    if scalar < 0:
        return edwards_scalar_mul(-scalar, edwards_neg(point))
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = edwards_add(result, addend)
        addend = edwards_add(addend, addend)
        scalar >>= 1
    return result


def decode_edwards(encoded: bytes) -> EdwardsPoint:
    if len(encoded) != FIELD_BYTES:
        raise ValueError("wrong Edwards length")
    sign = encoded[-1] >> 7
    raw = bytearray(encoded)
    raw[-1] &= 0x7F
    if raw[-1] & 0x60:
        raise ValueError("reserved Edwards bits")
    y = int.from_bytes(raw, "little")
    if y >= P:
        raise ValueError("noncanonical Edwards y")
    y2 = y * y % P
    x2 = (1 - y2) * inverse(EDWARDS_A - EDWARDS_D * y2) % P
    x = sqrt_mod(x2)
    if x & 1 != sign:
        x = -x % P
    if x == 0 and sign:
        raise ValueError("negative zero")
    point = (x, y)
    if not edwards_is_on_curve(point):
        raise ArithmeticError("decoded Edwards point is off curve")
    return point


G = decode_edwards(BASEPOINT_ENCODING)
SQRT_A = 45_677
ORDER_FOUR: EdwardsPoint = (inverse(SQRT_A), 0)


# B*v^2 = u^3 + A*u^2 + u.
MONTGOMERY_A = (
    2 * (EDWARDS_A + EDWARDS_D) * inverse(EDWARDS_A - EDWARDS_D)
) % P
MONTGOMERY_B = 4 * inverse(EDWARDS_A - EDWARDS_D) % P
A24_MINUS = (MONTGOMERY_A - 2) * inverse(4) % P
WEIERSTRASS_A2 = MONTGOMERY_A * MONTGOMERY_B % P
WEIERSTRASS_A4 = MONTGOMERY_B * MONTGOMERY_B % P


def montgomery_is_on_curve(point: MontgomeryPoint) -> bool:
    if point is None:
        return True
    u, v = point
    return (
        MONTGOMERY_B * v * v - (u * u * u + MONTGOMERY_A * u * u + u)
    ) % P == 0


def edwards_to_montgomery(point: EdwardsPoint) -> MontgomeryPoint:
    """Apply the complete birational map, including both exceptional points."""

    if not edwards_is_on_curve(point):
        raise ValueError("off-curve Edwards point")
    if point == IDENTITY:
        return None
    if point == ORDER_TWO:
        return (0, 0)
    x, y = point
    u = (1 + y) * inverse(1 - y) % P
    v = u * inverse(x) % P
    result = (u, v)
    if not montgomery_is_on_curve(result):
        raise ArithmeticError("Edwards-to-Montgomery map left the curve")
    return result


def montgomery_to_edwards(point: MontgomeryPoint) -> EdwardsPoint:
    """Apply the inverse map, including infinity and (0,0)."""

    if not montgomery_is_on_curve(point):
        raise ValueError("off-curve Montgomery point")
    if point is None:
        return IDENTITY
    if point == (0, 0):
        return ORDER_TWO
    u, v = point
    x = u * inverse(v) % P
    y = (u - 1) * inverse(u + 1) % P
    result = (x, y)
    if not edwards_is_on_curve(result):
        raise ArithmeticError("Montgomery-to-Edwards map left the curve")
    return result


def _montgomery_to_weierstrass(point: MontgomeryPoint) -> MontgomeryPoint:
    if point is None:
        return None
    u, v = point
    return (MONTGOMERY_B * u % P, MONTGOMERY_B**2 * v % P)


def _weierstrass_to_montgomery(point: MontgomeryPoint) -> MontgomeryPoint:
    if point is None:
        return None
    x, y = point
    return (x * inverse(MONTGOMERY_B) % P, y * inverse(MONTGOMERY_B**2) % P)


def _weierstrass_add(left: MontgomeryPoint, right: MontgomeryPoint) -> MontgomeryPoint:
    """Independent group law for y^2=x^3+a2*x^2+a4*x."""

    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        slope = (
            (3 * x1 * x1 + 2 * WEIERSTRASS_A2 * x1 + WEIERSTRASS_A4)
            * inverse(2 * y1)
            % P
        )
    else:
        slope = (y2 - y1) * inverse(x2 - x1) % P
    x3 = (slope * slope - WEIERSTRASS_A2 - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return (x3, y3)


def montgomery_add(left: MontgomeryPoint, right: MontgomeryPoint) -> MontgomeryPoint:
    """Montgomery group addition through an independently evaluated model."""

    result = _weierstrass_to_montgomery(
        _weierstrass_add(
            _montgomery_to_weierstrass(left),
            _montgomery_to_weierstrass(right),
        )
    )
    if not montgomery_is_on_curve(result):
        raise ArithmeticError("Montgomery addition left the curve")
    return result


def encode_u(value: int) -> bytes:
    if not 0 <= value < P:
        raise ValueError("u is not canonical")
    return value.to_bytes(FIELD_BYTES, "little")


class X301Error(ValueError):
    """An independently classified X301 input or all-zero failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class EvidenceError(RuntimeError):
    """A deterministic oracle invariant or frozen expectation did not hold."""


def decode_u(encoded: bytes) -> int:
    if not isinstance(encoded, bytes) or len(encoded) != FIELD_BYTES:
        raise X301Error("length")
    if encoded[-1] & 0xE0:
        raise X301Error("reserved_bits")
    value = int.from_bytes(encoded, "little")
    if value >= P:
        raise X301Error("noncanonical")
    return value


def clamp_scalar(secret: bytes) -> int:
    if not isinstance(secret, bytes) or len(secret) != FIELD_BYTES:
        raise X301Error("secret_length")
    clamped = bytearray(secret)
    clamped[0] &= 0xFC
    clamped[-1] = (clamped[-1] & 0x0F) | 0x10
    return int.from_bytes(clamped, "little")


def montgomery_ladder(scalar: int, u: int) -> tuple[int, int]:
    """RFC-7748-shaped, variable-time 301-round Montgomery ladder."""

    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for bit_index in range(FIELD_BITS - 1, -1, -1):
        bit = (scalar >> bit_index) & 1
        if swap ^ bit:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24_MINUS * e) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return x2, z2


def x301(secret: bytes, encoded_u: bytes) -> bytes:
    scalar = clamp_scalar(secret)
    u = decode_u(encoded_u)
    x, z = montgomery_ladder(scalar, u)
    if z == 0:
        raise X301Error("all_zero")
    output = x * inverse(z) % P
    encoded = encode_u(output)
    if not any(encoded):
        raise X301Error("all_zero")
    return encoded


BASE_U = edwards_to_montgomery(G)
if BASE_U is None:
    raise EvidenceError("base point mapped to infinity")
BASE_U_ENCODING = encode_u(BASE_U[0])


def validate_parameters() -> None:
    """Validate every ED301-to-X301 parameter relation without Python assert."""

    if P != 2**301 - 2**99 + 947:
        raise EvidenceError("field modulus formula mismatch")
    if P.bit_length() != FIELD_BITS or P % 4 != 3:
        raise EvidenceError("field modulus shape mismatch")
    if SQRT_A * SQRT_A != EDWARDS_A:
        raise EvidenceError("declared square root of Edwards a mismatch")
    if not edwards_is_on_curve(G):
        raise EvidenceError("base point is off the Edwards curve")
    if edwards_scalar_mul(Q, G) != IDENTITY:
        raise EvidenceError("base point order relation mismatch")
    if 4 * Q + 4 * Q_TWIST != 2 * P + 2:
        raise EvidenceError("main/twist order sum mismatch")
    expected_a = 2 * (EDWARDS_A + EDWARDS_D) * inverse(EDWARDS_A - EDWARDS_D) % P
    expected_b = 4 * inverse(EDWARDS_A - EDWARDS_D) % P
    expected_a24 = (expected_a - 2) * inverse(4) % P
    if MONTGOMERY_A != expected_a:
        raise EvidenceError("Montgomery A derivation mismatch")
    if MONTGOMERY_B != expected_b:
        raise EvidenceError("Montgomery B derivation mismatch")
    if A24_MINUS != expected_a24:
        raise EvidenceError("Montgomery A24 derivation mismatch")
    mapped = edwards_to_montgomery(G)
    if mapped is None or encode_u(mapped[0]) != BASE_U_ENCODING:
        raise EvidenceError("base u derivation mismatch")


def iteration_result(count: int) -> bytes:
    """RFC 7748 Section 5 iteration pattern, initialized with BASE_U."""

    if count < 1:
        raise ValueError("iteration count must be positive")
    scalar = BASE_U_ENCODING
    u = BASE_U_ENCODING
    for _ in range(count):
        result = x301(scalar, u)
        scalar, u = result, scalar
    return scalar


def long_iteration_document(count: int = 1_000_000) -> dict[str, object]:
    """Compute the separately gated RFC-7748-shaped L1 fixture."""

    return {
        "schema": "x301-rfc7748-style-long-iteration-v1",
        "warning": "variable-time test oracle; never use with production secrets",
        "source": "RFC 7748 Section 5 iteration-test state update, translated by docs/X301_DRAFT.md",
        "iterations": count,
        "initial_scalar_and_u_hex": BASE_U_ENCODING.hex(),
        "result_hex": iteration_result(count).hex(),
    }


def validate_long_iteration_document(document: object) -> None:
    """Recompute and validate the separate L1 long-running fixture."""

    validate_parameters()
    if not isinstance(document, dict):
        raise EvidenceError("L1 document is not an object")
    count = document.get("iterations")
    if not isinstance(count, int) or isinstance(count, bool) or count != 1_000_000:
        raise EvidenceError("L1 iteration count is not exactly one million")
    expected = long_iteration_document(count)
    if document != expected:
        raise EvidenceError("L1 one-million iteration block mismatch")


def derive_small_order_corpus() -> dict[str, object]:
    """Derive every affine x-line of rational order 2 or 4.

    The order-two polynomial is u*(u^2+A*u+1).  Its quadratic factor has
    nonsquare discriminant, leaving u=0.  The Montgomery doubling numerator
    is (u^2-1)^2, hence the order-four x-lines are u=+1 and u=-1.  Quadratic
    characters classify +1 on the main curve and -1 on the twist.
    """

    discriminant = (MONTGOMERY_A * MONTGOMERY_A - 4) % P
    if legendre(discriminant) != -1:
        raise EvidenceError("unexpected rational two-torsion root")
    rhs_at_one = (1 + MONTGOMERY_A + 1) * inverse(MONTGOMERY_B) % P
    rhs_at_minus_one = (MONTGOMERY_A - 2) * inverse(MONTGOMERY_B) % P
    if rhs_at_one != EDWARDS_A or rhs_at_minus_one != EDWARDS_D:
        raise EvidenceError("order-four model classification changed")
    if legendre(rhs_at_one) != 1 or legendre(rhs_at_minus_one) != -1:
        raise EvidenceError("main/twist order-four classification changed")

    return {
        "derivation": {
            "order_two_polynomial": "u*(u^2+A*u+1)",
            "quadratic_discriminant_hex": f"{discriminant:x}",
            "quadratic_discriminant_legendre": -1,
            "doubling_numerator": "(u^2-1)^2",
        },
        "main_curve": [
            {"order": 1, "u": None, "encoding_le38_hex": None, "points": 1},
            {"order": 2, "u": 0, "encoding_le38_hex": encode_u(0).hex(), "points": 1},
            {
                "order": 4,
                "u": 1,
                "encoding_le38_hex": encode_u(1).hex(),
                "points": 2,
                "v_values": [SQRT_A, P - SQRT_A],
            },
        ],
        "quadratic_twist": [
            {"order": 1, "u": None, "encoding_le38_hex": None, "points": 1},
            {"order": 2, "u": 0, "encoding_le38_hex": encode_u(0).hex(), "points": 1},
            {
                "order": 4,
                "u": P - 1,
                "encoding_le38_hex": encode_u(P - 1).hex(),
                "points": 2,
            },
        ],
        "unique_rejection_encodings_le38_hex": [
            encode_u(0).hex(),
            encode_u(1).hex(),
            encode_u(P - 1).hex(),
        ],
        "identity_has_no_affine_u_encoding": True,
    }


def _shake(domain: bytes, index: int, length: int = FIELD_BYTES) -> bytes:
    return hashlib.shake_256(domain + index.to_bytes(8, "big")).digest(length)


def verify_birational_structure(case_count: int = 256) -> None:
    """D1: deterministic random round trips and group homomorphisms."""

    if edwards_scalar_mul(Q, G) != IDENTITY:
        raise EvidenceError("base point does not have order q")
    if edwards_scalar_mul(4, ORDER_FOUR) != IDENTITY:
        raise EvidenceError("chosen torsion point does not have order four")
    if edwards_scalar_mul(2, ORDER_FOUR) != ORDER_TWO:
        raise EvidenceError("chosen torsion point has wrong double")

    boundaries = [
        IDENTITY,
        ORDER_TWO,
        ORDER_FOUR,
        edwards_neg(ORDER_FOUR),
        G,
        edwards_neg(G),
    ]
    for point in boundaries:
        mapped = edwards_to_montgomery(point)
        if montgomery_to_edwards(mapped) != point:
            raise EvidenceError("boundary map round trip failed")

    torsion_cosets_seen: set[int] = set()
    for index in range(case_count):
        left_scalar = int.from_bytes(_shake(b"X301-D1-left-v1/", index), "little") % Q
        right_scalar = int.from_bytes(_shake(b"X301-D1-right-v1/", index), "little") % Q
        left_torsion = _shake(b"X301-D1-left-torsion-v1/", index, 1)[0] & 3
        right_torsion = _shake(b"X301-D1-right-torsion-v1/", index, 1)[0] & 3
        torsion_cosets_seen.add(left_torsion)
        torsion_cosets_seen.add(right_torsion)
        left = edwards_add(
            edwards_scalar_mul(left_scalar, G),
            edwards_scalar_mul(left_torsion, ORDER_FOUR),
        )
        right = edwards_add(
            edwards_scalar_mul(right_scalar, G),
            edwards_scalar_mul(right_torsion, ORDER_FOUR),
        )
        left_m = edwards_to_montgomery(left)
        right_m = edwards_to_montgomery(right)
        if montgomery_to_edwards(left_m) != left:
            raise EvidenceError(f"D1 left round trip failed at {index}")
        if montgomery_to_edwards(right_m) != right:
            raise EvidenceError(f"D1 right round trip failed at {index}")
        mapped_sum = edwards_to_montgomery(edwards_add(left, right))
        direct_sum = montgomery_add(left_m, right_m)
        if mapped_sum != direct_sum:
            raise EvidenceError(f"D1 homomorphism failed at {index}")
        if edwards_to_montgomery(montgomery_to_edwards(direct_sum)) != direct_sum:
            raise EvidenceError(f"D1 reverse round trip failed at {index}")
    if case_count >= 4 and torsion_cosets_seen != {0, 1, 2, 3}:
        raise EvidenceError("D1 cases did not cover all four torsion cosets")


@dataclass(frozen=True)
class CorpusCase:
    index: int
    secret_a: bytes
    public_a: bytes
    secret_b: bytes
    public_b: bytes
    shared: bytes

    def line(self) -> bytes:
        fields = (
            str(self.index),
            self.secret_a.hex(),
            self.public_a.hex(),
            self.secret_b.hex(),
            self.public_b.hex(),
            self.shared.hex(),
        )
        return ("\t".join(fields) + "\n").encode("ascii")


def corpus_cases(count: int) -> Iterator[CorpusCase]:
    """Yield deterministic keygen/basepoint/DH cases for T5."""

    for index in range(count):
        secret_a = _shake(b"X301-T5-secret-a-v1/", index)
        secret_b = _shake(b"X301-T5-secret-b-v1/", index)
        public_a = x301(secret_a, BASE_U_ENCODING)
        public_b = x301(secret_b, BASE_U_ENCODING)
        shared_ab = x301(secret_a, public_b)
        shared_ba = x301(secret_b, public_a)
        if shared_ab != shared_ba:
            raise EvidenceError(f"DH disagreement at corpus case {index}")
        yield CorpusCase(index, secret_a, public_a, secret_b, public_b, shared_ab)


def corpus_digest(count: int) -> str:
    digest = hashlib.sha256()
    for case in corpus_cases(count):
        digest.update(case.line())
    return digest.hexdigest()


def corpus_summary(count: int) -> tuple[str, CorpusCase, CorpusCase]:
    """Compute the canonical T5 digest and endpoint records in one pass."""

    if count < 1:
        raise ValueError("corpus count must be positive")
    digest = hashlib.sha256()
    cases = corpus_cases(count)
    first = next(cases)
    last = first
    digest.update(first.line())
    for case in cases:
        digest.update(case.line())
        last = case
    return digest.hexdigest(), first, last


def kat_vectors() -> list[dict[str, str]]:
    """Return fixed RFC-7748-shaped scalar/u/result vectors for T1 and D3."""

    peer_u = x301(_shake(b"X301-T1-u-source-v1/", 0), BASE_U_ENCODING)
    inputs = [
        ("zero-base", bytes(FIELD_BYTES), BASE_U_ENCODING),
        ("incrementing-base", bytes(range(FIELD_BYTES)), BASE_U_ENCODING),
        ("ones-base", bytes([0xFF]) * FIELD_BYTES, BASE_U_ENCODING),
        ("shake-peer", _shake(b"X301-T1-scalar-v1/", 0), peer_u),
    ]
    vectors = []
    for vector_id, secret, encoded_u in inputs:
        clamped = clamp_scalar(secret).to_bytes(FIELD_BYTES, "little")
        result = x301(secret, encoded_u)
        if encoded_u == BASE_U_ENCODING:
            expected_point = edwards_scalar_mul(int.from_bytes(clamped, "little"), G)
            expected_montgomery = edwards_to_montgomery(expected_point)
            if expected_montgomery is None:
                raise EvidenceError(f"T1 {vector_id} unexpectedly mapped to infinity")
            expected_result = encode_u(expected_montgomery[0])
            if result != expected_result:
                raise EvidenceError(
                    f"T1 {vector_id} ladder disagrees with Edwards scalar multiplication"
                )
        vectors.append(
            {
                "id": vector_id,
                "scalar_input_hex": secret.hex(),
                "scalar_clamped_hex": clamped.hex(),
                "u_input_le38_hex": encoded_u.hex(),
                "result_le38_hex": result.hex(),
            }
        )
    return vectors


def boundary_vectors() -> list[dict[str, object]]:
    p_bytes = P.to_bytes(FIELD_BYTES, "little")
    p_plus_one = (P + 1).to_bytes(FIELD_BYTES, "little")
    vectors: list[dict[str, object]] = [
        {"id": "u-equals-p", "input_hex": p_bytes.hex(), "expected_error": "noncanonical"},
        {"id": "u-equals-p-plus-one", "input_hex": p_plus_one.hex(), "expected_error": "noncanonical"},
    ]
    for bit in (301, 302, 303):
        encoded = bytearray(FIELD_BYTES)
        encoded[bit // 8] = 1 << (bit % 8)
        vectors.append(
            {
                "id": f"u-bit-{bit}-set",
                "input_hex": bytes(encoded).hex(),
                "expected_error": "reserved_bits",
            }
        )
    encoded = bytearray(FIELD_BYTES)
    encoded[-1] = 0xE0
    vectors.extend(
        [
            {
                "id": "u-bits-301-through-303-set",
                "input_hex": bytes(encoded).hex(),
                "expected_error": "reserved_bits",
            },
            {"id": "u-length-37", "input_hex": bytes(FIELD_BYTES - 1).hex(), "expected_error": "length"},
            {"id": "u-length-39", "input_hex": bytes(FIELD_BYTES + 1).hex(), "expected_error": "length"},
        ]
    )
    return vectors


def computed_vector_document(corpus_count: int = 10_000) -> dict[str, object]:
    digest, first, last = corpus_summary(corpus_count)
    return {
        "schema": "x301-independent-reference-v1",
        "warning": "variable-time test oracle; never use with production secrets",
        "sources": [
            "RFC 7748 Sections 4-6",
            "inputs/round4/ED301-EdDSA-draft.md Sections 2-3",
            "docs/X301_DRAFT.md",
        ],
        "parameters": {
            "p": P,
            "a": EDWARDS_A,
            "d": EDWARDS_D,
            "q": Q,
            "q_twist": Q_TWIST,
            "montgomery_A": MONTGOMERY_A,
            "montgomery_B": MONTGOMERY_B,
            "a24_minus": A24_MINUS,
            "base_edwards_encoding_hex": BASEPOINT_ENCODING.hex(),
            "base_u_encoding_le38_hex": BASE_U_ENCODING.hex(),
        },
        "t1": kat_vectors(),
        "d1": {
            "deterministic_random_cases": 256,
            "checks": ["Edwards-to-Montgomery round trip", "Montgomery-to-Edwards round trip", "group homomorphism"],
        },
        "t2": {
            "initial_scalar_and_u_hex": BASE_U_ENCODING.hex(),
            "after_1_hex": iteration_result(1).hex(),
            "after_1000_hex": iteration_result(1000).hex(),
        },
        "t3": boundary_vectors(),
        "t4": derive_small_order_corpus(),
        "t5": {
            "count": corpus_count,
            "record_format": "index TAB secret_a TAB public_a TAB secret_b TAB public_b TAB shared NEWLINE",
            "sha256": digest,
            "first_record": first.line().decode("ascii").rstrip("\n"),
            "last_record": last.line().decode("ascii").rstrip("\n"),
        },
    }


def validate_vector_document(document: object, verify_corpus: bool = True) -> None:
    """Validate frozen evidence, optionally recomputing the full T5 stream."""

    validate_parameters()
    if not isinstance(document, dict):
        raise EvidenceError("vector document is not an object")
    if document.get("schema") != "x301-independent-reference-v1":
        raise EvidenceError("vector schema mismatch")
    expected_parameters = {
        "p": P,
        "a": EDWARDS_A,
        "d": EDWARDS_D,
        "q": Q,
        "q_twist": Q_TWIST,
        "montgomery_A": MONTGOMERY_A,
        "montgomery_B": MONTGOMERY_B,
        "a24_minus": A24_MINUS,
        "base_edwards_encoding_hex": BASEPOINT_ENCODING.hex(),
        "base_u_encoding_le38_hex": BASE_U_ENCODING.hex(),
    }
    if document.get("parameters") != expected_parameters:
        raise EvidenceError("frozen parameter block mismatch")
    if document.get("t1") != kat_vectors():
        raise EvidenceError("T1 KAT block mismatch")
    expected_d1 = {
        "deterministic_random_cases": 256,
        "checks": [
            "Edwards-to-Montgomery round trip",
            "Montgomery-to-Edwards round trip",
            "group homomorphism",
        ],
    }
    if document.get("d1") != expected_d1:
        raise EvidenceError("D1 evidence block mismatch")
    t2 = document.get("t2")
    if not isinstance(t2, dict):
        raise EvidenceError("T2 block missing")
    expected_t2 = {
        "initial_scalar_and_u_hex": BASE_U_ENCODING.hex(),
        "after_1_hex": iteration_result(1).hex(),
        "after_1000_hex": iteration_result(1000).hex(),
    }
    if t2 != expected_t2:
        raise EvidenceError("T2 iteration block mismatch")
    if document.get("t3") != boundary_vectors():
        raise EvidenceError("T3 boundary block mismatch")
    if document.get("t4") != derive_small_order_corpus():
        raise EvidenceError("T4 corpus mismatch")
    t5 = document.get("t5")
    if not isinstance(t5, dict):
        raise EvidenceError("T5 block missing")
    count = t5.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 10_000:
        raise EvidenceError("T5 corpus is smaller than 10000 cases")
    if t5.get("record_format") != (
        "index TAB secret_a TAB public_a TAB secret_b TAB public_b TAB shared NEWLINE"
    ):
        raise EvidenceError("T5 record format mismatch")
    if verify_corpus:
        digest, first, last = corpus_summary(count)
        if t5.get("sha256") != digest:
            raise EvidenceError("T5 digest mismatch")
        if t5.get("first_record") != first.line().decode("ascii").rstrip("\n"):
            raise EvidenceError("T5 first record mismatch")
        if t5.get("last_record") != last.line().decode("ascii").rstrip("\n"):
            raise EvidenceError("T5 last record mismatch")


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")
    verify_parser = subparsers.add_parser("verify-vectors")
    verify_parser.add_argument(
        "--path", type=Path, default=Path(__file__).with_name("x301-test-vectors.json")
    )
    verify_long_parser = subparsers.add_parser("verify-long-iteration")
    verify_long_parser.add_argument(
        "--path",
        type=Path,
        default=Path(__file__).with_name("x301-long-iteration.json"),
    )
    vectors_parser = subparsers.add_parser("emit-vectors")
    vectors_parser.add_argument("--corpus-count", type=int, default=10_000)
    long_parser = subparsers.add_parser("emit-long-iteration")
    long_parser.add_argument("--count", type=int, default=1_000_000)
    corpus_parser = subparsers.add_parser("emit-corpus")
    corpus_parser.add_argument("--count", type=int, default=10_000)
    digest_parser = subparsers.add_parser("corpus-digest")
    digest_parser.add_argument("--count", type=int, default=10_000)
    args = parser.parse_args(argv)

    if args.command == "self-test":
        validate_parameters()
        verify_birational_structure()
        derive_small_order_corpus()
        print("x301_independent_reference_self_test=PASS d1_cases=256")
        return 0
    if args.command == "verify-vectors":
        document = json.loads(args.path.read_text(encoding="utf-8"))
        validate_vector_document(document)
        print("x301_independent_vectors=PASS corpus_cases=10000")
        return 0
    if args.command == "verify-long-iteration":
        document = json.loads(args.path.read_text(encoding="utf-8"))
        validate_long_iteration_document(document)
        print("x301_long_iteration=PASS iterations=1000000")
        return 0
    if args.command == "emit-vectors":
        json.dump(computed_vector_document(args.corpus_count), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    if args.command == "emit-long-iteration":
        json.dump(long_iteration_document(args.count), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    if args.command == "emit-corpus":
        for case in corpus_cases(args.count):
            sys.stdout.buffer.write(case.line())
        return 0
    if args.command == "corpus-digest":
        print(corpus_digest(args.count))
        return 0
    raise EvidenceError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
