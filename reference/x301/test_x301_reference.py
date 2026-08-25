#!/usr/bin/env python3
"""Regression tests for the independent, variable-time X301 oracle."""

from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import sys
import unittest
from unittest import mock

VECTOR_PATH = pathlib.Path(__file__).with_name("x301-test-vectors.json")
REFERENCE_PATH = pathlib.Path(__file__).with_name("x301_reference.py")


def _load_reference_module():
    """Load the adjacent oracle without relying on the ambient import path."""

    spec = importlib.util.spec_from_file_location("x301_reference", REFERENCE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load X301 oracle from {REFERENCE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load_reference_module()


class X301ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    def test_parameter_derivation_and_basepoint(self) -> None:
        self.assertEqual(ref.P % 4, 3)
        self.assertEqual(ref.SQRT_A * ref.SQRT_A, ref.EDWARDS_A)
        self.assertTrue(ref.edwards_is_on_curve(ref.G))
        self.assertEqual(ref.edwards_scalar_mul(ref.Q, ref.G), ref.IDENTITY)
        self.assertEqual(4 * ref.Q + 4 * ref.Q_TWIST, 2 * ref.P + 2)
        self.assertEqual(
            ref.BASE_U_ENCODING.hex(),
            self.vectors["parameters"]["base_u_encoding_le38_hex"],
        )

    def test_d1_random_roundtrips_and_homomorphism(self) -> None:
        ref.verify_birational_structure(
            self.vectors["d1"]["deterministic_random_cases"]
        )

    def test_t1_fixed_kats_and_clamping(self) -> None:
        self.assertEqual(ref.kat_vectors(), self.vectors["t1"])
        for vector in self.vectors["t1"]:
            with self.subTest(vector=vector["id"]):
                secret = bytes.fromhex(vector["scalar_input_hex"])
                encoded_u = bytes.fromhex(vector["u_input_le38_hex"])
                self.assertEqual(
                    ref.clamp_scalar(secret).to_bytes(ref.FIELD_BYTES, "little").hex(),
                    vector["scalar_clamped_hex"],
                )
                self.assertEqual(ref.x301(secret, encoded_u).hex(), vector["result_le38_hex"])

    def test_d2_strict_boundaries(self) -> None:
        self.assertEqual(ref.boundary_vectors(), self.vectors["t3"])
        for vector in self.vectors["t3"]:
            with self.subTest(vector=vector["id"]):
                with self.assertRaises(ref.X301Error) as caught:
                    ref.decode_u(bytes.fromhex(vector["input_hex"]))
                self.assertEqual(caught.exception.code, vector["expected_error"])

    def test_d3_exact_clamp_bits(self) -> None:
        raw = bytes(range(ref.FIELD_BYTES))
        scalar = ref.clamp_scalar(raw)
        self.assertEqual(scalar & 3, 0)
        self.assertEqual((scalar >> 300) & 1, 1)
        self.assertEqual(scalar >> 301, 0)

    def test_t2_iteration_vectors(self) -> None:
        self.assertEqual(ref.iteration_result(1).hex(), self.vectors["t2"]["after_1_hex"])
        self.assertEqual(
            ref.iteration_result(1000).hex(),
            self.vectors["t2"]["after_1000_hex"],
        )

    def test_t4_complete_small_order_derivation(self) -> None:
        self.assertEqual(ref.derive_small_order_corpus(), self.vectors["t4"])
        secret_domains = [
            b"X301-T4-secret-a-v1/",
            b"X301-T4-secret-b-v1/",
            b"X301-T4-secret-c-v1/",
        ]
        for encoding_hex in self.vectors["t4"]["unique_rejection_encodings_le38_hex"]:
            encoded = bytes.fromhex(encoding_hex)
            for index, domain in enumerate(secret_domains):
                with self.subTest(u=encoding_hex, secret=index):
                    with self.assertRaises(ref.X301Error) as caught:
                        ref.x301(ref._shake(domain, index), encoded)
                    self.assertEqual(caught.exception.code, "all_zero")

    def test_t5_frozen_ten_thousand_case_digest(self) -> None:
        ref.validate_vector_document(self.vectors)

    def test_negative_control_rejects_mutated_constant(self) -> None:
        with mock.patch.object(ref, "MONTGOMERY_A", ref.MONTGOMERY_A + 1):
            with self.assertRaisesRegex(ref.EvidenceError, "Montgomery A derivation"):
                ref.validate_parameters()

    def test_negative_control_rejects_mutated_vector(self) -> None:
        mutated = copy.deepcopy(self.vectors)
        mutated["t2"]["after_1_hex"] = "00" * ref.FIELD_BYTES
        with self.assertRaisesRegex(ref.EvidenceError, "T2 iteration block"):
            ref.validate_vector_document(mutated, verify_corpus=False)


if __name__ == "__main__":
    unittest.main()
