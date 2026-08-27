#!/usr/bin/env python3
"""Generate the X301 Wycheproof-taxonomy adversarial corpus.

Method sources are the X25519/X448 case classes used by Project Wycheproof,
RFC 7748 sections 5-6, and the D2-D4 decisions in
``docs/X301_DRAFT.md``.  No foreign curve value is copied.  Every expected
X301 byte string is calculated by the adjacent, variable-time specification
oracle.  This script is test-only and must never process production secrets.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent
REFERENCE = ROOT / "x301_reference.py"
DEFAULT_JSON = ROOT / "x301-wycheproof-corpus.json"
DEFAULT_HEADER = ROOT.parents[1] / "provider-tests/x301/generated/x301_adversarial_vectors.h"
DEFAULT_EVP = ROOT.parents[1] / "provider-tests/x301/openssl_evp_x301.txt"


def _load_reference():
    spec = importlib.util.spec_from_file_location("x301_adversarial_reference", REFERENCE)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load X301 oracle from {REFERENCE}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ref = _load_reference()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ref.EvidenceError(message)


def _case(
    tc_id: int,
    family: str,
    flags: list[str],
    operation: str,
    secret: bytes,
    public: bytes,
    expected: str,
    output: bytes | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "tcId": tc_id,
        "family": family,
        "flags": flags,
        "operation": operation,
        "secret_hex": secret.hex(),
        "public_hex": public.hex(),
        "expected": expected,
        "expected_output_hex": "" if output is None else output.hex(),
        "expected_error": "" if error is None else error,
    }


def _montgomery_character(u: int) -> int:
    rhs_over_b = (
        (u * u * u + ref.MONTGOMERY_A * u * u + u) * ref.inverse(ref.MONTGOMERY_B)
    ) % ref.P
    return ref.legendre(rhs_over_b)


def _valid_case(
    tc_id: int,
    family: str,
    flags: list[str],
    secret: bytes,
    public: bytes,
    operation: str = "derive",
) -> dict[str, Any]:
    if operation == "derive":
        output = ref.x301(secret, public)
    elif operation == "public_from_secret":
        _require(public == b"", "public_from_secret case unexpectedly has peer bytes")
        output = ref.x301(secret, ref.BASE_U_ENCODING)
    else:
        raise ref.EvidenceError(f"unsupported valid operation: {operation}")
    return _case(tc_id, family, flags, operation, secret, public, "valid", output=output)


def _invalid_case(
    tc_id: int,
    family: str,
    flags: list[str],
    secret: bytes,
    public: bytes,
    operation: str,
    error: str,
) -> dict[str, Any]:
    return _case(tc_id, family, flags, operation, secret, public, "invalid", error=error)


def _build_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    tc_id = 1

    def add(case: dict[str, Any]) -> None:
        nonlocal tc_id
        _require(case["tcId"] == tc_id, "non-contiguous adversarial tcId")
        cases.append(case)
        tc_id += 1

    # W1: the complete set of canonical affine x-lines of order 2 or 4.
    # The identity has no affine u encoding and is recorded in metadata.
    w1_secret = ref._shake(b"X301-W1-secret-v1/", 0)
    for label, u in (("Order2", 0), ("Order4Main", 1), ("Order4Twist", ref.P - 1)):
        add(
            _invalid_case(
                tc_id,
                "W1-LowOrderPublic",
                ["LowOrderPublic", label],
                w1_secret,
                ref.encode_u(u),
                "derive",
                "all_zero",
            )
        )

    # W2: one twist low-order line plus seven deterministic large-order twist
    # representatives.  Membership is determined algebraically, before X301.
    add(
        _invalid_case(
            tc_id,
            "W2-TwistPublic",
            ["TwistPublic", "LowOrderPublic"],
            ref._shake(b"X301-W2-secret-v1/", 0),
            ref.encode_u(ref.P - 1),
            "derive",
            "all_zero",
        )
    )
    candidate_index = 0
    accepted_twist = 0
    while accepted_twist < 7:
        candidate = int.from_bytes(
            ref._shake(b"X301-W2-u-v1/", candidate_index), "little"
        ) % ref.P
        candidate_index += 1
        if candidate in (0, 1, ref.P - 1) or _montgomery_character(candidate) != -1:
            continue
        secret = ref._shake(b"X301-W2-secret-v1/", accepted_twist + 1)
        add(
            _valid_case(
                tc_id,
                "W2-TwistPublic",
                ["TwistPublic", "LargeOrderTwist"],
                secret,
                ref.encode_u(candidate),
            )
        )
        accepted_twist += 1

    # W3: D2 masks the three unused bits and subtracts p once.
    for index, value in enumerate((ref.P, ref.P + 1)):
        add(
            _invalid_case(
                tc_id,
                "W3-AliasPublic",
                ["AliasPublic", "ReducedModP", f"AllZero-{index}"],
                ref._shake(b"X301-W3-secret-v1/", index),
                value.to_bytes(ref.FIELD_BYTES, "little"),
                "derive",
                "all_zero",
            )
        )
    for index, value in enumerate((ref.P + 947, 2**301 - 1), start=2):
        add(
            _valid_case(
                tc_id,
                "W3-AliasPublic",
                ["AliasPublic", "ReducedModP", f"Boundary-{index}"],
                ref._shake(b"X301-W3-secret-v1/", index),
                value.to_bytes(ref.FIELD_BYTES, "little"),
            )
        )
    high_masks = range(0x20, 0x100, 0x20)
    for index, mask in enumerate(high_masks):
        encoded = bytearray(ref.BASE_U_ENCODING)
        encoded[-1] |= mask
        add(
            _valid_case(
                tc_id,
                "W3-AliasPublic",
                ["AliasPublic", "IgnoredHighBits", f"Mask-{mask:02x}"],
                ref._shake(b"X301-W3-high-secret-v1/", index),
                bytes(encoded),
            )
        )

    # W4: raw scalar boundaries.  Expected public keys are evaluated only
    # after the normative D3 clamp.
    scalar_patterns = [
        ("AllZero", bytes(ref.FIELD_BYTES)),
        ("AllOnes", bytes([0xFF]) * ref.FIELD_BYTES),
        ("ClampBitsOnly", bytes([0x03]) + bytes(ref.FIELD_BYTES - 2) + bytes([0xE0])),
        ("Bit300Only", bytes(ref.FIELD_BYTES - 1) + bytes([0x10])),
        ("Bit301Only", bytes(ref.FIELD_BYTES - 1) + bytes([0x20])),
        ("Bit303Only", bytes(ref.FIELD_BYTES - 1) + bytes([0x80])),
        ("AlternatingAA", bytes([0xAA]) * ref.FIELD_BYTES),
        ("Alternating55", bytes([0x55]) * ref.FIELD_BYTES),
    ]
    for label, secret in scalar_patterns:
        add(
            _valid_case(
                tc_id,
                "W4-SpecialScalars",
                ["SpecialScalars", label],
                secret,
                b"",
                operation="public_from_secret",
            )
        )

    # W5: four results with a zero least-significant byte and four with a
    # zero most-significant storage byte.  None is the all-zero string.
    fixed_secret = ref._shake(b"X301-W5-fixed-secret-v1/", 0)
    low_zero: list[tuple[bytes, bytes]] = []
    high_zero: list[tuple[bytes, bytes]] = []
    search_index = 0
    while len(low_zero) < 4 or len(high_zero) < 4:
        peer_secret = ref._shake(b"X301-W5-peer-secret-v1/", search_index)
        search_index += 1
        peer_public = ref.x301(peer_secret, ref.BASE_U_ENCODING)
        shared = ref.x301(fixed_secret, peer_public)
        _require(any(shared), "W5 search produced an all-zero secret")
        if shared[0] == 0 and len(low_zero) < 4:
            low_zero.append((peer_public, shared))
        if shared[-1] == 0 and len(high_zero) < 4:
            high_zero.append((peer_public, shared))
        _require(search_index <= 100_000, "W5 deterministic search budget exhausted")
    for label, selected in (("LowByteZero", low_zero), ("HighByteZero", high_zero)):
        for peer_public, shared in selected:
            case = _valid_case(
                tc_id,
                "W5-SharedSecretEdges",
                ["SharedSecretEdges", label],
                fixed_secret,
                peer_public,
            )
            _require(case["expected_output_hex"] == shared.hex(), "W5 oracle drift")
            add(case)

    # W6: every requested adjacent and remote wrong length.  Empty peer bytes
    # are unambiguous because the operation distinguishes absence from length.
    length_secret = ref._shake(b"X301-W6-valid-secret-v1/", 0)
    for length in (0, 1, 37, 39, 76):
        add(
            _invalid_case(
                tc_id,
                "W6-LengthAndType",
                ["LengthAndType", "SecretLength", f"Length-{length}"],
                ref._shake(b"X301-W6-bad-secret-v1/", length, length),
                b"",
                "public_from_secret",
                "secret_length",
            )
        )
    for length in (0, 1, 37, 39, 76):
        add(
            _invalid_case(
                tc_id,
                "W6-LengthAndType",
                ["LengthAndType", "PublicLength", f"Length-{length}"],
                length_secret,
                ref._shake(b"X301-W6-bad-public-v1/", length, length),
                "derive",
                "length",
            )
        )

    # 512 valid oracle-generated DH cases augment the taxonomy without
    # pretending to be foreign Wycheproof vectors.
    for index in range(512):
        secret_a = ref._shake(b"X301-WRANDOM-secret-a-v1/", index)
        secret_b = ref._shake(b"X301-WRANDOM-secret-b-v1/", index)
        public_b = ref.x301(secret_b, ref.BASE_U_ENCODING)
        case = _valid_case(
            tc_id,
            "W-RandomValid",
            ["RandomValid", "DH"],
            secret_a,
            public_b,
        )
        shared_ba = ref.x301(secret_b, ref.x301(secret_a, ref.BASE_U_ENCODING))
        _require(
            bytes.fromhex(case["expected_output_hex"]) == shared_ba,
            f"random DH disagreement at {index}",
        )
        add(case)

    return cases


def _evaluate(case: dict[str, Any]) -> tuple[str, bytes | None, str | None]:
    secret = bytes.fromhex(case["secret_hex"])
    public = bytes.fromhex(case["public_hex"])
    try:
        if case["operation"] == "derive":
            output = ref.x301(secret, public)
        elif case["operation"] == "public_from_secret":
            if public:
                raise ref.EvidenceError("public_from_secret case contains peer bytes")
            output = ref.x301(secret, ref.BASE_U_ENCODING)
        else:
            raise ref.EvidenceError(f"unknown operation {case['operation']}")
    except ref.X301Error as error:
        return "invalid", None, error.code
    return "valid", output, None


def _case_digest(cases: list[dict[str, Any]]) -> str:
    canonical = json.dumps(cases, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_document() -> dict[str, Any]:
    ref.validate_parameters()
    cases = _build_cases()
    family_counts: dict[str, int] = {}
    for case in cases:
        family_counts[case["family"]] = family_counts.get(case["family"], 0) + 1
        actual, output, error = _evaluate(case)
        _require(actual == case["expected"], f"expectation class mismatch at tcId {case['tcId']}")
        if actual == "valid":
            _require(output is not None, f"missing output at tcId {case['tcId']}")
            _require(
                output.hex() == case["expected_output_hex"],
                f"output mismatch at tcId {case['tcId']}",
            )
        else:
            _require(error == case["expected_error"], f"error mismatch at tcId {case['tcId']}")

    expected_counts = {
        "W1-LowOrderPublic": 3,
        "W2-TwistPublic": 8,
        "W3-AliasPublic": 11,
        "W4-SpecialScalars": 8,
        "W5-SharedSecretEdges": 8,
        "W6-LengthAndType": 10,
        "W-RandomValid": 512,
    }
    _require(family_counts == expected_counts, "adversarial family cardinality mismatch")
    return {
        "schema": "x301-wycheproof-taxonomy-v2",
        "warning": "Taxonomy only; no X25519/X448 vector value is copied",
        "sources": [
            "Project Wycheproof X25519/X448 test-case taxonomy",
            "RFC 7748 sections 5-6",
            "docs/X301_DRAFT.md D2-D4",
            "reference/x301/x301_reference.py specification oracle",
        ],
        "identity_has_no_affine_u_encoding": True,
        "field_bytes": ref.FIELD_BYTES,
        "family_counts": family_counts,
        "case_count": len(cases),
        "case_sha256": _case_digest(cases),
        "cases": cases,
    }


def render_json(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def _c_string(value: str) -> str:
    return json.dumps(value)


def render_header(document: dict[str, Any]) -> str:
    lines = [
        "/* Generated by reference/x301/generate_adversarial_corpus.py.",
        " * Method sources: Project Wycheproof X25519/X448 taxonomy, RFC 7748",
        " * sections 5-6, and X301 D2-D4. No foreign curve value is copied.",
        " * Test-only: never use these deterministic values as real keys.",
        " */",
        "#ifndef ED301_X301_ADVERSARIAL_VECTORS_H",
        "#define ED301_X301_ADVERSARIAL_VECTORS_H",
        "",
        "typedef struct {",
        "    unsigned int tc_id;",
        "    const char *family;",
        "    const char *flags;",
        "    const char *operation;",
        "    const char *secret_hex;",
        "    const char *public_hex;",
        "    const char *expected;",
        "    const char *expected_output_hex;",
        "    const char *expected_error;",
        "} X301_ADVERSARIAL_VECTOR;",
        "",
        f"#define X301_ADVERSARIAL_CASE_SHA256 {_c_string(document['case_sha256'])}",
        f"#define X301_ADVERSARIAL_VECTOR_COUNT {document['case_count']}u",
        "",
        "static const X301_ADVERSARIAL_VECTOR x301_adversarial_vectors[] = {",
    ]
    for case in document["cases"]:
        fields = [
            f"{case['tcId']}u",
            _c_string(case["family"]),
            _c_string(",".join(case["flags"])),
            _c_string(case["operation"]),
            _c_string(case["secret_hex"]),
            _c_string(case["public_hex"]),
            _c_string(case["expected"]),
            _c_string(case["expected_output_hex"]),
            _c_string(case["expected_error"]),
        ]
        lines.append("    { " + ", ".join(fields) + " },")
    lines.extend(["};", "", "#endif", ""])
    return "\n".join(lines)


def render_evp_data(document: dict[str, Any]) -> str:
    """Render OpenSSL evp_test-shaped raw-key and derive contracts.

    The grammar follows OpenSSL 3.5.7/4.0.1
    ``test/recipes/30-test_evp_data/evppkey_ecx.txt``. Expected bytes still
    come from the independent X301 oracle and never from the provider.
    """

    t1_vectors = ref.kat_vectors()
    t1 = t1_vectors[1]
    selected = [
        case
        for case in document["cases"]
        if case["operation"] == "derive" and case["expected"] == "valid"
    ][:24]
    _require(len(selected) == 24, "insufficient valid EVP derive cases")
    lines = [
        "# Generated by reference/x301/generate_adversarial_corpus.py.",
        "# Contract grammar: OpenSSL 3.5.7/4.0.1 evppkey_ecx.txt.",
        "# Expected values: independent X301 specification oracle.",
        "",
        "Title = X301 raw-key and derive contracts",
        "",
        (
            "PrivateKeyRaw=X301-PAIR-PRIVATE:X301:"
            f"{t1['scalar_input_hex']}"
        ),
        "",
        (
            "PublicKeyRaw=X301-PAIR-PUBLIC:X301:"
            f"{t1['result_le38_hex']}"
        ),
        "",
        "PrivPubKeyPair = X301-PAIR-PRIVATE:X301-PAIR-PUBLIC",
        "",
        "Sign=X301-PAIR-PRIVATE",
        "Result = KEYOP_INIT_ERROR",
        "Reason = operation not supported for this keytype",
        "",
        "Verify=X301-PAIR-PRIVATE",
        "Result = KEYOP_INIT_ERROR",
        "Reason = operation not supported for this keytype",
        "",
    ]

    for index, vector in enumerate(t1_vectors, start=1):
        private_name = f"X301-T1-{index}-PRIVATE"
        peer_name = f"X301-T1-{index}-PEER"
        lines.extend(
            [
                (
                    f"PrivateKeyRaw={private_name}:X301:"
                    f"{vector['scalar_input_hex']}"
                ),
                "",
                (
                    f"PublicKeyRaw={peer_name}:X301:"
                    f"{vector['u_input_le38_hex']}"
                ),
                "",
                f"Derive={private_name}",
                f"PeerKey={peer_name}",
                f"SharedSecret={vector['result_le38_hex']}",
                "",
            ]
        )

    low_order = [
        case
        for case in document["cases"]
        if case["family"] == "W1-LowOrderPublic"
    ]
    _require(len(low_order) == 3, "W1 EVP representative count drift")
    for index, case in enumerate(low_order, start=1):
        private_name = f"X301-W1-{index}-PRIVATE"
        peer_name = f"X301-W1-{index}-PEER"
        lines.extend(
            [
                (
                    f"PrivateKeyRaw={private_name}:X301:"
                    f"{case['secret_hex']}"
                ),
                "",
                (
                    f"PublicKeyRaw={peer_name}:X301:"
                    f"{case['public_hex']}"
                ),
                "",
                f"Derive={private_name}",
                f"PeerKey={peer_name}",
                "Result = DERIVE_ERROR",
                "",
            ]
        )

    # O2 cases that the stock evp_test grammar can express. Raw-key length
    # failures occur while parsing global key definitions and therefore have
    # no Result stanza in upstream evp_test; those stay in the C API harness.
    lines.extend(
        [
            (
                "PublicKeyRaw=X301-O2-ED301-PEER:Ed301-EdDSA-draft-00:"
                "ebf3c760f2236f9e5295f3f9f783b37a49064a809ed5689bb231a2ffeceff922"
                "c97153316112"
            ),
            "",
            "Derive=X301-PAIR-PRIVATE",
            "PeerKey=X301-O2-ED301-PEER",
            "Result = DERIVE_SET_PEER_ERROR",
            "",
            "Derive=X301-PAIR-PRIVATE",
            "Result = DERIVE_SET_PEER_ERROR",
            "",
        ]
    )

    for index, case in enumerate(selected, start=1):
        private_name = f"X301-DERIVE-{index}-PRIVATE"
        peer_name = f"X301-DERIVE-{index}-PEER"
        lines.extend(
            [
                (
                    f"PrivateKeyRaw={private_name}:X301:"
                    f"{case['secret_hex']}"
                ),
                "",
                (
                    f"PublicKeyRaw={peer_name}:X301:"
                    f"{case['public_hex']}"
                ),
                "",
                f"Derive={private_name}",
                f"PeerKey={peer_name}",
                f"SharedSecret={case['expected_output_hex']}",
                "",
            ]
        )
    return "\n".join(lines)


def _write_or_check(path: pathlib.Path, expected: str, check: bool) -> None:
    if check:
        if not path.is_file() or path.read_text(encoding="utf-8") != expected:
            raise ref.EvidenceError(f"generated artifact differs: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(expected, encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=pathlib.Path, default=DEFAULT_JSON)
    parser.add_argument("--header-out", type=pathlib.Path, default=DEFAULT_HEADER)
    parser.add_argument("--evp-out", type=pathlib.Path, default=DEFAULT_EVP)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    document = build_document()
    _write_or_check(args.json_out, render_json(document), args.check)
    _write_or_check(args.header_out, render_header(document), args.check)
    _write_or_check(args.evp_out, render_evp_data(document), args.check)
    print(
        f"x301_adversarial_corpus=PASS cases={document['case_count']} "
        f"sha256={document['case_sha256']} mode={'check' if args.check else 'write'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
