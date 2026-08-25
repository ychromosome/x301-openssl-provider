//! Core acceptance tests for the RFC 7748-pattern X301 implementation.
//!
//! Fixed expectations come from the independently maintained integer oracle
//! in `reference/x301`; algebraic tests use the D1 birational map directly.
//! No expected value is read back from the Rust implementation.

extern crate std;

use crypto_bigint::Choice;
use std::{path::Path, process::Command, string::String, vec::Vec};

use crate::{
    edwards::{BASEPOINT_ENCODING, EdwardsPoint},
    field_5x64::Fe301,
    parameters::{EDWARDS_A, EDWARDS_D, FIELD_BYTES},
    test_support::{decode_hex_array, splitmix64},
    x301::{
        BASE_U_BYTES, PUBLIC_BYTES, SECRET_BYTES, SHARED_BYTES, X301_BYTES, X301Error,
        clamped_scalar_for_test, montgomery_a_for_test, public_from_secret, shared_secret,
        validate_public_encoding, x301,
    },
};

const SECRET_A: [u8; SECRET_BYTES] = decode_hex_array(
    b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425",
);
const PUBLIC_A: [u8; PUBLIC_BYTES] = decode_hex_array(
    b"b5d19e31e6bfa6f5c47411738360ba94b7bbff1c4bb9fc646e9775bbd7565a6052819781c21a",
);
const SECRET_B: [u8; SECRET_BYTES] = decode_hex_array(
    b"2524232221201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
);
const PUBLIC_B: [u8; PUBLIC_BYTES] = decode_hex_array(
    b"86a7fa2ccb11a76c34fd7bca0f6e592c9991cb554cd7b326a2177df7dbb0f4c514381519921d",
);
const SHARED_AB: [u8; SHARED_BYTES] = decode_hex_array(
    b"70a54bebecf4a6f68aa30e6b081d29fb59da71ebd6fbf34f14780650ea2baa076c3afc7a4111",
);
const ITERATION_ONE: [u8; X301_BYTES] = decode_hex_array(
    b"2866fa9dafb46a557566d84931090545f86f6c4f90b73d41da0bd39a248f561b102ca0a76b1e",
);
const ITERATION_THOUSAND: [u8; X301_BYTES] = decode_hex_array(
    b"8684cf6cebf163576e535abaf21f539129f31498e18e97abb0cf736ed9dd703cdd28768fd915",
);
const ITERATION_MILLION: [u8; X301_BYTES] = decode_hex_array(
    b"14ab929a330ac560c738369f025c046ab422731b8c562b6769e2ced5a2054ff6746ec52b9b00",
);
const MODULUS: [u8; PUBLIC_BYTES] = decode_hex_array(
    b"b30300000000000000000000f8ffffffffffffffffffffffffffffffffffffffffffffffff1f",
);
const MODULUS_PLUS_ONE: [u8; PUBLIC_BYTES] = decode_hex_array(
    b"b40300000000000000000000f8ffffffffffffffffffffffffffffffffffffffffffffffff1f",
);
const MODULUS_MINUS_ONE: [u8; PUBLIC_BYTES] = decode_hex_array(
    b"b20300000000000000000000f8ffffffffffffffffffffffffffffffffffffffffffffffff1f",
);
const FORMER_N_TWIST_RAW: [u8; SECRET_BYTES] = decode_hex_array(
    b"5caf05bd7871f4673bd712e08efdb5dddf8ca4ffffffffffffffffffffffffffffffffffff1f",
);
const FORMER_N_TWIST_PUBLIC: [u8; PUBLIC_BYTES] = decode_hex_array(
    b"d366d30b58a3f5d34eebf0355acea1314196a95bd9bcd73310e385585fcddb332d0064338300",
);

#[test]
fn sizes_and_fixed_rfc_style_kats_match_the_independent_oracle() {
    assert_eq!(SECRET_BYTES, 38);
    assert_eq!(PUBLIC_BYTES, 38);
    assert_eq!(SHARED_BYTES, 38);
    assert_eq!(X301_BYTES, FIELD_BYTES);

    assert_eq!(public_from_secret(&SECRET_A), Ok(PUBLIC_A));
    assert_eq!(public_from_secret(&SECRET_B), Ok(PUBLIC_B));
    let shared_a = shared_secret(&SECRET_A, &PUBLIC_B).expect("A derives with B");
    let shared_b = shared_secret(&SECRET_B, &PUBLIC_A).expect("B derives with A");
    assert_eq!(shared_a.as_bytes(), &SHARED_AB);
    assert_eq!(shared_b.as_bytes(), &SHARED_AB);
}

#[test]
fn deterministic_pairs_commute() {
    let mut state = 0x3010_7748_d1ff_1e55_u64;
    for case in 0..64 {
        let secret_a = random_secret(&mut state);
        let secret_b = random_secret(&mut state);
        let public_a = public_from_secret(&secret_a).expect("basepoint A");
        let public_b = public_from_secret(&secret_b).expect("basepoint B");
        let shared_a = shared_secret(&secret_a, &public_b).expect("A with B");
        let shared_b = shared_secret(&secret_b, &public_a).expect("B with A");
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes(), "case {case}");
    }
}

#[test]
fn wycheproof_style_adversarial_corpus_matches_the_x301_contract() {
    let document: serde_json::Value = serde_json::from_str(include_str!(
        "../../../reference/x301/x301-wycheproof-corpus.json"
    ))
    .expect("the generated adversarial corpus parses");
    let cases = document["cases"]
        .as_array()
        .expect("the adversarial corpus has a case array");
    assert_eq!(
        document["schema"].as_str(),
        Some("x301-wycheproof-taxonomy-v1")
    );
    assert_eq!(document["case_count"].as_u64(), Some(559));
    assert_eq!(
        document["case_sha256"].as_str(),
        Some("519724ffa7c2cbd205f40203be02e0fb092325ecaaf6e10f34a41bbac1640b62")
    );
    assert_eq!(cases.len(), 559);

    let mut family_counts = std::collections::BTreeMap::<&str, usize>::new();
    for case in cases {
        let tc_id = case["tcId"].as_u64().expect("numeric tcId");
        let family = case["family"].as_str().expect("case family");
        let operation = case["operation"].as_str().expect("case operation");
        let expected = case["expected"].as_str().expect("case expectation");
        let expected_error = case["expected_error"].as_str().expect("error code");
        let secret = decode_runtime_hex_vec(case["secret_hex"].as_str().expect("hex secret"));
        let public = decode_runtime_hex_vec(case["public_hex"].as_str().expect("hex public input"));
        let expected_output = decode_runtime_hex_vec(
            case["expected_output_hex"]
                .as_str()
                .expect("hex expected output"),
        );
        *family_counts.entry(family).or_default() += 1;

        match (operation, expected) {
            ("derive", "valid") => {
                let output = x301(&secret, &public)
                    .unwrap_or_else(|error| panic!("tcId {tc_id}: {error:?}"));
                assert_eq!(
                    &output.as_bytes()[..],
                    expected_output.as_slice(),
                    "tcId {tc_id}"
                );
            }
            ("derive", "invalid") => assert_eq!(
                x301(&secret, &public).err(),
                Some(adversarial_error(expected_error)),
                "tcId {tc_id}"
            ),
            ("public_from_secret", "valid") => assert_eq!(
                public_from_secret(&secret)
                    .unwrap_or_else(|error| panic!("tcId {tc_id}: {error:?}"))
                    .as_slice(),
                expected_output.as_slice(),
                "tcId {tc_id}"
            ),
            ("public_from_secret", "invalid") => assert_eq!(
                public_from_secret(&secret).err(),
                Some(adversarial_error(expected_error)),
                "tcId {tc_id}"
            ),
            _ => panic!("tcId {tc_id}: unsupported operation/expectation"),
        }
    }

    assert_eq!(family_counts.get("W1-LowOrderPublic"), Some(&3));
    assert_eq!(family_counts.get("W2-TwistPublic"), Some(&8));
    assert_eq!(family_counts.get("W3-NonCanonicalPublic"), Some(&10));
    assert_eq!(family_counts.get("W4-SpecialScalars"), Some(&8));
    assert_eq!(family_counts.get("W5-SharedSecretEdges"), Some(&8));
    assert_eq!(family_counts.get("W6-LengthAndType"), Some(&10));
    assert_eq!(family_counts.get("W-RandomValid"), Some(&512));
}

#[test]
#[ignore = "explicit P1-P4 1000-case property gate; run in release mode"]
fn x301_properties_hold_for_1000_deterministic_cases() {
    let mut state = 0x3010_7072_6f70_0001_u64;
    for case in 0..1000 {
        let secret_a = random_secret(&mut state);
        let secret_b = random_secret(&mut state);

        // P3: D3 clamping is idempotent and enforces the exact bit contract.
        let clamped = clamped_scalar_for_test(&secret_a);
        assert_eq!(clamped_scalar_for_test(&clamped), clamped, "case {case}");
        assert_eq!(clamped[0] & 3, 0, "case {case}");
        assert_eq!(clamped[SECRET_BYTES - 1] & 0xe0, 0, "case {case}");
        assert_ne!(clamped[SECRET_BYTES - 1] & 0x10, 0, "case {case}");

        let public_a = public_from_secret(&secret_a).expect("P1 public A");
        let public_b = public_from_secret(&secret_b).expect("P1 public B");

        // P4: every generated public value is strict-canonical and a
        // decode/encode roundtrip preserves its exact 38-byte encoding.
        validate_public_encoding(&public_a).expect("P4 canonical public");
        let decoded = Fe301::from_canonical_bytes(&public_a).expect_copied("P4 public decodes");
        assert_eq!(decoded.to_canonical_bytes(), public_a, "case {case}");

        // P1: XDH commutativity for independently generated scalar pairs.
        let shared_a = shared_secret(&secret_a, &public_b).expect("P1 A with B");
        let shared_b = shared_secret(&secret_b, &public_a).expect("P1 B with A");
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes(), "case {case}");

        // P2: the public X301 base multiplication agrees with the D1
        // birational image of the existing Edwards scalar multiplication.
        let edwards = EdwardsPoint::BASEPOINT.scalar_mul_pruned(&clamped);
        let encoded = edwards
            .encode_public_artifact()
            .expect("P2 Edwards result encodes");
        let mapped = edwards_y_to_montgomery_u(y_from_edwards_encoding(encoded));
        assert_eq!(mapped.to_canonical_bytes(), public_a, "case {case}");
    }
}

#[test]
fn rfc_style_iteration_results_are_frozen_at_one_and_one_thousand() {
    let mut scalar = BASE_U_BYTES;
    let mut u = BASE_U_BYTES;
    for iteration in 1..=1000 {
        let old_scalar = scalar;
        let output = x301(&old_scalar, &u).expect("iteration remains nonzero");
        scalar = *output.as_bytes();
        u = old_scalar;
        if iteration == 1 {
            assert_eq!(scalar, ITERATION_ONE);
        }
    }
    assert_eq!(scalar, ITERATION_THOUSAND);
}

#[test]
#[ignore = "explicit L1 one-million iteration gate; run in release mode"]
fn rfc_style_iteration_result_is_frozen_at_one_million() {
    let mut scalar = BASE_U_BYTES;
    let mut u = BASE_U_BYTES;
    for _ in 0..1_000_000 {
        let old_scalar = scalar;
        let output = x301(&old_scalar, &u).expect("iteration remains nonzero");
        scalar = *output.as_bytes();
        u = old_scalar;
    }
    assert_eq!(scalar, ITERATION_MILLION);
}

#[test]
fn d3_clamping_sets_and_clears_exact_bits_without_scalar_rejection() {
    let zero = clamped_scalar_for_test(&[0_u8; SECRET_BYTES]);
    assert_eq!(zero[0], 0);
    assert!(zero[1..SECRET_BYTES - 1].iter().all(|byte| *byte == 0));
    assert_eq!(zero[SECRET_BYTES - 1], 0x10);

    let ones = clamped_scalar_for_test(&[0xff_u8; SECRET_BYTES]);
    assert_eq!(ones[0], 0xfc);
    assert!(ones[1..SECRET_BYTES - 1].iter().all(|byte| *byte == 0xff));
    assert_eq!(ones[SECRET_BYTES - 1], 0x1f);

    let mut representative = [0x5a_u8; SECRET_BYTES];
    representative[0] = 0xa7;
    representative[SECRET_BYTES - 1] = 0xea;
    let clamped = clamped_scalar_for_test(&representative);
    assert_eq!(clamped[0], 0xa4);
    assert_eq!(clamped[SECRET_BYTES - 1], 0x1a);

    // The scalar which an earlier, nonstandard draft special-cased is a
    // normal D3 scalar. Its expected public key is independently calculated.
    assert_eq!(
        clamped_scalar_for_test(&FORMER_N_TWIST_RAW),
        FORMER_N_TWIST_RAW
    );
    assert_eq!(
        public_from_secret(&FORMER_N_TWIST_RAW),
        Ok(FORMER_N_TWIST_PUBLIC)
    );
}

#[test]
fn d2_rejects_wrong_lengths_modulus_boundaries_and_each_high_bit() {
    assert_eq!(public_from_secret(&[]), Err(X301Error::InvalidSecretLength));
    assert_eq!(
        public_from_secret(&[0_u8; SECRET_BYTES - 1]),
        Err(X301Error::InvalidSecretLength)
    );
    assert_eq!(
        public_from_secret(&[0_u8; SECRET_BYTES + 1]),
        Err(X301Error::InvalidSecretLength)
    );

    for public in [
        &[][..],
        &[0_u8; PUBLIC_BYTES - 1],
        &[0_u8; PUBLIC_BYTES + 1],
    ] {
        assert_eq!(
            validate_public_encoding(public),
            Err(X301Error::InvalidPublicLength)
        );
        assert!(matches!(
            shared_secret(&SECRET_A, public),
            Err(X301Error::InvalidPublicLength)
        ));
    }

    for public in [MODULUS, MODULUS_PLUS_ONE] {
        assert_eq!(
            validate_public_encoding(&public),
            Err(X301Error::NonCanonicalPublic)
        );
        assert!(matches!(
            shared_secret(&SECRET_A, &public),
            Err(X301Error::NonCanonicalPublic)
        ));
    }

    for mask in [0x20_u8, 0x40, 0x80] {
        let mut public = BASE_U_BYTES;
        public[PUBLIC_BYTES - 1] |= mask;
        assert_eq!(
            validate_public_encoding(&public),
            Err(X301Error::NonCanonicalPublic)
        );
    }
}

#[test]
fn d4_rejects_every_affine_main_and_twist_cofactor_coordinate() {
    let zero = [0_u8; PUBLIC_BYTES];
    let mut one = [0_u8; PUBLIC_BYTES];
    one[0] = 1;

    // The independent derivation is: u=0 is the sole rational affine
    // two-torsion coordinate because A^2-4 is nonsquare; the doubling
    // numerator (u^2-1)^2 adds u=+1 (main) and u=-1 (twist), both order four.
    // The identity has no affine u encoding.
    for public in [zero, one, MODULUS_MINUS_ONE] {
        assert_eq!(validate_public_encoding(&public), Ok(()));
        for secret in [SECRET_A, [0_u8; SECRET_BYTES], [0xff_u8; SECRET_BYTES]] {
            assert!(matches!(
                shared_secret(&secret, &public),
                Err(X301Error::AllZeroSharedSecret)
            ));
        }
    }
}

#[test]
fn fe301_cswap_obeys_both_public_choices() {
    let five = Fe301::from_u64(5);
    let seven = Fe301::from_u64(7);
    let mut left = five;
    let mut right = seven;
    Fe301::conditional_swap(&mut left, &mut right, Choice::FALSE);
    assert!(left.ct_eq(&five).to_bool());
    assert!(right.ct_eq(&seven).to_bool());

    Fe301::conditional_swap(&mut left, &mut right, Choice::TRUE);
    assert!(left.ct_eq(&seven).to_bool());
    assert!(right.ct_eq(&five).to_bool());
}

#[test]
fn d1_parameters_basepoint_and_random_multiples_follow_the_birational_map() {
    let edwards_a = Fe301::from_u64(u64::from(EDWARDS_A));
    let edwards_d = Fe301::from_u64(u64::from(EDWARDS_D));
    let denominator_inverse = edwards_a
        .sub(edwards_d)
        .invert()
        .expect_copied("a-d is nonzero");
    let montgomery_a = edwards_a
        .add(edwards_d)
        .mul_small(2)
        .mul(denominator_inverse);
    let montgomery_b = Fe301::from_u64(4).mul(denominator_inverse);
    assert!(montgomery_a.ct_eq(&montgomery_a_for_test()).to_bool());

    let base_y = y_from_edwards_encoding(BASEPOINT_ENCODING);
    let base_u = edwards_y_to_montgomery_u(base_y);
    assert_eq!(base_u.to_canonical_bytes(), BASE_U_BYTES);

    // Check the mapped base point on B*v^2 = u^3 + A*u^2 + u.
    let yy = base_y.square();
    let base_x = Fe301::sqrt_ratio(Fe301::ONE.sub(yy), edwards_a.sub(yy.mul(edwards_d)))
        .expect_copied("the frozen Edwards base point has an x coordinate");
    let v = base_u.mul(base_x.invert().expect_copied("base x is nonzero"));
    let left = montgomery_b.mul(v.square());
    let right = base_u
        .square()
        .mul(base_u)
        .add(montgomery_a.mul(base_u.square()))
        .add(base_u);
    assert!(left.ct_eq(&right).to_bool());

    // Scalar multiplication commutes with the map in both directions: map
    // each Edwards multiple to u, then recover y=(u-1)/(u+1).
    let mut state = 0xd1b1_a710_3010_0001_u64;
    for case in 0..64 {
        let raw = random_secret(&mut state);
        let clamped = clamped_scalar_for_test(&raw);
        let edwards = EdwardsPoint::BASEPOINT.scalar_mul_pruned(&clamped);
        let encoded = edwards
            .encode_public_artifact()
            .expect("internally generated Edwards multiple encodes");
        let expected_y = y_from_edwards_encoding(encoded);
        let expected_u = edwards_y_to_montgomery_u(expected_y);
        let actual_bytes = public_from_secret(&raw).expect("X301 public key");
        assert_eq!(actual_bytes, expected_u.to_canonical_bytes(), "case {case}");

        let actual_u = Fe301::from_canonical_bytes(&actual_bytes)
            .expect_copied("X301 public output is canonical");
        let recovered_y = actual_u
            .sub(Fe301::ONE)
            .mul(actual_u.add(Fe301::ONE).invert().expect_copied("u+1"));
        assert!(recovered_y.ct_eq(&expected_y).to_bool(), "case {case}");
    }
}

#[test]
#[ignore = "explicit 10^4-case T5 long test; run this named test in release mode"]
fn x301_python_oracle_matches_10000_cases_and_torsion_derivation() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = repository.join("reference/x301/x301_reference.py");
    let fixture = repository.join("reference/x301/x301-test-vectors.json");
    // `-O` proves that every oracle invariant is an explicit check rather
    // than a Python assertion which could disappear in optimized mode.
    let verification = Command::new("python3")
        .args(["-I", "-B", "-O"])
        .arg(&script)
        .arg("verify-vectors")
        .arg("--path")
        .arg(&fixture)
        .output()
        .expect("python3 must be available for the explicit T5 gate");
    assert!(
        verification.status.success(),
        "frozen oracle evidence failed: {}",
        String::from_utf8_lossy(&verification.stderr)
    );

    let output = Command::new("python3")
        .args(["-I", "-B", "-O"])
        .arg(script)
        .arg("emit-corpus")
        .args(["--count", "10000"])
        .output()
        .expect("python3 must be available for the explicit T5 gate");
    assert!(
        output.status.success(),
        "oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("oracle output is UTF-8");
    let evidence: serde_json::Value = serde_json::from_str(include_str!(
        "../../../reference/x301/x301-test-vectors.json"
    ))
    .expect("frozen X301 evidence parses");
    let expected_count = evidence["t5"]["count"]
        .as_u64()
        .expect("T5 count is an integer") as usize;
    let expected_first = evidence["t5"]["first_record"]
        .as_str()
        .expect("T5 first record");
    let expected_last = evidence["t5"]["last_record"]
        .as_str()
        .expect("T5 last record");

    let mut cases = 0_usize;
    let mut last_line = None;
    for line in stdout.lines() {
        if cases == 0 {
            assert_eq!(line, expected_first);
        }
        let columns: Vec<&str> = line.split('\t').collect();
        assert_eq!(columns.len(), 6, "case line {cases}");
        assert_eq!(
            columns[0].parse::<usize>().expect("numeric case index"),
            cases
        );
        let secret_a = decode_runtime_hex(columns[1]);
        let expected_public_a = decode_runtime_hex(columns[2]);
        let secret_b = decode_runtime_hex(columns[3]);
        let expected_public_b = decode_runtime_hex(columns[4]);
        let expected_shared = decode_runtime_hex(columns[5]);

        assert_eq!(public_from_secret(&secret_a), Ok(expected_public_a));
        assert_eq!(public_from_secret(&secret_b), Ok(expected_public_b));
        let shared_a = shared_secret(&secret_a, &expected_public_b).expect("A with B");
        let shared_b = shared_secret(&secret_b, &expected_public_a).expect("B with A");
        assert_eq!(shared_a.as_bytes(), &expected_shared, "case {cases}");
        assert_eq!(shared_b.as_bytes(), &expected_shared, "case {cases}");
        last_line = Some(line);
        cases += 1;
    }
    assert_eq!(cases, expected_count);
    assert_eq!(last_line, Some(expected_last));
}

fn y_from_edwards_encoding(mut encoded: [u8; FIELD_BYTES]) -> Fe301 {
    encoded[FIELD_BYTES - 1] &= 0x1f;
    Fe301::from_canonical_bytes(&encoded).expect_copied("canonical Edwards y")
}

fn edwards_y_to_montgomery_u(y: Fe301) -> Fe301 {
    Fe301::ONE
        .add(y)
        .mul(Fe301::ONE.sub(y).invert().expect_copied("y is not one"))
}

fn random_secret(state: &mut u64) -> [u8; SECRET_BYTES] {
    let mut output = [0_u8; SECRET_BYTES];
    let mut offset = 0;
    while offset < output.len() {
        let bytes = splitmix64(state).to_le_bytes();
        let take = core::cmp::min(bytes.len(), output.len() - offset);
        output[offset..offset + take].copy_from_slice(&bytes[..take]);
        offset += take;
    }
    output
}

fn decode_runtime_hex(value: &str) -> [u8; X301_BYTES] {
    assert_eq!(value.len(), X301_BYTES * 2);
    let mut output = [0_u8; X301_BYTES];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (hex_nibble(value.as_bytes()[index * 2]) << 4)
            | hex_nibble(value.as_bytes()[index * 2 + 1]);
    }
    output
}

fn decode_runtime_hex_vec(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex input has complete bytes");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn adversarial_error(code: &str) -> X301Error {
    match code {
        "secret_length" => X301Error::InvalidSecretLength,
        "length" => X301Error::InvalidPublicLength,
        "noncanonical" | "reserved_bits" => X301Error::NonCanonicalPublic,
        "all_zero" => X301Error::AllZeroSharedSecret,
        _ => panic!("unknown adversarial error code: {code}"),
    }
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid lowercase oracle hex"),
    }
}
