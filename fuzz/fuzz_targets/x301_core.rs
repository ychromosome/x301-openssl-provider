#![no_main]

use ed301_eddsa::x301::{
    BASE_U_BYTES, X301_BYTES, public_from_secret, shared_secret, validate_public_encoding,
};
use libfuzzer_sys::fuzz_target;

const PAIR_BYTES: usize = X301_BYTES * 2;
const MODULUS: [u8; X301_BYTES] = [
    0xb3, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x1f,
];

fuzz_target!(|data: &[u8]| {
    assert_eq!(validate_public_encoding(data).is_ok(), data.len() == X301_BYTES);

    if let Some(expected) = canonicalize_oracle(data) {
        match (shared_secret(data, data), shared_secret(data, &expected)) {
            (Ok(left), Ok(right)) => assert_eq!(left.as_bytes(), right.as_bytes()),
            (Err(left), Err(right)) => assert_eq!(left, right),
            _ => panic!("alias and canonical coordinate disagree"),
        }
    }

    let _ = public_from_secret(data);
    let _ = shared_secret(data, data);

    let Ok(pair) = <&[u8; PAIR_BYTES]>::try_from(data) else {
        return;
    };
    let secret_a: &[u8; X301_BYTES] = pair[..X301_BYTES]
        .try_into()
        .expect("fixed first scalar slice");
    let secret_b: &[u8; X301_BYTES] = pair[X301_BYTES..]
        .try_into()
        .expect("fixed second scalar slice");

    let public_a = public_from_secret(secret_a).expect("38-byte scalar A");
    let public_b = public_from_secret(secret_b).expect("38-byte scalar B");
    let ladder_public_a = shared_secret(secret_a, &BASE_U_BYTES).expect("basepoint ladder A");
    let ladder_public_b = shared_secret(secret_b, &BASE_U_BYTES).expect("basepoint ladder B");
    assert_eq!(public_a, *ladder_public_a.as_bytes());
    assert_eq!(public_b, *ladder_public_b.as_bytes());

    let shared_ab = shared_secret(secret_a, &public_b).expect("A with public B");
    let shared_ba = shared_secret(secret_b, &public_a).expect("B with public A");
    assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());

    let mut clamp_alias = *secret_a;
    clamp_alias[0] ^= 0x03;
    clamp_alias[X301_BYTES - 1] ^= 0xf0;
    let alias_public = public_from_secret(&clamp_alias).expect("clamp alias");
    assert_eq!(public_a, alias_public);
});

fn canonicalize_oracle(value: &[u8]) -> Option<[u8; X301_BYTES]> {
    let Ok(value) = <&[u8; X301_BYTES]>::try_from(value) else {
        return None;
    };

    let mut output = *value;
    output[X301_BYTES - 1] &= 0x1f;
    if output
        .iter()
        .rev()
        .cmp(MODULUS.iter().rev())
        .is_lt()
    {
        return Some(output);
    }

    let mut borrow = 0_u16;
    for (byte, modulus) in output.iter_mut().zip(MODULUS) {
        let right = u16::from(modulus) + borrow;
        let left = u16::from(*byte);
        *byte = left.wrapping_sub(right) as u8;
        borrow = u16::from(left < right);
    }
    if borrow != 0 {
        return None;
    }
    Some(output)
}
