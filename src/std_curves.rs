// This module contains definitions for standardized EC
use num_bigint::BigUint;
use num_traits::Num;
use once_cell::sync::Lazy;

use crate::elliptic_curves::Curve;

// ---------------------------CURVE PARAMETERS----------------------------
// NIST P-256 Curve parameters
const NIST_P_256_P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
const NIST_P_256_A: &str = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
const NIST_P_256_B: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
// Secp256k1 curve parameters; This is the curve used in Bitcoin
const SECP_256_K1_P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const SECP_256_K1_A: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const SECP_256_K1_B: &str = "0000000000000000000000000000000000000000000000000000000000000007";
// ----------------------------CURVES--------------------------------------
/// NIST P-256 Curve
pub static NIST_P_256: Lazy<Curve> = Lazy::new(|| {
    let p = BigUint::from_str_radix(NIST_P_256_P, 16).unwrap();
    let a = BigUint::from_str_radix(NIST_P_256_A, 16).unwrap();
    let b = BigUint::from_str_radix(NIST_P_256_B, 16).unwrap();

    Curve::new(a, b, p)
});
/// Secp256k1 Curve
pub static SECP_256_K1: Lazy<Curve> = Lazy::new(|| {
    let p = BigUint::from_str_radix(SECP_256_K1_P, 16).unwrap();
    let a = BigUint::from_str_radix(SECP_256_K1_A, 16).unwrap();
    let b = BigUint::from_str_radix(SECP_256_K1_B, 16).unwrap();

    Curve::new(a, b, p)
});
// ---------------------------GENERATOR POINTS----------------------------
// The generator coordinates for NIST P-256
const NIST_P_256_G_X: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const NIST_P_256_G_Y: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
// The generator coordinates for Secp256k1
const SECP_256_K1_G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const SECP_256_K1_G_Y: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
// ----------------------------GENERATORS---------------------------------
pub static NIST_P_256_G: Lazy<(BigUint, BigUint)> = Lazy::new(|| {
    (
        BigUint::from_str_radix(NIST_P_256_G_X, 16).unwrap(),
        BigUint::from_str_radix(NIST_P_256_G_Y, 16).unwrap(),
    )
});
pub static SECP_256_K1_G: Lazy<(BigUint, BigUint)> = Lazy::new(|| {
    (
        BigUint::from_str_radix(SECP_256_K1_G_X, 16).unwrap(),
        BigUint::from_str_radix(SECP_256_K1_G_Y, 16).unwrap(),
    )
});
// -----------------------------CURVE ORDERS------------------------------
/// The order of the NIST P-256 Curve
pub static NIST_P_256_N: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from_str_radix(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        16,
    )
    .unwrap()
});
/// The order of the Secp256k1 curve
pub static SECP_256_K1_N: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from_str_radix(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap()
});
