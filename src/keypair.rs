use num_bigint::{BigUint, RandBigInt};
use num_traits::Num;
use rand::thread_rng;
use sha256::digest;

use crate::elliptic_curves::{Curve, CurvePoint};

/// A keypair, containing a private key and a public key, along with some parameters
/// such as what curve is used, and the generator point
pub struct Keypair {
    // The private key d; This is the scalar by which we multiply the base point
    d: BigUint,
    // The public key Q = d * G, where G is the generator point
    pub_key: CurvePoint,
    // The curve used
    curve: Curve,
    // The generator point
    gen: (BigUint, BigUint),
    // The order of the curve. This is optional, since it's only required in case the user
    // wants to use ECDSA
    order: Option<BigUint>,
}

#[derive(Debug)]
pub enum KeypairError {
    // The user tried to use ECDSA w/o specifying the curve order
    SignatureWithoutOrder,
}

impl Keypair {
    /// Create a new Keypair, that lies on curve `curve` w/Generator `g`
    /// We also require the order `n` of the curve as a parameter, since this value is needed
    /// for ECDSA
    /// We require the user to specify the order of the curve explicitly,
    /// even though we could just derive it from the curve itself,
    /// since the order is pre-computed for some standardized curves (see the `std_curves.rs` module)
    pub fn new(curve: &Curve, g: &(BigUint, BigUint), order: Option<&BigUint>) -> Keypair {
        // Pick a private key d, which is a random number between 0 and p - 1, where p
        // is the modulus of the curve (i.e. the order of the field over which the curve is defined)
        let mut rng = thread_rng();
        let d = rng.gen_biguint_below(&curve.p());
        // Generate the public key Q, which is defined as d * G
        // First, convert g into a CurvePoint (point that lies on the curve we get as the argument)
        let g_point = curve.gen_point(Some((&g.0, &g.1)));
        let pub_key = g_point.clone().dot(&d);
        // That's it; Return a new Keypair now

        Keypair {
            d,
            pub_key,
            curve: curve.clone(),
            gen: g.clone(),
            order: order.cloned(),
        }
    }

    // Getters
    pub fn d(&self) -> BigUint {
        self.d.clone()
    }

    pub fn pub_key(&self) -> CurvePoint {
        self.pub_key.clone()
    }

    pub fn curve(&self) -> Curve {
        self.curve.clone()
    }

    pub fn order(&self) -> Option<BigUint> {
        self.order.clone()
    }

    pub fn gen(&self) -> (BigUint, BigUint) {
        self.gen.clone()
    }

    /// Derive a shared secret using ECDH (EC Diffie-Hellman); As input, this method takes in the other peer's
    /// public key, which is a CurvePoint
    /// We return the shared point (`d_A * d_B * G`), from which other methods can derive a secret
    /// (e.g. by hashing the two coordinates)
    pub fn ecdh_shared_secret(&self, peer_point: CurvePoint) -> (BigUint, BigUint) {
        let shared_point = peer_point.dot(&self.d);

        shared_point.point().coords().unwrap()
    }

    /// Sign a message m using ECDSA (EC Digital Signature Algorithm)
    /// This function receives, as input, the the bytes of the message to be signed
    /// and outputs the signature, which is of the form (r, s)
    /// Can also fail in case the user hadn't specified the order of the curve
    pub fn sign(&self, m: &[u8]) -> Result<(BigUint, BigUint), KeypairError> {
        if let Some(n) = &self.order {
            let mut rng = thread_rng();
            // We interpret the hash of the message as a number between 1 and n - 1
            // where n is the order of the curve
            let m_hash = (1u64 + BigUint::from_str_radix(&digest(m), 16).unwrap()) % n;
            // Pick a random number k between 1 and n - 1
            let k = rng.gen_biguint_range(&1u64.into(), n);
            // Compute R = kG
            let (gen_x, gen_y) = &self.gen;
            let base_point = self.curve.gen_point(Some((gen_x, gen_y)));
            let secret_point = base_point.dot(&k);
            // Set r = x_R mod n, and compute s = (h + rd) / k in modulo n
            // x_R is the x-coordinate of point R
            let r = secret_point.point().coords().unwrap().0 % n;
            let s = ((m_hash + &r * &self.d) * k.modinv(n).unwrap()) % n;

            return Ok((r, s));
        }

        Err(KeypairError::SignatureWithoutOrder)
    }

    /// Verifies a signature (r, s) for a message m, given the signer's public key, which is
    /// (presumably) used to sign m
    pub fn verify(
        &self,
        m: &[u8],
        sig: (BigUint, BigUint),
        peer_point: &CurvePoint,
    ) -> Result<bool, KeypairError> {
        if let Some(n) = &self.order {
            let (r, s) = sig;
            // This is equal to `k / (m_hash + rd)` in modulo n
            let w = s.modinv(n).unwrap();
            let m_hash = (1u64 + BigUint::from_str_radix(&digest(m), 16).unwrap()) % n;
            // Compute u and v, which are equal to `w * m_hash`, and `w * r`, respectively
            let u = (&w * m_hash) % n;
            let v = (&w * &r) % n;
            // Compute `Q = u * G + v * P`
            let (gen_x, gen_y) = &self.gen;
            let base_point = self.curve.gen_point(Some((gen_x, gen_y)));
            let capital_q = (base_point.dot(&u) + peer_point.dot(&v)).unwrap();
            // Accept iff the X-coordinate of Q is equal to r
            let q_x = capital_q.point().coords().unwrap().0;

            return Ok(q_x == r);
        }

        Err(KeypairError::SignatureWithoutOrder)
    }
}

#[cfg(test)]
mod tests {
    use crate::std_curves;

    use super::Keypair;

    #[test]
    fn test_ecdsa_valid_sig() {
        let curve_order = &std_curves::NIST_P_256_N;
        let keypair = Keypair::new(
            &std_curves::NIST_P_256,
            &std_curves::NIST_P_256_G,
            Some(&curve_order),
        );
        let my_msg = b"Hello, World!";
        let sig = keypair.sign(my_msg).unwrap();

        assert_eq!(
            keypair.verify(my_msg, sig, &keypair.pub_key()).unwrap(),
            true
        );
    }

    #[test]
    fn test_ecdsa_invalid_sig() {
        let curve_order = &std_curves::NIST_P_256_N;
        let keypair = Keypair::new(
            &std_curves::NIST_P_256,
            &std_curves::NIST_P_256_G,
            Some(&curve_order),
        );
        let my_msg = b"Hello, World!";
        // A fake signature; The `verify` function shouldn't accept this
        let sig = (1337u64.into(), 7331u64.into());

        assert_eq!(
            keypair.verify(my_msg, sig, &keypair.pub_key()).unwrap(),
            false
        );
    }
}
