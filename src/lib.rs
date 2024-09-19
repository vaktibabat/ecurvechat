use elliptic_curves::Curve;
use keypair::Keypair;
use num_bigint::BigUint;
use protos::CurveParameters;

pub mod aes_ctr;
pub mod backend;
pub mod client_server_shared;
pub mod elliptic_curves;
pub mod hmac;
pub mod keypair;
pub mod message;
pub mod std_curves;
pub mod ttp_msg_codes;
include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));

impl From<&Keypair> for CurveParameters {
    fn from(value: &Keypair) -> Self {
        let mut curve_params = CurveParameters::new();
        let curve = value.curve();
        curve_params.p = curve.p().to_bytes_be();
        curve_params.a = curve.a().to_bytes_be();
        curve_params.b = curve.b().to_bytes_be();
        curve_params.order = value.order().unwrap().to_bytes_be();
        let (gen_x, gen_y) = value.gen();
        curve_params.x = gen_x.to_bytes_be();
        curve_params.y = gen_y.to_bytes_be();
        let (pub_x, pub_y) = value.pub_key().point().coords().unwrap();
        curve_params.pub_x = pub_x.to_bytes_be();
        curve_params.pub_y = pub_y.to_bytes_be();

        curve_params
    }
}

// Construct a new keypair on the curve described by CurveParameters
impl From<&CurveParameters> for Keypair {
    fn from(value: &CurveParameters) -> Self {
        let (a, b, p) = (
            BigUint::from_bytes_be(&value.a),
            BigUint::from_bytes_be(&value.b),
            BigUint::from_bytes_be(&value.p),
        );
        let curve = Curve::new(a, b, p);
        let (x, y) = (
            BigUint::from_bytes_be(&value.x),
            BigUint::from_bytes_be(&value.y),
        );
        let order = BigUint::from_bytes_be(&value.order);

        Keypair::new(&curve, &(x, y), Some(&order))
    }
}
