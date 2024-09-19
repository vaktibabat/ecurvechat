use std::{
    io::{self, stdin, stdout, Write},
    net::TcpStream,
};

use num_bigint::BigUint;
use protobuf::{Message, MessageField};

use crate::{
    elliptic_curves::{Curve, CurvePoint},
    keypair::Keypair,
    message::{MessageStream, TypedMessageSender},
    protos::{
        AbortHandshake, CurveParameters, GetTtpPubkey, ShowCertificate, TtpGetSignature,
        TtpSignResponse, ValidationResponse,
    },
};

pub const TTP_PUBKEY_MSG: u8 = 0u8;
pub const TTP_SIG_REQ_MSG: u8 = 1u8;
pub const TTP_BYE_MSG: u8 = 2u8;

/// This information identifies each user, and is required for the TTP
/// to grant one a cert
pub struct IdentityInfo<'a> {
    /// Keypair of the grantee
    keypair: &'a Keypair,
    /// Name of the grantee (e.g. John Doe)
    name: String,
    /// Oranization of the grantee (e.g. Example Organization Inc.)
    org: String,
}

/// Given a stream to the TTP, (1) generate a keypair on the TTP's curve
/// and (2) return the TTP's pubkey as a CurvePoint
pub fn get_ttp_pubinfo(ttp_stream: &mut TcpStream) -> (Keypair, CurvePoint) {
    // Ask the TTP for its pubkey
    let get_pubkey_req = GetTtpPubkey::new();

    ttp_stream
        .send_typed_msg(get_pubkey_req, TTP_PUBKEY_MSG)
        .unwrap();

    let ttp_pubkey_msg = MessageStream::<CurveParameters>::receive_msg(ttp_stream).unwrap();

    let (a, b, p) = (
        BigUint::from_bytes_be(&ttp_pubkey_msg.a),
        BigUint::from_bytes_be(&ttp_pubkey_msg.b),
        BigUint::from_bytes_be(&ttp_pubkey_msg.p),
    );
    let ttp_curve = Curve::new(a, b, p);
    let (x, y) = (
        BigUint::from_bytes_be(&ttp_pubkey_msg.x),
        BigUint::from_bytes_be(&ttp_pubkey_msg.y),
    );
    let order = BigUint::from_bytes_be(&ttp_pubkey_msg.order);
    // Generate our keypair on the **TTP**'s curve, which may be different than the curve used
    // to talk to the client
    let ttp_curve_keypair = Keypair::new(&ttp_curve, &(x, y), Some(&order));
    // The TTP's pubkey
    let ttp_pubkey_coords = (
        BigUint::from_bytes_be(&ttp_pubkey_msg.pub_x),
        BigUint::from_bytes_be(&ttp_pubkey_msg.pub_y),
    );
    let ttp_pubkey = ttp_curve.gen_point(Some((&ttp_pubkey_coords.0, &ttp_pubkey_coords.1)));

    (ttp_curve_keypair, ttp_pubkey)
}

/// Establish the shared secret, given our (the server's) keypair, and the client's cert (which includes the
/// client's pubkey)
pub fn est_shared_secret(client_cert: ShowCertificate, keypair: &Keypair) -> (BigUint, BigUint) {
    let client_pubkey_info = client_cert.cert.unwrap().pub_key.unwrap();
    let (client_pub_x, client_pub_y) = (
        BigUint::from_bytes_be(&client_pubkey_info.pub_x),
        BigUint::from_bytes_be(&client_pubkey_info.pub_y),
    );
    let curve = keypair.curve();
    let server_pubkey = curve.gen_point(Some((&client_pub_x, &client_pub_y)));

    keypair.ecdh_shared_secret(server_pubkey)
}

/// Send the other side our cert, given a reference to the cert data, and the TTP's signature
pub fn show_peer_cert(stream: &mut TcpStream, cert: TtpGetSignature, ttp_sig: TtpSignResponse) {
    let mut cert_show_msg = ShowCertificate::new();
    cert_show_msg.cert = MessageField::some(cert);
    cert_show_msg.r = ttp_sig.r.unwrap();
    cert_show_msg.s = ttp_sig.s.unwrap();

    stream.send_msg(cert_show_msg).unwrap();
}

/// Tell the other side whether their cert is valid
pub fn send_val_status(stream: &mut TcpStream, val_status: bool) -> Result<usize, std::io::Error> {
    let mut msg = ValidationResponse::new();
    msg.is_valid = val_status;

    stream.send_msg(msg)
}

/// Print the other side's identity from their cert
pub fn print_cert_identity(show_cert: &ShowCertificate) {
    println!(
        "---\nName: {}\nOrganization: {}\n---",
        show_cert.cert.name, show_cert.cert.org
    );
}

/// Ask the user whether they want to talk with the other peer
pub fn ask_user_peer(show_cert: &ShowCertificate) -> bool {
    println!("The other peer presents itself as follows: ");
    print_cert_identity(show_cert);
    println!("Is this who you want to talk to? (y/n): ");
    let should_continue;
    let mut input = String::new();

    loop {
        print!("Enter 'y' or 'n': ");
        stdout().flush().unwrap();

        stdin().read_line(&mut input).expect("Failed to read line");
        input = input.trim().to_lowercase();

        if input == "y" {
            should_continue = true;
            break;
        } else if input == "n" {
            should_continue = false;
            break;
        } else {
            println!("Invalid input. Please enter 'y' or 'n'.");
            input.clear();
        }
    }

    should_continue
}

// Tell the other peer whether the user wants to continue the handshake
// or abort it
pub fn send_abort_msg(stream: &mut TcpStream, is_abort: bool) -> Result<usize, io::Error> {
    let mut msg = AbortHandshake::new();
    msg.is_abort = is_abort;

    stream.send_msg(msg)
}

impl ShowCertificate {
    /// Establish the shared secret using the other side's cert (self) and our keypair
    pub fn est_shared_secret(self, keypair: &Keypair) -> (BigUint, BigUint) {
        let client_pubkey_info = self.cert.unwrap().pub_key.unwrap();
        let (client_pub_x, client_pub_y) = (
            BigUint::from_bytes_be(&client_pubkey_info.pub_x),
            BigUint::from_bytes_be(&client_pubkey_info.pub_y),
        );
        let curve = keypair.curve();
        let server_pubkey = curve.gen_point(Some((&client_pub_x, &client_pub_y)));

        keypair.ecdh_shared_secret(server_pubkey)
    }

    /// Validate the client's cert. Also requires our keypair on the TTP's curve
    /// and the TTP's pubkey (since the cert is validated against the TTP's pubkey)
    pub fn validate_peer_cert(&self, ttp_curve_keypair: &Keypair, ttp_pubkey: &CurvePoint) -> bool {
        let client_cert_bytes = self.cert.write_to_bytes().unwrap();
        let sig = (
            BigUint::from_bytes_be(&self.r),
            BigUint::from_bytes_be(&self.s),
        );

        ttp_curve_keypair
            .verify(&client_cert_bytes, sig, ttp_pubkey)
            .unwrap()
    }
}

impl<'a> IdentityInfo<'a> {
    /// Generate a new IdentityInfo
    /// We receive string slices as arguments and convert them to Strings inside
    /// the function to save work
    pub fn new(keypair: &'a Keypair, name: &str, org: &str) -> IdentityInfo<'a> {
        IdentityInfo {
            keypair,
            name: name.to_string(),
            org: org.to_string(),
        }
    }

    /// Ask the TTP for a certificate, given our pubkey (the one on the **server's curve** and not the TTP's curve)
    /// and a stream to the TTP
    /// The TTP's curve is only used to validate the TTP's signatures
    /// This function also returns the certificiate which is the actual data being signed
    pub fn ask_ttp_cert(self, ttp_stream: &mut TcpStream) -> (TtpGetSignature, TtpSignResponse) {
        // Request the TTP to sign our cert
        let ttp_get_signature = TtpGetSignature::new();
        let mut ttp_sign_req = ttp_get_signature;
        let curve_params = CurveParameters::from(self.keypair);
        ttp_sign_req.pub_key = MessageField::some(curve_params);
        ttp_sign_req.name = self.name;
        ttp_sign_req.org = self.org;

        ttp_stream
            .send_typed_msg(ttp_sign_req.clone(), TTP_SIG_REQ_MSG)
            .unwrap();
        // Read the response we got
        (
            ttp_sign_req,
            MessageStream::<TtpSignResponse>::receive_msg(ttp_stream).unwrap(),
        )
    }
}
