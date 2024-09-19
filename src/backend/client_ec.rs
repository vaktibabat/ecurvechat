use num_bigint::BigUint;

use crate::protos::{AbortHandshake, ShowCertificate, TtpBye, ValidationResponse};
use crate::{
    client_server_shared::*,
    keypair::Keypair,
    message::{MessageStream, TypedMessageSender},
    std_curves,
};
use std::net::TcpStream;

use super::{ChatArguments, HandshakeError, Peer};

pub fn client_ec(
    state: &ChatArguments,
    peer: &mut Peer,
) -> Result<(BigUint, BigUint), HandshakeError> {
    let curve = &std_curves::NIST_P_256;
    // Generate a keypair
    let keypair = Keypair::new(
        curve,
        &std_curves::NIST_P_256_G,
        Some(&std_curves::NIST_P_256_N),
    );
    // Generate our identity
    let identity = IdentityInfo::new(&keypair, &state.name, &state.org);
    let mut ttp_stream =
        TcpStream::connect(format!("{}:{}", state.ttp_address, state.ttp_port)).unwrap();
    let (ttp_curve_keypair, ttp_pubkey) = get_ttp_pubinfo(&mut ttp_stream);
    // Request the TTP to sign our cert
    let (ttp_sign_req, ttp_sig) = identity.ask_ttp_cert(&mut ttp_stream);

    // Bye bye TTP
    let bye_msg = TtpBye::new();
    ttp_stream.send_typed_msg(bye_msg, TTP_BYE_MSG).unwrap();

    // If the TTP hasn't signed our cert, we can't continue the handshake
    if !ttp_sig.signed {
        eprintln!("CA hasn't agreed to sign our cert.");
        return Err(HandshakeError::CertNotSigned);
    }

    // Connect to server
    let mut stream = TcpStream::connect(format!("{}:{}", state.address, state.port)).unwrap();
    // Show it our cert
    show_peer_cert(&mut stream, ttp_sign_req, ttp_sig);

    // Check whether the server has validated our identity
    let is_identity_valid = MessageStream::<ValidationResponse>::receive_msg(&mut stream).unwrap();

    if !is_identity_valid.is_valid {
        eprintln!("Server says that our identity is invalid.");
        return Err(HandshakeError::PeerRejects);
    }
    // Check whether the server wants to abort the handshake
    let abort_handshake = MessageStream::<AbortHandshake>::receive_msg(&mut stream).unwrap();

    if abort_handshake.is_abort {
        eprintln!("The other peer wants to abort the handshake.");
        stream.shutdown(std::net::Shutdown::Both).unwrap();
        return Err(HandshakeError::PeerAborts);
    }

    // Validate the server's cert
    let server_cert = MessageStream::<ShowCertificate>::receive_msg(&mut stream).unwrap();

    // Verify the signature on the certificate using the TTP's pubkey
    let is_server_valid = server_cert.validate_peer_cert(&ttp_curve_keypair, &ttp_pubkey);
    send_val_status(&mut stream, is_server_valid).unwrap();

    if !is_server_valid {
        eprintln!("The server's certificate is not valid. Aborting handshake...");
        stream.shutdown(std::net::Shutdown::Both).unwrap();
        
        return Err(HandshakeError::BadPeerCert);
    }

    // Ask the user whether they want to continue the handshake, based on the (validated by the CA) identity
    // of the server
    let should_continue = ask_user_peer(&server_cert);
    // Tell the server whether the user wants to abort the message
    send_abort_msg(&mut stream, !should_continue).unwrap();

    if !should_continue {
        stream.shutdown(std::net::Shutdown::Both).unwrap();
        return Err(HandshakeError::AbortConnection);
    }

    // At this point, since both sides have each other's certs (and hence each other's pubkeys)
    // we can perform an ECDH and establish a shared secret
    let shared_secret = server_cert.est_shared_secret(&keypair);

    peer.stream = Some(stream);

    Ok(shared_secret)
}
