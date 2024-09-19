use num_bigint::BigUint;

use crate::backend::HandshakeError;
use crate::protos::{AbortHandshake, ShowCertificate, TtpBye, ValidationResponse};
use crate::{
    client_server_shared::*,
    keypair::Keypair,
    message::{MessageStream, TypedMessageSender},
    std_curves,
};
use std::net::{TcpListener, TcpStream};

use super::{ChatArguments, Peer};

pub fn server_ec(
    args: &ChatArguments,
    peer: &mut Peer,
) -> Result<(BigUint, BigUint), HandshakeError> {
    let curve = &std_curves::NIST_P_256;
    // Generate a keypair
    let keypair = Keypair::new(
        curve,
        &std_curves::NIST_P_256_G,
        Some(&std_curves::NIST_P_256_N),
    );
    // Generate our identity so we can sign a cert
    let identity = IdentityInfo::new(&keypair, &args.name, &args.org);
    let mut ttp_stream =
        TcpStream::connect(format!("{}:{}", args.ttp_address, args.ttp_port)).unwrap();
    // Ask the TTP for its pubkey
    let (ttp_curve_keypair, ttp_pubkey) = get_ttp_pubinfo(&mut ttp_stream);
    // Ask the TTP for a cert
    let (ttp_sign_req, ttp_sig) = identity.ask_ttp_cert(&mut ttp_stream);

    // Bye bye TTP
    let bye_msg = TtpBye::new();
    ttp_stream.send_typed_msg(bye_msg, TTP_BYE_MSG).unwrap();

    if !ttp_sig.signed {
        eprintln!("The CA hasn't signed our cert.");
        return Err(HandshakeError::CertNotSigned);
    }

    // Start the server
    println!("Listening on port {}...", args.port);
    let listener = TcpListener::bind(format!("{}:{}", args.address, args.port)).unwrap();

    if let Some(stream) = listener.incoming().next() {
        let mut stream = stream.unwrap();
        // Wait for client's cert
        let client_cert = MessageStream::<ShowCertificate>::receive_msg(&mut stream).unwrap();

        // Verify the signature on the certificate using the TTP's pubkey
        let is_client_valid = client_cert.validate_peer_cert(&ttp_curve_keypair, &ttp_pubkey);

        send_val_status(&mut stream, is_client_valid).unwrap();
        // Ask the user whether they want to continue the handshake,
        // based on the (now validated by the CA) identity of the client
        let should_continue = ask_user_peer(&client_cert);

        send_abort_msg(&mut stream, !should_continue).unwrap();

        if !should_continue {
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            return Err(HandshakeError::AbortConnection);
        }

        // Send our certificate for the client to validate
        show_peer_cert(&mut stream, ttp_sign_req.clone(), ttp_sig.clone());

        let is_identity_valid =
            MessageStream::<ValidationResponse>::receive_msg(&mut stream).unwrap();

        if !is_identity_valid.is_valid {
            eprintln!("Client says that our identity is invalid.");
            stream.shutdown(std::net::Shutdown::Both).unwrap();

            return Err(HandshakeError::PeerRejects);
        }

        let client_aborts = MessageStream::<AbortHandshake>::receive_msg(&mut stream).unwrap();

        if client_aborts.is_abort {
            eprintln!("The client wants to abort the handshake.");
            stream.shutdown(std::net::Shutdown::Both).unwrap();

            return Err(HandshakeError::PeerAborts);
        }

        // We use the SHA256 of the x-coordinate as the AES-CTR key
        peer.stream = Some(stream);
        // At this point, since both sides have each other's certs (and hence each other's pubkeys)
        // we can perform an ECDH and establish a shared secret
        Ok(client_cert.est_shared_secret(&keypair))
    } else {
        Err(HandshakeError::ServerConnection)
    }
}
