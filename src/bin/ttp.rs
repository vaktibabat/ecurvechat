use std::{
    io::{self, stdin, stdout, Write},
    net::{TcpListener, TcpStream},
};

use protobuf::Message;
use ecurvechat::protos::{
    CurveParameters, GetTtpPubkey, TtpGetSignature, TtpSignResponse,
};
use ecurvechat::{
    keypair::Keypair,
    message::{MessageStream, TypedMessageReader},
    std_curves,
    ttp_msg_codes::*,
};

fn handle_get_pubkey_req(stream: &mut TcpStream, keypair: &Keypair) -> Result<usize, io::Error> {
    // Construct the CurveParameters message, which contains our pubkey
    let curve_params = CurveParameters::from(keypair);
    // Send the pubkey to the client over the stream
    stream.send_msg(curve_params)
}

// Handle a request to sign a certificate
fn handle_get_sig_req(
    stream: &mut TcpStream,
    keypair: &Keypair,
    req: TtpGetSignature,
) -> Result<usize, io::Error> {
    // The name and organization of the signee
    let (name, org) = (&req.name, &req.org);

    print!(
        r#"Got a request to sign a certificate for the following person:
----------------------
Name: {}
Organization: {}
----------------------
Do you want to sign the certificate? (y/n):
"#,
        name, org
    );

    let should_sign;

    let mut input = String::new();

    loop {
        print!("Enter 'y' or 'n': ");
        stdout().flush().unwrap();

        stdin().read_line(&mut input).expect("Failed to read line");
        input = input.trim().to_lowercase();

        if input == "y" {
            should_sign = true;
            break;
        } else if input == "n" {
            should_sign = false;
            break;
        } else {
            println!("Invalid input. Please enter 'y' or 'n'.");
            input.clear();
        }
    }

    if should_sign {
        // Construct the certificate, which is the data we sign
        // We can just do this by converting the request to bytes
        // since it contains, by design, all the data we need
        let cert = req.write_to_bytes().unwrap();
        // Sign the cert
        let (r, s) = keypair.sign(&cert).unwrap();
        // Construct a response, and send it to the client
        let mut sign_response = TtpSignResponse::new();
        sign_response.signed = true;
        sign_response.r = Some(r.to_bytes_be());
        sign_response.s = Some(s.to_bytes_be());

        return stream.send_msg(sign_response);
    }

    let mut sign_response = TtpSignResponse::new();
    sign_response.signed = false;
    sign_response.r = None;
    sign_response.s = None;

    stream.send_msg(sign_response)
}

fn handle_stream(stream: &mut TcpStream, keypair: &Keypair) -> Result<(), io::Error> {
    loop {
        // Read the protobuf from the client
        let typed_msg = stream
            .receive_typed_msg()
            .expect("Failed to receive message from client");

        match typed_msg.msg_type() {
            // The client requested our public key
            TTP_PUBKEY_MSG => {
                let _ = GetTtpPubkey::parse_from_bytes(&typed_msg.payload()).unwrap();

                handle_get_pubkey_req(stream, keypair).expect("Failed to send pubkey to client");
            }
            // The client requested us to sign a cert
            TTP_SIG_REQ_MSG => {
                let get_sig_req = TtpGetSignature::parse_from_bytes(&typed_msg.payload()).unwrap();

                handle_get_sig_req(stream, keypair, get_sig_req).unwrap();
            }
            TTP_BYE_MSG => break,
            // Unknown message type
            _ => {
                println!("Unknown message type {}", typed_msg.msg_type());
            }
        }
    }

    Ok(())
}

fn main() {
    println!("Listening on port 8888...");
    let listener = TcpListener::bind("127.0.0.1:8888").unwrap();
    let keypair = Keypair::new(
        &std_curves::SECP_256_K1,
        &std_curves::SECP_256_K1_G,
        Some(&std_curves::SECP_256_K1_N),
    );

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();

        handle_stream(&mut stream, &keypair).expect("Error occurred while handling client");
    }
}
