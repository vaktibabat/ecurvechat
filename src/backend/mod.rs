use std::{io, net::TcpStream};

use rand::{thread_rng, Rng};

use crate::{aes_ctr::AesCtr, hmac::HMAC, message::MessageStream, protos::ChatMessage};

pub mod client_ec;
pub mod server_ec;

/// The arguments the chat frontend needs to provide to use
/// server and client functions
pub struct ChatArguments {
    // The port of the server
    pub port: u16,
    // The address of the server
    pub address: String,
    // The TTP's port
    pub ttp_port: u16,
    // The TTP's address
    pub ttp_address: String,
    // User's name
    pub name: String,
    // User's organization
    pub org: String,
}

/// The connection with the peer
pub struct Peer {
    stream: Option<TcpStream>,
    pub cipher: Option<AesCtr>,
    pub hmac: Option<HMAC>,
}

pub enum HandshakeError {
    /// The other peer rejects our cert
    PeerRejects,
    /// The CA doesn't sign our cert
    CertNotSigned,
    /// The other peer wants to abort the handshake
    PeerAborts,
    /// The user hasn't filled all parameters (e.g. CA address)
    /// in the interactive CLI, so the handshake can't be carried out
    UnfilledParams,
    /// An error happened while the server accepted a connection
    ServerConnection,
    /// The user wants to abort the connection
    AbortConnection,
    /// The other peer's cert is not valid
    BadPeerCert,
}

impl Default for Peer {
    fn default() -> Self {
        Self::new()
    }
}

impl Peer {
    pub fn new() -> Peer {
        Peer {
            stream: None,
            cipher: None,
            hmac: None,
        }
    }

    pub fn stream(&self) -> Option<&TcpStream> {
        self.stream.as_ref()
    }

    pub fn send_encrypted(&mut self, msg: &[u8]) -> Result<usize, io::Error> {
        // Send the CTR mode nonce (the initial value of the counter)
        // using a constant nonce is bad, since it causes the same plaintext
        // to result in the same ciphertext
        let mut rng = thread_rng();
        let nonce = rng.gen::<usize>();
        // Encrypt the message
        let ciphertext = self.cipher.as_mut().unwrap().encrypt(msg, nonce);
        let mut msg = ChatMessage::new();
        msg.nonce = nonce.to_be_bytes().to_vec();
        // Compute a MAC on the ciphertext (i.e. encrypt-then-mac)
        msg.mac = self.hmac.as_ref().unwrap().mac(&ciphertext);
        msg.ciphertext = ciphertext;

        self.stream.as_mut().unwrap().send_msg(msg)
    }
}
