use std::{
    io::{stdin, stdout, Write},
    net::{Ipv4Addr, TcpStream},
    thread,
};

use num_bigint::BigUint;
use num_traits::Num;
use ecurvechat::{
    aes_ctr::AesCtr,
    backend::{client_ec, server_ec, ChatArguments, HandshakeError, Peer},
    hmac::HMAC,
    message::MessageStream,
    protos::ChatMessage,
};

pub enum CommandType {
    Set,
    Connect,
    Listen,
    Send,
    Help,
    Exit,
    Unk,
}

#[derive(Clone, Copy)]
pub enum Algorithm {
    EllipticCurve,
    RSA,
}

pub struct Command {
    op: CommandType,
    args: Vec<String>,
}

// The current state of the chat - e.g. what is the TTP's IP and Address, what algorithm should be used etc.
#[derive(Clone)]
pub struct State {
    server_addr: Option<Ipv4Addr>,
    server_port: Option<u16>,
    ttp_addr: Option<Ipv4Addr>,
    ttp_port: Option<u16>,
    algo: Algorithm,
    name: Option<String>,
    org: Option<String>,
}

fn check_state_full(state: &State) -> bool {
    let mut is_missing = false;

    if state.server_addr.is_none() {
        eprintln!("Server address (variable 'address') not set.");
        eprintln!("Please fill it ('set address ...') before running the command.");

        is_missing = true;
    }
    if state.server_port.is_none() {
        eprintln!("Server port (variable 'port') not set.");
        eprintln!("Please fill it ('set port ...') before running the command.");

        is_missing = true;
    }
    if state.ttp_addr.is_none() {
        eprintln!("CA address (variable 'ttp_addr') not set.");
        eprintln!("Please fill it ('set ttp_addr ...') before running the command");

        is_missing = true;
    }
    if state.ttp_port.is_none() {
        eprintln!("CA port (variable 'ttp_port') not set.");
        eprintln!("Please fill it ('set ttp_port ...') before running the command");

        is_missing = true;
    }
    if state.name.is_none() {
        eprintln!("Your name is not set.");
        eprintln!("Please fill it ('set name ...') before running the command.");

        is_missing = true;
    }
    if state.server_addr.is_none() {
        eprintln!("Your organization is not set.");
        eprintln!("Please fill it ('set org ...') before running the command.");

        is_missing = true;
    }

    !is_missing
}

fn help() {
    println!("set - Change the state of the chat. Variables are shown below.");
    println!("set address <IPv4 Address> - set the address of the server");
    println!("set port <port> - set the port of the server");
    println!("set ttp_addr <IPv4 Address> - set the address of the CA");
    println!("set ttp_port <port> - set the port of the CA");
    println!("set name <your name> - configure the name shown on your certificate");
    println!("set org <organization> - configure the organization shown on your certificate");
    println!("listen - start a server");
    println!("connect - connect to a server");
    println!("send <message> - send an encrypted message");
    println!("exit - exit");
    println!("help - show this help message");
}

fn set(args: Vec<String>, state: &mut State) {
    let var_name = &args[0];
    let value = &args[1];

    match var_name.as_str() {
        "address" => {
            if let Ok(server_addr) = value.as_str().parse::<Ipv4Addr>() {
                state.server_addr = Some(server_addr)
            } else {
                eprintln!("Bad value for server address: '{}'", value);
                eprintln!("Server address should be an IPv4 address in the format x.x.x.x");
            }
        }
        "port" => {
            if let Ok(server_port) = value.as_str().parse::<u16>() {
                state.server_port = Some(server_port)
            } else {
                eprintln!("Bad value for port: '{}'", value);
                eprintln!("Port value should be an integer in the range 1-65536");
            }
        }
        "ttp_addr" => {
            if let Ok(ttp_addr) = value.as_str().parse::<Ipv4Addr>() {
                state.ttp_addr = Some(ttp_addr)
            } else {
                eprintln!("Bad value for server address: '{}'", value);
                eprintln!("Server address should be an IPv4 address in the format x.x.x.x");
            }
        }
        "ttp_port" => {
            if let Ok(ttp_port) = value.as_str().parse::<u16>() {
                state.ttp_port = Some(ttp_port)
            } else {
                eprintln!("Bad value for port: '{}'", value);
                eprintln!("Port value should be an integer in the range 1-65536");
            }
        }
        "algo" => {
            state.algo = if value.as_str() == "rsa" {
                Algorithm::RSA
            } else {
                Algorithm::EllipticCurve
            }
        }
        "name" => {
            // If the value to be set is a name, e.g. "John Doe", we captialize each first letter
            // and take all the tokens instead of just one
            let value = &args[1..]
                .iter()
                .map(|x| x.to_owned() + " ")
                .collect::<Vec<String>>()
                .concat();
            state.name = Some(value.clone())
        }
        "org" => {
            // If the value to be set is an organization, e.g. "Test Org Inc.", we captialize each first letter
            // and take all the tokens instead of just one
            let value = &args[1..]
                .iter()
                .map(|x| x.to_owned() + " ")
                .collect::<Vec<String>>()
                .concat();
            state.org = Some(value.clone())
        }
        _ => println!("Unknown variable '{}'.", var_name),
    }
}

fn listen(state: &State, peer: &mut Peer) -> Result<(), HandshakeError> {
    // Make sure that the state has all the values we need
    if !check_state_full(state) {
        return Err(HandshakeError::UnfilledParams);
    }

    match state.algo {
        Algorithm::EllipticCurve => {
            let args = ChatArguments::from(state);
            // Use the hash of the x-coordinate of the shared secret returned by ECDH
            // as an AES-CTR key
            let shared_secret = server_ec::server_ec(&args, peer)?.0;
            let key =
                BigUint::from_str_radix(&sha256::digest(shared_secret.to_bytes_be()), 16).unwrap();
            let cipher = AesCtr::new(&key.to_bytes_be());
            let hmac = HMAC::new(&key.to_bytes_be());
            peer.cipher = Some(cipher);
            peer.hmac = Some(hmac);
        }
        Algorithm::RSA => {
            //println!("Unimplemented server for RSA.");
        }
    }

    Ok(())
}

fn connect(state: &State, peer: &mut Peer) -> Result<(), HandshakeError> {
    if !check_state_full(state) {
        return Err(HandshakeError::UnfilledParams);
    }

    match state.algo {
        Algorithm::EllipticCurve => {
            let args = ChatArguments::from(state);
            let shared_secret = client_ec::client_ec(&args, peer)?.0;
            let key =
                BigUint::from_str_radix(&sha256::digest(shared_secret.to_bytes_be()), 16).unwrap();
            let cipher = AesCtr::new(&key.to_bytes_be());
            let hmac = HMAC::new(&key.to_bytes_be());
            peer.cipher = Some(cipher);
            peer.hmac = Some(hmac);
        }
        Algorithm::RSA => {
            //println!("Unimplemented server for RSA.");
        }
    }

    Ok(())
}

fn send(args: Vec<String>, peer: &mut Peer) {
    let msg = args
        .iter()
        .map(|x| x.to_owned() + " ")
        .collect::<Vec<String>>()
        .concat();
    peer.send_encrypted(msg.as_bytes()).unwrap();
}

impl From<&State> for ChatArguments {
    fn from(value: &State) -> Self {
        let state = (*value).clone();

        ChatArguments {
            port: state.server_port.expect("No port"),
            address: state.server_addr.unwrap().to_string(),
            ttp_port: state.ttp_port.unwrap(),
            ttp_address: state.ttp_addr.unwrap().to_string(),
            name: state.name.unwrap(),
            org: state.org.unwrap(),
        }
    }
}

impl Command {
    /// Parse a command from the line entered in stdin
    pub fn new(line: &str) -> Result<Command, String> {
        let mut parts = line.split(' ');
        let op_str = parts.next().unwrap();
        let args = parts.map(|s| s.to_string()).collect();
        let op = match op_str {
            "set" => Ok(CommandType::Set),
            "connect" => Ok(CommandType::Connect),
            "listen" => Ok(CommandType::Listen),
            "send" => Ok(CommandType::Send),
            "help" => Ok(CommandType::Help),
            "exit" => Ok(CommandType::Exit),
            unk => Err(unk),
        };

        match op {
            Ok(op) => Ok(Command { op, args }),
            Err(bad) => Err(bad.to_string()),
        }
    }

    // In case we've established a new connection, this method returns a clone of the TcpStream
    //s so that main can read from it
    pub fn handle(&self, state: &mut State, peer: &mut Peer) -> Option<TcpStream> {
        let args = self.args.clone();

        match self.op {
            CommandType::Help => help(),
            CommandType::Set => set(args, state),
            CommandType::Listen => {
                // TODO: handle errors here instead of in client_ec and server_ec
                let _ = listen(state, peer);
            }
            CommandType::Connect => {
                // TODO: handle errors here instead of in client_ec and server_ec
                let _ = connect(state, peer);
            }
            CommandType::Send => send(args, peer),
            _ => println!("Unimplemented."),
        };

        let stream_clone = peer.stream().map(|stream| stream.try_clone().unwrap());

        stream_clone
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    pub fn new() -> State {
        State {
            server_addr: None,
            server_port: None,
            ttp_addr: None,
            ttp_port: None,
            algo: Algorithm::EllipticCurve,
            name: None,
            org: None,
        }
    }
}

fn recv_thread(stream: &mut TcpStream, cipher: &AesCtr, hmac: &HMAC) {
    loop {
        let msg = MessageStream::<ChatMessage>::receive_msg(&mut *stream).unwrap();
        let ciphertext = msg.ciphertext;
        let mac = msg.mac;
        let nonce = usize::from_be_bytes(msg.nonce.try_into().unwrap());
        // Before decrypting, verify the MAC to protect against attacks
        if hmac.verify(&ciphertext, &mac) {
            let plaintext = cipher.decrypt(&ciphertext, nonce);

            println!("recv< {}", String::from_utf8(plaintext).unwrap());
        } else {
            eprintln!("Invalid MAC detected. Your connection is (probably) under an MITM attack.");
        }
    }
}

fn main() {
    let mut state = State::new();
    //let mut peer = Arc::new(Mutex::new(Peer::new()));
    // let mut peer = Arc::new(Mutex::new(Peer::new()));
    let mut peer = Peer::new();
    let mut stream_clone;
    let mut cipher_clone;
    let mut hmac_clone: Option<HMAC>;
    let mut has_spawned = false;

    println!("Welcome to securechat 2.0");
    println!("Enter 'help' for the help message");

    loop {
        let mut input = String::new();

        print!("> ");
        stdout().flush().unwrap();

        stdin().read_line(&mut input).expect("Failed to read line");
        input = input.trim().to_lowercase();

        if input.is_empty() {
            continue;
        }

        match Command::new(&input) {
            Ok(cmd) => {
                stream_clone = cmd.handle(&mut state, &mut peer);
                cipher_clone = peer.cipher.clone();
                hmac_clone = peer.hmac.clone();

                if stream_clone.is_some() && !has_spawned {
                    thread::spawn(move || {
                        let mut stream_clone = stream_clone.unwrap();
                        let cipher_clone = &cipher_clone.unwrap();
                        let hmac_clone = &hmac_clone.unwrap();

                        recv_thread(&mut stream_clone, cipher_clone, hmac_clone);
                    });

                    has_spawned = true;
                }
            }
            Err(name) => println!("Unknown command '{}'", name),
        }
    }
}
