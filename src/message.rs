use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

use protobuf::Message as ProtobufMessage;

/// A message of a certain type
pub struct TypedMessage {
    msg_type: u8,
    payload: Vec<u8>,
}

/// This trait allows us to send and receive untyped messages over a stream
/// We implement it for TcpStream
pub trait MessageStream<T: ProtobufMessage> {
    // Receive a message of type T from the stream
    fn receive_msg(&mut self) -> Result<T, io::Error>;
    // Send a message of type T over the stream
    fn send_msg(&mut self, msg: T) -> Result<usize, io::Error>;
}

/// Simialr to `MessageStream`. The main difference is that this trait
/// sends **typed** messages, i.e. the type of the message is transmitted over the wire
/// and the receiver can perform specific actions according to the type of the message received
pub trait TypedMessageReader {
    // Receive a message
    fn receive_typed_msg(&mut self) -> Result<TypedMessage, io::Error>;
}

pub trait TypedMessageSender<T: ProtobufMessage> {
    // Send a message of type T over the stream. We also require
    // a u8 that indicates the type of the message
    fn send_typed_msg(&mut self, msg: T, msg_type: u8) -> Result<usize, io::Error>;
}

impl<T: ProtobufMessage> MessageStream<T> for TcpStream {
    fn receive_msg(&mut self) -> Result<T, io::Error> {
        // Parse the size
        let mut size_bytes = [0u8; 8];
        self.read_exact(&mut size_bytes)?;
        // Read `size` bytes from the stream
        let mut payload_bytes = vec![0u8; u64::from_be_bytes(size_bytes).try_into().unwrap()];
        self.read_exact(&mut payload_bytes)?;
        // Parse the payload and return it
        let msg = T::parse_from_bytes(&payload_bytes)?;

        Ok(msg)
    }

    fn send_msg(&mut self, msg: T) -> Result<usize, io::Error> {
        // The first 8 bytes of the message are its size (in big-endian)
        // and the rest of the bytes are the proto itself
        let mut wire_bytes = msg.compute_size().to_be_bytes().to_vec();
        let mut msg_bytes = msg.write_to_bytes()?;
        // These are the bytes we send over the wire
        wire_bytes.append(&mut msg_bytes);

        self.write(&wire_bytes)
    }
}

impl TypedMessageReader for TcpStream {
    fn receive_typed_msg(&mut self) -> Result<TypedMessage, io::Error> {
        // Parse the size
        let mut size_bytes = [0u8; 8];
        self.read_exact(&mut size_bytes)?;
        // Parse the msg type
        let mut type_bytes = [0u8; 1];
        self.read_exact(&mut type_bytes)?;
        // Read `size` bytes from the stream
        let mut payload_bytes = vec![0u8; u64::from_be_bytes(size_bytes).try_into().unwrap()];
        self.read_exact(&mut payload_bytes)?;

        Ok(TypedMessage {
            msg_type: type_bytes[0],
            payload: payload_bytes,
        })
    }
}

impl<T: ProtobufMessage> TypedMessageSender<T> for TcpStream {
    fn send_typed_msg(&mut self, msg: T, msg_type: u8) -> Result<usize, io::Error> {
        // The first 8 bytes of the message are its size (in big-endian)
        // , after that we have one byte indicating the type, and the rest of the bytes are the proto itself
        let mut wire_bytes = msg.compute_size().to_be_bytes().to_vec();
        let mut msg_bytes = msg.write_to_bytes()?;
        // These are the bytes we send over the wire
        wire_bytes.push(msg_type);
        wire_bytes.append(&mut msg_bytes);

        self.write(&wire_bytes)
    }
}

impl TypedMessage {
    // Getters
    pub fn msg_type(&self) -> u8 {
        self.msg_type
    }

    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
}
