use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};

pub const AES_BLOCK_SIZE: usize = 16;

#[derive(Clone)]
pub struct AesCtr {
    cipher: Aes256,
}

impl AesCtr {
    // Create a new AES-CTR cipher
    pub fn new(key: &[u8]) -> AesCtr {
        let key_arr = GenericArray::from_slice(key);
        let cipher = Aes256::new(key_arr);

        AesCtr { cipher }
    }

    pub fn encrypt(&self, msg: &[u8], nonce: usize) -> Vec<u8> {
        // AES-CTR encrypts using a running counter, where we XOR each byte of the msg
        // with a byte from a running keystream

        let num_blocks = msg.len().div_ceil(AES_BLOCK_SIZE);
        let mut msg_bytes = msg.chunks(AES_BLOCK_SIZE);
        let mut ciphertext = vec![];

        for i in nonce..nonce + num_blocks {
            // Pad it to the block size
            let mut i_slice = vec![0u8; AES_BLOCK_SIZE - 8];
            i_slice.extend(&i.to_be_bytes());
            let i_slice: [u8; AES_BLOCK_SIZE] = i_slice.try_into().unwrap();
            let mut key_block = GenericArray::from(i_slice);
            self.cipher.encrypt_block(&mut key_block);
            // # Of bytes to encrypt in this block
            let msg_block = msg_bytes.next().unwrap();
            let to_encrypt = msg_block.len().min(AES_BLOCK_SIZE);

            for j in 0..to_encrypt {
                ciphertext.push(key_block.get(j).unwrap() ^ msg_block.get(j).unwrap());
            }
        }

        ciphertext
    }

    pub fn decrypt(&self, msg: &[u8], nonce: usize) -> Vec<u8> {
        // Encryption is the same as decryption in CTR mode
        self.encrypt(msg, nonce)
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::Num;

    use super::AesCtr;

    #[test]
    fn aes_ctr_test() {
        let key = sha256::digest("0");
        let key = BigUint::from_str_radix(&key, 16).unwrap().to_bytes_be();
        let cipher = AesCtr::new(&key);
        let ciphertext = cipher.encrypt(b"ATTACK AT DAWN HELLO", 0);
        let plaintext = cipher.decrypt(&ciphertext, 0);

        assert_eq!(plaintext, b"ATTACK AT DAWN HELLO");
    }
}
