const HMAC_OUTER_PAD: u8 = 0x5c;
const HMAC_INNER_PAD: u8 = 0x36;

#[derive(Clone)]
pub struct HMAC {
    key: Vec<u8>,
}

impl HMAC {
    pub fn new(key: &[u8]) -> HMAC {
        HMAC { key: key.to_vec() }
    }

    /// Derive the MAC for message msg; Returns the bytes of the MAC
    pub fn mac(&self, msg: &[u8]) -> Vec<u8> {
        // The inner & outer hashes are the key XORed with 0x5c and 0x36, respectively
        let mut outer_pad: Vec<u8> = self.key.iter().map(|x| x ^ HMAC_OUTER_PAD).collect();
        let mut inner_pad: Vec<u8> = self.key.iter().map(|x| x ^ HMAC_INNER_PAD).collect();
        // Compute sha256(inner_pad || msg)
        inner_pad.append(&mut msg.to_vec());
        let mut inner_hash = hex::decode(sha256::digest(inner_pad)).unwrap();
        // Compute sha256(outer_pad || inner_hash)
        outer_pad.append(&mut inner_hash);

        hex::decode(sha256::digest(outer_pad)).unwrap()
    }

    /// Verify the MAC for a message
    pub fn verify(&self, msg: &[u8], tag: &[u8]) -> bool {
        self.mac(msg) == tag.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::HMAC;

    #[test]
    fn test_valid_mac() {
        let my_msg = b"I <3 HMAC-SHA-256!!!";
        let my_key = b"Secret HMAC-SHA-256 Key";
        let hmac = HMAC::new(my_key);
        let tag = hmac.mac(my_msg);

        assert_eq!(hmac.verify(my_msg, &tag), true)
    }

    #[test]
    fn test_invalid_mac() {
        let my_msg = b"I <3 HMAC-SHA-256!!!";
        let my_key = b"Secret HMAC-SHA-256 Key";
        let hmac = HMAC::new(my_key);
        let fake_tag = b"I <3 Forging MACssssssssssssssss";

        assert_eq!(hmac.verify(my_msg, fake_tag), false)
    }
}
