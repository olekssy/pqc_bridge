use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct EncryptedContainer {
    pub kyber_ciphertext: Vec<u8>,
    pub aes_ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
}

impl EncryptedContainer {
    pub fn new(
        kyber_ciphertext: Vec<u8>,
        aes_ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        EncryptedContainer {
            kyber_ciphertext,
            aes_ciphertext,
            nonce,
            signature,
        }
    }

    pub fn to_json(&self, path: &Path) {
        let json = serde_json::to_string_pretty(self).unwrap();
        std::fs::write(path, json).unwrap();
    }

    pub fn from_json(path: &Path) -> Self {
        let json = std::fs::read_to_string(path).unwrap();
        serde_json::from_str(&json).unwrap()
    }
}
