use serde::{Deserialize, Serialize};
use std::path::Path;

#[allow(dead_code)]
#[derive(Serialize, Deserialize)]
pub struct PublicKeys {
    pub kyber: Vec<u8>,
    pub dilithium: Vec<u8>,
}

#[allow(dead_code)]
impl PublicKeys {
    pub fn new(kyber: Vec<u8>, dilithium: Vec<u8>) -> Self {
        PublicKeys { kyber, dilithium }
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
