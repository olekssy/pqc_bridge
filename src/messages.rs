use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub sender: String,
    pub recipient: String,
    kyber_ciphertext: Option<Vec<u8>>,
    aes_ciphertext: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
}

impl EncryptedMessage {
    pub fn new(
        sender: String,
        recipient: String,
        kyber_ciphertext: Option<Vec<u8>>,
        aes_ciphertext: Option<Vec<u8>>,
        nonce: Option<Vec<u8>>,
        signature: Option<Vec<u8>>,
    ) -> Self {
        EncryptedMessage {
            sender,
            recipient,
            kyber_ciphertext,
            aes_ciphertext,
            nonce,
            signature,
        }
    }

    pub fn to_json(&self, path: &Path) {
        let json = serde_json::to_string_pretty(self).unwrap();
        std::fs::write(path, json).expect("Failed to write JSON to file");
    }

    pub fn from_json(path: &Path) -> Self {
        let json = std::fs::read_to_string(path).expect("Failed to read JSON from file");
        serde_json::from_str(&json).expect("Failed to parse JSON from file")
    }

    pub fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = Some(signature);
    }

    pub fn get_signature(&self) -> Option<&Vec<u8>> {
        self.signature.as_ref()
    }

    pub fn get_ciphers(&self) -> (Option<&Vec<u8>>, Option<&Vec<u8>>, Option<&Vec<u8>>) {
        (
            self.kyber_ciphertext.as_ref(),
            self.aes_ciphertext.as_ref(),
            self.nonce.as_ref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::Path, vec};

    #[test]
    fn test_encrypted_message_serialization() {
        let message = EncryptedMessage::new(
            "Alice".to_string(),
            "Bob".to_string(),
            vec![1, 2, 3].into(),
            vec![4, 5, 6].into(),
            vec![7, 8, 9].into(),
            vec![10, 11, 12].into(),
        );

        let path = Path::new("test_encrypted_message.json");
        message.to_json(path);

        let loaded_message = EncryptedMessage::from_json(path);
        assert_eq!(message.sender, loaded_message.sender);
        assert_eq!(message.recipient, loaded_message.recipient);
        assert_eq!(message.kyber_ciphertext, loaded_message.kyber_ciphertext);
        assert_eq!(message.aes_ciphertext, loaded_message.aes_ciphertext);
        assert_eq!(message.nonce, loaded_message.nonce);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_signature() {
        let mut message = EncryptedMessage::new(
            "Alice".to_string(),
            "Bob".to_string(),
            None,
            None,
            None,
            None,
        );

        let signature = vec![10, 11, 12];
        message.set_signature(signature.clone());

        let retrieved_signature = message.get_signature().unwrap();
        assert_eq!(retrieved_signature, &signature);
    }

    #[test]
    fn test_get_ciphers() {
        let kyber_ciphertext = vec![1, 2, 3];
        let aes_ciphertext = vec![4, 5, 6];
        let nonce = vec![7, 8, 9];
        let message = EncryptedMessage::new(
            "Alice".to_string(),
            "Bob".to_string(),
            Some(kyber_ciphertext.clone()),
            Some(aes_ciphertext.clone()),
            Some(nonce.clone()),
            None,
        );
        let (k_cipher, a_cipher, n) = message.get_ciphers();
        assert_eq!(k_cipher.unwrap(), &kyber_ciphertext);
        assert_eq!(a_cipher.unwrap(), &aes_ciphertext);
        assert_eq!(n.unwrap(), &nonce);
    }
}
