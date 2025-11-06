use serde::{Deserialize, Serialize};

/// Message container for encrypted data and signature
#[derive(Serialize, Deserialize)]
pub struct Message {
    pub signature: Option<String>,
    kyber_ciphertext: Option<String>,
    aes_ciphertext: Option<String>,
    nonce: Option<String>,
}

impl Message {
    pub fn new(
        kyber_ciphertext: Option<String>,
        aes_ciphertext: Option<String>,
        nonce: Option<String>,
        signature: Option<String>,
    ) -> Self {
        Message {
            kyber_ciphertext,
            aes_ciphertext,
            nonce,
            signature,
        }
    }

    pub fn get_ciphers(&self) -> (Option<&String>, Option<&String>, Option<&String>) {
        (
            self.kyber_ciphertext.as_ref(),
            self.aes_ciphertext.as_ref(),
            self.nonce.as_ref(),
        )
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }

    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature() {
        let mut message = Message::new(None, None, None, None);

        let signature = "TestSignature".to_string();
        message.signature = Some(signature.clone());
        assert_eq!(message.signature.as_ref().unwrap(), &signature);
    }

    #[test]
    fn test_ciphers() {
        let kyber_ciphertext = "KyberCiphertext".to_string();
        let aes_ciphertext = "AESCiphertext".to_string();
        let nonce = "Nonce".to_string();

        let message = Message::new(
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

    #[test]
    fn test_json_serialization() {
        let kyber_ciphertext = "KyberCiphertext".to_string();
        let aes_ciphertext = "AESCiphertext".to_string();
        let nonce = "Nonce".to_string();
        let signature = "TestSignature".to_string();
        let message = Message::new(
            Some(kyber_ciphertext.clone()),
            Some(aes_ciphertext.clone()),
            Some(nonce.clone()),
            Some(signature.clone()),
        );
        let json_str = message.to_json();
        let deserialized_message = Message::from_json(&json_str).unwrap();

        let (ct, at, n) = deserialized_message.get_ciphers();
        assert_eq!(ct.unwrap(), &kyber_ciphertext);
        assert_eq!(at.unwrap(), &aes_ciphertext);
        assert_eq!(n.unwrap(), &nonce);
        assert_eq!(&deserialized_message.signature.unwrap(), &signature);
    }
}
