//! Post-quantum cryptography library for secure key management, encryption, and digital signatures.
//!
//! This library provides a simple interface for:
//! - Key generation using Kyber (encryption) and Dilithium (signatures)
//! - Hybrid encryption with AES-GCM and post-quantum key encapsulation
//! - Digital signatures with post-quantum algorithms
//!
//! # Example
//! ```
//! use pqc_bridge::{KeyPair, encrypt, decrypt, sign, verify};
//!
//! let keypair = KeyPair::generate();
//! let message = "Secret message";
//!
//! let encrypted = encrypt(message, &keypair.to_public_key());
//! let decrypted = decrypt(encrypted, &keypair);
//! assert_eq!(message, decrypted);
//!
//! let signature = sign(message, &keypair);
//! let is_valid_sig = verify(message, &signature, &keypair.to_public_key());
//! assert!(is_valid_sig);
//! ```

pub mod keys;
pub mod messages;
mod symmetric;

pub use keys::KeyPair;
pub use messages::Message;

use base64::{Engine, prelude::BASE64_STANDARD};

/// Encrypts a message with recipient's public key.
pub fn encrypt(message: &str, pub_key: &KeyPair) -> Message {
    // encapsulate symmetric key
    let (kyber_ciphertext, aes_key) = pub_key.encapsulate();
    // encrypt message with symmetric key
    let (aes_ciphertext, nonce) = symmetric::aes_encrypt(message.as_bytes(), &aes_key);

    Message::new(
        Some(BASE64_STANDARD.encode(&kyber_ciphertext)),
        Some(BASE64_STANDARD.encode(&aes_ciphertext)),
        Some(BASE64_STANDARD.encode(&nonce)),
        None,
    )
}

/// Decrypts a message with the recipient's secret key.
pub fn decrypt(ciphertext: Message, key: &KeyPair) -> String {
    let (kyber_ct_opt, aes_ct_opt, nonce_opt) = ciphertext.get_ciphers();

    let kyber_ct = BASE64_STANDARD.decode(kyber_ct_opt.unwrap()).unwrap();
    let aes_ct = BASE64_STANDARD.decode(aes_ct_opt.unwrap()).unwrap();
    let nonce = BASE64_STANDARD.decode(nonce_opt.unwrap()).unwrap();

    // decapsulate symmetric key
    let aes_key = key.decapsulate(&kyber_ct);
    // decrypt message with symmetric key
    let decrypted_message = symmetric::aes_decrypt(&aes_ct, &aes_key, &nonce);

    String::from_utf8(decrypted_message).unwrap()
}

/// Signs a message with sender's secret key.
pub fn sign(message: &str, key: &KeyPair) -> String {
    let message_hash = symmetric::sha3_hash(message.as_bytes());
    let signature = key.sign(&message_hash);
    BASE64_STANDARD.encode(&signature)
}

pub fn verify(message: &str, signature: &str, key: &KeyPair) -> bool {
    let message_hash = symmetric::sha3_hash(message.as_bytes());
    let signature = BASE64_STANDARD.decode(signature).unwrap();
    key.verify(&message_hash, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_with_pub_key() {
        let keypair = KeyPair::generate().to_public_key();
        let message = "Hello, PQC!";
        let encrypted_message = encrypt(message, &keypair);
        let (kyber_ct, aes_ct, nonce) = encrypted_message.get_ciphers();
        assert!(kyber_ct.is_some());
        assert!(aes_ct.is_some());
        assert!(nonce.is_some());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let keypair = KeyPair::generate();
        let message = "Hello, PQC!";
        let encrypted_message = encrypt(message, &keypair.to_public_key());
        let decrypted_message = decrypt(encrypted_message, &keypair);
        assert_eq!(message, decrypted_message);
    }

    #[test]
    fn test_sign_verify() {
        let keypair = KeyPair::generate();
        let message = "Important message, please sign me!";
        let signature = sign(message, &keypair);
        assert!(!signature.is_empty());

        let is_valid = verify(message, &signature, &keypair.to_public_key());
        assert!(is_valid);
    }
}
