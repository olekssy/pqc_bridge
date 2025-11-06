use crate::keys::KeyPair;
use crate::messages::Message;
use crate::symmetric;
use base64::{prelude::BASE64_STANDARD, Engine};
use zeroize::Zeroize;

/// Encrypts a message with recipient's public key.
/// ```
/// use pqc_bridge::{KeyPair, encrypt};
/// let keypair = KeyPair::generate();
/// let message = "Hello, PQC!";
/// let encrypted_message = encrypt(message, &keypair.to_public_key());
/// ```
pub fn encrypt(message: &str, pub_key: &KeyPair) -> Message {
    // encapsulate symmetric key
    let (kyber_ciphertext, mut aes_key) = pub_key.encapsulate();
    // encrypt message with symmetric key
    let (aes_ciphertext, nonce) = symmetric::aes_encrypt(message.as_bytes(), &aes_key);

    aes_key.zeroize();

    Message::new(
        Some(BASE64_STANDARD.encode(&kyber_ciphertext)),
        Some(BASE64_STANDARD.encode(&aes_ciphertext)),
        Some(BASE64_STANDARD.encode(&nonce)),
        None,
    )
}

/// Decrypts a message with recipient's secret key.
/// ```
/// use pqc_bridge::{KeyPair, encrypt, decrypt};
///
/// let keypair = KeyPair::generate();
/// let message = "Hello, PQC!";
/// let encrypted_message = encrypt(message, &keypair.to_public_key());
/// let decrypted_message = decrypt(encrypted_message, &keypair);
/// assert_eq!(message, decrypted_message);
/// ```
pub fn decrypt(ciphertext: Message, key: &KeyPair) -> String {
    let (kyber_ct_opt, aes_ct_opt, nonce_opt) = ciphertext.get_ciphers();

    let kyber_ct = BASE64_STANDARD.decode(kyber_ct_opt.unwrap()).unwrap();
    let aes_ct = BASE64_STANDARD.decode(aes_ct_opt.unwrap()).unwrap();
    let nonce = BASE64_STANDARD.decode(nonce_opt.unwrap()).unwrap();

    // decapsulate symmetric key
    let mut aes_key = key.decapsulate(&kyber_ct);
    // decrypt message with symmetric key
    let decrypted_message = symmetric::aes_decrypt(&aes_ct, &aes_key, &nonce);

    aes_key.zeroize();

    String::from_utf8(decrypted_message).unwrap()
}

/// Signs a message with sender's secret key.
/// ```
/// use pqc_bridge::{KeyPair, sign};
///
/// let keypair = KeyPair::generate();
/// let message = "Important message, please sign me!";
/// let signature = sign(message, &keypair);
/// ```
pub fn sign(message: &str, key: &KeyPair) -> String {
    let mut message_hash = symmetric::sha3_hash(message.as_bytes());
    let signature = key.sign(&message_hash);
    message_hash.zeroize();
    BASE64_STANDARD.encode(&signature)
}

/// Verifies a message signature with sender's public key.
/// ```
/// use pqc_bridge::{KeyPair, sign, verify};
///
/// let keypair = KeyPair::generate();
/// let message = "Important message, please sign me!";
/// let signature = sign(message, &keypair);
/// let is_valid = verify(message, &signature, &keypair.to_public_key());
/// assert!(is_valid);
/// ```
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
