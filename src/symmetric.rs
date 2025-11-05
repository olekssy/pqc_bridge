use aes_gcm::aead::{Aead, AeadCore};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use sha3::{Digest, Sha3_256};

/// Encrypts data using AES-256-GCM with provided key.
/// Returns (ciphertext, nonce).
pub fn aes_encrypt(data: &[u8], key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let mut rng = rand::thread_rng();
    let nonce = Aes256Gcm::generate_nonce(&mut rng);
    let ciphertext = cipher
        .encrypt(&nonce, data.as_ref())
        .expect("encryption failure");
    (ciphertext, nonce.as_slice().to_vec())
}

/// Decrypts data using AES-256-GCM with provided key and nonce.
pub fn aes_decrypt(data: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    cipher
        .decrypt(nonce, data)
        .expect("Failed to decrypt message")
}

/// Hashes data using SHA3-256.
/// Returns fixed-size hash digest of 32 bytes.
pub fn sha3_hash(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        panic!("Cannot hash empty data");
    }
    Sha3_256::digest(data).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encrypt_decrypt() {
        let key = [0u8; 32];
        let message = b"Hello, AES-GCM!";
        let (ciphertext, nonce) = aes_encrypt(message, &key);
        assert!(!ciphertext.is_empty());
        assert!(!nonce.is_empty());

        let decrypted_message = aes_decrypt(&ciphertext, &key, &nonce);
        assert_eq!(decrypted_message, message);
    }

    #[test]
    fn test_hashing() {
        let data = b"Test data for hashing";
        let digest = sha3_hash(data);
        assert_eq!(digest.len(), 32); // SHA3-256 produces a 32-byte hash
    }
}
