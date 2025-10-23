use aes_gcm::aead::{Aead, AeadCore};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand;

pub fn encrypt(key: &[u8], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let mut rng = rand::thread_rng();
    let nonce = Aes256Gcm::generate_nonce(&mut rng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("encryption failure");
    (ciphertext, nonce.to_vec())
}

pub fn decrypt(key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .expect("decryption failure")
}
