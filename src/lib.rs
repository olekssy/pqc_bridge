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
//! // Generate a new keypair and share the public key with a recipient
//! let keypair = KeyPair::generate();
//! let pub_key = keypair.to_public_key();
//!
//! let message = "Secret message";
//!
//! // Encrypt message with the public key and decrypt with the private key
//! let encrypted = encrypt(message, &pub_key);
//! let decrypted = decrypt(encrypted, &keypair);
//! assert_eq!(message, decrypted);
//!
//! // Sign message with the private key and verify with the public key
//! let signature = sign(message, &keypair);
//! let is_valid_sig = verify(message, &signature, &pub_key);
//! assert!(is_valid_sig);
//! ```

mod api;
mod keys;
mod messages;
mod symmetric;

pub use api::{decrypt, encrypt, sign, verify};
pub use keys::KeyPair;
pub use messages::Message;
