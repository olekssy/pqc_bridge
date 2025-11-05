# pqc_bridge

[![docs.rs (with version)](https://img.shields.io/docsrs/pqc_bridge/latest)](https://docs.rs/pqc_bridge/latest/pqc_bridge/)
[![Crates.io](https://img.shields.io/crates/v/pqc_bridge)](https://crates.io/crates/pqc_bridge)
![Last commit](https://img.shields.io/github/last-commit/olekssy/pqc_bridge)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/olekssy/pqc_bridge/rust.yml)
![License](https://img.shields.io/github/license/olekssy/pqc_bridge)


A lightweight Rust library for post-quantum cryptography providing secure key management, encryption, and digital signatures using NIST-standardized algorithms.

**Key Features:**
- Simple, clean API for quantum-resistant cryptography
- Hybrid encryption combining post-quantum key encapsulation with symmetric encryption
- Digital signatures with post-quantum algorithms
- Based on NIST FIPS 203 (ML-KEM/Kyber) and FIPS 204 (ML-DSA/Dilithium)

## Quick Start

```bash
git clone https://github.com/olekssy/pqc_bridge.git
cd pqc_bridge
cargo run -- demo
```

## Usage

```rust
use pqc_bridge::{KeyPair, encrypt, decrypt, sign, verify};

fn main() {
    let message = "Secret message";
    
    // Generate keypair
    let keypair = KeyPair::generate();
    
    // Encrypt with recipient's public key
    let encrypted = encrypt(message, &keypair.to_public_key());
    
    // Decrypt with recipient's secret key
    let decrypted = decrypt(encrypted, &keypair);
    assert_eq!(message, decrypted);
    
    // Sign with sender's secret key
    let signature = sign(message, &keypair);
    
    // Verify with sender's public key
    assert!(verify(message, &signature, &keypair.to_public_key()));
}
```

## Architecture

### Cryptographic Components

- **ML-KEM-768 (Kyber)** - Post-quantum key encapsulation mechanism (NIST FIPS 203)
- **ML-DSA-65 (Dilithium3)** - Post-quantum digital signature algorithm (NIST FIPS 204)
- **AES-256-GCM** - Authenticated symmetric encryption
- **SHA3-256** - Cryptographic hashing for message integrity

### How It Works

**Encryption Flow:**
1. **Key Encapsulation** - Kyber encapsulates a random AES-256 key using recipient's public key
2. **Symmetric Encryption** - AES-256-GCM encrypts the message with the encapsulated key
3. **Packaging** - Returns a `Message` containing Kyber ciphertext, AES ciphertext, and nonce

**Decryption Flow:**
1. **Key Decapsulation** - Kyber decapsulates the AES-256 key using recipient's secret key
2. **Symmetric Decryption** - AES-256-GCM decrypts the message
3. **Verification** - Returns the plaintext message

**Signing & Verification:**
1. **Signing** - SHA3-256 hashes the message, Dilithium signs the hash
2. **Verification** - Dilithium verifies the signature against the message hash

**Why Hybrid Encryption?**
- Kyber provides quantum-resistant key exchange but is computationally expensive
- AES provides fast bulk encryption but requires secure key distribution
- Combining them provides both quantum resistance and performance

## API

### KeyPair

A universal container for Dilithium and Kyber keypairs.
It can be generated anew or constructed from existing public keys shared by the counterparty.

```rust
// Generate a new keypair
let keypair = KeyPair::generate(); // contains both secret and public keys

// Extract public key for sharing
let public_key = keypair.to_public_key(); // no secret keys exposed

// Create keypair from public keys only
let public_keypair = KeyPair::new_from_public_keys(
    Some(dilithium_public),
    Some(kyber_public)
);
```

### Encryption & Decryption

```rust
// Encrypt a message
let encrypted: Message = encrypt("Hello!", &recipient_public_key);

// Decrypt a message
let plaintext: String = decrypt(encrypted, &recipient_secret_key);
```

### Signing & Verification

```rust
// Sender signs a message
let signature: String = sign("Important message", &sender_secret_key);

// Recipient verifies sender's signature
let is_valid: bool = verify("Important message", &signature, &sender_public_key);
```

## CLI Demo

Run an interactive demonstration:

```bash
cargo run -- demo
```

The demo showcases:
- Keypair generation
- Message encryption and decryption
- Message signing and verification

## Testing

```bash
cargo test
```

## Documentation

Generate and view documentation:

```bash
cargo doc --open
```

## References

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST FIPS 203 - ML-KEM](https://csrc.nist.gov/publications/detail/fips/203/final)
- [NIST FIPS 204 - ML-DSA](https://csrc.nist.gov/publications/detail/fips/204/final)
- [CRYSTALS-Kyber Specification](https://pq-crystals.org/kyber/)
- [CRYSTALS-Dilithium Specification](https://pq-crystals.org/dilithium/)
- [AES-256-GCM Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

## License

MIT License

---

**Note:** This is a demonstration project. For production use, consult cryptography experts and follow security best practices.