# pqc_bridge

[![docs.rs (with version)](https://img.shields.io/docsrs/pqc_bridge/latest)](https://docs.rs/pqc_bridge/latest/pqc_bridge/)
[![Crates.io](https://img.shields.io/crates/v/pqc_bridge)](https://crates.io/crates/pqc_bridge)
![Last commit](https://img.shields.io/github/last-commit/olekssy/pqc_bridge)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/olekssy/pqc_bridge/rust.yml)
![License](https://img.shields.io/github/license/olekssy/pqc_bridge)


A lightweight Rust library for post-quantum cryptography providing secure key management, encryption, and digital signatures using NIST-standardized algorithms.

**Key Features:**
- 🔐 Simple API for quantum-resistant cryptography
- ⚡ Hybrid encryption (ML-KEM/Kyber + AES-256-GCM) + digital signatures (ML-DSA/Dilithium)
- 🔒 Automatic memory zeroization for secret keys
- 💾 JSON serialization and CLI for file-based operations
- 🎯 NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) compliant

## Quick Start

### Installation

Install as a dependency in your `Cargo.toml`:

```toml
[dependencies]
pqc_bridge = "0.1.1"
```

Or via Cargo CLI:
```bash
cargo add pqc_bridge
```

Install the CLI tool:
```bash
cargo install pqc_bridge
```

### Library Usage

```rust
use pqc_bridge::{KeyPair, encrypt, decrypt, sign, verify};

let message = "Secret message";
let keypair = KeyPair::generate();

// Encryption
let encrypted = encrypt(message, &keypair.to_public_key());
let decrypted = decrypt(encrypted, &keypair);
assert_eq!(message, decrypted);

// Signing
let signature = sign(message, &keypair);
let is_signature_valid = verify(message, &signature, &keypair.to_public_key());
assert!(is_signature_valid);
```

### CLI Usage

```bash
# Generate keypair
pqc keygen -o alice  # Creates alice.sec and alice.pub

# Encrypt message
pqc encrypt -m "Hello!" -k alice.pub -o encrypted.pqc

# Alternative way to encrypt a file
pqc encrypt -m @message.txt -k alice.pub -o encrypted.pqc

# Decrypt message
pqc decrypt -i encrypted.pqc -k alice.sec
```

## How It Works

**Hybrid Encryption:**
1. Kyber encapsulates a random AES-256 key using recipient's public key
2. AES-256-GCM encrypts the message with the encapsulated key (fast + quantum-resistant)

**Digital Signatures:**
1. SHA3-256 hashes the message, Dilithium signs the hash
2. Verification checks signature against message hash with sender's public key

**Security Features:**
- Automatic zeroization of secret keys in memory
- JSON serialization with Base64 encoding
- File-based operations via CLI

## References

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST FIPS 203 - ML-KEM](https://csrc.nist.gov/publications/detail/fips/203/final)
- [NIST FIPS 204 - ML-DSA](https://csrc.nist.gov/publications/detail/fips/204/final)
- [CRYSTALS-Kyber Specification](https://pq-crystals.org/kyber/)
- [CRYSTALS-Dilithium Specification](https://pq-crystals.org/dilithium/)
- [AES-256-GCM Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

## License

MIT License - See [LICENSE](LICENSE) for details.

---

**Note:** Educational project. Consult cryptography experts for production use.