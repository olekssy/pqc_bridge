# Bridge

![License](https://img.shields.io/github/license/olekssy/pq_bridge)
![Last commit](https://img.shields.io/github/last-commit/olekssy/pq_bridge)

## Post-Quantum Computing Secure Communication Bridge

Bridge is a library for quantum-resistant encrypted communication between parties using NIST post-quantum cryptography standards.
It protects against the potential threats posed by quantum algorithms using lattice-based cryptography and true quantum randomness for key generation.
The encryption framework is based on reputable cryptographic primitives to ensure both security and performance.

## Demo Quickstart

```bash
# Clone and run
git clone https://github.com/yourusername/pqc_bridge.git
cd pqc_bridge
cargo run --release
```

## Features

- **ML-KEM (Kyber-768)** - NIST FIPS 203 post-quantum key encapsulation (NIST Level 3)
- **ML-DSA (Dilithium3)** - NIST FIPS 204 post-quantum digital signatures (NIST Level 3)
- **AES-256-GCM** - Authenticated symmetric encryption with embedded quantum randomness
- **SHA3-256** - Cryptographic hashing for message integrity
- **NISQ Quantum RNG** - True quantum randomness for enhanced security (planned)
- **Hybrid Security** - Combines quantum-resistant key exchange with fast symmetric encryption

## How It Works

### Encryption Flow (Bob → Alice)

```
📝 Message → 🔗 Hash (SHA3-256) → ✍️ Sign (Dilithium) → 📦 Encapsulate Key (Kyber) → 🔒 Encrypt (AES-256-GCM) → 💾 JSON Payload
```

1. **🔗 Hash Message** - SHA3-256 creates a fixed-size digest for signing
2. **✍️ Sign Hash** - Bob's Dilithium private key signs the hash, proving authenticity
3. **📦 Encapsulate AES Key** - Kyber encapsulates a random AES-256 key using Alice's public key and NISQ randomness (only Alice can decrypt)
4. **🔒 Encrypt Message** - AES-256-GCM encrypts the actual message with the encapsulated key (fast symmetric encryption)
5. **💾 Package & Send** - All components (Kyber ciphertext, AES ciphertext, nonce, signature) are packaged in JSON

**Why this approach?**
- Kyber provides quantum-resistant key exchange but is slower for bulk data
- AES provides fast encryption but needs secure key distribution
- Combining them gives both quantum resistance and performance
- Dilithium provides quantum-resistant signatures, ensuring that the message came from Bob and wasn't tampered with

### Decryption Flow (Alice receives from Bob)

```
💾 JSON Payload → 📦 Decapsulate Key (Kyber) → 🔓 Decrypt (AES-256-GCM) → ✅ Verify (Dilithium) → 📝 Message
```

1. **📦 Decapsulate AES Key** - Alice's Kyber private key recovers the AES-256 key
2. **🔓 Decrypt Message** - AES-256-GCM decrypts the message using the recovered key
3. **✅ Verify Signature** - Bob's Dilithium public key verifies the signature, confirming authenticity

## Demo

```rust
use pq_bridge::{classical::aes, container::EncryptedContainer, pq::{DilithiumKeyPair, KyberKeyPair}};
use sha3::{Digest, Sha3_256};
use std::path::Path;

fn main() {
    let message = "Hello Alice! This is Bob. 👋 I'm sending you this message through PQBridge—our \
        quantum-resistant secure channel. Your Kyber public key encrypted this, and my Dilithium signature \
        proves it's really from me. Even quantum computers can't break this! Welcome to secure communication \
        in the post-quantum world. 🌉🔐✨"
        .as_bytes();

    // Alice generates key pairs
    let kyber_keypair = KyberKeyPair::generate();
    let dilithium_keypair = DilithiumKeyPair::generate();

    // Bob encrypts & signs for Alice
    let message_hash = Sha3_256::digest(&message);
    let signature = dilithium_keypair.sign(&message_hash);
    let (kyber_ciphertext, aes_key) = KyberKeyPair::encapsulate(&kyber_keypair.public_key);
    let (aes_ciphertext, nonce) = aes::encrypt(&aes_key, message);

    let payload_for_alice = EncryptedContainer::new(kyber_ciphertext, aes_ciphertext, nonce, signature);
    payload_for_alice.to_json(Path::new("encrypted_payload_for_alice.json"));

    // Alice decrypts & verifies
    let payload = EncryptedContainer::from_json(Path::new("encrypted_payload_for_alice.json"));
    let aes_key = KyberKeyPair::decapsulate(&payload.kyber_ciphertext, kyber_keypair.expose_secret());
    let decrypted_message = aes::decrypt(&aes_key, &payload.aes_ciphertext, &payload.nonce);
    
    let message_hash = Sha3_256::digest(&decrypted_message);
    let is_valid = DilithiumKeyPair::verify(&payload.signature, &message_hash, &dilithium_keypair.public_key);
    
    println!("Signature Valid: {}", is_valid);
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted_message));
}
```

### Output

```
┌─────────────────────────────────────────────────────────────────┐
│  🌉 PQBridge: Quantum-Resistant Secure Communication Demo      │
└─────────────────────────────────────────────────────────────────┘

📝 Original Message:
   "Hello Alice! This is Bob. 👋 I'm sending you this message through PQBridge—our 
    quantum-resistant secure channel. Your Kyber public key encrypted this, and my 
    Dilithium signature proves it's really from me. Even quantum computers can't 
    break this! Welcome to secure communication in the post-quantum world. 🌉🔐✨"
   Length: 321 bytes

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
👩 ALICE: Generate Key Pairs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🔑 ML-KEM (Kyber) Key Exchange:
     • Public Key:  1184 bytes
     • Secret Key:  2400 bytes

  ✍️  ML-DSA (Dilithium) Signatures:
     • Public Key:  1952 bytes
     • Secret Key:  4000 bytes

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
👨 BOB: Encrypt Message for Alice & Sign
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🔗 Step 1: Hash message with SHA3-256
     • Hash: 32 bytes

  ✍️  Step 2: Sign hash with ML-DSA (Dilithium)
     • Signature: 3293 bytes

  📦 Step 3: Encapsulate AES key with ML-KEM (Kyber)
     • Kyber Ciphertext: 1088 bytes
     • Encapsulated AES Key: 32 bytes

  🔒 Step 4: Encrypt message with AES-256-GCM
     • Ciphertext: 337 bytes
     • Nonce: 12 bytes

  💾 Payload saved to: 'encrypted_payload.json'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
👩 ALICE: Decrypt Message & Verify Signature
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  📦 Step 1: Decapsulate AES key with ML-KEM (Kyber)
     • Recovered AES Key: 32 bytes

  🔓 Step 2: Decrypt with AES-256-GCM
     • Decrypted: 321 bytes

  ✅ Step 3: Verify signature with ML-DSA (Dilithium)
     • Signature Valid: ✓ YES

  📝 Decrypted Message:
     "Hello Alice! This is Bob. 👋 I'm sending you this message through PQBridge—our 
      quantum-resistant secure channel. Your Kyber public key encrypted this, and my 
      Dilithium signature proves it's really from me. Even quantum computers can't 
      break this! Welcome to secure communication in the post-quantum world. 🌉🔐✨"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✨ Success! Secure quantum-resistant bridge established! ✨
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## References

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [NIST FIPS 203 - ML-KEM (Kyber)](https://csrc.nist.gov/publications/detail/fips/203/final)
- [NIST FIPS 204 - ML-DSA (Dilithium)](https://csrc.nist.gov/publications/detail/fips/204/final)
- [Kyber Specification (CRYSTALS-Kyber)](https://pq-crystals.org/kyber/)
- [Dilithium Specification (CRYSTALS-Dilithium)](https://pq-crystals.org/dilithium/)
- [Qiskit - Open-source quantum computing SDK](https://qiskit.org/)

## License

MIT License

---

**Note**: This is a demonstration project for educational purposes. For production use, consult cryptography experts and follow security best practices.