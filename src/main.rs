mod classical;
mod container;
mod keys;
mod pq;
mod quantum;

use classical::aes;
use container::EncryptedContainer;
use pq::{DilithiumKeyPair, KyberKeyPair};
use sha3::{Digest, Sha3_256};
use std::path::Path;

fn main() {
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│  PQBridge: Quantum-Resistant Secure Communication Demo      │");
    println!("└─────────────────────────────────────────────────────────────────┘\n");

    // Message
    let plain_message = "Hello Alice! This is Bob. 👋 I'm sending you this message through PQBridge—our \
        quantum-resistant secure channel. Your Kyber public key encrypted this, and my Dilithium signature \
        proves it's really from me. Even quantum computers can't break this! Welcome to secure communication \
        in the post-quantum world. 🌉🔐✨"
        .as_bytes();

    println!("📝 Original Message:");
    println!("   \"{}\"", String::from_utf8_lossy(plain_message));
    println!("   Length: {} bytes\n", plain_message.len());

    // === Alice: Generate Keys ===
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("👩 ALICE: Generate Key Pairs");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // ML-KEM Kyber
    let kyber_keypair = KyberKeyPair::generate();
    println!("  🔑 ML-KEM (Kyber) Key Exchange:");
    println!(
        "     • Public Key:  {} bytes",
        kyber_keypair.public_key.len()
    );
    println!(
        "     • Secret Key:  {} bytes",
        kyber_keypair.expose_secret().len()
    );

    // ML-DSA Dilithium
    let dilithium_keypair = DilithiumKeyPair::generate();
    println!("\n  ✍️  ML-DSA (Dilithium) Signatures:");
    println!(
        "     • Public Key:  {} bytes",
        dilithium_keypair.public_key.len()
    );
    println!(
        "     • Secret Key:  {} bytes",
        dilithium_keypair.expose_secret().len()
    );
    println!();

    // === Bob: Encrypt & Sign ===
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("👨 BOB: Encrypt Message for Alice & Sign");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Hash message
    let message_hash = Sha3_256::digest(plain_message);
    println!("  🔗 Step 1: Hash message with SHA3-256");
    println!("     • Hash: {} bytes", message_hash.len());

    // Sign
    let signature = dilithium_keypair.sign(&message_hash);
    println!("\n  ✍️  Step 2: Sign hash with ML-DSA (Dilithium)");
    println!("     • Signature: {} bytes", signature.len());

    // Encapsulate AES Key using Kyber
    let (kyber_ciphertext, aes_key) = KyberKeyPair::encapsulate(&kyber_keypair.public_key);
    println!("\n  📦 Step 3: Encapsulate AES key with ML-KEM (Kyber)");
    println!("     • Kyber Ciphertext: {} bytes", kyber_ciphertext.len());
    println!("     • Encapsulated AES Key: {} bytes", aes_key.len());

    // AES-256-GCM Encryption
    let (aes_ciphertext, nonce) = aes::encrypt(&aes_key, plain_message);
    println!("\n  🔒 Step 4: Encrypt message with AES-256-GCM");
    println!("     • Ciphertext: {} bytes", aes_ciphertext.len());
    println!("     • Nonce: {} bytes", nonce.len());

    // Package everything
    let payload_for_alice =
        EncryptedContainer::new(kyber_ciphertext, aes_ciphertext, nonce, signature);

    // Save payload to JSON
    payload_for_alice.to_json(Path::new("encrypted_payload_for_alice.json"));
    println!("\n  💾 Payload saved to: 'encrypted_payload_for_alice.json'");
    println!();

    // === Alice: Decrypt & Verify ===
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("👩 ALICE: Decrypt Message & Verify Signature");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Load payload
    let payload = EncryptedContainer::from_json(Path::new("encrypted_payload_for_alice.json"));

    // Decapsulate AES Key using Kyber
    let decapsulated_aes_key =
        KyberKeyPair::decapsulate(&payload.kyber_ciphertext, kyber_keypair.expose_secret());
    println!("  📦 Step 1: Decapsulate AES key with ML-KEM (Kyber)");
    println!(
        "     • Recovered AES Key: {} bytes",
        decapsulated_aes_key.len()
    );

    // Decrypt message using AES-256-GCM
    let decrypted_message = aes::decrypt(
        &decapsulated_aes_key,
        &payload.aes_ciphertext,
        &payload.nonce,
    );
    println!("\n  🔓 Step 2: Decrypt with AES-256-GCM");
    println!("     • Decrypted: {} bytes", decrypted_message.len());

    // Verify hash signature
    let message_hash = Sha3_256::digest(&decrypted_message);
    let signature_valid = DilithiumKeyPair::verify(
        &payload.signature,
        &message_hash,
        &dilithium_keypair.public_key,
    );
    println!("\n  ✅ Step 3: Verify signature with ML-DSA (Dilithium)");
    println!(
        "     • Signature Valid: {}",
        if signature_valid { "✓ YES" } else { "✗ NO" }
    );

    println!("\n  📝 Decrypted Message:");
    println!("     \"{}\"", String::from_utf8_lossy(&decrypted_message));

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✨ Success! Secure quantum-resistant bridge established! ✨");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}
