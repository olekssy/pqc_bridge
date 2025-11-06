use clap::{Parser, Subcommand};
use pqc_bridge::*;

#[derive(Parser)]
#[command(name = "pqc_bridge")]
#[command(author, version, about = "Post-quantum cryptography CLI for secure communication", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair
    Keygen {
        /// Output path for the keypair (default: keypair)
        #[arg(short, long, default_value = "keypair")]
        output: String,
    },

    /// Encrypt a message
    Encrypt {
        /// Message to encrypt (use @file to read from file)
        #[arg(short, long)]
        message: String,

        /// Path to recipient's public key
        #[arg(short = 'k', long)]
        public_key: String,

        /// Output file for encrypted message
        #[arg(short, long, default_value = "encrypted.pqc")]
        output: String,
    },

    /// Decrypt a message
    Decrypt {
        /// Path to encrypted message file
        #[arg(short, long)]
        input: String,

        /// Path to keypair file
        #[arg(short, long)]
        keypair: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { output } => keygen_command(output),
        Commands::Encrypt {
            message,
            public_key,
            output,
        } => encrypt_command(message, public_key, output),
        Commands::Decrypt { input, keypair } => decrypt_command(input, keypair),
    }
}

fn keygen_command(output: String) {
    println!("🔑 Generating new keypair...");
    let keypair = KeyPair::generate();
    let pub_key = keypair.to_public_key();
    let sec_key_path = format!("{}.sec", output);
    let pub_key_path = format!("{}.pub", output);

    // serialize and save keypair
    let serialized_keypair = keypair.to_json();
    match std::fs::write(&sec_key_path, serialized_keypair) {
        Ok(_) => println!("✅ Keypair saved to: {}", sec_key_path),
        Err(e) => {
            eprintln!("❌ Failed to save keypair: {}", e);
        }
    }
    // serialize and save public key
    let serialized_pubkey = pub_key.to_json();
    match std::fs::write(&pub_key_path, serialized_pubkey) {
        Ok(_) => println!("✅ Public key saved to: {}", pub_key_path),
        Err(e) => {
            eprintln!("❌ Failed to save public key: {}", e);
        }
    }
}

fn read_message(input: &str) -> String {
    if input.starts_with('@') {
        let path = &input[1..];
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("❌ Failed to read file {}: {}", path, e))
    } else {
        input.to_string()
    }
}

fn read_key(input: &str) -> KeyPair {
    let key_json =
        std::fs::read_to_string(&input).unwrap_or_else(|e| panic!("❌ Failed to load key: {}", e));
    let key =
        KeyPair::from_json(&key_json).unwrap_or_else(|e| panic!("❌ Failed to parse key: {}", e));
    key
}

fn read_encrypted_message(input: &str) -> Message {
    let message_json = std::fs::read_to_string(&input)
        .unwrap_or_else(|e| panic!("❌ Failed to load message: {}", e));
    let message = Message::from_json(&message_json)
        .unwrap_or_else(|e| panic!("❌ Failed to parse message: {}", e));
    message
}

fn encrypt_command(message: String, public_key_path: String, output: String) {
    println!("🔒 Encrypting message...");

    // Read message
    let message_text = read_message(&message);

    // Load public key
    let public_key = read_key(&public_key_path);

    // Encrypt
    let encrypted = encrypt(&message_text, &public_key);

    // Serialize and save encrypted message
    let encrypted_json = encrypted.to_json();
    match std::fs::write(&output, encrypted_json) {
        Ok(_) => println!("✅ Encrypted message saved to: {}", output),
        Err(e) => eprintln!("❌ Failed to save encrypted message: {}", e),
    }
}

fn decrypt_command(input: String, keypair_path: String) {
    println!("🔓 Decrypting message...");

    // Load keypair
    let keypair = read_key(&keypair_path);

    // Load encrypted message
    let encrypted = read_encrypted_message(&input);

    // Decrypt
    let decrypted = decrypt(encrypted, &keypair);

    println!("📝 Decrypted message:\n{}", decrypted);
}
