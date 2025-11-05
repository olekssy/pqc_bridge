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
    /// Run a quick demo
    Demo,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Demo => {
            println!("PQC Bridge Demo");
            println!("==================\n");

            let message = "Hello from the post-quantum world! 🔐";
            println!("📝 Original message: {}", message);

            println!("\n🔑 Generating keypair...");
            let keypair = KeyPair::generate();

            println!("🔒 Encrypting message...");
            let encrypted = encrypt(message, &keypair.to_public_key());

            println!("🔓 Decrypting message...");
            let decrypted = decrypt(encrypted, &keypair);

            println!("📝 Decrypted message: {}", decrypted);
            println!("✅ Messages match: {}", message == decrypted);

            println!("\n✍️  Signing message...");
            let signature = sign(message, &keypair);

            println!("✅ Verifying signature...");
            let is_valid = verify(message, &signature, &keypair.to_public_key());
            println!("✅ Signature valid: {}", is_valid);

            println!("\n🎉 Demo complete!");
        }
    }
}
