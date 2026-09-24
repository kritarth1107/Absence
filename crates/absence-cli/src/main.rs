//! Absence CLI

use clap::Parser;

#[derive(Parser)]
#[command(name = "absence")]
#[command(about = "Sparse Merkle Tree with non-membership proofs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Encode a JSON fact to its fact-id (SHA-256 of canonical JSON)
    Encode {
        /// JSON string to encode
        json: String,
    },
}

fn main() {
    let _cli = Cli::parse();
    println!("Absence CLI v0.1.0");
}
