//! Absence CLI — Sparse Merkle Tree with non-membership proofs
//!
//! Commands:
//! - encode: Compute fact-id (SHA-256 of canonical JSON)
//! - insert: Insert facts into a store file
//! - root: Print the current root hash
//! - prove-absent: Generate absence proof
//! - prove-present: Generate presence proof  
//! - verify: Verify a proof against a root

use absence::{AbsenceStore, FactId, MembershipProof, NonMembershipProof};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "absence")]
#[command(version = "0.1.0")]
#[command(about = "Sparse Merkle Tree with non-membership proofs")]
#[command(
    long_about = "Prove a fact is missing from a committed store — sparse Merkle non-membership for agent memory."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encode a JSON value to its fact-id (SHA-256 of canonical JSON)
    Encode {
        /// JSON string to encode
        json: String,
    },

    /// Insert one or more facts into a store file
    Insert {
        /// Path to the store file (created if missing)
        #[arg(short, long, default_value = "absence.store")]
        store: PathBuf,

        /// JSON values to insert
        #[arg(required = true)]
        json: Vec<String>,
    },

    /// Print the current root hash of a store
    Root {
        /// Path to the store file
        #[arg(short, long, default_value = "absence.store")]
        store: PathBuf,
    },

    /// Generate a non-membership (absence) proof
    ProveAbsent {
        /// Path to the store file
        #[arg(short, long, default_value = "absence.store")]
        store: PathBuf,

        /// JSON value to prove absent
        json: String,

        /// Output file for the proof (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Generate a membership (presence) proof
    ProvePresent {
        /// Path to the store file
        #[arg(short, long, default_value = "absence.store")]
        store: PathBuf,

        /// JSON value to prove present
        json: String,

        /// Output file for the proof (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify a proof against a root hash
    Verify {
        /// Path to the proof file
        proof: PathBuf,

        /// Root hash (hex) to verify against
        #[arg(short, long)]
        root: String,
    },
}

/// Serializable store format
#[derive(Serialize, Deserialize, Default)]
struct StoreFile {
    fact_ids: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encode { json } => cmd_encode(&json),
        Commands::Insert { store, json } => cmd_insert(&store, &json),
        Commands::Root { store } => cmd_root(&store),
        Commands::ProveAbsent {
            store,
            json,
            output,
        } => cmd_prove_absent(&store, &json, output),
        Commands::ProvePresent {
            store,
            json,
            output,
        } => cmd_prove_present(&store, &json, output),
        Commands::Verify { proof, root } => cmd_verify(&proof, &root),
    }
}

fn cmd_encode(json: &str) {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(value) => {
            let fact_id = FactId::from_json_value(&value);
            println!("{}", fact_id.to_hex());
        }
        Err(e) => {
            eprintln!("Error parsing JSON: {}", e);
            std::process::exit(1);
        }
    }
}

fn load_store(path: &PathBuf) -> AbsenceStore {
    let mut store = AbsenceStore::new();

    if path.exists() {
        let content = fs::read_to_string(path).expect("Failed to read store file");
        let store_file: StoreFile =
            serde_json::from_str(&content).expect("Failed to parse store file");

        for hex in &store_file.fact_ids {
            if let Ok(fact_id) = FactId::from_hex(hex) {
                let _ = store.record(&fact_id);
            }
        }
    }

    store
}

fn save_store(path: &PathBuf, _store: &AbsenceStore, fact_ids: &[String]) {
    let store_file = StoreFile {
        fact_ids: fact_ids.to_vec(),
    };
    let content = serde_json::to_string_pretty(&store_file).expect("Failed to serialize store");
    fs::write(path, content).expect("Failed to write store file");
}

fn cmd_insert(store_path: &PathBuf, json_values: &[String]) {
    let mut existing_ids: Vec<String> = if store_path.exists() {
        let content = fs::read_to_string(store_path).expect("Failed to read store file");
        let store_file: StoreFile = serde_json::from_str(&content).unwrap_or_default();
        store_file.fact_ids
    } else {
        Vec::new()
    };

    let mut store = AbsenceStore::new();
    for hex in &existing_ids {
        if let Ok(fact_id) = FactId::from_hex(hex) {
            let _ = store.record(&fact_id);
        }
    }

    let mut inserted = 0;
    for json in json_values {
        match serde_json::from_str::<serde_json::Value>(json) {
            Ok(value) => {
                let fact_id = FactId::from_json_value(&value);
                match store.record(&fact_id) {
                    Ok(()) => {
                        existing_ids.push(fact_id.to_hex());
                        inserted += 1;
                        println!("Inserted: {}", fact_id.to_hex());
                    }
                    Err(_) => {
                        println!("Already present: {}", fact_id.to_hex());
                    }
                }
            }
            Err(e) => {
                eprintln!("Error parsing JSON '{}': {}", json, e);
            }
        }
    }

    save_store(store_path, &store, &existing_ids);
    println!("---");
    println!("Inserted {} fact(s). Total: {}", inserted, store.len());
    println!("Root: {}", hex::encode(store.root()));
}

fn cmd_root(store_path: &PathBuf) {
    let store = load_store(store_path);
    let commitment = store.commitment();

    println!("Root: {}", commitment.root_hex());
    println!("Facts: {}", commitment.fact_count);
}

/// Proof file format
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
enum ProofFile {
    #[serde(rename = "absence")]
    Absence {
        fact_id: String,
        siblings: Vec<String>,
    },
    #[serde(rename = "presence")]
    Presence {
        fact_id: String,
        siblings: Vec<String>,
    },
}

fn cmd_prove_absent(store_path: &PathBuf, json: &str, output: Option<PathBuf>) {
    let store = load_store(store_path);

    let value: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing JSON: {}", e);
            std::process::exit(1);
        }
    };

    let fact_id = FactId::from_json_value(&value);

    match store.prove_absent(&fact_id) {
        Ok(proof) => {
            let proof_file = ProofFile::Absence {
                fact_id: hex::encode(proof.fact_id),
                siblings: proof.siblings.iter().map(hex::encode).collect(),
            };

            let json_out = serde_json::to_string_pretty(&proof_file).unwrap();

            match output {
                Some(path) => {
                    fs::write(&path, &json_out).expect("Failed to write proof file");
                    println!("Absence proof written to {:?}", path);
                    println!(
                        "Verify with: absence verify {:?} --root {}",
                        path,
                        hex::encode(store.root())
                    );
                }
                None => {
                    println!("{}", json_out);
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_prove_present(store_path: &PathBuf, json: &str, output: Option<PathBuf>) {
    let store = load_store(store_path);

    let value: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error parsing JSON: {}", e);
            std::process::exit(1);
        }
    };

    let fact_id = FactId::from_json_value(&value);

    match store.prove_present(&fact_id) {
        Ok(proof) => {
            let proof_file = ProofFile::Presence {
                fact_id: hex::encode(proof.fact_id),
                siblings: proof.siblings.iter().map(hex::encode).collect(),
            };

            let json_out = serde_json::to_string_pretty(&proof_file).unwrap();

            match output {
                Some(path) => {
                    fs::write(&path, &json_out).expect("Failed to write proof file");
                    println!("Presence proof written to {:?}", path);
                    println!(
                        "Verify with: absence verify {:?} --root {}",
                        path,
                        hex::encode(store.root())
                    );
                }
                None => {
                    println!("{}", json_out);
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_verify(proof_path: &PathBuf, root_hex: &str) {
    let root_bytes = match hex::decode(root_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            eprintln!("Error: root must be 64 hex characters (32 bytes)");
            std::process::exit(1);
        }
    };

    let content = fs::read_to_string(proof_path).expect("Failed to read proof file");
    let proof_file: ProofFile = serde_json::from_str(&content).expect("Failed to parse proof file");

    match proof_file {
        ProofFile::Absence { fact_id, siblings } => {
            let fact_bytes = hex::decode(&fact_id).expect("Invalid fact_id hex");
            let mut fact_arr = [0u8; 32];
            fact_arr.copy_from_slice(&fact_bytes);

            let sibling_hashes: Vec<[u8; 32]> = siblings
                .iter()
                .map(|s| {
                    let bytes = hex::decode(s).expect("Invalid sibling hex");
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                })
                .collect();

            let proof = NonMembershipProof {
                fact_id: fact_arr,
                siblings: sibling_hashes,
            };

            match proof.verify(&root_bytes) {
                Ok(()) => {
                    println!("✓ Absence proof VALID");
                    println!("  Fact ID {} is NOT in the committed set.", fact_id);
                }
                Err(e) => {
                    eprintln!("✗ Absence proof INVALID: {}", e);
                    std::process::exit(1);
                }
            }
        }
        ProofFile::Presence { fact_id, siblings } => {
            let fact_bytes = hex::decode(&fact_id).expect("Invalid fact_id hex");
            let mut fact_arr = [0u8; 32];
            fact_arr.copy_from_slice(&fact_bytes);

            let sibling_hashes: Vec<[u8; 32]> = siblings
                .iter()
                .map(|s| {
                    let bytes = hex::decode(s).expect("Invalid sibling hex");
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                })
                .collect();

            let proof = MembershipProof {
                fact_id: fact_arr,
                siblings: sibling_hashes,
            };

            match proof.verify(&root_bytes) {
                Ok(()) => {
                    println!("✓ Presence proof VALID");
                    println!("  Fact ID {} IS in the committed set.", fact_id);
                }
                Err(e) => {
                    eprintln!("✗ Presence proof INVALID: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
