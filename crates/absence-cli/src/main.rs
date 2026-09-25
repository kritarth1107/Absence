//! Absence CLI — Sparse Merkle Tree with non-membership proofs
//!
//! Commands:
//! - encode: Compute fact-id (SHA-256 of canonical JSON)
//! - insert: Insert facts into a store file
//! - root: Print the current root hash
//! - checkpoint / checkpoints: Epoch root snapshots
//! - prove-absent / prove-present: Single proofs
//! - prove-absent-batch / verify-batch: Batch absence proofs
//! - compact-encode / compact-decode: CompactProof hex
//! - verify: Verify a proof against a root

use absence::{
    AbsenceStore, Checkpoint, CompactProof, FactId, MembershipProof, NonMembershipProof,
};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "absence")]
#[command(version = env!("CARGO_PKG_VERSION"))]
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

    /// Snapshot the current root as an epoch checkpoint
    Checkpoint {
        /// Path to the store file
        #[arg(short, long, default_value = "absence.store")]
        store: PathBuf,
    },

    /// List retained epoch checkpoints
    Checkpoints {
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

    /// Generate absence proofs for many JSON facts
    ProveAbsentBatch {
        /// Path to the store file
        #[arg(short, long, default_value = "absence.store")]
        store: PathBuf,

        /// JSON values to prove absent (ignored if --file is set)
        json: Vec<String>,

        /// File of JSON lines (one fact per line)
        #[arg(short = 'f', long)]
        file: Option<PathBuf>,

        /// Output file for the batch proof JSON (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Verify a batch of absence proofs against a root
    VerifyBatch {
        /// Path to the batch proof JSON file (array of NonMembershipProof)
        proof: PathBuf,

        /// Root hash (hex) to verify against
        #[arg(short, long)]
        root: String,
    },

    /// Encode a JSON proof file to CompactProof hex
    CompactEncode {
        /// Path to a single proof JSON file (absence or presence)
        proof: PathBuf,
    },

    /// Decode CompactProof hex to JSON (absence by default)
    CompactDecode {
        /// Compact proof as hex (or pass --file)
        hex: Option<String>,

        /// Read hex from file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Treat as membership proof instead of absence
        #[arg(long)]
        membership: bool,
    },

    /// Verify a proof against a root hash
    Verify {
        /// Path to the proof file
        proof: PathBuf,

        /// Root hash (hex) to verify against
        #[arg(short, long)]
        root: String,

        /// Optional epoch to verify against a stored checkpoint (requires --store)
        #[arg(long)]
        epoch: Option<u64>,

        /// Store file (needed with --epoch)
        #[arg(short, long, default_value = "absence.store")]
        store: PathBuf,
    },
}

/// Serializable store format (facts + checkpoint history)
#[derive(Serialize, Deserialize, Default)]
struct StoreFile {
    fact_ids: Vec<String>,
    #[serde(default)]
    checkpoints: Vec<StoredCheckpoint>,
}

#[derive(Serialize, Deserialize, Clone)]
struct StoredCheckpoint {
    epoch: u64,
    root: String,
    fact_count: u64,
    unix_ts: u64,
}

impl From<&Checkpoint> for StoredCheckpoint {
    fn from(cp: &Checkpoint) -> Self {
        Self {
            epoch: cp.epoch,
            root: hex::encode(cp.root),
            fact_count: cp.fact_count,
            unix_ts: cp.unix_ts,
        }
    }
}

impl StoredCheckpoint {
    fn to_checkpoint(&self) -> Checkpoint {
        let bytes = hex::decode(&self.root).expect("invalid checkpoint root hex");
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        Checkpoint {
            epoch: self.epoch,
            root,
            fact_count: self.fact_count,
            unix_ts: self.unix_ts,
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encode { json } => cmd_encode(&json),
        Commands::Insert { store, json } => cmd_insert(&store, &json),
        Commands::Root { store } => cmd_root(&store),
        Commands::Checkpoint { store } => cmd_checkpoint(&store),
        Commands::Checkpoints { store } => cmd_checkpoints(&store),
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
        Commands::ProveAbsentBatch {
            store,
            json,
            file,
            output,
        } => cmd_prove_absent_batch(&store, &json, file, output),
        Commands::VerifyBatch { proof, root } => cmd_verify_batch(&proof, &root),
        Commands::CompactEncode { proof } => cmd_compact_encode(&proof),
        Commands::CompactDecode {
            hex,
            file,
            membership,
        } => cmd_compact_decode(hex, file, membership),
        Commands::Verify {
            proof,
            root,
            epoch,
            store,
        } => cmd_verify(&proof, &root, epoch, &store),
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

fn load_store_file(path: &PathBuf) -> StoreFile {
    if path.exists() {
        let content = fs::read_to_string(path).expect("Failed to read store file");
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        StoreFile::default()
    }
}

fn load_store(path: &PathBuf) -> (AbsenceStore, StoreFile) {
    let store_file = load_store_file(path);
    let mut store = AbsenceStore::new();

    for hex_id in &store_file.fact_ids {
        if let Ok(fact_id) = FactId::from_hex(hex_id) {
            let _ = store.record(&fact_id);
        }
    }

    let checkpoints: Vec<Checkpoint> = store_file
        .checkpoints
        .iter()
        .map(StoredCheckpoint::to_checkpoint)
        .collect();
    store.set_checkpoint_history(checkpoints);

    (store, store_file)
}

fn save_store(path: &PathBuf, store: &AbsenceStore, fact_ids: &[String]) {
    let store_file = StoreFile {
        fact_ids: fact_ids.to_vec(),
        checkpoints: store.checkpoints().iter().map(StoredCheckpoint::from).collect(),
    };
    let content = serde_json::to_string_pretty(&store_file).expect("Failed to serialize store");
    fs::write(path, content).expect("Failed to write store file");
}

fn cmd_insert(store_path: &PathBuf, json_values: &[String]) {
    let (mut store, store_file) = load_store(store_path);
    let mut existing_ids = store_file.fact_ids;

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
    let (store, _) = load_store(store_path);
    let commitment = store.commitment();

    println!("Root: {}", commitment.root_hex());
    println!("Facts: {}", commitment.fact_count);
    println!("Checkpoints: {}", store.checkpoints().len());
}

fn cmd_checkpoint(store_path: &PathBuf) {
    let (mut store, store_file) = load_store(store_path);
    let cp = store.checkpoint();
    save_store(store_path, &store, &store_file.fact_ids);
    println!("Epoch: {}", cp.epoch);
    println!("Root: {}", cp.root_hex());
    println!("Facts: {}", cp.fact_count);
    println!("Unix ts: {}", cp.unix_ts);
}

fn cmd_checkpoints(store_path: &PathBuf) {
    let (store, _) = load_store(store_path);
    if store.checkpoints().is_empty() {
        println!("(no checkpoints)");
        return;
    }
    for cp in store.checkpoints() {
        println!(
            "epoch={} facts={} ts={} root={}",
            cp.epoch,
            cp.fact_count,
            cp.unix_ts,
            cp.root_hex()
        );
    }
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
    let (store, _) = load_store(store_path);

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
    let (store, _) = load_store(store_path);

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

fn read_json_facts(json_args: &[String], file: Option<PathBuf>) -> Vec<serde_json::Value> {
    let mut values = Vec::new();
    if let Some(path) = file {
        let f = fs::File::open(&path).expect("Failed to open facts file");
        for line in io::BufReader::new(f).lines() {
            let line = line.expect("Failed to read line");
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(v) => values.push(v),
                Err(e) => {
                    eprintln!("Error parsing JSON line: {}: {}", line, e);
                    std::process::exit(1);
                }
            }
        }
    } else {
        if json_args.is_empty() {
            eprintln!("Error: provide JSON args or --file with JSON lines");
            std::process::exit(1);
        }
        for json in json_args {
            match serde_json::from_str::<serde_json::Value>(json) {
                Ok(v) => values.push(v),
                Err(e) => {
                    eprintln!("Error parsing JSON '{}': {}", json, e);
                    std::process::exit(1);
                }
            }
        }
    }
    values
}

fn cmd_prove_absent_batch(
    store_path: &PathBuf,
    json_args: &[String],
    file: Option<PathBuf>,
    output: Option<PathBuf>,
) {
    let (store, _) = load_store(store_path);
    let values = read_json_facts(json_args, file);

    match store.prove_absent_batch_json(&values) {
        Ok(proofs) => {
            let json_out = AbsenceStore::batch_proofs_to_json(&proofs).unwrap();
            match output {
                Some(path) => {
                    fs::write(&path, &json_out).expect("Failed to write batch proof");
                    println!(
                        "Batch absence proof ({} facts) written to {:?}",
                        proofs.len(),
                        path
                    );
                    println!(
                        "Verify with: absence verify-batch {:?} --root {}",
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

fn cmd_verify_batch(proof_path: &PathBuf, root_hex: &str) {
    let root_bytes = parse_root(root_hex);
    let content = fs::read_to_string(proof_path).expect("Failed to read batch proof file");
    let proofs = match AbsenceStore::batch_proofs_from_json(&content) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error parsing batch proofs: {}", e);
            std::process::exit(1);
        }
    };

    match AbsenceStore::verify_absent_batch(&proofs, &root_bytes) {
        Ok(()) => {
            println!("✓ Batch absence proofs VALID ({} proofs)", proofs.len());
        }
        Err(e) => {
            eprintln!("✗ Batch absence proofs INVALID: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_compact_encode(proof_path: &PathBuf) {
    let content = fs::read_to_string(proof_path).expect("Failed to read proof file");
    let proof_file: ProofFile = serde_json::from_str(&content).expect("Failed to parse proof file");

    match proof_file {
        ProofFile::Absence { fact_id, siblings } => {
            let proof = rebuild_absence(&fact_id, &siblings);
            println!("{}", CompactProof::encode_absence_hex(&proof));
        }
        ProofFile::Presence { fact_id, siblings } => {
            let proof = rebuild_presence(&fact_id, &siblings);
            println!("{}", CompactProof::encode_membership_hex(&proof));
        }
    }
}

fn cmd_compact_decode(hex_arg: Option<String>, file: Option<PathBuf>, membership: bool) {
    let hex_s = if let Some(path) = file {
        fs::read_to_string(path)
            .expect("Failed to read hex file")
            .trim()
            .to_string()
    } else if let Some(h) = hex_arg {
        h
    } else {
        eprintln!("Error: provide hex argument or --file");
        std::process::exit(1);
    };

    if membership {
        match CompactProof::decode_membership_hex(&hex_s) {
            Ok(proof) => {
                let proof_file = ProofFile::Presence {
                    fact_id: hex::encode(proof.fact_id),
                    siblings: proof.siblings.iter().map(hex::encode).collect(),
                };
                println!("{}", serde_json::to_string_pretty(&proof_file).unwrap());
            }
            Err(e) => {
                eprintln!("Error decoding compact membership proof: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        match CompactProof::decode_absence_hex(&hex_s) {
            Ok(proof) => {
                let proof_file = ProofFile::Absence {
                    fact_id: hex::encode(proof.fact_id),
                    siblings: proof.siblings.iter().map(hex::encode).collect(),
                };
                println!("{}", serde_json::to_string_pretty(&proof_file).unwrap());
            }
            Err(e) => {
                eprintln!("Error decoding compact absence proof: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn parse_root(root_hex: &str) -> [u8; 32] {
    match hex::decode(root_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            eprintln!("Error: root must be 64 hex characters (32 bytes)");
            std::process::exit(1);
        }
    }
}

fn rebuild_absence(fact_id: &str, siblings: &[String]) -> NonMembershipProof {
    let fact_bytes = hex::decode(fact_id).expect("Invalid fact_id hex");
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

    NonMembershipProof {
        fact_id: fact_arr,
        siblings: sibling_hashes,
    }
}

fn rebuild_presence(fact_id: &str, siblings: &[String]) -> MembershipProof {
    let fact_bytes = hex::decode(fact_id).expect("Invalid fact_id hex");
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

    MembershipProof {
        fact_id: fact_arr,
        siblings: sibling_hashes,
    }
}

fn cmd_verify(proof_path: &PathBuf, root_hex: &str, epoch: Option<u64>, store_path: &PathBuf) {
    let root_bytes = if let Some(ep) = epoch {
        let (store, _) = load_store(store_path);
        match store.checkpoint_at(ep) {
            Some(cp) => {
                println!("Using checkpoint epoch {} root {}", ep, cp.root_hex());
                cp.root
            }
            None => {
                eprintln!("Error: unknown epoch {}", ep);
                std::process::exit(1);
            }
        }
    } else {
        parse_root(root_hex)
    };

    let content = fs::read_to_string(proof_path).expect("Failed to read proof file");
    let proof_file: ProofFile = serde_json::from_str(&content).expect("Failed to parse proof file");

    match proof_file {
        ProofFile::Absence { fact_id, siblings } => {
            let proof = rebuild_absence(&fact_id, &siblings);

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
            let proof = rebuild_presence(&fact_id, &siblings);

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

