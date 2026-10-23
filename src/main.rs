use merkle_log_db::{MerkleLogDb, MerkleTree};
use std::env;
use std::path::PathBuf;

fn print_usage() {
    println!("merkle-log-db - Zero-dependency embedded append-only audit database in Rust\n");
    println!("Usage:");
    println!("  merkle-log-db append <db_path> <message>");
    println!("  merkle-log-db root <db_path>");
    println!("  merkle-log-db verify <db_path> <index>");
    println!("  merkle-log-db dump <db_path>");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let command = args[1].as_str();

    match command {
        "append" => {
            if args.len() < 4 {
                eprintln!("Error: missing db_path or message");
                return Ok(());
            }
            let path = PathBuf::from(&args[2]);
            let message = args[3].as_bytes();

            let mut db = MerkleLogDb::open(&path)?;
            let (idx, _root) = db.append(message)?;
            println!("✅ Appended record #{}", idx);
            println!("🔒 Updated Merkle Root: {}", db.merkle_root_hex());
        }

        "root" => {
            if args.len() < 3 {
                eprintln!("Error: missing db_path");
                return Ok(());
            }
            let path = PathBuf::from(&args[2]);
            let db = MerkleLogDb::open(&path)?;
            println!("🔒 Merkle Root: {}", db.merkle_root_hex());
            println!("📊 Total Records: {}", db.len());
        }

        "verify" => {
            if args.len() < 4 {
                eprintln!("Error: missing db_path or record index");
                return Ok(());
            }
            let path = PathBuf::from(&args[2]);
            let idx: u64 = args[3].parse()?;
            let db = MerkleLogDb::open(&path)?;

            match db.generate_proof(idx) {
                Ok(proof) => {
                    let valid = MerkleTree::verify_proof(&proof);
                    if valid {
                        println!("✅ Record #{} is cryptographically committed under current Merkle root!", idx);
                        println!("   Audit Path Length: {} hashes", proof.audit_path.len());
                    } else {
                        println!("❌ Record verification FAILED: Root mismatch");
                    }
                }
                Err(e) => eprintln!("Error generating proof: {}", e),
            }
        }

        "dump" => {
            if args.len() < 3 {
                eprintln!("Error: missing db_path");
                return Ok(());
            }
            let path = PathBuf::from(&args[2]);
            let db = MerkleLogDb::open(&path)?;
            println!("=== Merkle Log Dump ({} records) ===", db.len());
            for i in 0..db.len() {
                if let Some(r) = db.get(i) {
                    println!("[#{}] ts={} | payload: {}", r.index, r.timestamp, String::from_utf8_lossy(&r.payload));
                }
            }
            println!("Root: {}", db.merkle_root_hex());
        }

        _ => print_usage(),
    }

    Ok(())
}
