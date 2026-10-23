use crate::merkle::{MerkleProof, MerkleTree};
use crate::sha256::Hash256;
use crate::wal::{LogRecord, WriteAheadLog};
use std::io;
use std::path::Path;

pub struct MerkleLogDb {
    wal: WriteAheadLog,
    tree: MerkleTree,
    records: Vec<LogRecord>,
}

impl MerkleLogDb {
    /// Opens or creates an embedded Merkle Log Database.
    /// Automatically replays existing WAL records and reconstructs the Merkle Root.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let (wal, loaded_records) = WriteAheadLog::open(path)?;
        let mut tree = MerkleTree::new();

        for r in &loaded_records {
            tree.append_leaf(&r.payload);
        }

        Ok(Self {
            wal,
            tree,
            records: loaded_records,
        })
    }

    /// Appends a payload to the database, persisting to disk and updating the Merkle root in O(log N).
    pub fn append(&mut self, payload: &[u8]) -> io::Result<(u64, Hash256)> {
        let record = self.wal.append(payload)?;
        let (index, root) = self.tree.append_leaf(payload);
        self.records.push(record);
        Ok((index, root))
    }

    pub fn get(&self, index: u64) -> Option<&LogRecord> {
        self.records.get(index as usize)
    }

    pub fn len(&self) -> u64 {
        self.records.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn merkle_root(&self) -> Hash256 {
        self.tree.root()
    }

    pub fn merkle_root_hex(&self) -> String {
        let r = self.tree.root();
        let mut s = String::with_capacity(64);
        for b in r {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    /// Generates cryptographic inclusion proof for a given record index.
    pub fn generate_proof(&self, index: u64) -> Result<MerkleProof, &'static str> {
        self.tree.generate_proof(index)
    }

    /// Verifies if a specific record index is cryptographically committed under the current Merkle root.
    pub fn verify_record(&self, index: u64) -> bool {
        if let Ok(proof) = self.generate_proof(index) {
            MerkleTree::verify_proof(&proof)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_log_db_persistence_and_recovery() {
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!(
            "merkle_test_{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let root_after_write;
        {
            let mut db = MerkleLogDb::open(&db_path).expect("open db");
            db.append(b"AUDIT: user_1 created contract CDLZ").unwrap();
            db.append(b"AUDIT: user_2 minted 500 tokens").unwrap();
            let (idx, root) = db.append(b"AUDIT: admin paused protocol").unwrap();
            assert_eq!(idx, 2);
            assert_eq!(db.len(), 3);
            root_after_write = root;

            // Inclusion proof test
            let proof = db.generate_proof(1).unwrap();
            assert!(MerkleTree::verify_proof(&proof));
        }

        // Re-open existing database: verify crash recovery & root preservation
        {
            let db2 = MerkleLogDb::open(&db_path).expect("reopen db");
            assert_eq!(db2.len(), 3);
            assert_eq!(db2.merkle_root(), root_after_write);
            assert_eq!(db2.get(0).unwrap().payload, b"AUDIT: user_1 created contract CDLZ");
            assert!(db2.verify_record(0));
            assert!(db2.verify_record(1));
            assert!(db2.verify_record(2));
        }

        let _ = std::fs::remove_file(db_path);
    }
}
