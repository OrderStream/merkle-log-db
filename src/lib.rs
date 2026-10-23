//! High-throughput, zero-dependency embedded append-only audit database in Rust.
//! Automatically computes SHA-256 Merkle root on every write.

pub mod db;
pub mod merkle;
pub mod sha256;
pub mod wal;

pub use db::MerkleLogDb;
pub use merkle::{MerkleProof, MerkleTree, ProofNode};
pub use sha256::{sha256, sha256_hex, Hash256};
pub use wal::LogRecord;
