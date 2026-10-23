use crate::sha256::{sha256, Hash256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofDirection {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofNode {
    pub hash: Hash256,
    pub direction: ProofDirection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf_index: u64,
    pub leaf_hash: Hash256,
    pub audit_path: Vec<ProofNode>,
    pub expected_root: Hash256,
}

pub struct MerkleTree {
    leaf_hashes: Vec<Hash256>,
    root: Hash256,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            leaf_hashes: Vec::new(),
            root: [0u8; 32],
        }
    }

    pub fn len(&self) -> usize {
        self.leaf_hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_hashes.is_empty()
    }

    pub fn root(&self) -> Hash256 {
        self.root
    }

    /// Appends a leaf payload, updates the tree, and recalculates the Merkle root in O(log N).
    pub fn append_leaf(&mut self, payload: &[u8]) -> (u64, Hash256) {
        // RFC 6962 leaf domain separator: 0x00
        let mut leaf_preimage = Vec::with_capacity(1 + payload.len());
        leaf_preimage.push(0x00);
        leaf_preimage.extend_from_slice(payload);
        let leaf_hash = sha256(&leaf_preimage);

        let index = self.leaf_hashes.len() as u64;
        self.leaf_hashes.push(leaf_hash);
        self.recompute_root();

        (index, self.root)
    }

    fn combine_hashes(left: &Hash256, right: &Hash256) -> Hash256 {
        // RFC 6962 interior node domain separator: 0x01
        let mut interior = Vec::with_capacity(1 + 32 + 32);
        interior.push(0x01);
        interior.extend_from_slice(left);
        interior.extend_from_slice(right);
        sha256(&interior)
    }

    fn recompute_root(&mut self) {
        if self.leaf_hashes.is_empty() {
            self.root = [0u8; 32];
            return;
        }

        let mut current_level = self.leaf_hashes.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(Self::combine_hashes(&chunk[0], &chunk[1]));
                } else {
                    // Odd number of nodes: promote duplicate or single node
                    next_level.push(Self::combine_hashes(&chunk[0], &chunk[0]));
                }
            }
            current_level = next_level;
        }

        self.root = current_level[0];
    }

    /// Generates an audit inclusion proof for a given leaf index.
    pub fn generate_proof(&self, index: u64) -> Result<MerkleProof, &'static str> {
        let idx = index as usize;
        if idx >= self.leaf_hashes.len() {
            return Err("Leaf index out of bounds");
        }

        let mut path = Vec::new();
        let mut current_level = self.leaf_hashes.clone();
        let mut current_idx = idx;

        while current_level.len() > 1 {
            let is_right_child = (current_idx % 2) == 1;
            let sibling_idx = if is_right_child {
                current_idx - 1
            } else if current_idx + 1 < current_level.len() {
                current_idx + 1
            } else {
                current_idx // Duplicate self if odd end
            };

            path.push(ProofNode {
                hash: current_level[sibling_idx],
                direction: if is_right_child {
                    ProofDirection::Left
                } else {
                    ProofDirection::Right
                },
            });

            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(Self::combine_hashes(&chunk[0], &chunk[1]));
                } else {
                    next_level.push(Self::combine_hashes(&chunk[0], &chunk[0]));
                }
            }
            current_level = next_level;
            current_idx /= 2;
        }

        Ok(MerkleProof {
            leaf_index: index,
            leaf_hash: self.leaf_hashes[idx],
            audit_path: path,
            expected_root: self.root,
        })
    }

    /// Verifies a Merkle audit inclusion proof independently against a known root hash.
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current_hash = proof.leaf_hash;

        for node in &proof.audit_path {
            current_hash = match node.direction {
                ProofDirection::Left => Self::combine_hashes(&node.hash, &current_hash),
                ProofDirection::Right => Self::combine_hashes(&current_hash, &node.hash),
            };
        }

        current_hash == proof.expected_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_proof_lifecycle() {
        let mut tree = MerkleTree::new();
        let payloads = vec![
            b"tx_1: alice -> bob (100 XLM)".to_vec(),
            b"tx_2: bob -> charlie (50 XLM)".to_vec(),
            b"tx_3: charlie -> dave (25 XLM)".to_vec(),
            b"tx_4: dave -> eve (10 XLM)".to_vec(),
            b"tx_5: eve -> frank (5 XLM)".to_vec(),
        ];

        for p in &payloads {
            tree.append_leaf(p);
        }

        assert_eq!(tree.len(), 5);
        assert_ne!(tree.root(), [0u8; 32]);

        // Verify proofs for all leaves
        for i in 0..5 {
            let proof = tree.generate_proof(i).expect("Proof should be generated");
            assert!(MerkleTree::verify_proof(&proof));
        }

        // Tampering test: modify proof hash
        let mut bad_proof = tree.generate_proof(2).unwrap();
        bad_proof.leaf_hash[0] ^= 0xFF;
        assert!(!MerkleTree::verify_proof(&bad_proof));
    }
}
