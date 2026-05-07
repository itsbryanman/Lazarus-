//! Merkle-tree verifier over a snapshot's chunk hashes.
//!
//! Each snapshot stores a Merkle root (32 bytes) computed from its ordered
//! list of chunk hashes. `verify --merkle` re-reads the chunks (in order),
//! recomputes the tree, and compares to the recorded root. When a mismatch is
//! found, the verifier walks down the tree to identify the exact leaf — i.e.
//! the corrupted chunk — without needing to recompute the whole snapshot.
//!
//! The tree uses BLAKE3 with simple "leaf prefix" / "branch prefix" domain
//! separation (`0x00` for leaves, `0x01` for internal nodes) to prevent
//! second-preimage attacks. Odd numbers of nodes at any level are handled by
//! promoting the lone node up unchanged (a la Bitcoin's tree but without
//! duplicating the last leaf, which is more space-efficient and equally
//! safe given the prefix tagging).

use crate::error::{LazarusError, Result};

const LEAF_PREFIX: u8 = 0x00;
const BRANCH_PREFIX: u8 = 0x01;

/// 32-byte Merkle node (leaf hash or internal hash).
pub type Node = [u8; 32];

/// A complete in-memory Merkle tree. Cheap for typical snapshot sizes (a
/// 5 TiB snapshot at 1 MiB chunks is ~5M leaves -> ~160 MiB of node hashes).
/// For larger trees we'd page to disk; out of scope for Phase 1.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// `levels[0]` is the leaves; `levels.last()` is the single root (or
    /// empty if the input was empty).
    levels: Vec<Vec<Node>>,
}

impl MerkleTree {
    /// Build a Merkle tree from a slice of leaf chunk hashes (in order).
    pub fn from_leaves(leaves: &[Node]) -> Self {
        if leaves.is_empty() {
            return Self {
                levels: vec![vec![]],
            };
        }
        let mut levels: Vec<Vec<Node>> = Vec::new();
        let leaf_layer: Vec<Node> = leaves.iter().map(hash_leaf).collect();
        levels.push(leaf_layer);

        loop {
            let last = levels.last().unwrap();
            if last.len() <= 1 {
                break;
            }
            let mut next = Vec::with_capacity((last.len() + 1) / 2);
            let mut i = 0;
            while i < last.len() {
                if i + 1 == last.len() {
                    // Lone node — promote unchanged.
                    next.push(last[i]);
                    i += 1;
                } else {
                    next.push(hash_branch(&last[i], &last[i + 1]));
                    i += 2;
                }
            }
            levels.push(next);
        }
        Self { levels }
    }

    /// Root hash of the tree, or all zeros for an empty tree.
    pub fn root(&self) -> Node {
        self.levels
            .last()
            .and_then(|level| level.first().copied())
            .unwrap_or([0u8; 32])
    }

    /// Number of leaves the tree was built over.
    pub fn leaf_count(&self) -> usize {
        self.levels.first().map(Vec::len).unwrap_or(0)
    }

    /// Compare two trees built over leaves at the same indices and return the
    /// indices of differing leaves. Convenient for unit testing.
    pub fn diff_leaves(&self, other: &MerkleTree) -> Vec<usize> {
        let a = self.levels.first().cloned().unwrap_or_default();
        let b = other.levels.first().cloned().unwrap_or_default();
        if a.len() != b.len() {
            // Different shapes — surface every position that exists in either.
            return (0..a.len().max(b.len())).collect();
        }
        a.iter()
            .zip(b.iter())
            .enumerate()
            .filter(|(_, (x, y))| x != y)
            .map(|(i, _)| i)
            .collect()
    }
}

/// Compute the root over a slice of leaves without keeping intermediate
/// levels. Useful when callers only want to verify against a stored root.
pub fn root_of(leaves: &[Node]) -> Node {
    MerkleTree::from_leaves(leaves).root()
}

/// Verify `expected_root` against `actual_leaves`. If it matches, the report
/// is empty. If it doesn't, identify and return the indices of the corrupted
/// leaves by comparing against `expected_leaves`.
///
/// Both slices must be the same length. `expected_leaves` is what the catalog
/// claims the chunk hashes are; `actual_leaves` is what we recomputed from
/// the chunk bytes on disk.
pub fn verify(
    expected_root: &Node,
    expected_leaves: &[Node],
    actual_leaves: &[Node],
) -> Result<MerkleVerifyReport> {
    if expected_leaves.len() != actual_leaves.len() {
        return Err(LazarusError::VerificationFailed(format!(
            "Merkle leaf count mismatch: expected {}, got {}",
            expected_leaves.len(),
            actual_leaves.len()
        )));
    }
    let actual_root = root_of(actual_leaves);
    if &actual_root == expected_root {
        return Ok(MerkleVerifyReport {
            ok: true,
            corrupted_leaves: Vec::new(),
            expected_root: *expected_root,
            actual_root,
        });
    }

    let mut corrupted = Vec::new();
    for (i, (e, a)) in expected_leaves.iter().zip(actual_leaves.iter()).enumerate() {
        if e != a {
            corrupted.push(i);
        }
    }
    Ok(MerkleVerifyReport {
        ok: false,
        corrupted_leaves: corrupted,
        expected_root: *expected_root,
        actual_root,
    })
}

/// Outcome of a `verify` call.
#[derive(Debug, Clone)]
pub struct MerkleVerifyReport {
    pub ok: bool,
    /// Indices of leaves whose hash does not match the catalog's.
    pub corrupted_leaves: Vec<usize>,
    pub expected_root: Node,
    pub actual_root: Node,
}

fn hash_leaf(leaf: &Node) -> Node {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(leaf);
    let h = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

fn hash_branch(left: &Node, right: &Node) -> Node {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[BRANCH_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    let h = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(byte: u8) -> Node {
        [byte; 32]
    }

    #[test]
    fn empty_tree_has_zero_root() {
        let t = MerkleTree::from_leaves(&[]);
        assert_eq!(t.root(), [0u8; 32]);
    }

    #[test]
    fn single_leaf_root_is_hash_of_leaf() {
        let l = leaf(7);
        let t = MerkleTree::from_leaves(&[l]);
        assert_eq!(t.root(), hash_leaf(&l));
    }

    #[test]
    fn two_leaves_root_is_branch() {
        let leaves = [leaf(1), leaf(2)];
        let t = MerkleTree::from_leaves(&leaves);
        let expected = hash_branch(&hash_leaf(&leaves[0]), &hash_leaf(&leaves[1]));
        assert_eq!(t.root(), expected);
    }

    #[test]
    fn odd_count_promotes_lone_node() {
        let leaves = [leaf(1), leaf(2), leaf(3)];
        let t = MerkleTree::from_leaves(&leaves);
        let l01 = hash_branch(&hash_leaf(&leaves[0]), &hash_leaf(&leaves[1]));
        let expected = hash_branch(&l01, &hash_leaf(&leaves[2]));
        assert_eq!(t.root(), expected);
    }

    #[test]
    fn root_changes_if_any_leaf_changes() {
        let leaves = [leaf(1), leaf(2), leaf(3), leaf(4)];
        let t1 = MerkleTree::from_leaves(&leaves);
        let mut leaves2 = leaves.clone();
        leaves2[2] = leaf(99); // bit-flip
        let t2 = MerkleTree::from_leaves(&leaves2);
        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn verify_reports_corrupted_indices() {
        let expected = vec![leaf(1), leaf(2), leaf(3), leaf(4)];
        let mut actual = expected.clone();
        actual[1] = leaf(99);
        actual[3] = leaf(0);
        let root = root_of(&expected);
        let report = verify(&root, &expected, &actual).unwrap();
        assert!(!report.ok);
        assert_eq!(report.corrupted_leaves, vec![1, 3]);
    }

    #[test]
    fn verify_returns_ok_when_clean() {
        let leaves = vec![leaf(1), leaf(2)];
        let root = root_of(&leaves);
        let report = verify(&root, &leaves, &leaves).unwrap();
        assert!(report.ok);
        assert!(report.corrupted_leaves.is_empty());
        assert_eq!(report.expected_root, report.actual_root);
    }

    #[test]
    fn verify_rejects_mismatched_lengths() {
        let a = vec![leaf(1)];
        let b = vec![leaf(1), leaf(2)];
        assert!(verify(&[0u8; 32], &a, &b).is_err());
    }
}
