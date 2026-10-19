//! `le-sync-core`: `no_std`, allocation-free Ethereum light-client primitives.
//!
//! Scope (Sprint 1): SSZ Merkle-branch verification as the consensus specs define it,
//! with the light-client generalized indices selected per fork.
//!
//! Spec map (all from `ethereum/consensus-specs`):
//! * `phase0/beacon-chain.md`            `is_valid_merkle_branch`
//! * `altair/light-client/sync-protocol` `get_subtree_index`, `is_valid_normalized_merkle_branch`,
//!   `initialize_light_client_store` (bootstrap checks), `validate_light_client_update`
//!   (finality-branch check incl. the genesis special case)
//! * `electra/light-client/sync-protocol` `*_GINDEX_ELECTRA` (169 / 86 / 87) and the
//!   `*_gindex_at_slot` helpers that switch on `ELECTRA_FORK_EPOCH`
//! * Fulu: `BeaconState` only gains `proposer_lookahead` as its last field (38 fields, still
//!   padded to 64 leaves) so every light-client gindex is unchanged. Light-client data for
//!   Electra..=Fulu uses the Electra SSZ types (see Gloas LC networking spec).
//! * Gloas changes the gindices (`*_GINDEX_GLOAS`). They are NOT implemented here, so
//!   slots at/after the Gloas fork epoch are rejected (fail closed), never verified with
//!   the wrong depth.
//!
//! Not covered yet (Sprint 2+): BLS aggregate check, period/relevance asserts,
//! weak-subjectivity period, `Capella+` execution-branch checks.

#![cfg_attr(not(test), no_std)]

use sha2::{Digest, Sha256};

pub type Bytes32 = [u8; 32];
pub type BlsPubkey = [u8; 48];
pub const ZERO: Bytes32 = [0u8; 32];

/// Mainnet preset `SYNC_COMMITTEE_SIZE`. Upper bound used for the on-stack buffer.
pub const MAX_SYNC_COMMITTEE_SIZE: usize = 512;

// Altair (frozen for Altair..=Deneb data). Altair sync-protocol "Constants".
pub const FINALIZED_ROOT_GINDEX: u64 = 105;
pub const CURRENT_SYNC_COMMITTEE_GINDEX: u64 = 54;
pub const NEXT_SYNC_COMMITTEE_GINDEX: u64 = 55;
// Electra sync-protocol "New constants". Unchanged by Fulu.
pub const FINALIZED_ROOT_GINDEX_ELECTRA: u64 = 169;
pub const CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA: u64 = 86;
pub const NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA: u64 = 87;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `hash_tree_root(bootstrap.header.beacon) != trusted_block_root`.
    TrustedRootMismatch,
    /// Merkle branch does not prove the leaf under the given root.
    InvalidBranch,
    /// Slot is at/after a fork whose light-client gindices this crate does not implement.
    UnsupportedFork,
    /// `slots_per_epoch == 0` or similar.
    BadConfig,
    /// Sync committee length is not a power of two within `MAX_SYNC_COMMITTEE_SIZE`.
    BadSyncCommitteeSize,
    /// Finalized header at genesis slot must be the empty header.
    GenesisFinalizedHeaderNotEmpty,
}

fn hash_pair(a: &Bytes32, b: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// `floorlog2` from the SSZ merkle-proofs spec (`x` must be > 0; returns 0 for 0).
pub fn floorlog2(x: u64) -> u32 {
    if x == 0 {
        0
    } else {
        63 - x.leading_zeros()
    }
}

/// Altair `get_subtree_index`: `gindex % 2**floorlog2(gindex)`.
pub fn get_subtree_index(gindex: u64) -> u64 {
    gindex ^ (1u64 << floorlog2(gindex))
}

/// phase0 `is_valid_merkle_branch`. Returns false (instead of panicking) on a short branch.
pub fn is_valid_merkle_branch(
    leaf: &Bytes32,
    branch: &[Bytes32],
    depth: u32,
    index: u64,
    root: &Bytes32,
) -> bool {
    if depth >= 64 || branch.len() < depth as usize {
        return false;
    }
    let mut value = *leaf;
    for i in 0..depth {
        let sibling = &branch[i as usize];
        value = if (index >> i) & 1 == 1 {
            hash_pair(sibling, &value)
        } else {
            hash_pair(&value, sibling)
        };
    }
    value == *root
}

/// Altair `is_valid_normalized_merkle_branch`: the branch may be longer than the gindex
/// depth, in which case the extra leading nodes must all be zero. A shorter branch is
/// rejected.
pub fn is_valid_normalized_merkle_branch(
    leaf: &Bytes32,
    branch: &[Bytes32],
    gindex: u64,
    root: &Bytes32,
) -> bool {
    let depth = floorlog2(gindex);
    let index = get_subtree_index(gindex);
    if branch.len() < depth as usize {
        return false;
    }
    let num_extra = branch.len() - depth as usize;
    if branch[..num_extra].iter().any(|n| *n != ZERO) {
        return false;
    }
    is_valid_merkle_branch(leaf, &branch[num_extra..], depth, index, root)
}

/// True if any node is non-zero. Altair `is_finality_update` / `is_sync_committee_update`
/// use "branch != all-zero branch" as the presence test.
pub fn is_branch_present(branch: &[Bytes32]) -> bool {
    branch.iter().any(|n| *n != ZERO)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

fn u64_chunk(v: u64) -> Bytes32 {
    let mut c = ZERO;
    c[..8].copy_from_slice(&v.to_le_bytes());
    c
}

impl BeaconBlockHeader {
    /// SSZ `hash_tree_root`: container of 5 fields, merkleized over 8 chunks.
    pub fn hash_tree_root(&self) -> Bytes32 {
        let l = [
            u64_chunk(self.slot),
            u64_chunk(self.proposer_index),
            self.parent_root,
            self.state_root,
            self.body_root,
            ZERO,
            ZERO,
            ZERO,
        ];
        let a = [
            hash_pair(&l[0], &l[1]),
            hash_pair(&l[2], &l[3]),
            hash_pair(&l[4], &l[5]),
            hash_pair(&l[6], &l[7]),
        ];
        hash_pair(&hash_pair(&a[0], &a[1]), &hash_pair(&a[2], &a[3]))
    }

    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// `hash_tree_root(BLSPubkey)`: ByteVector[48] -> two chunks (second zero-padded) -> hash.
fn pubkey_root(pk: &BlsPubkey) -> Bytes32 {
    let mut a = ZERO;
    let mut b = ZERO;
    a.copy_from_slice(&pk[..32]);
    b[..16].copy_from_slice(&pk[32..]);
    hash_pair(&a, &b)
}

/// `hash_tree_root(SyncCommittee{pubkeys: Vector[BLSPubkey, N], aggregate_pubkey})`.
pub fn sync_committee_root(
    pubkeys: &[BlsPubkey],
    aggregate_pubkey: &BlsPubkey,
) -> Result<Bytes32, Error> {
    let n = pubkeys.len();
    if n == 0 || !n.is_power_of_two() || n > MAX_SYNC_COMMITTEE_SIZE {
        return Err(Error::BadSyncCommitteeSize);
    }
    let mut buf = [ZERO; MAX_SYNC_COMMITTEE_SIZE];
    for (i, pk) in pubkeys.iter().enumerate() {
        buf[i] = pubkey_root(pk);
    }
    let mut len = n;
    while len > 1 {
        for i in 0..len / 2 {
            buf[i] = hash_pair(&buf[2 * i], &buf[2 * i + 1]);
        }
        len /= 2;
    }
    Ok(hash_pair(&buf[0], &pubkey_root(aggregate_pubkey)))
}

/// Light-client generalized indices in force at a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LcGindices {
    pub finalized_root: u64,
    pub current_sync_committee: u64,
    pub next_sync_committee: u64,
}

/// Per-chain fork parameters (from the beacon `/eth/v1/config/spec` endpoint).
/// Fulu needs no entry: its light-client gindices equal Electra's.
#[derive(Clone, Copy, Debug)]
pub struct ChainConfig {
    pub slots_per_epoch: u64,
    pub electra_fork_epoch: u64,
    /// `None` if the chain has no scheduled Gloas fork.
    pub gloas_fork_epoch: Option<u64>,
}

impl ChainConfig {
    /// Electra `*_gindex_at_slot` helpers, plus fail-closed handling of Gloas.
    pub fn gindices_at_slot(&self, slot: u64) -> Result<LcGindices, Error> {
        if self.slots_per_epoch == 0 {
            return Err(Error::BadConfig);
        }
        let epoch = slot / self.slots_per_epoch;
        if let Some(g) = self.gloas_fork_epoch {
            if epoch >= g {
                return Err(Error::UnsupportedFork);
            }
        }
        Ok(if epoch >= self.electra_fork_epoch {
            LcGindices {
                finalized_root: FINALIZED_ROOT_GINDEX_ELECTRA,
                current_sync_committee: CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA,
                next_sync_committee: NEXT_SYNC_COMMITTEE_GINDEX_ELECTRA,
            }
        } else {
            LcGindices {
                finalized_root: FINALIZED_ROOT_GINDEX,
                current_sync_committee: CURRENT_SYNC_COMMITTEE_GINDEX,
                next_sync_committee: NEXT_SYNC_COMMITTEE_GINDEX,
            }
        })
    }
}

/// Altair `initialize_light_client_store` checks, minus constructing the store:
/// header matches the trusted (weak-subjectivity) root, and the current sync committee is
/// proven under `header.state_root`.
pub fn verify_bootstrap(
    cfg: &ChainConfig,
    trusted_block_root: &Bytes32,
    header: &BeaconBlockHeader,
    current_sync_committee_pubkeys: &[BlsPubkey],
    current_sync_committee_aggregate_pubkey: &BlsPubkey,
    current_sync_committee_branch: &[Bytes32],
) -> Result<(), Error> {
    if header.hash_tree_root() != *trusted_block_root {
        return Err(Error::TrustedRootMismatch);
    }
    let g = cfg.gindices_at_slot(header.slot)?.current_sync_committee;
    let leaf = sync_committee_root(
        current_sync_committee_pubkeys,
        current_sync_committee_aggregate_pubkey,
    )?;
    if is_valid_normalized_merkle_branch(
        &leaf,
        current_sync_committee_branch,
        g,
        &header.state_root,
    ) {
        Ok(())
    } else {
        Err(Error::InvalidBranch)
    }
}

/// The finality-branch part of Altair `validate_light_client_update`:
/// `finality_branch` proves `finalized_checkpoint.root` under `attested.state_root`.
/// At the genesis slot the finalized header must be empty and the leaf is the zero hash.
///
/// Caller is responsible for the other asserts (slot ordering, periods, BLS) and for
/// checking `is_branch_present` first (a non-finality update has an all-zero branch and an
/// empty finalized header).
pub fn verify_finality_branch(
    cfg: &ChainConfig,
    attested: &BeaconBlockHeader,
    finalized: &BeaconBlockHeader,
    finality_branch: &[Bytes32],
) -> Result<(), Error> {
    let g = cfg.gindices_at_slot(attested.slot)?.finalized_root;
    let leaf = if finalized.slot == 0 {
        if !finalized.is_empty() {
            return Err(Error::GenesisFinalizedHeaderNotEmpty);
        }
        ZERO
    } else {
        finalized.hash_tree_root()
    };
    if is_valid_normalized_merkle_branch(&leaf, finality_branch, g, &attested.state_root) {
        Ok(())
    } else {
        Err(Error::InvalidBranch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- independent-ish oracle: naive full tree + branch extraction --------------------

    fn leaf_n(i: u64) -> Bytes32 {
        let mut h = Sha256::new();
        h.update(b"le-sync-test-leaf");
        h.update(i.to_le_bytes());
        h.finalize().into()
    }

    /// levels[0] = leaves, last level = [root]. `leaves.len()` must be a power of two.
    fn build_levels(leaves: &[Bytes32]) -> Vec<Vec<Bytes32>> {
        let mut levels = vec![leaves.to_vec()];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let next = prev.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
            levels.push(next);
        }
        levels
    }

    fn branch_for(levels: &[Vec<Bytes32>], mut index: usize) -> Vec<Bytes32> {
        let mut out = Vec::new();
        for lvl in &levels[..levels.len() - 1] {
            out.push(lvl[index ^ 1]);
            index /= 2;
        }
        out
    }

    fn tree(depth: u32) -> Vec<Vec<Bytes32>> {
        let leaves: Vec<_> = (0..(1u64 << depth)).map(leaf_n).collect();
        build_levels(&leaves)
    }

    // ---- gindex constants derived from the spec's BeaconState field lists ----------------

    /// gindex of `<container field idx>` then optional child step, per SSZ merkleization.
    fn field_gindex(field_count: u64, field_idx: u64) -> u64 {
        field_count.next_power_of_two() + field_idx
    }

    #[test]
    fn gindices_match_beacon_state_layout() {
        // Field indices from the spec BeaconState: finalized_checkpoint=20,
        // current_sync_committee=22, next_sync_committee=23 (unchanged since Altair).
        // Checkpoint{epoch, root}: `.root` is child 1 => gindex*2+1.
        // Altair BeaconState: 24 fields. Electra: 37. Fulu (adds proposer_lookahead): 38.
        for (fork, n) in [("altair", 24u64), ("electra", 37), ("fulu", 38)] {
            let fin = field_gindex(n, 20) * 2 + 1;
            let cur = field_gindex(n, 22);
            let next = field_gindex(n, 23);
            let want = if fork == "altair" {
                (105, 54, 55)
            } else {
                (169, 86, 87)
            };
            assert_eq!((fin, cur, next), want, "{fork}");
        }
        assert_eq!(FINALIZED_ROOT_GINDEX, 105);
        assert_eq!(FINALIZED_ROOT_GINDEX_ELECTRA, 169);
        // depth / subtree index used by the verifier
        assert_eq!((floorlog2(169), get_subtree_index(169)), (7, 41));
        assert_eq!((floorlog2(86), get_subtree_index(86)), (6, 22));
        assert_eq!((floorlog2(87), get_subtree_index(87)), (6, 23));
        assert_eq!((floorlog2(105), get_subtree_index(105)), (6, 41));
        assert_eq!((floorlog2(54), get_subtree_index(54)), (5, 22));
    }

    // ---- merkle branch ---------------------------------------------------------------------

    #[test]
    fn branch_verifies_and_every_flipped_byte_fails() {
        for depth in [5u32, 6, 7] {
            let levels = tree(depth);
            let root = levels.last().unwrap()[0];
            for index in [0usize, 1, 22, 41 % (1 << depth)] {
                let leaf = levels[0][index];
                let branch = branch_for(&levels, index);
                assert!(is_valid_merkle_branch(&leaf, &branch, depth, index as u64, &root));
                // wrong index / wrong leaf / wrong root
                assert!(!is_valid_merkle_branch(&leaf, &branch, depth, (index ^ 1) as u64, &root));
                assert!(!is_valid_merkle_branch(&leaf_n(999), &branch, depth, index as u64, &root));
                assert!(!is_valid_merkle_branch(&leaf, &branch, depth, index as u64, &leaf_n(7)));
                // flip each bit-0 of every byte of every node
                for n in 0..branch.len() {
                    for b in 0..32 {
                        let mut bad = branch.clone();
                        bad[n][b] ^= 1;
                        assert!(!is_valid_merkle_branch(&leaf, &bad, depth, index as u64, &root));
                    }
                }
                // short branch is rejected, not a panic
                assert!(!is_valid_merkle_branch(&leaf, &branch[1..], depth, index as u64, &root));
            }
        }
    }

    #[test]
    fn normalized_branch_extra_nodes_must_be_zero() {
        let levels = tree(6);
        let root = levels.last().unwrap()[0];
        let leaf = levels[0][41];
        let b6 = branch_for(&levels, 41);
        assert!(is_valid_normalized_merkle_branch(&leaf, &b6, FINALIZED_ROOT_GINDEX, &root));
        let mut b7 = vec![ZERO];
        b7.extend_from_slice(&b6);
        assert!(is_valid_normalized_merkle_branch(&leaf, &b7, FINALIZED_ROOT_GINDEX, &root));
        b7[0] = leaf_n(1);
        assert!(!is_valid_normalized_merkle_branch(&leaf, &b7, FINALIZED_ROOT_GINDEX, &root));
        // too short for the gindex
        assert!(!is_valid_normalized_merkle_branch(&leaf, &b6, FINALIZED_ROOT_GINDEX_ELECTRA, &root));
    }

    // ---- header / committee roots (structure checks vs a recursive merkleizer) ------------

    fn merkleize_recursive(chunks: &[Bytes32]) -> Bytes32 {
        if chunks.len() == 1 {
            return chunks[0];
        }
        let h = chunks.len() / 2;
        hash_pair(&merkleize_recursive(&chunks[..h]), &merkleize_recursive(&chunks[h..]))
    }

    #[test]
    fn header_root_matches_recursive_merkleization() {
        let h = BeaconBlockHeader {
            slot: 11_343_904,
            proposer_index: 123_456,
            parent_root: leaf_n(1),
            state_root: leaf_n(2),
            body_root: leaf_n(3),
        };
        let chunks = [
            u64_chunk(h.slot),
            u64_chunk(h.proposer_index),
            h.parent_root,
            h.state_root,
            h.body_root,
            ZERO,
            ZERO,
            ZERO,
        ];
        assert_eq!(h.hash_tree_root(), merkleize_recursive(&chunks));
        assert_ne!(h.hash_tree_root(), BeaconBlockHeader::default().hash_tree_root());
    }

    fn pk(i: u64) -> BlsPubkey {
        let mut p = [0u8; 48];
        p[..32].copy_from_slice(&leaf_n(i));
        p[32..].copy_from_slice(&leaf_n(i + 1_000)[..16]);
        p
    }

    fn committee(n: u64) -> (Vec<BlsPubkey>, BlsPubkey) {
        ((0..n).map(pk).collect(), pk(9_999))
    }

    #[test]
    fn committee_root_matches_recursive_merkleization() {
        let (pks, agg) = committee(512);
        let roots: Vec<Bytes32> = pks.iter().map(pubkey_root).collect();
        let want = hash_pair(&merkleize_recursive(&roots), &pubkey_root(&agg));
        assert_eq!(sync_committee_root(&pks, &agg).unwrap(), want);
        assert_eq!(sync_committee_root(&pks[..100], &agg), Err(Error::BadSyncCommitteeSize));
        assert_eq!(sync_committee_root(&[], &agg), Err(Error::BadSyncCommitteeSize));
    }

    // ---- fork selection ---------------------------------------------------------------------

    const CFG: ChainConfig = ChainConfig {
        slots_per_epoch: 32,
        electra_fork_epoch: 10,
        gloas_fork_epoch: Some(100),
    };

    #[test]
    fn gindices_switch_at_electra_and_fail_closed_at_gloas() {
        assert_eq!(CFG.gindices_at_slot(10 * 32 - 1).unwrap().finalized_root, 105);
        assert_eq!(CFG.gindices_at_slot(10 * 32).unwrap().finalized_root, 169);
        assert_eq!(CFG.gindices_at_slot(100 * 32 - 1).unwrap().finalized_root, 169);
        assert_eq!(CFG.gindices_at_slot(100 * 32), Err(Error::UnsupportedFork));
        let bad = ChainConfig { slots_per_epoch: 0, ..CFG };
        assert_eq!(bad.gindices_at_slot(1), Err(Error::BadConfig));
    }

    // ---- finality branch: synthetic BeaconState-shaped trees --------------------------------

    fn finality_fixture(attested_slot: u64, depth: u32) -> (BeaconBlockHeader, BeaconBlockHeader, Vec<Bytes32>) {
        let finalized = BeaconBlockHeader {
            slot: attested_slot - 64,
            proposer_index: 7,
            parent_root: leaf_n(11),
            state_root: leaf_n(12),
            body_root: leaf_n(13),
        };
        let mut leaves: Vec<Bytes32> = (0..(1u64 << depth)).map(leaf_n).collect();
        leaves[41] = finalized.hash_tree_root();
        let levels = build_levels(&leaves);
        let attested = BeaconBlockHeader {
            slot: attested_slot,
            proposer_index: 1,
            parent_root: leaf_n(21),
            state_root: levels.last().unwrap()[0],
            body_root: leaf_n(23),
        };
        (attested, finalized, branch_for(&levels, 41))
    }

    #[test]
    fn finality_branch_electra_and_pre_electra() {
        // Electra-era attested slot: 7-node branch, gindex 169
        let (att, fin, br) = finality_fixture(20 * 32, 7);
        assert_eq!(br.len(), 7);
        assert_eq!(verify_finality_branch(&CFG, &att, &fin, &br), Ok(()));
        // pre-Electra attested slot: 6-node branch, gindex 105
        let (att, fin, br) = finality_fixture(5 * 32, 6);
        assert_eq!(br.len(), 6);
        assert_eq!(verify_finality_branch(&CFG, &att, &fin, &br), Ok(()));
    }

    #[test]
    fn finality_branch_rejects_every_tamper() {
        let (att, fin, br) = finality_fixture(20 * 32, 7);
        for n in 0..br.len() {
            for b in 0..32 {
                let mut bad = br.clone();
                bad[n][b] ^= 0x01;
                assert_eq!(verify_finality_branch(&CFG, &att, &fin, &bad), Err(Error::InvalidBranch));
            }
        }
        let mut f2 = fin;
        f2.slot += 1; // different finalized header => different leaf
        assert_eq!(verify_finality_branch(&CFG, &att, &f2, &br), Err(Error::InvalidBranch));
        let mut a2 = att;
        a2.state_root[0] ^= 1;
        assert_eq!(verify_finality_branch(&CFG, &a2, &fin, &br), Err(Error::InvalidBranch));
    }

    #[test]
    fn finality_branch_fork_mismatch_and_gloas() {
        // Electra branch (7) presented for a pre-Electra slot: leading node non-zero => reject
        let (mut att, fin, br) = finality_fixture(20 * 32, 7);
        att.slot = 5 * 32;
        assert_eq!(verify_finality_branch(&CFG, &att, &fin, &br), Err(Error::InvalidBranch));
        // Pre-Electra branch (6) presented for an Electra slot: too short => reject
        let (mut att6, fin6, br6) = finality_fixture(5 * 32, 6);
        att6.slot = 20 * 32;
        assert_eq!(verify_finality_branch(&CFG, &att6, &fin6, &br6), Err(Error::InvalidBranch));
        // Gloas slot: refuse rather than guess a depth
        let (mut att, fin, br) = finality_fixture(20 * 32, 7);
        att.slot = 100 * 32;
        assert_eq!(verify_finality_branch(&CFG, &att, &fin, &br), Err(Error::UnsupportedFork));
    }

    #[test]
    fn finality_branch_genesis_special_case() {
        // finalized slot 0 => empty header, leaf = zero hash
        let mut leaves: Vec<Bytes32> = (0..128u64).map(leaf_n).collect();
        leaves[41] = ZERO;
        let levels = build_levels(&leaves);
        let att = BeaconBlockHeader { slot: 20 * 32, state_root: levels.last().unwrap()[0], ..Default::default() };
        let br = branch_for(&levels, 41);
        assert_eq!(verify_finality_branch(&CFG, &att, &BeaconBlockHeader::default(), &br), Ok(()));
        let nonempty = BeaconBlockHeader { slot: 0, proposer_index: 1, ..Default::default() };
        assert_eq!(
            verify_finality_branch(&CFG, &att, &nonempty, &br),
            Err(Error::GenesisFinalizedHeaderNotEmpty)
        );
    }

    // ---- bootstrap ------------------------------------------------------------------------------

    fn bootstrap_fixture(slot: u64, depth: u32, gindex_index: usize) -> (BeaconBlockHeader, Vec<BlsPubkey>, BlsPubkey, Vec<Bytes32>) {
        let (pks, agg) = committee(512);
        let mut leaves: Vec<Bytes32> = (0..(1u64 << depth)).map(leaf_n).collect();
        leaves[gindex_index] = sync_committee_root(&pks, &agg).unwrap();
        let levels = build_levels(&leaves);
        let header = BeaconBlockHeader {
            slot,
            proposer_index: 5,
            parent_root: leaf_n(31),
            state_root: levels.last().unwrap()[0],
            body_root: leaf_n(33),
        };
        (header, pks, agg, branch_for(&levels, gindex_index))
    }

    #[test]
    fn bootstrap_verifies_and_rejects_tamper() {
        // Electra: gindex 86 => depth 6, index 22
        let (h, pks, agg, br) = bootstrap_fixture(20 * 32, 6, 22);
        let root = h.hash_tree_root();
        assert_eq!(verify_bootstrap(&CFG, &root, &h, &pks, &agg, &br), Ok(()));
        // pre-Electra: gindex 54 => depth 5, index 22
        let (h5, pks5, agg5, br5) = bootstrap_fixture(5 * 32, 5, 22);
        assert_eq!(verify_bootstrap(&CFG, &h5.hash_tree_root(), &h5, &pks5, &agg5, &br5), Ok(()));

        // wrong trusted root
        assert_eq!(verify_bootstrap(&CFG, &leaf_n(1), &h, &pks, &agg, &br), Err(Error::TrustedRootMismatch));
        // tampered pubkey / aggregate / branch node
        let mut p2 = pks.clone();
        p2[300][47] ^= 1;
        assert_eq!(verify_bootstrap(&CFG, &root, &h, &p2, &agg, &br), Err(Error::InvalidBranch));
        let mut a2 = agg;
        a2[0] ^= 1;
        assert_eq!(verify_bootstrap(&CFG, &root, &h, &pks, &a2, &br), Err(Error::InvalidBranch));
        for n in 0..br.len() {
            let mut bad = br.clone();
            bad[n][31] ^= 1;
            assert_eq!(verify_bootstrap(&CFG, &root, &h, &pks, &agg, &bad), Err(Error::InvalidBranch));
        }
    }
}
