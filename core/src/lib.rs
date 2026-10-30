//! `le-sync-core`: `no_std`, allocation-free Ethereum light-client primitives.
//!
//! Scope (Sprints 4 and 5): execution-layer proofs: `ExecutionPayloadHeader` root (`exec`),
//! strict RLP (`rlp`), Merkle-Patricia proofs (`mpt`), account, storage and log lookups
//! (`state`), receipt and log decoding (`receipt`), predicates (`predicate`) and statement
//! IDs (`statement`).
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
//!   Electra..=Fulu uses the Electra SSZ types.

#![cfg_attr(not(test), no_std)]

use sha2::{Digest, Sha256};

// Lets `testkit/src/trie.rs`, which names this crate `le_sync_core`, also compile as a module of
// this crate's own tests (see `mpt::testutil`).
#[cfg(test)]
extern crate self as le_sync_core;

pub mod exec;
pub mod keccak;
pub mod mpt;
pub mod predicate;
pub mod receipt;
pub mod rlp;
pub mod state;
pub mod statement;
pub mod store_codec;
pub mod sync;
pub mod update_job;

pub type Bytes32 = [u8; 32];
pub type BlsPubkey = [u8; 48];
pub const ZERO: Bytes32 = [0u8; 32];

/// Mainnet preset `SYNC_COMMITTEE_SIZE`. Upper bound used for the on-stack buffer.
pub const MAX_SYNC_COMMITTEE_SIZE: usize = 512;

// Altair (frozen for Altair..=Deneb data). Altair sync-protocol "Constants".
pub const FINALIZED_ROOT_GINDEX: u64 = 105;
pub const CURRENT_SYNC_COMMITTEE_GINDEX: u64 = 54;
pub const NEXT_SYNC_COMMITTEE_GINDEX: u64 = 55;

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
    /// RLP is malformed or not canonical (Sprint 4). Also: a decoded account / storage value
    /// has the wrong shape (bad arity, leading zeros, wrong hash length).
    InvalidRlp,
    /// A Merkle-Patricia proof does not verify under the given root: hash mismatch, missing or
    /// surplus nodes, bad hex-prefix path, or malformed node structure (Sprint 4).
    InvalidTrieProof,
    /// A verified receipt does not yield the requested log (Sprint 5): the transaction failed,
    /// there is no receipt at the index, the log index is out of range, or the log's address
    /// or topics differ from the filter.
    LogMismatch,
    /// The predicate does not hold over the verified value, or its target is absent from it
    /// (Sprint 5, provisional until RFP-021 Func #4 is confirmed).
    PredicateFalse,
    CommitteeSizeMismatch,
    InsufficientParticipants,
    BadSlotOrder,
    PeriodSkipped,
    UpdateNotRelevant,
    FinalizedHeaderNotEmpty,
    NextCommitteeNotEmpty,
    NextCommitteeMismatch,
    BadSignature,
    /// Checkpoint is older than the operator's weak-subjectivity guideline
    /// (`LightClientStore::assert_within_weak_subjectivity_period`). Not a spec assert.
    CheckpointStale,
    /// Participation is below 2/3. **Project-defined, not an Altair spec error**: the spec
    /// accepts such an update as valid (it can move the optimistic header and
    /// `best_valid_update`, never the finalized header). Returned only by the `wire` strict
    /// gate, never by `process_light_client_update`, so the spec vectors are unaffected.
    BelowThreshold,
    /// The chain binding (chain ID, genesis validators root, fork schedule, preset timing)
    /// the verifier expected differs from the one the proof commits to. Consumer-side check;
    /// the guest itself cannot detect a mislabelled `chain_id`.
    ChainMismatch,
    /// A staged update step was called out of order (`update_job`): the saved job is not at
    /// the step this call expects. Nothing was changed.
    WrongStep,
    /// The saved job does not belong to the update presented now (or the job bytes are
    /// malformed). Nothing was changed.
    JobMismatch,
    /// The light-client store is not the one the staged job was begun against (another
    /// update was applied in between). Nothing was changed; begin again.
    StoreChanged,
    /// Store bytes are not a canonical `store_codec` v1 encoding, or the store cannot be
    /// encoded (invalid committee length).
    StoreEncoding,
}

/// Stable numeric error code. Numbers are part of the public contract (dry-run and on-chain
/// paths report the same codes): never renumber or reuse a retired value.
pub type ErrorCode = u16;

impl Error {
    /// Every variant, for coverage tests. Keep in sync with the enum; `code()` and
    /// `message()` are exhaustive matches, so a new variant fails to compile until it has both.
    pub const ALL: [Error; 26] = [
        Error::BadConfig,
        Error::UnsupportedFork,
        Error::BadSyncCommitteeSize,
        Error::TrustedRootMismatch,
        Error::InvalidBranch,
        Error::GenesisFinalizedHeaderNotEmpty,
        Error::InvalidRlp,
        Error::InvalidTrieProof,
        Error::LogMismatch,
        Error::PredicateFalse,
        Error::CommitteeSizeMismatch,
        Error::InsufficientParticipants,
        Error::BadSlotOrder,
        Error::PeriodSkipped,
        Error::UpdateNotRelevant,
        Error::FinalizedHeaderNotEmpty,
        Error::NextCommitteeNotEmpty,
        Error::NextCommitteeMismatch,
        Error::BadSignature,
        Error::CheckpointStale,
        Error::BelowThreshold,
        Error::ChainMismatch,
        Error::WrongStep,
        Error::JobMismatch,
        Error::StoreChanged,
        Error::StoreEncoding,
    ];

    /// Stable code. Ranges: 1xx config, 2xx bootstrap/branches, 3xx update validity,
    /// 4xx signature, 5xx policy and chain identity.
    pub const fn code(&self) -> ErrorCode {
        match self {
            Error::BadConfig => 100,
            Error::UnsupportedFork => 101,
            Error::BadSyncCommitteeSize => 102,
            Error::TrustedRootMismatch => 200,
            Error::InvalidBranch => 201,
            Error::GenesisFinalizedHeaderNotEmpty => 202,
            Error::InvalidRlp => 203,
            Error::InvalidTrieProof => 204,
            Error::LogMismatch => 205,
            Error::PredicateFalse => 206,
            Error::CommitteeSizeMismatch => 300,
            Error::InsufficientParticipants => 301,
            Error::BadSlotOrder => 302,
            Error::PeriodSkipped => 303,
            Error::UpdateNotRelevant => 304,
            Error::FinalizedHeaderNotEmpty => 305,
            Error::NextCommitteeNotEmpty => 306,
            Error::NextCommitteeMismatch => 307,
            Error::WrongStep => 308,
            Error::JobMismatch => 309,
            Error::StoreChanged => 310,
            Error::StoreEncoding => 311,
            Error::BadSignature => 400,
            Error::CheckpointStale => 500,
            Error::BelowThreshold => 501,
            Error::ChainMismatch => 502,
        }
    }

    /// Actionable, human-readable text. Static so it is usable in `no_std`.
    pub const fn message(&self) -> &'static str {
        match self {
            Error::BadConfig => "chain configuration is invalid (zero slots_per_epoch, zero epochs_per_period, or malformed fork schedule); fix the spec/config input",
            Error::UnsupportedFork => "slot is at or after a fork whose light-client layout is not supported; use a newer verifier build",
            Error::BadSyncCommitteeSize => "sync committee size is not a power of two within the supported maximum; check the preset",
            Error::TrustedRootMismatch => "bootstrap header does not hash to the trusted block root; obtain the bootstrap for the configured checkpoint or re-check the checkpoint",
            Error::InvalidBranch => "Merkle branch does not prove the claimed value under the given state root; the update or bootstrap data is corrupt or forged",
            Error::GenesisFinalizedHeaderNotEmpty => "finalized header at the genesis slot must be the empty header",
            Error::InvalidRlp => "RLP data is malformed or not canonically encoded, or a decoded account/storage value has the wrong shape; the proof payload is corrupt or forged",
            Error::InvalidTrieProof => "Merkle-Patricia proof does not verify under the given root (hash mismatch, missing or surplus node, or malformed path); the account/storage proof is corrupt, forged, or for another state",
            Error::LogMismatch => "the receipt does not yield the requested log (failed transaction, no receipt at that index, log index out of range, or address/topics differ from the request); check the transaction index, log index and filter",
            Error::PredicateFalse => "the predicate does not hold over the verified value, or its target is not present in it; the statement is not emitted",
            Error::CommitteeSizeMismatch => "participation bitfield or next committee size does not match the current sync committee",
            Error::InsufficientParticipants => "update has no sync committee participants",
            Error::BadSlotOrder => "slots must satisfy current >= signature > attested >= finalized",
            Error::PeriodSkipped => "update signature period is not the store's period (or the next one when the next committee is known); fetch the intermediate period updates first",
            Error::UpdateNotRelevant => "update is not newer than the finalized header and offers no next sync committee; nothing to apply",
            Error::FinalizedHeaderNotEmpty => "update carries a finalized header but no finality branch",
            Error::NextCommitteeNotEmpty => "update carries a next sync committee but no next-committee branch",
            Error::NextCommitteeMismatch => "update offers a next sync committee different from the one already proven for this period",
            Error::BadSignature => "sync committee aggregate signature is invalid for this chain's signing domain; check genesis_validators_root, fork versions and the signing committee",
            Error::CheckpointStale => "finalized checkpoint is older than the weak-subjectivity guideline; obtain a fresher trusted checkpoint",
            Error::BelowThreshold => "sync committee participation is below 2/3; update rejected without verifying the signature",
            Error::ChainMismatch => "proof commits to a different chain than expected (chain ID, genesis_validators_root, fork schedule or preset timing); verify against the correct chain",
            Error::WrongStep => "staged update step called out of order; the saved job is not at the step this call expects (begin, then miller, then finish)",
            Error::JobMismatch => "the saved update job does not match the update presented (or the job bytes are malformed); finish the job with the update it was begun with, or begin again",
            Error::StoreChanged => "the light-client store changed since this update job was begun; begin the update again against the current store",
            Error::StoreEncoding => "store bytes are not a canonical v1 encoding, or the store cannot be encoded; the stored state is corrupt or from another version",
        }
    }
}

pub fn hash_pair(a: &Bytes32, b: &Bytes32) -> Bytes32 {
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
    // `n` is a power of two (checked above): log2(n) halving passes.
    let mut len = n;
    for _ in 0..n.trailing_zeros() {
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

// ---- BLS signature verification ------------------------------------------------------------

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
                assert!(is_valid_merkle_branch(
                    &leaf,
                    &branch,
                    depth,
                    index as u64,
                    &root
                ));
                // wrong index / wrong leaf / wrong root
                assert!(!is_valid_merkle_branch(
                    &leaf,
                    &branch,
                    depth,
                    (index ^ 1) as u64,
                    &root
                ));
                assert!(!is_valid_merkle_branch(
                    &leaf_n(999),
                    &branch,
                    depth,
                    index as u64,
                    &root
                ));
                assert!(!is_valid_merkle_branch(
                    &leaf,
                    &branch,
                    depth,
                    index as u64,
                    &leaf_n(7)
                ));
                // flip each bit-0 of every byte of every node
                for n in 0..branch.len() {
                    for b in 0..32 {
                        let mut bad = branch.clone();
                        bad[n][b] ^= 1;
                        assert!(!is_valid_merkle_branch(
                            &leaf,
                            &bad,
                            depth,
                            index as u64,
                            &root
                        ));
                    }
                }
                // short branch is rejected, not a panic
                assert!(!is_valid_merkle_branch(
                    &leaf,
                    &branch[1..],
                    depth,
                    index as u64,
                    &root
                ));
            }
        }
    }

    #[test]
    fn normalized_branch_extra_nodes_must_be_zero() {
        let levels = tree(6);
        let root = levels.last().unwrap()[0];
        let leaf = levels[0][41];
        let b6 = branch_for(&levels, 41);
        assert!(is_valid_normalized_merkle_branch(
            &leaf,
            &b6,
            FINALIZED_ROOT_GINDEX,
            &root
        ));
        let mut b7 = vec![ZERO];
        b7.extend_from_slice(&b6);
        assert!(is_valid_normalized_merkle_branch(
            &leaf,
            &b7,
            FINALIZED_ROOT_GINDEX,
            &root
        ));
        b7[0] = leaf_n(1);
        assert!(!is_valid_normalized_merkle_branch(
            &leaf,
            &b7,
            FINALIZED_ROOT_GINDEX,
            &root
        ));
        // too short for the gindex
        assert!(!is_valid_normalized_merkle_branch(
            &leaf,
            &b6,
            FINALIZED_ROOT_GINDEX_ELECTRA,
            &root
        ));
    }

    // ---- header / committee roots (structure checks vs a recursive merkleizer) ------------

    fn merkleize_recursive(chunks: &[Bytes32]) -> Bytes32 {
        if chunks.len() == 1 {
            return chunks[0];
        }
        let h = chunks.len() / 2;
        hash_pair(
            &merkleize_recursive(&chunks[..h]),
            &merkleize_recursive(&chunks[h..]),
        )
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
        assert_ne!(
            h.hash_tree_root(),
            BeaconBlockHeader::default().hash_tree_root()
        );
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
        assert_eq!(
            sync_committee_root(&pks[..100], &agg),
            Err(Error::BadSyncCommitteeSize)
        );
        assert_eq!(
            sync_committee_root(&[], &agg),
            Err(Error::BadSyncCommitteeSize)
        );
    }

    // ---- fork selection ---------------------------------------------------------------------

    const CFG: ChainConfig = ChainConfig {
        slots_per_epoch: 32,
        electra_fork_epoch: 10,
        gloas_fork_epoch: Some(100),
    };

    #[test]
    fn gindices_switch_at_electra_and_fail_closed_at_gloas() {
        assert_eq!(
            CFG.gindices_at_slot(10 * 32 - 1).unwrap().finalized_root,
            105
        );
        assert_eq!(CFG.gindices_at_slot(10 * 32).unwrap().finalized_root, 169);
        assert_eq!(
            CFG.gindices_at_slot(100 * 32 - 1).unwrap().finalized_root,
            169
        );
        assert_eq!(CFG.gindices_at_slot(100 * 32), Err(Error::UnsupportedFork));
        let bad = ChainConfig {
            slots_per_epoch: 0,
            ..CFG
        };
        assert_eq!(bad.gindices_at_slot(1), Err(Error::BadConfig));
    }

    // ---- finality branch: synthetic BeaconState-shaped trees --------------------------------

    fn finality_fixture(
        attested_slot: u64,
        depth: u32,
    ) -> (BeaconBlockHeader, BeaconBlockHeader, Vec<Bytes32>) {
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
                assert_eq!(
                    verify_finality_branch(&CFG, &att, &fin, &bad),
                    Err(Error::InvalidBranch)
                );
            }
        }
        let mut f2 = fin;
        f2.slot += 1; // different finalized header => different leaf
        assert_eq!(
            verify_finality_branch(&CFG, &att, &f2, &br),
            Err(Error::InvalidBranch)
        );
        let mut a2 = att;
        a2.state_root[0] ^= 1;
        assert_eq!(
            verify_finality_branch(&CFG, &a2, &fin, &br),
            Err(Error::InvalidBranch)
        );
    }

    #[test]
    fn finality_branch_fork_mismatch_and_gloas() {
        // Electra branch (7) presented for a pre-Electra slot: leading node non-zero => reject
        let (mut att, fin, br) = finality_fixture(20 * 32, 7);
        att.slot = 5 * 32;
        assert_eq!(
            verify_finality_branch(&CFG, &att, &fin, &br),
            Err(Error::InvalidBranch)
        );
        // Pre-Electra branch (6) presented for an Electra slot: too short => reject
        let (mut att6, fin6, br6) = finality_fixture(5 * 32, 6);
        att6.slot = 20 * 32;
        assert_eq!(
            verify_finality_branch(&CFG, &att6, &fin6, &br6),
            Err(Error::InvalidBranch)
        );
        // Gloas slot: refuse rather than guess a depth
        let (mut att, fin, br) = finality_fixture(20 * 32, 7);
        att.slot = 100 * 32;
        assert_eq!(
            verify_finality_branch(&CFG, &att, &fin, &br),
            Err(Error::UnsupportedFork)
        );
    }

    #[test]
    fn finality_branch_genesis_special_case() {
        // finalized slot 0 => empty header, leaf = zero hash
        let mut leaves: Vec<Bytes32> = (0..128u64).map(leaf_n).collect();
        leaves[41] = ZERO;
        let levels = build_levels(&leaves);
        let att = BeaconBlockHeader {
            slot: 20 * 32,
            state_root: levels.last().unwrap()[0],
            ..Default::default()
        };
        let br = branch_for(&levels, 41);
        assert_eq!(
            verify_finality_branch(&CFG, &att, &BeaconBlockHeader::default(), &br),
            Ok(())
        );
        let nonempty = BeaconBlockHeader {
            slot: 0,
            proposer_index: 1,
            ..Default::default()
        };
        assert_eq!(
            verify_finality_branch(&CFG, &att, &nonempty, &br),
            Err(Error::GenesisFinalizedHeaderNotEmpty)
        );
    }

    // ---- bootstrap ------------------------------------------------------------------------------

    fn bootstrap_fixture(
        slot: u64,
        depth: u32,
        gindex_index: usize,
    ) -> (BeaconBlockHeader, Vec<BlsPubkey>, BlsPubkey, Vec<Bytes32>) {
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
        assert_eq!(
            verify_bootstrap(&CFG, &h5.hash_tree_root(), &h5, &pks5, &agg5, &br5),
            Ok(())
        );

        // wrong trusted root
        assert_eq!(
            verify_bootstrap(&CFG, &leaf_n(1), &h, &pks, &agg, &br),
            Err(Error::TrustedRootMismatch)
        );
        // tampered pubkey / aggregate / branch node
        let mut p2 = pks.clone();
        p2[300][47] ^= 1;
        assert_eq!(
            verify_bootstrap(&CFG, &root, &h, &p2, &agg, &br),
            Err(Error::InvalidBranch)
        );
        let mut a2 = agg;
        a2[0] ^= 1;
        assert_eq!(
            verify_bootstrap(&CFG, &root, &h, &pks, &a2, &br),
            Err(Error::InvalidBranch)
        );
        for n in 0..br.len() {
            let mut bad = br.clone();
            bad[n][31] ^= 1;
            assert_eq!(
                verify_bootstrap(&CFG, &root, &h, &pks, &agg, &bad),
                Err(Error::InvalidBranch)
            );
        }
    }

    // ---- stable error codes ---------------------------------------------------------------

    #[test]
    fn every_error_has_a_unique_code_and_a_message() {
        for (i, e) in Error::ALL.iter().enumerate() {
            assert_ne!(e.code(), 0, "{e:?}");
            assert!(e.message().len() > 10, "{e:?}");
            for o in &Error::ALL[i + 1..] {
                assert_ne!(e.code(), o.code(), "{e:?} vs {o:?}");
            }
        }
    }

    #[test]
    fn error_code_numbering_is_pinned() {
        // Changing any of these is a breaking change to the public error contract.
        let pinned: [(Error, ErrorCode); 26] = [
            (Error::BadConfig, 100),
            (Error::UnsupportedFork, 101),
            (Error::BadSyncCommitteeSize, 102),
            (Error::TrustedRootMismatch, 200),
            (Error::InvalidBranch, 201),
            (Error::GenesisFinalizedHeaderNotEmpty, 202),
            (Error::InvalidRlp, 203),
            (Error::InvalidTrieProof, 204),
            (Error::LogMismatch, 205),
            (Error::PredicateFalse, 206),
            (Error::CommitteeSizeMismatch, 300),
            (Error::InsufficientParticipants, 301),
            (Error::BadSlotOrder, 302),
            (Error::PeriodSkipped, 303),
            (Error::UpdateNotRelevant, 304),
            (Error::FinalizedHeaderNotEmpty, 305),
            (Error::NextCommitteeNotEmpty, 306),
            (Error::NextCommitteeMismatch, 307),
            (Error::WrongStep, 308),
            (Error::JobMismatch, 309),
            (Error::StoreChanged, 310),
            (Error::StoreEncoding, 311),
            (Error::BadSignature, 400),
            (Error::CheckpointStale, 500),
            (Error::BelowThreshold, 501),
            (Error::ChainMismatch, 502),
        ];
        assert_eq!(pinned.len(), Error::ALL.len());
        for (e, c) in pinned {
            assert_eq!(e.code(), c, "{e:?}");
            assert!(Error::ALL.contains(&e), "{e:?} missing from Error::ALL");
        }
    }

    #[test]
    fn subtree_index_strips_the_leading_one_bit() {
        // Through `is_valid_normalized_merkle_branch` only the low `depth` bits are ever read, so
        // a wrong high bit is invisible there; pin the function itself.
        assert_eq!(get_subtree_index(1), 0);
        assert_eq!(get_subtree_index(2), 0);
        assert_eq!(get_subtree_index(3), 1);
        assert_eq!(get_subtree_index(25), 9); // execution payload in BeaconBlockBody
        assert_eq!(get_subtree_index(54), 22); // altair current_sync_committee
        assert_eq!(get_subtree_index(55), 23); // altair next_sync_committee
        assert_eq!(get_subtree_index(105), 41); // altair finalized root
        assert_eq!(get_subtree_index(86), 22); // electra current_sync_committee
        assert_eq!(get_subtree_index(87), 23); // electra next_sync_committee
        assert_eq!(get_subtree_index(169), 41); // electra finalized root
    }
}
