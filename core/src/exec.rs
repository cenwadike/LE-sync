//! `ExecutionPayloadHeader` (the `execution` field of a `LightClientHeader`) and its SSZ
//! `hash_tree_root` (`no_std`, no alloc).
//!
//! Layout: Deneb. Electra and Fulu do not change the fields of `ExecutionPayloadHeader`
//! (Electra moved its request lists into `BeaconBlockBody.execution_requests`, and Fulu only
//! extends `BeaconState`). Checked against the Deneb/Electra/Fulu consensus-specs text: 17
//! fields in the order below, and `EXECUTION_PAYLOAD` gindex 25 (depth 4) still holds with
//! Electra's 13-field body. Preset sizes (`BYTES_PER_LOGS_BLOOM` = 256, `MAX_EXTRA_DATA_BYTES`
//! = 32) are the mainnet values and were not re-read from the preset files. A real header from
//! the target network is still the decisive test (its `hash_tree_root` must satisfy
//! `sync::verify_execution_branch`).
//!
//! 17 fields, padded to 32 leaves:
//!  0 parent_hash        Hash32            9 timestamp          uint64
//!  1 fee_recipient      ByteVector[20]   10 extra_data         ByteList[32]
//!  2 state_root         Bytes32          11 base_fee_per_gas   uint256
//!  3 receipts_root      Bytes32          12 block_hash         Hash32
//!  4 logs_bloom         ByteVector[256]  13 transactions_root  Bytes32
//!  5 prev_randao        Bytes32          14 withdrawals_root   Bytes32
//!  6 block_number       uint64           15 blob_gas_used      uint64
//!  7 gas_limit          uint64           16 excess_blob_gas    uint64
//!  8 gas_used           uint64

use crate::sync::verify_execution_branch;
use crate::{hash_pair, BeaconBlockHeader, Bytes32, ChainConfig, Error, ZERO};

pub const BLOOM_LEN: usize = 256;
pub const MAX_EXTRA_DATA: usize = 32;
const FIELDS_PADDED: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionPayloadHeader {
    pub parent_hash: Bytes32,
    pub fee_recipient: [u8; 20],
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
    pub logs_bloom: [u8; BLOOM_LEN],
    pub prev_randao: Bytes32,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    /// First `extra_data_len` bytes are the value; the rest must be zero padding.
    pub extra_data: [u8; MAX_EXTRA_DATA],
    pub extra_data_len: usize,
    /// uint256, SSZ little-endian.
    pub base_fee_per_gas: Bytes32,
    pub block_hash: Bytes32,
    pub transactions_root: Bytes32,
    pub withdrawals_root: Bytes32,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

fn u64_chunk(v: u64) -> Bytes32 {
    let mut c = ZERO;
    c[..8].copy_from_slice(&v.to_le_bytes());
    c
}

/// Merkleize `chunks` (a power-of-two count) in place on a stack buffer: log2(N) halving passes.
fn merkleize<const N: usize>(mut buf: [Bytes32; N]) -> Bytes32 {
    debug_assert!(N.is_power_of_two());
    let mut len = N;
    for _ in 0..N.trailing_zeros() {
        for i in 0..len / 2 {
            buf[i] = hash_pair(&buf[2 * i], &buf[2 * i + 1]);
        }
        len /= 2;
    }
    buf[0]
}

impl ExecutionPayloadHeader {
    /// `None` if `extra_data_len` exceeds the SSZ limit or the padding is not zero (a header
    /// that cannot be a valid `ByteList[32]` value).
    pub fn hash_tree_root(&self) -> Option<Bytes32> {
        if self.extra_data_len > MAX_EXTRA_DATA
            || self.extra_data[self.extra_data_len..]
                .iter()
                .any(|b| *b != 0)
        {
            return None;
        }
        let mut bloom = [ZERO; BLOOM_LEN / 32];
        for (i, c) in self.logs_bloom.chunks(32).enumerate() {
            bloom[i].copy_from_slice(c);
        }
        let mut fee = ZERO;
        fee[..20].copy_from_slice(&self.fee_recipient);
        // ByteList[32]: one data chunk, then the length is mixed in.
        let extra = hash_pair(&self.extra_data, &u64_chunk(self.extra_data_len as u64));

        let mut leaves = [ZERO; FIELDS_PADDED];
        leaves[0] = self.parent_hash;
        leaves[1] = fee;
        leaves[2] = self.state_root;
        leaves[3] = self.receipts_root;
        leaves[4] = merkleize(bloom);
        leaves[5] = self.prev_randao;
        leaves[6] = u64_chunk(self.block_number);
        leaves[7] = u64_chunk(self.gas_limit);
        leaves[8] = u64_chunk(self.gas_used);
        leaves[9] = u64_chunk(self.timestamp);
        leaves[10] = extra;
        leaves[11] = self.base_fee_per_gas;
        leaves[12] = self.block_hash;
        leaves[13] = self.transactions_root;
        leaves[14] = self.withdrawals_root;
        leaves[15] = u64_chunk(self.blob_gas_used);
        leaves[16] = u64_chunk(self.excess_blob_gas);
        Some(merkleize(leaves))
    }
}

/// The execution anchor: prove that `exec` is the execution payload header of the (already
/// verified, finalised) beacon header `finalized`, and return its `state_root`.
///
/// * `exec`'s root must satisfy `execution_branch` (gindex 25) under `finalized.body_root`.
///   Nothing from the caller is trusted: the returned state root is read out of `exec` only
///   after that check.
/// * Layout scope: Electra and later only (`UnsupportedFork` before `electra_fork_epoch`,
///   and, via `gindices_at_slot`, at or after a configured Gloas epoch). Earlier forks need
///   their own epoch configuration and layouts and are deliberately not guessed.
pub fn verify_execution_anchor(
    cfg: &ChainConfig,
    finalized: &BeaconBlockHeader,
    exec: &ExecutionPayloadHeader,
    execution_branch: &[Bytes32],
) -> Result<Bytes32, Error> {
    anchor_execution(cfg, finalized, exec, execution_branch).map(|a| a.state_root)
}

/// The fields of an execution header that `anchor_execution` has tied to a finalized beacon
/// header. Callers read the roots they prove against from here, never from the unverified
/// `ExecutionPayloadHeader` they were handed.
///
/// `transactions_root` is not included: in this header it is an SSZ root, not the
/// Merkle-Patricia transactions root, so it does not serve an MPT proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchoredExecution {
    /// Root of the account trie: account and storage proofs.
    pub state_root: Bytes32,
    /// Root of the receipts trie (`patriciaTrie(rlp(index) => receipt)`): log proofs.
    pub receipts_root: Bytes32,
    pub block_hash: Bytes32,
    pub block_number: u64,
}

/// Same checks as `verify_execution_anchor`; returns every verified field a proof needs.
pub fn anchor_execution(
    cfg: &ChainConfig,
    finalized: &BeaconBlockHeader,
    exec: &ExecutionPayloadHeader,
    execution_branch: &[Bytes32],
) -> Result<AnchoredExecution, Error> {
    // Also rejects slots_per_epoch == 0 (BadConfig) and the Gloas era (UnsupportedFork).
    cfg.gindices_at_slot(finalized.slot)?;
    if finalized.slot / cfg.slots_per_epoch < cfg.electra_fork_epoch {
        return Err(Error::UnsupportedFork);
    }
    let root = exec.hash_tree_root().ok_or(Error::InvalidBranch)?;
    verify_execution_branch(finalized, execution_branch, &root)?;
    Ok(AnchoredExecution {
        state_root: exec.state_root,
        receipts_root: exec.receipts_root,
        block_hash: exec.block_hash,
        block_number: exec.block_number,
    })
}

#[cfg(test)]
pub(crate) fn sample(seed: u8) -> ExecutionPayloadHeader {
    let b = |n: u8| [seed.wrapping_add(n); 32];
    let mut bloom = [0u8; BLOOM_LEN];
    for (i, x) in bloom.iter_mut().enumerate() {
        *x = (i as u8).wrapping_mul(seed.wrapping_add(3));
    }
    let mut extra = [0u8; MAX_EXTRA_DATA];
    extra[..5].copy_from_slice(b"hello");
    ExecutionPayloadHeader {
        parent_hash: b(1),
        fee_recipient: [seed; 20],
        state_root: b(2),
        receipts_root: b(3),
        logs_bloom: bloom,
        prev_randao: b(4),
        block_number: 1_000_000 + seed as u64,
        gas_limit: 30_000_000,
        gas_used: 12_345,
        timestamp: 1_700_000_000,
        extra_data: extra,
        extra_data_len: 5,
        base_fee_per_gas: b(5),
        block_hash: b(6),
        transactions_root: b(7),
        withdrawals_root: b(8),
        blob_gas_used: 131_072,
        excess_blob_gas: 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Independent oracle: recursive merkleization over a Vec of chunks.
    fn rec(chunks: &[Bytes32]) -> Bytes32 {
        if chunks.len() == 1 {
            return chunks[0];
        }
        let h = chunks.len() / 2;
        let mut x = Sha256::new();
        x.update(rec(&chunks[..h]));
        x.update(rec(&chunks[h..]));
        x.finalize().into()
    }
    fn sha(a: &[u8], b: &[u8]) -> Bytes32 {
        let mut x = Sha256::new();
        x.update(a);
        x.update(b);
        x.finalize().into()
    }

    /// The 17 field chunks, padded to 32, in spec order.
    fn leaves(h: &ExecutionPayloadHeader) -> Vec<Bytes32> {
        let pad = |b: &[u8]| {
            let mut c = [0u8; 32];
            c[..b.len()].copy_from_slice(b);
            c
        };
        let bloom_chunks: Vec<Bytes32> = h.logs_bloom.chunks(32).map(pad).collect();
        // ByteList[32]: data chunks (ceil(len/32), min handled by limit = 1 chunk), then mix len
        let data = pad(&h.extra_data[..h.extra_data_len]);
        let mut len_chunk = [0u8; 32];
        len_chunk[..8].copy_from_slice(&(h.extra_data_len as u64).to_le_bytes());
        let mut leaves = vec![
            h.parent_hash,
            pad(&h.fee_recipient),
            h.state_root,
            h.receipts_root,
            rec(&bloom_chunks),
            h.prev_randao,
            pad(&h.block_number.to_le_bytes()),
            pad(&h.gas_limit.to_le_bytes()),
            pad(&h.gas_used.to_le_bytes()),
            pad(&h.timestamp.to_le_bytes()),
            sha(&data, &len_chunk),
            h.base_fee_per_gas,
            h.block_hash,
            h.transactions_root,
            h.withdrawals_root,
            pad(&h.blob_gas_used.to_le_bytes()),
            pad(&h.excess_blob_gas.to_le_bytes()),
        ];
        leaves.resize(32, [0u8; 32]);
        leaves
    }

    fn oracle(h: &ExecutionPayloadHeader) -> Bytes32 {
        rec(&leaves(h))
    }

    #[test]
    fn root_matches_the_recursive_oracle() {
        for seed in [0u8, 1, 7, 200] {
            let h = sample(seed);
            assert_eq!(h.hash_tree_root(), Some(oracle(&h)), "seed {seed}");
        }
    }

    #[test]
    fn every_field_changes_the_root() {
        let base = sample(1);
        let r0 = base.hash_tree_root().unwrap();
        let mut variants: Vec<ExecutionPayloadHeader> = vec![];
        macro_rules! v {
            ($f:ident, $e:expr) => {{
                let mut h = base;
                h.$f = $e;
                variants.push(h);
            }};
        }
        v!(parent_hash, [0xEE; 32]);
        v!(fee_recipient, [0xEE; 20]);
        v!(state_root, [0xEE; 32]);
        v!(receipts_root, [0xEE; 32]);
        v!(prev_randao, [0xEE; 32]);
        v!(block_number, base.block_number + 1);
        v!(gas_limit, base.gas_limit + 1);
        v!(gas_used, base.gas_used + 1);
        v!(timestamp, base.timestamp + 1);
        v!(base_fee_per_gas, [0xEE; 32]);
        v!(block_hash, [0xEE; 32]);
        v!(transactions_root, [0xEE; 32]);
        v!(withdrawals_root, [0xEE; 32]);
        v!(blob_gas_used, base.blob_gas_used + 1);
        v!(excess_blob_gas, base.excess_blob_gas + 1);
        let mut h = base;
        h.logs_bloom[255] ^= 1;
        variants.push(h);
        let mut h = base;
        h.logs_bloom[0] ^= 1;
        variants.push(h);
        let mut h = base;
        h.extra_data[0] ^= 1;
        variants.push(h);
        let mut h = base;
        h.extra_data_len = 4;
        h.extra_data[4] = 0; // 'hell' + zero padding: shorter list
        variants.push(h);
        for (i, h) in variants.iter().enumerate() {
            assert_ne!(h.hash_tree_root(), Some(r0), "variant {i}");
        }
    }

    #[test]
    fn anchored_fields_sit_at_their_spec_leaf_positions() {
        // consensus-specs order: state_root 2, receipts_root 3, block_number 6, block_hash 12
        let h = sample(9);
        let l = leaves(&h);
        assert_eq!(l.len(), 32);
        assert_eq!(l[2], h.state_root);
        assert_eq!(l[3], h.receipts_root);
        assert_eq!(l[6][..8], h.block_number.to_le_bytes());
        assert_eq!(l[12], h.block_hash);
        // and the production root follows that order: moving one value changes only that leaf
        let mut m = h;
        m.receipts_root = [0xEE; 32];
        let mut l2 = l.clone();
        l2[3] = [0xEE; 32];
        assert_eq!(m.hash_tree_root(), Some(rec(&l2)));
        let mut m = h;
        m.block_hash = [0xEE; 32];
        let mut l2 = l;
        l2[12] = [0xEE; 32];
        assert_eq!(m.hash_tree_root(), Some(rec(&l2)));
    }

    #[test]
    fn extra_data_length_mix_in_and_limits() {
        let mut a = sample(1);
        a.extra_data = [0; 32];
        a.extra_data_len = 0;
        let mut b = a;
        b.extra_data_len = 1; // [0x00] vs []: same chunk, different length
        assert_ne!(a.hash_tree_root(), b.hash_tree_root());
        // full 32 bytes is legal
        let mut c = sample(1);
        c.extra_data = [0xAB; 32];
        c.extra_data_len = 32;
        assert!(c.hash_tree_root().is_some());
        // beyond the limit, or dirty padding: not a valid value
        c.extra_data_len = 33;
        assert_eq!(c.hash_tree_root(), None);
        let mut d = sample(1);
        d.extra_data[10] = 1; // padding after the 5 bytes of 'hello'
        assert_eq!(d.hash_tree_root(), None);
    }

    // ---- execution anchor ------------------------------------------------------------------

    /// BeaconBlockBody (16 padded leaves), execution_payload = field 9 => gindex 25, depth 4.
    fn anchor_fixture(
        slot: u64,
        exec: &ExecutionPayloadHeader,
    ) -> (BeaconBlockHeader, Vec<Bytes32>) {
        let mut leaves: Vec<Bytes32> = (0..16u8).map(|i| [0x40 + i; 32]).collect();
        leaves[9] = exec.hash_tree_root().unwrap();
        let mut level = leaves;
        let mut idx = 9usize;
        let mut branch = vec![];
        while level.len() > 1 {
            branch.push(level[idx ^ 1]);
            level = level.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
            idx /= 2;
        }
        let header = BeaconBlockHeader {
            slot,
            proposer_index: 3,
            parent_root: [1; 32],
            state_root: [2; 32],
            body_root: level[0],
        };
        (header, branch)
    }
    const CFG: ChainConfig = ChainConfig {
        slots_per_epoch: 32,
        electra_fork_epoch: 10,
        gloas_fork_epoch: Some(100),
    };

    #[test]
    fn anchor_returns_the_state_root_of_the_proven_execution_header() {
        let e = sample(3);
        let (h, br) = anchor_fixture(20 * 32, &e);
        assert_eq!(br.len(), 4);
        assert_eq!(verify_execution_anchor(&CFG, &h, &e, &br), Ok(e.state_root));
    }

    #[test]
    fn anchor_execution_returns_exactly_the_verified_fields() {
        let e = sample(3);
        let (h, br) = anchor_fixture(20 * 32, &e);
        let a = anchor_execution(&CFG, &h, &e, &br).unwrap();
        assert_eq!(a.state_root, e.state_root);
        assert_eq!(a.receipts_root, e.receipts_root);
        assert_eq!(a.block_hash, e.block_hash);
        assert_eq!(a.block_number, e.block_number);
        // the sample's values differ, so a swapped field cannot pass the checks above
        assert_ne!(a.state_root, a.receipts_root);
        assert_ne!(a.receipts_root, a.block_hash);
        assert_ne!(a.state_root, a.block_hash);
        // the older entry point returns the same state root
        assert_eq!(verify_execution_anchor(&CFG, &h, &e, &br), Ok(a.state_root));
    }

    #[test]
    fn forged_receipts_root_block_hash_and_number_do_not_anchor() {
        let e = sample(3);
        let (h, br) = anchor_fixture(20 * 32, &e);
        let mut f = e;
        f.receipts_root = [0xEE; 32];
        assert_eq!(
            anchor_execution(&CFG, &h, &f, &br),
            Err(Error::InvalidBranch)
        );
        let mut f = e;
        f.block_hash = [0xEE; 32];
        assert_eq!(
            anchor_execution(&CFG, &h, &f, &br),
            Err(Error::InvalidBranch)
        );
        let mut f = e;
        f.block_number += 1;
        assert_eq!(
            anchor_execution(&CFG, &h, &f, &br),
            Err(Error::InvalidBranch)
        );
        // the fork rules are shared with the older entry point
        let (h, br) = anchor_fixture(9 * 32, &e);
        assert_eq!(
            anchor_execution(&CFG, &h, &e, &br),
            Err(Error::UnsupportedFork)
        );
    }

    #[test]
    fn anchor_rejects_every_tamper() {
        let e = sample(3);
        let (h, br) = anchor_fixture(20 * 32, &e);
        // each branch node, each bit-0 of each byte
        for n in 0..br.len() {
            for b in 0..32 {
                let mut bad = br.clone();
                bad[n][b] ^= 1;
                assert_eq!(
                    verify_execution_anchor(&CFG, &h, &e, &bad),
                    Err(Error::InvalidBranch)
                );
            }
        }
        // a header with a substituted state root (the thing an attacker wants) does not verify
        let mut forged = e;
        forged.state_root = [0xEE; 32];
        assert_eq!(
            verify_execution_anchor(&CFG, &h, &forged, &br),
            Err(Error::InvalidBranch)
        );
        // every other field of the execution header is covered by the same root
        let mut forged = e;
        forged.block_number += 1;
        assert_eq!(
            verify_execution_anchor(&CFG, &h, &forged, &br),
            Err(Error::InvalidBranch)
        );
        // a different beacon header (body root) does not vouch for this execution header
        let mut other = h;
        other.body_root[0] ^= 1;
        assert_eq!(
            verify_execution_anchor(&CFG, &other, &e, &br),
            Err(Error::InvalidBranch)
        );
        // short branch, empty branch
        assert_eq!(
            verify_execution_anchor(&CFG, &h, &e, &br[1..]),
            Err(Error::InvalidBranch)
        );
        assert_eq!(
            verify_execution_anchor(&CFG, &h, &e, &[]),
            Err(Error::InvalidBranch)
        );
        // an invalid ByteList value cannot be hashed, so it cannot verify
        let mut bad = e;
        bad.extra_data_len = 40;
        assert_eq!(
            verify_execution_anchor(&CFG, &h, &bad, &br),
            Err(Error::InvalidBranch)
        );
    }

    #[test]
    fn anchor_is_electra_and_later_only_and_fails_closed_at_gloas() {
        let e = sample(3);
        // slot in epoch 9 (pre-Electra): refused even though the branch is valid
        let (h, br) = anchor_fixture(9 * 32 + 31, &e);
        assert_eq!(
            verify_execution_anchor(&CFG, &h, &e, &br),
            Err(Error::UnsupportedFork)
        );
        // first slot of Electra: accepted
        let (h, br) = anchor_fixture(10 * 32, &e);
        assert_eq!(verify_execution_anchor(&CFG, &h, &e, &br), Ok(e.state_root));
        // last slot before Gloas: accepted; first Gloas slot: refused
        let (h, br) = anchor_fixture(100 * 32 - 1, &e);
        assert_eq!(verify_execution_anchor(&CFG, &h, &e, &br), Ok(e.state_root));
        let (h, br) = anchor_fixture(100 * 32, &e);
        assert_eq!(
            verify_execution_anchor(&CFG, &h, &e, &br),
            Err(Error::UnsupportedFork)
        );
        // zero slots_per_epoch is a config error, not a division by zero
        let bad = ChainConfig {
            slots_per_epoch: 0,
            ..CFG
        };
        let (h, br) = anchor_fixture(20 * 32, &e);
        assert_eq!(
            verify_execution_anchor(&bad, &h, &e, &br),
            Err(Error::BadConfig)
        );
    }
}
