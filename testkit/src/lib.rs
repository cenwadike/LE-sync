//! Test-only fixtures shared by `wire`'s unit tests and integration tests.
//!
//! SECURITY: keys are derived as `secret = id + 1`. They are trivially guessable by design
//! (deterministic tests). This crate is `publish = false` and must never be reachable from the
//! guest or any production dependency graph.
//!
//! This crate deliberately does NOT depend on `le-sync-wire`: it is the independent oracle the
//! wire tests check against. The signing code here is written separately from `wire/src/bls.rs`.

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use le_sync_core::sync::SyncCommittee;
use le_sync_core::{hash_pair, sync_committee_root, BlsPubkey, Bytes32};
use sha2::{Digest, Sha256};

/// Ethereum BLS ciphersuite. Duplicated on purpose; `wire` tests assert it equals `bls::DST`.
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

// ---- keys -----------------------------------------------------------------------------------

pub struct Keypair {
    pub secret: Scalar,
    pub public: BlsPubkey,
}

/// Deterministic keypair for an arbitrary 64-bit id (no wraparound, no duplicate keys).
pub fn keypair(id: u64) -> Keypair {
    let secret = Scalar::from(id + 1);
    let public = G1Affine::from(G1Projective::generator() * secret).to_compressed();
    Keypair { secret, public }
}

pub struct Committee {
    pub keypairs: Vec<Keypair>,
    pub pubkeys: Vec<BlsPubkey>,
    /// Honest value: the sum of all member keys (the consensus rule for `aggregate_pubkey`).
    /// Tests may overwrite it to model an inconsistent committed aggregate.
    pub aggregate: BlsPubkey,
}

/// `n` members with ids `seed * 100_000 + i`. Distinct seeds give disjoint committees.
pub fn committee(seed: u32, n: usize) -> Committee {
    let keypairs: Vec<Keypair> = (0..n as u64)
        .map(|i| keypair(seed as u64 * 100_000 + i))
        .collect();
    let pubkeys = keypairs.iter().map(|k| k.public).collect();
    let mut total = Scalar::from(0u64);
    for k in &keypairs {
        total += k.secret;
    }
    let aggregate = G1Affine::from(G1Projective::generator() * total).to_compressed();
    Committee {
        keypairs,
        pubkeys,
        aggregate,
    }
}

impl Committee {
    pub fn len(&self) -> usize {
        self.pubkeys.len()
    }
    pub fn is_empty(&self) -> bool {
        self.pubkeys.is_empty()
    }
    /// Keys concatenated, the wire layout (`committee_size * 48` bytes).
    pub fn flat(&self) -> Vec<u8> {
        self.pubkeys.concat()
    }
    pub fn sync_committee(&self) -> SyncCommittee {
        SyncCommittee::new(&self.pubkeys, self.aggregate).unwrap()
    }
    /// SSZ root of the committee exactly as committed (uses `self.aggregate` as stored).
    pub fn root(&self) -> Bytes32 {
        sync_committee_root(&self.pubkeys, &self.aggregate).unwrap()
    }
    /// Aggregate signature over `msg` by exactly the members whose bit is set in `bits`.
    pub fn sign(&self, bits: &[u8], msg: &Bytes32) -> [u8; 96] {
        sign(&self.keypairs, bits, msg)
    }
}

/// Aggregate BLS signature by the members selected in `bits` (LSB-first within each byte).
pub fn sign(keypairs: &[Keypair], bits: &[u8], msg: &Bytes32) -> [u8; 96] {
    let h = <G2Projective as HashToCurve<ExpandMsgXmd<sha2_09::Sha256>>>::hash_to_curve(msg, DST);
    let mut secret = Scalar::from(0u64);
    for (i, kp) in keypairs.iter().enumerate() {
        if (bits[i / 8] >> (i % 8)) & 1 == 1 {
            secret += kp.secret;
        }
    }
    G2Affine::from(h * secret).to_compressed()
}

// ---- bitfields ------------------------------------------------------------------------------

/// A bitfield of `n` bits with the first `set` bits on.
pub fn bits_set(n: usize, set: usize) -> Vec<u8> {
    let mut b = vec![0u8; (n + 7) / 8];
    for i in 0..set {
        b[i / 8] |= 1 << (i % 8);
    }
    b
}

/// A bitfield of `n` bits with exactly the listed indices on.
pub fn bits_from(n: usize, indices: &[usize]) -> Vec<u8> {
    let mut b = vec![0u8; (n + 7) / 8];
    for &i in indices {
        assert!(i < n, "bit index {i} out of range for {n} bits");
        b[i / 8] |= 1 << (i % 8);
    }
    b
}

// ---- merkle / BeaconState-shaped fixtures ---------------------------------------------------

pub fn leaf(i: u64) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"le-sync-testkit-leaf");
    h.update(i.to_le_bytes());
    h.finalize().into()
}

/// levels[0] = leaves, last = [root]. `leaves.len()` must be a power of two.
pub fn levels(leaves: Vec<Bytes32>) -> Vec<Vec<Bytes32>> {
    let mut l = vec![leaves];
    while l.last().unwrap().len() > 1 {
        let n = l
            .last()
            .unwrap()
            .chunks(2)
            .map(|p| hash_pair(&p[0], &p[1]))
            .collect();
        l.push(n);
    }
    l
}

pub fn branch(l: &[Vec<Bytes32>], mut i: usize) -> Vec<Bytes32> {
    let mut out = vec![];
    for lv in &l[..l.len() - 1] {
        out.push(lv[i ^ 1]);
        i /= 2;
    }
    out
}

pub fn root_and_branch(leaves: Vec<Bytes32>, i: usize) -> (Bytes32, Vec<Bytes32>) {
    let l = levels(leaves);
    (l.last().unwrap()[0], branch(&l, i))
}

/// A 64-leaf BeaconState-shaped tree: field 20 = Checkpoint{epoch, root}, 22 = current sync
/// committee, 23 = next sync committee. `salt` varies the filler so different states differ.
pub struct State {
    pub root: Bytes32,
    /// 7 nodes (Electra gindex 169): `[epoch chunk] ++ branch(field 20)`.
    pub finality_branch: Vec<Bytes32>,
    /// 6 nodes (gindex 86).
    pub cur_branch: Vec<Bytes32>,
    /// 6 nodes (gindex 87).
    pub next_branch: Vec<Bytes32>,
}

pub fn state(
    salt: u64,
    finalized_root: &Bytes32,
    cur_root: &Bytes32,
    next_root: &Bytes32,
) -> State {
    let epoch_chunk = leaf(77_777 + salt);
    let mut f: Vec<Bytes32> = (0..64).map(|i| leaf(5_000 + salt * 100 + i)).collect();
    f[20] = hash_pair(&epoch_chunk, finalized_root);
    f[22] = *cur_root;
    f[23] = *next_root;
    let l = levels(f);
    let mut fin = vec![epoch_chunk];
    fin.extend(branch(&l, 20));
    State {
        root: l.last().unwrap()[0],
        finality_branch: fin,
        cur_branch: branch(&l, 22),
        next_branch: branch(&l, 23),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_seeds_give_disjoint_committees_and_no_duplicates() {
        let a = committee(1, 512);
        let b = committee(2, 512);
        let mut all: Vec<_> = a.pubkeys.iter().chain(b.pubkeys.iter()).collect();
        all.sort();
        all.dedup();
        assert_eq!(
            all.len(),
            1024,
            "no key may repeat across or within committees"
        );
    }

    #[test]
    fn bit_helpers_are_lsb_first() {
        assert_eq!(bits_set(10, 9), vec![0xFF, 0x01]);
        assert_eq!(bits_from(16, &[0, 9, 15]), vec![0x01, 0x82]);
    }

    #[test]
    fn state_branches_reach_the_root() {
        let s = state(3, &leaf(1), &leaf(2), &leaf(3));
        assert_eq!(s.finality_branch.len(), 7);
        assert_eq!(s.cur_branch.len(), 6);
        let other = state(4, &leaf(1), &leaf(2), &leaf(3));
        assert_ne!(s.root, other.root);
    }
}
