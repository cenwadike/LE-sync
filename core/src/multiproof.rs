//! Merkle multiproof over the sync committee's key tree, and the rule that ties the keys an
//! update supplies to its participation bits (`no_std`, no alloc).
//!
//! WHY. The staged update (`update_job::begin_update_rooted`) does not keep the committee's
//! keys. The store holds the committee's 32-byte keys root and its aggregate key. To check an
//! update the caller supplies the keys of the members that did NOT sign (the aggregate minus
//! those is the aggregate of the signers), and this module proves them:
//!
//! * `verify_multiproof`: the supplied leaves (`pubkey_root` of each key) are leaves of the tree
//!   with root `keys_root`, one proof for all of them.
//! * `absent_matches_bits`: the supplied positions are exactly the zero bits of the update's
//!   participation bitfield. Without this a caller could list other members than the absent
//!   ones, and the aggregate would no longer be the aggregate of the members `bits` claims.
//!
//! The tree is the SSZ one: `n` leaves (a power of two, at most `MAX_SYNC_COMMITTEE_SIZE`),
//! `hash_pair` for inner nodes, leaf `i` is `pubkey_root(key i)`.
//!
//! Proof order, which the verifier requires and a prover must follow: level by level from the
//! leaves up, and within a level from left to right, one sibling for every node whose sibling
//! is not itself on the path. Every sibling must be used.
use crate::{hash_pair, Bytes32, MAX_SYNC_COMMITTEE_SIZE, ZERO};

/// `true` iff `index` lists, in ascending order and with no other entry, exactly the positions
/// of the zero bits of `bits` (bit `i` is `(bits[i / 8] >> (i % 8)) & 1`, the SSZ bitvector
/// order).
pub fn absent_matches_bits(bits: &[u8], index: &[u16]) -> bool {
    let mut listed = index.iter();
    let mut want = listed.next();
    for i in 0..bits.len() * 8 {
        let present = (bits[i / 8] >> (i % 8)) & 1 == 1;
        if !present {
            match want {
                Some(&w) if w as usize == i => want = listed.next(),
                _ => return false,
            }
        }
    }
    want.is_none()
}

/// `true` iff `leaves[i]` is leaf `index[i]` of the `n`-leaf tree with root `root`, proven by
/// `siblings`. `index` must be strictly ascending and below `n`; `n` a power of two within
/// `MAX_SYNC_COMMITTEE_SIZE`. An empty `index` proves nothing and is accepted only with no
/// siblings (there is no key to bind to the root).
pub fn verify_multiproof(
    root: &Bytes32,
    n: usize,
    index: &[u16],
    leaves: &[Bytes32],
    mut siblings: impl Iterator<Item = Bytes32>,
) -> bool {
    if n == 0 || !n.is_power_of_two() || n > MAX_SYNC_COMMITTEE_SIZE {
        return false;
    }
    if index.len() != leaves.len() || index.len() > n {
        return false;
    }
    if index.windows(2).any(|w| w[0] >= w[1]) {
        return false;
    }
    if index.last().is_some_and(|&last| last as usize >= n) {
        return false;
    }
    if index.is_empty() {
        return siblings.next().is_none();
    }
    let mut pos = [0u16; MAX_SYNC_COMMITTEE_SIZE];
    let mut val = [ZERO; MAX_SYNC_COMMITTEE_SIZE];
    pos[..index.len()].copy_from_slice(index);
    val[..leaves.len()].copy_from_slice(leaves);
    let mut count = index.len();
    let mut width = n;
    while width > 1 {
        // Parents are written over the entries already consumed: `out <= i` always.
        let mut out = 0usize;
        let mut i = 0usize;
        while i < count {
            let p = pos[i];
            let parent = if p & 1 == 1 {
                let Some(s) = siblings.next() else {
                    return false;
                };
                let h = hash_pair(&s, &val[i]);
                i += 1;
                h
            } else if i + 1 < count && pos[i + 1] == p + 1 {
                let h = hash_pair(&val[i], &val[i + 1]);
                i += 2;
                h
            } else {
                let Some(s) = siblings.next() else {
                    return false;
                };
                let h = hash_pair(&val[i], &s);
                i += 1;
                h
            };
            pos[out] = p >> 1;
            val[out] = parent;
            out += 1;
        }
        count = out;
        width /= 2;
    }
    siblings.next().is_none() && count == 1 && val[0] == *root
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn leaf(i: usize) -> Bytes32 {
        let mut l = [0u8; 32];
        l[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        l[31] = 0x5A;
        l
    }

    /// The whole tree, 1-indexed by generalized index: `t[1]` is the root, `t[n + i]` leaf `i`.
    fn tree(n: usize) -> Vec<Bytes32> {
        let mut t = vec![ZERO; 2 * n];
        for i in 0..n {
            t[n + i] = leaf(i);
        }
        for g in (1..n).rev() {
            t[g] = hash_pair(&t[2 * g], &t[2 * g + 1]);
        }
        t
    }

    /// An independent prover: the helper nodes are the siblings of the path nodes that are not
    /// on the path themselves, deepest level first and left to right inside a level.
    fn prove(n: usize, index: &[u16]) -> Vec<Bytes32> {
        let t = tree(n);
        let mut path = BTreeSet::new();
        for &i in index {
            let mut g = n + i as usize;
            while g >= 1 {
                path.insert(g);
                g /= 2;
            }
        }
        let mut helpers: Vec<usize> = path
            .iter()
            .filter(|&&g| g > 1)
            .map(|&g| g ^ 1)
            .filter(|g| !path.contains(g))
            .collect();
        // deeper (larger) gindex first is "deeper level first" only within one depth class:
        // sort by (depth descending, gindex ascending)
        let depth = |g: usize| usize::BITS - 1 - g.leading_zeros();
        helpers.sort_by(|a, b| depth(*b).cmp(&depth(*a)).then(a.cmp(b)));
        helpers.into_iter().map(|g| t[g]).collect()
    }

    fn check(n: usize, index: &[u16]) -> bool {
        let t = tree(n);
        let leaves: Vec<Bytes32> = index.iter().map(|&i| leaf(i as usize)).collect();
        verify_multiproof(&t[1], n, index, &leaves, prove(n, index).into_iter())
    }

    #[test]
    fn accepts_honest_proofs_of_every_shape() {
        // one leaf, neighbours, a gap, the ends, a whole subtree, everything
        for n in [1usize, 2, 4, 8, 32, 512] {
            let all: Vec<u16> = (0..n as u16).collect();
            assert!(check(n, &all), "n={n} all");
            assert!(check(n, &all[..1]), "n={n} first");
            assert!(check(n, &all[n - 1..]), "n={n} last");
        }
        assert!(check(8, &[0, 1]));
        assert!(check(8, &[1, 2]));
        assert!(check(8, &[2, 3, 4]));
        assert!(check(8, &[0, 3, 7]));
        assert!(check(8, &[0, 1, 2, 3]));
        assert!(check(512, &[0, 5, 6, 100, 101, 102, 103, 300, 511]));
        // a pseudo-random subset, at the size and density of a real update (170 of 512)
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let mut set = BTreeSet::new();
        while set.len() < 170 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            set.insert((x % 512) as u16);
        }
        let idx: Vec<u16> = set.into_iter().collect();
        assert!(check(512, &idx));
    }

    #[test]
    fn proof_lengths_are_the_minimum() {
        // one leaf of 512 needs one sibling per level
        assert_eq!(prove(512, &[17]).len(), 9);
        // both children of a node need none for that level
        assert_eq!(prove(8, &[0, 1]).len(), 2);
        assert_eq!(prove(8, &[0, 1, 2, 3, 4, 5, 6, 7]).len(), 0);
    }

    #[test]
    fn rejects_a_wrong_root_leaf_or_sibling() {
        let n = 16;
        let index = [2u16, 3, 9];
        let t = tree(n);
        let leaves: Vec<Bytes32> = index.iter().map(|&i| leaf(i as usize)).collect();
        let proof = prove(n, &index);
        assert!(verify_multiproof(
            &t[1],
            n,
            &index,
            &leaves,
            proof.clone().into_iter()
        ));
        let mut root = t[1];
        root[0] ^= 1;
        assert!(!verify_multiproof(
            &root,
            n,
            &index,
            &leaves,
            proof.clone().into_iter()
        ));
        for k in 0..leaves.len() {
            let mut bad = leaves.clone();
            bad[k][5] ^= 1;
            assert!(
                !verify_multiproof(&t[1], n, &index, &bad, proof.clone().into_iter()),
                "leaf {k}"
            );
        }
        for k in 0..proof.len() {
            let mut bad = proof.clone();
            bad[k][7] ^= 1;
            assert!(
                !verify_multiproof(&t[1], n, &index, &leaves, bad.into_iter()),
                "sibling {k}"
            );
        }
        // swapped siblings
        let mut swapped = proof.clone();
        swapped.swap(0, 1);
        assert!(!verify_multiproof(
            &t[1],
            n,
            &index,
            &leaves,
            swapped.into_iter()
        ));
    }

    #[test]
    fn rejects_a_short_or_long_proof() {
        let n = 16;
        let index = [2u16, 9];
        let t = tree(n);
        let leaves: Vec<Bytes32> = index.iter().map(|&i| leaf(i as usize)).collect();
        let proof = prove(n, &index);
        for cut in 0..proof.len() {
            assert!(
                !verify_multiproof(&t[1], n, &index, &leaves, proof[..cut].iter().copied()),
                "cut {cut}"
            );
        }
        let mut long = proof.clone();
        long.push(ZERO);
        assert!(!verify_multiproof(
            &t[1],
            n,
            &index,
            &leaves,
            long.into_iter()
        ));
    }

    #[test]
    fn rejects_bad_indexes_and_sizes() {
        let n = 8;
        let t = tree(n);
        let ok = |index: &[u16], leaves: &[Bytes32], n: usize| {
            verify_multiproof(&t[1], n, index, leaves, prove(8, &[1, 2]).into_iter())
        };
        let l = |i: usize| leaf(i);
        assert!(ok(&[1, 2], &[l(1), l(2)], 8));
        // unsorted, duplicate, out of range
        assert!(!ok(&[2, 1], &[l(2), l(1)], 8));
        assert!(!ok(&[1, 1], &[l(1), l(1)], 8));
        assert!(!ok(&[1, 8], &[l(1), l(8)], 8));
        // leaf count differs from index count
        assert!(!ok(&[1, 2], &[l(1)], 8));
        assert!(!ok(&[1], &[l(1), l(2)], 8));
        // not a power of two, zero, too large
        assert!(!ok(&[1, 2], &[l(1), l(2)], 6));
        assert!(!ok(&[1, 2], &[l(1), l(2)], 0));
        assert!(!ok(&[1, 2], &[l(1), l(2)], 1024));
        // more entries than leaves in the tree
        let many: Vec<u16> = (0..9).collect();
        let ls: Vec<Bytes32> = (0..9).map(l).collect();
        assert!(!ok(&many, &ls, 8));
    }

    #[test]
    fn a_single_leaf_tree_is_its_own_root() {
        let root = leaf(0);
        assert!(verify_multiproof(
            &root,
            1,
            &[0],
            &[leaf(0)],
            core::iter::empty()
        ));
        assert!(!verify_multiproof(
            &root,
            1,
            &[0],
            &[leaf(1)],
            core::iter::empty()
        ));
        assert!(!verify_multiproof(
            &root,
            1,
            &[1],
            &[leaf(0)],
            core::iter::empty()
        ));
    }

    #[test]
    fn nothing_listed_is_accepted_only_without_siblings() {
        let root = [9u8; 32];
        assert!(verify_multiproof(&root, 8, &[], &[], core::iter::empty()));
        assert!(!verify_multiproof(
            &root,
            8,
            &[],
            &[],
            core::iter::once(ZERO)
        ));
    }

    #[test]
    fn absent_positions_are_exactly_the_zero_bits() {
        // 16 members, bits 0..=2 and 8 set; absent: 3..=7 and 9..=15
        let bits = [0b0000_0111u8, 0b0000_0001];
        let absent: Vec<u16> = vec![3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15];
        assert!(absent_matches_bits(&bits, &absent));
        // a present member listed, an absent one left out, a repeat, a swap, an extra at the end
        let mut with_present = absent.clone();
        with_present.insert(0, 2);
        assert!(!absent_matches_bits(&bits, &with_present));
        assert!(!absent_matches_bits(&bits, &absent[1..]));
        assert!(!absent_matches_bits(&bits, &absent[..absent.len() - 1]));
        let mut repeat = absent.clone();
        repeat.insert(1, 3);
        assert!(!absent_matches_bits(&bits, &repeat));
        let mut swap = absent.clone();
        swap.swap(0, 1);
        assert!(!absent_matches_bits(&bits, &swap));
        let mut extra = absent.clone();
        extra.push(16);
        assert!(!absent_matches_bits(&bits, &extra));
        // everyone signed: nothing may be listed; no one signed: everyone must be
        assert!(absent_matches_bits(&[0xFF, 0xFF], &[]));
        assert!(!absent_matches_bits(&[0xFF, 0xFF], &[0]));
        let all: Vec<u16> = (0..16).collect();
        assert!(absent_matches_bits(&[0, 0], &all));
        assert!(!absent_matches_bits(&[0, 0], &all[1..]));
    }
}
