//! Generic Merkle-Patricia-trie proof verifier for Ethereum's secure tries (`no_std`, no alloc).
//!
//! Used for the account trie and storage trie (Sprint 4) and, with the same walk, the
//! receipts trie (Sprint 5). The key is always the 32-byte hashed key (64 nibbles), which
//! is what the "secure" state and storage tries use; the receipts trie keys are RLP-encoded
//! indices, not hashes, so Sprint 5 needs either a variable-length key entry point or a
//! padded form: this file does not pretend to cover that yet.
//!
//! Proof format is the `eth_getProof` one: the list of RLP-encoded nodes on the path from
//! the root, root first. Nodes whose encoding is shorter than 32 bytes are embedded in their
//! parent and are NOT separate proof entries.
//!
//! Result of a verified walk:
//! * `Ok(Some(value))`: the key is present with `value` (the leaf's second RLP item).
//! * `Ok(None)`: the proof is a valid proof of ABSENCE (empty branch slot, or a leaf /
//!   extension whose path diverges from the key).
//! * `Err(Error::InvalidTrieProof)` / `Err(Error::InvalidRlp)`: nothing is proven.
//!
//! Every proof node must be consumed: surplus nodes are rejected, so a proof has exactly one
//! accepted shape.
//!
//! Spec: Yellow Paper Appendix D (trie) and Appendix C (hex-prefix); ethereum.org
//! "Merkle Patricia Trie"; EIP-1186.

use crate::keccak::{keccak256, EMPTY_TRIE_ROOT};
use crate::rlp::{decode_exact, split_list, Item};
use crate::{Bytes32, Error};

/// Nibbles in a hashed key.
pub const KEY_NIBBLES: usize = 64;

/// How the next node is referenced by its parent.
#[derive(Clone, Copy)]
enum NodeRef<'a> {
    Hash(Bytes32),
    /// Embedded node: its full RLP encoding (always shorter than 32 bytes).
    Inline(&'a [u8]),
}

fn nibble(key: &Bytes32, pos: usize) -> u8 {
    let b = key[pos / 2];
    if pos % 2 == 0 {
        b >> 4
    } else {
        b & 0x0f
    }
}

/// A decoded hex-prefix path (first item of a leaf or extension node). `bytes` is the raw
/// encoding, including the flag byte; nibbles are read with `at(i)`.
struct HexPrefix<'a> {
    is_leaf: bool,
    odd: bool,
    bytes: &'a [u8],
}

/// Decode a hex-prefix path. Strict: the flag nibble must be 0..=3 and, for an even path, the
/// low nibble of the first byte must be zero.
fn decode_hex_prefix(b: &[u8]) -> Result<HexPrefix<'_>, Error> {
    let first = *b.first().ok_or(Error::InvalidTrieProof)?;
    let flag = first >> 4;
    if flag > 3 {
        return Err(Error::InvalidTrieProof);
    }
    let odd = flag & 1 == 1;
    if !odd && first & 0x0f != 0 {
        return Err(Error::InvalidTrieProof);
    }
    Ok(HexPrefix {
        is_leaf: flag & 2 == 2,
        odd,
        bytes: b,
    })
}

impl HexPrefix<'_> {
    fn len(&self) -> usize {
        (self.bytes.len() - 1) * 2 + usize::from(self.odd)
    }
    /// `i`-th nibble of the path (`i < len()`).
    fn at(&self, i: usize) -> u8 {
        if self.odd {
            // nibble 0 is the low nibble of byte 0, then whole bytes follow
            if i == 0 {
                self.bytes[0] & 0x0f
            } else {
                let j = i - 1;
                let b = self.bytes[1 + j / 2];
                if j % 2 == 0 {
                    b >> 4
                } else {
                    b & 0x0f
                }
            }
        } else {
            let b = self.bytes[1 + i / 2];
            if i % 2 == 0 {
                b >> 4
            } else {
                b & 0x0f
            }
        }
    }
    /// Does the path equal the key nibbles starting at `pos`? `false` if the key is too short.
    fn matches(&self, key: &Bytes32, pos: usize) -> bool {
        let n = self.len();
        if pos + n > KEY_NIBBLES {
            return false;
        }
        (0..n).all(|i| self.at(i) == nibble(key, pos + i))
    }
}

fn child_ref<'a>(item: Item<'a>) -> Result<Option<NodeRef<'a>>, Error> {
    match item {
        // empty slot: nothing below
        Item::Bytes(b) if b.is_empty() => Ok(None),
        Item::Bytes(b) if b.len() == 32 => {
            let mut h = [0u8; 32];
            h.copy_from_slice(b);
            Ok(Some(NodeRef::Hash(h)))
        }
        Item::Bytes(_) => Err(Error::InvalidTrieProof),
        // An embedded node must be shorter than 32 bytes; a longer one would have been hashed.
        Item::List { raw, .. } if raw.len() < 32 => Ok(Some(NodeRef::Inline(raw))),
        Item::List { .. } => Err(Error::InvalidTrieProof),
    }
}

/// Verify `nodes` as a proof for `key` (a 32-byte hashed key) under `root`.
pub fn verify_proof<'a, N: AsRef<[u8]>>(
    root: &Bytes32,
    key: &Bytes32,
    nodes: &'a [N],
) -> Result<Option<&'a [u8]>, Error> {
    // An empty trie proves absence of everything and has no nodes.
    if *root == EMPTY_TRIE_ROOT && nodes.is_empty() {
        return Ok(None);
    }
    let mut next = NodeRef::Hash(*root);
    let mut used = 0usize;
    let mut pos = 0usize;
    let result: Option<&'a [u8]> = loop {
        let raw: &'a [u8] = match next {
            NodeRef::Hash(h) => {
                let n = nodes.get(used).ok_or(Error::InvalidTrieProof)?.as_ref();
                used += 1;
                if keccak256(n) != h {
                    return Err(Error::InvalidTrieProof);
                }
                n
            }
            NodeRef::Inline(r) => r,
        };
        let Item::List { payload, .. } = decode_exact(raw)? else {
            return Err(Error::InvalidTrieProof);
        };
        let (items, count) = split_list::<17>(payload)?;
        match count {
            17 => {
                if pos == KEY_NIBBLES {
                    // key ends at a branch: its value slot decides
                    let v = items[16].as_bytes()?;
                    break if v.is_empty() { None } else { Some(v) };
                }
                let child = child_ref(items[nibble(key, pos) as usize])?;
                pos += 1;
                match child {
                    None => break None,
                    Some(c) => next = c,
                }
            }
            2 => {
                let hp = decode_hex_prefix(items[0].as_bytes()?)?;
                if !hp.matches(key, pos) {
                    // diverging path: a valid proof of absence
                    break None;
                }
                pos += hp.len();
                if hp.is_leaf {
                    // a leaf fully consumes a fixed-length key
                    if pos != KEY_NIBBLES {
                        return Err(Error::InvalidTrieProof);
                    }
                    break Some(items[1].as_bytes()?);
                }
                match child_ref(items[1])? {
                    // an extension must point somewhere
                    None => return Err(Error::InvalidTrieProof),
                    Some(c) => next = c,
                }
            }
            _ => return Err(Error::InvalidTrieProof),
        }
    };
    // no surplus nodes
    if used != nodes.len() {
        return Err(Error::InvalidTrieProof);
    }
    Ok(result)
}

#[cfg(test)]
pub(crate) mod testutil {
    //! A naive reference trie builder: the oracle for `verify_proof`. It shares no code with
    //! the verifier beyond keccak and the length-prefix rules of RLP, which it implements itself.
    use super::*;
    use std::collections::BTreeMap;

    pub fn rlp_bytes(b: &[u8]) -> Vec<u8> {
        if b.len() == 1 && b[0] < 0x80 {
            return b.to_vec();
        }
        let mut o = len_prefix(b.len(), 0x80);
        o.extend_from_slice(b);
        o
    }
    pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.concat();
        let mut o = len_prefix(payload.len(), 0xc0);
        o.extend(payload);
        o
    }
    fn len_prefix(len: usize, base: u8) -> Vec<u8> {
        if len < 56 {
            vec![base + len as u8]
        } else {
            let be: Vec<u8> = len
                .to_be_bytes()
                .iter()
                .copied()
                .skip_while(|b| *b == 0)
                .collect();
            let mut o = vec![base + 55 + be.len() as u8];
            o.extend(be);
            o
        }
    }
    pub fn hp(nibs: &[u8], leaf: bool) -> Vec<u8> {
        let flag = if leaf { 2 } else { 0 };
        let mut out = vec![];
        let mut i = 0;
        if nibs.len() % 2 == 1 {
            out.push(((flag | 1) << 4) | nibs[0]);
            i = 1;
        } else {
            out.push(flag << 4);
        }
        while i < nibs.len() {
            out.push((nibs[i] << 4) | nibs[i + 1]);
            i += 2;
        }
        out
    }
    fn to_nibs(k: &Bytes32) -> Vec<u8> {
        k.iter().flat_map(|b| [b >> 4, b & 0xf]).collect()
    }

    /// Encoded node for `entries` (suffix-nibbles -> value), all sharing the consumed prefix.
    /// Returns the node's RLP encoding.
    fn build(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        if entries.len() == 1 {
            let (k, v) = &entries[0];
            return rlp_list(&[rlp_bytes(&hp(k, true)), rlp_bytes(v)]);
        }
        // common prefix
        let mut cp = 0;
        while entries
            .iter()
            .all(|(k, _)| k.len() > cp && k[cp] == entries[0].0[cp])
        {
            cp += 1;
        }
        if cp > 0 {
            let rest: Vec<_> = entries
                .iter()
                .map(|(k, v)| (k[cp..].to_vec(), v.clone()))
                .collect();
            let child = build(&rest);
            return rlp_list(&[
                rlp_bytes(&hp(&entries[0].0[..cp], false)),
                child_ref(&child),
            ]);
        }
        let mut slots: Vec<Vec<u8>> = vec![rlp_bytes(&[]); 17];
        for n in 0..16u8 {
            let sub: Vec<_> = entries
                .iter()
                .filter(|(k, _)| k[0] == n)
                .map(|(k, v)| (k[1..].to_vec(), v.clone()))
                .collect();
            if !sub.is_empty() {
                slots[n as usize] = child_ref(&build(&sub));
            }
        }
        rlp_list(&slots)
    }
    /// Reference by hash, or embedded when shorter than 32 bytes.
    fn child_ref(enc: &[u8]) -> Vec<u8> {
        if enc.len() < 32 {
            enc.to_vec()
        } else {
            rlp_bytes(&keccak256(enc))
        }
    }

    pub struct Trie {
        pub root: Bytes32,
        map: BTreeMap<Bytes32, Vec<u8>>,
    }
    impl Trie {
        pub fn new(entries: &[(Bytes32, Vec<u8>)]) -> Trie {
            let map: BTreeMap<_, _> = entries.iter().cloned().collect();
            if map.is_empty() {
                return Trie {
                    root: EMPTY_TRIE_ROOT,
                    map,
                };
            }
            let es: Vec<_> = map.iter().map(|(k, v)| (to_nibs(k), v.clone())).collect();
            let root_node = build(&es);
            Trie {
                root: keccak256(&root_node),
                map,
            }
        }
        /// Proof for `key`: walk the structure, collecting hashed (non-embedded) nodes.
        pub fn prove(&self, key: &Bytes32) -> Vec<Vec<u8>> {
            if self.map.is_empty() {
                return vec![];
            }
            let es: Vec<_> = self
                .map
                .iter()
                .map(|(k, v)| (to_nibs(k), v.clone()))
                .collect();
            let mut out = vec![];
            collect(&es, &to_nibs(key), &mut out, true);
            out
        }
    }
    fn collect(entries: &[(Vec<u8>, Vec<u8>)], key: &[u8], out: &mut Vec<Vec<u8>>, top: bool) {
        let enc = build(entries);
        if top || enc.len() >= 32 {
            out.push(enc);
        }
        if entries.len() == 1 {
            return;
        }
        let mut cp = 0;
        while entries
            .iter()
            .all(|(k, _)| k.len() > cp && k[cp] == entries[0].0[cp])
        {
            cp += 1;
        }
        if cp > 0 {
            if key.len() >= cp && key[..cp] == entries[0].0[..cp] {
                let rest: Vec<_> = entries
                    .iter()
                    .map(|(k, v)| (k[cp..].to_vec(), v.clone()))
                    .collect();
                collect(&rest, &key[cp..], out, false);
            }
            return;
        }
        if key.is_empty() {
            return;
        }
        let sub: Vec<_> = entries
            .iter()
            .filter(|(k, _)| k[0] == key[0])
            .map(|(k, v)| (k[1..].to_vec(), v.clone()))
            .collect();
        if !sub.is_empty() {
            collect(&sub, &key[1..], out, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    fn key(i: u64) -> Bytes32 {
        keccak256(&i.to_be_bytes())
    }
    fn val(i: u64) -> Vec<u8> {
        // long enough that leaves are hashed, as real account leaves are
        vec![i as u8; 70]
    }
    fn trie(n: u64) -> Trie {
        Trie::new(&(0..n).map(|i| (key(i), val(i))).collect::<Vec<_>>())
    }

    #[test]
    fn oracle_builder_matches_known_single_leaf_root() {
        // sanity check of the oracle itself: a one-entry trie root is keccak of its leaf node
        let t = Trie::new(&[([0x11; 32], vec![1, 2, 3])]);
        let leaf = rlp_list(&[rlp_bytes(&hp(&[1; 64], true)), rlp_bytes(&[1, 2, 3])]);
        assert_eq!(t.root, keccak256(&leaf));
    }

    #[test]
    fn inclusion_for_every_key_in_tries_of_many_sizes() {
        for n in [1u64, 2, 3, 5, 16, 17, 40] {
            let t = trie(n);
            for i in 0..n {
                let p = t.prove(&key(i));
                let got = verify_proof(&t.root, &key(i), &p).unwrap();
                assert_eq!(got, Some(&val(i)[..]), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn exclusion_for_absent_keys() {
        for n in [1u64, 2, 5, 17, 40] {
            let t = trie(n);
            for i in 1000..1030u64 {
                let p = t.prove(&key(i));
                assert_eq!(verify_proof(&t.root, &key(i), &p), Ok(None), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn empty_trie_proves_absence_with_no_nodes_only() {
        let t = Trie::new(&[]);
        let none: [Vec<u8>; 0] = [];
        assert_eq!(verify_proof(&t.root, &key(1), &none), Ok(None));
        let junk = [vec![0xc0u8]];
        assert_eq!(
            verify_proof(&t.root, &key(1), &junk),
            Err(Error::InvalidTrieProof)
        );
    }

    #[test]
    fn inline_nodes_are_followed() {
        // tiny values make deep leaves shorter than 32 bytes: embedded in their parent
        let es: Vec<_> = (0..30u64).map(|i| (key(i), vec![i as u8 + 1])).collect();
        let t = Trie::new(&es);
        let mut embedded = 0;
        for i in 0..30u64 {
            let p = t.prove(&key(i));
            assert_eq!(
                verify_proof(&t.root, &key(i), &p),
                Ok(Some(&[i as u8 + 1][..]))
            );
            // a leaf shorter than 32 bytes is not a proof entry of its own: count the proofs
            // that end on a branch whose last child was embedded
            let last = p.last().unwrap();
            if last.len() < 32 + 17 && last[0] >= 0xc0 {
                embedded += 1;
            }
        }
        assert!(embedded > 0, "fixture must exercise embedded children");
    }

    #[test]
    fn every_flipped_byte_of_every_node_is_rejected() {
        let t = trie(20);
        let k = key(7);
        let p = t.prove(&k);
        assert!(p.len() >= 2);
        for n in 0..p.len() {
            for b in 0..p[n].len() {
                let mut bad = p.clone();
                bad[n][b] ^= 1;
                // it must not verify as the original inclusion
                assert_ne!(
                    verify_proof(&t.root, &k, &bad),
                    Ok(Some(&val(7)[..])),
                    "node {n} byte {b} accepted"
                );
            }
        }
    }

    #[test]
    fn wrong_root_wrong_key_truncated_extra_and_reordered_proofs_fail() {
        let t = trie(20);
        let k = key(7);
        let p = t.prove(&k);
        // wrong root
        let mut r = t.root;
        r[0] ^= 1;
        assert_eq!(verify_proof(&r, &k, &p), Err(Error::InvalidTrieProof));
        // proof for another key does not prove this one
        let other = t.prove(&key(8));
        assert_ne!(verify_proof(&t.root, &k, &other), Ok(Some(&val(7)[..])));
        // truncated
        assert_eq!(
            verify_proof(&t.root, &k, &p[..p.len() - 1]),
            Err(Error::InvalidTrieProof)
        );
        assert_eq!(
            verify_proof(&t.root, &k, &p[..0]),
            Err(Error::InvalidTrieProof)
        );
        // extra trailing node
        let mut extra = p.clone();
        extra.push(p[0].clone());
        assert_eq!(
            verify_proof(&t.root, &k, &extra),
            Err(Error::InvalidTrieProof)
        );
        // reordered
        let mut re = p.clone();
        re.swap(0, 1);
        assert_eq!(verify_proof(&t.root, &k, &re), Err(Error::InvalidTrieProof));
    }

    #[test]
    fn an_inclusion_proof_does_not_prove_a_different_key_present() {
        let t = trie(20);
        let p = t.prove(&key(3));
        let mut other = key(3);
        other[31] ^= 1;
        // either an error or an exclusion; never the original value
        assert_ne!(verify_proof(&t.root, &other, &p), Ok(Some(&val(3)[..])));
    }

    #[test]
    fn malformed_nodes_are_rejected() {
        let k = key(1);
        // helper: a "trie" whose root is the hash of an arbitrary node encoding
        let case = |node: Vec<u8>| {
            let root = keccak256(&node);
            verify_proof(&root, &k, &[node]).map(|o| o.map(|v| v.to_vec()))
        };
        // not a list
        assert!(case(rlp_bytes(&[1, 2, 3])).is_err());
        // list of 3 items
        assert_eq!(
            case(rlp_list(&[
                rlp_bytes(&[1]),
                rlp_bytes(&[2]),
                rlp_bytes(&[3])
            ])),
            Err(Error::InvalidTrieProof)
        );
        // 2 items, hex-prefix flag nibble > 3
        assert_eq!(
            case(rlp_list(&[rlp_bytes(&[0x40]), rlp_bytes(&[9])])),
            Err(Error::InvalidTrieProof)
        );
        // even-length path with a non-zero low nibble in the flag byte
        assert_eq!(
            case(rlp_list(&[rlp_bytes(&[0x21]), rlp_bytes(&[9])])),
            Err(Error::InvalidTrieProof)
        );
        // empty path bytes
        assert_eq!(
            case(rlp_list(&[rlp_bytes(&[]), rlp_bytes(&[9])])),
            Err(Error::InvalidTrieProof)
        );
        // branch child that is neither empty, 32 bytes nor a list
        let mut slots = vec![rlp_bytes(&[]); 17];
        let n = nibble(&k, 0) as usize;
        slots[n] = rlp_bytes(&[1, 2, 3]);
        assert_eq!(case(rlp_list(&slots)), Err(Error::InvalidTrieProof));
        // 17 items where the value slot is a list
        let mut slots = vec![rlp_bytes(&[]); 17];
        slots[16] = rlp_list(&[]);
        // The key is not exhausted, so the value slot is never read. The child at the key's
        // nibble is empty, so this is a verified exclusion, not an error.
        assert_eq!(case(rlp_list(&slots)), Ok(None));
        // malformed RLP inside
        assert_eq!(case(vec![0xc2, 0x83, 0x01]), Err(Error::InvalidRlp));
    }

    #[test]
    fn leaf_shorter_than_the_key_and_extension_to_nothing_are_rejected() {
        let k = key(1);
        // leaf whose (matching) path ends before the key does
        let kn: Vec<u8> = k.iter().flat_map(|b| [b >> 4, b & 0xf]).collect();
        let leaf = rlp_list(&[rlp_bytes(&hp(&kn[..10], true)), rlp_bytes(&[1])]);
        let root = keccak256(&leaf);
        assert_eq!(
            verify_proof(&root, &k, &[leaf]),
            Err(Error::InvalidTrieProof)
        );
        // extension pointing at an empty child
        let ext = rlp_list(&[rlp_bytes(&hp(&kn[..4], false)), rlp_bytes(&[])]);
        let root = keccak256(&ext);
        assert_eq!(
            verify_proof(&root, &k, &[ext]),
            Err(Error::InvalidTrieProof)
        );
        // embedded child that is not shorter than 32 bytes
        let big = rlp_list(&[rlp_bytes(&[0x20]), rlp_bytes(&[7u8; 40])]);
        assert!(big.len() >= 32);
        let ext = rlp_list(&[rlp_bytes(&hp(&kn[..4], false)), big]);
        let root = keccak256(&ext);
        assert_eq!(
            verify_proof(&root, &k, &[ext]),
            Err(Error::InvalidTrieProof)
        );
    }

    #[test]
    fn odd_and_even_extension_and_leaf_paths() {
        // keys that force odd/even shared prefixes of several lengths
        for shared in 1..6usize {
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            // identical first `shared` nibbles, then differ
            for i in 0..shared {
                let nib = (i as u8 + 3) & 0xf;
                if i % 2 == 0 {
                    a[i / 2] |= nib << 4;
                    b[i / 2] |= nib << 4;
                } else {
                    a[i / 2] |= nib;
                    b[i / 2] |= nib;
                }
            }
            if shared % 2 == 0 {
                a[shared / 2] = 0x10;
                b[shared / 2] = 0x20;
            } else {
                a[shared / 2] |= 0x1;
                b[shared / 2] |= 0x2;
            }
            let t = Trie::new(&[(a, val(1)), (b, val(2))]);
            for (k, v) in [(a, val(1)), (b, val(2))] {
                let p = t.prove(&k);
                assert_eq!(
                    verify_proof(&t.root, &k, &p),
                    Ok(Some(&v[..])),
                    "shared={shared}"
                );
            }
            // a key sharing only part of the prefix is proven absent
            let mut c = a;
            c[0] ^= 0xf0;
            let p = t.prove(&c);
            assert_eq!(verify_proof(&t.root, &c, &p), Ok(None), "shared={shared}");
        }
    }

    #[test]
    fn hex_prefix_decoding_pins() {
        let h = decode_hex_prefix(&[0x00, 0xab]).unwrap();
        assert!(!h.is_leaf && !h.odd && h.len() == 2 && h.at(0) == 0xa && h.at(1) == 0xb);
        let h = decode_hex_prefix(&[0x1a, 0xbc]).unwrap();
        assert!(!h.is_leaf && h.odd && h.len() == 3);
        assert_eq!((h.at(0), h.at(1), h.at(2)), (0xa, 0xb, 0xc));
        let h = decode_hex_prefix(&[0x20, 0xab]).unwrap();
        assert!(h.is_leaf && !h.odd && h.len() == 2);
        let h = decode_hex_prefix(&[0x3f]).unwrap();
        assert!(h.is_leaf && h.odd && h.len() == 1 && h.at(0) == 0xf);
        let h = decode_hex_prefix(&[0x00]).unwrap();
        assert_eq!(h.len(), 0);
        assert!(decode_hex_prefix(&[]).is_err());
        assert!(decode_hex_prefix(&[0x40]).is_err());
        assert!(decode_hex_prefix(&[0x05]).is_err());
    }

    #[test]
    fn nibble_extraction() {
        let mut k = [0u8; 32];
        k[0] = 0xab;
        k[31] = 0xcd;
        assert_eq!((nibble(&k, 0), nibble(&k, 1)), (0xa, 0xb));
        assert_eq!((nibble(&k, 62), nibble(&k, 63)), (0xc, 0xd));
    }

    #[test]
    fn embedded_child_of_31_bytes_is_followed_and_of_32_bytes_is_rejected() {
        let k = key(1);
        let kn: Vec<u8> = k.iter().flat_map(|b| [b >> 4, b & 0xf]).collect();
        // Extension over the first 62 nibbles; its child is a leaf over the last 2 nibbles,
        // embedded in the extension. The leaf is 5 + v bytes long for a v-byte value (v >= 2).
        let run = |v: usize| {
            let value = vec![7u8; v];
            let leaf = rlp_list(&[rlp_bytes(&hp(&kn[62..], true)), rlp_bytes(&value)]);
            let ext = rlp_list(&[rlp_bytes(&hp(&kn[..62], false)), leaf.clone()]);
            let root = keccak256(&ext);
            let got = verify_proof(&root, &k, &[ext]).map(|o| o.map(|b| b.to_vec()));
            (leaf.len(), value, got)
        };
        // 31 bytes: embedded, followed to the value
        let (len, value, got) = run(26);
        assert_eq!(len, 31);
        assert_eq!(got, Ok(Some(value)));
        // 32 bytes would have been hashed by an honest encoder: not a valid embedded node
        let (len, _, got) = run(27);
        assert_eq!(len, 32);
        assert_eq!(got, Err(Error::InvalidTrieProof));
    }

    #[test]
    fn embedded_branch_and_leaves_down_to_the_last_nibble() {
        // Keys that differ only in the final nibble: one extension over 63 nibbles whose child
        // is a 22-byte branch holding two 3-byte leaves. Everything below the root is embedded,
        // so the proof is the single root node.
        let mut a = key(5);
        let mut b = a;
        let mut c = a;
        a[31] = (a[31] & 0xf0) | 0x1;
        b[31] = (b[31] & 0xf0) | 0x2;
        c[31] = (c[31] & 0xf0) | 0x3;
        let t = Trie::new(&[(a, vec![1]), (b, vec![2])]);
        let pa = t.prove(&a);
        assert_eq!(pa.len(), 1);
        assert_eq!(verify_proof(&t.root, &a, &pa), Ok(Some(&[1u8][..])));
        assert_eq!(
            verify_proof(&t.root, &b, &t.prove(&b)),
            Ok(Some(&[2u8][..]))
        );
        // empty slot inside the embedded branch: a verified exclusion
        assert_eq!(verify_proof(&t.root, &c, &t.prove(&c)), Ok(None));
    }
}
