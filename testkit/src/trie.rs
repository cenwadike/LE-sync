//! Test-only: a naive reference Merkle-Patricia trie builder with proof extraction, the oracle
//! for `le_sync_core::mpt::verify_proof` and the account/storage layers. It shares no code with
//! the verifier beyond keccak; RLP length prefixes are implemented independently here.
//! `Trie::new` / `prove` take 32-byte hashed keys (64 nibbles), like the secure state and
//! storage tries. `Trie::new_raw` / `prove_raw` take keys of any length, none a prefix of
//! another: the receipts and transactions tries, keyed by `index_key(i) = rlp(i)`.
//!
//! NOTE: this is a copy of the builder in `core/src/mpt.rs` (`testutil`, `cfg(test)`-private).
//! Keep the two in sync, or point core's tests at this crate and delete the copy.
use le_sync_core::keccak::{keccak256, EMPTY_TRIE_ROOT};
use le_sync_core::Bytes32;
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
fn to_nibs(k: &[u8]) -> Vec<u8> {
    k.iter().flat_map(|b| [b >> 4, b & 0xf]).collect()
}

/// `rlp(index)` as a trie key, built from this file's own RLP: the minimal big-endian bytes of
/// `index` (none for 0) as an RLP string. Index 0 is `0x80`.
pub fn index_key(index: u64) -> Vec<u8> {
    let be: Vec<u8> = index
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|b| *b == 0)
        .collect();
    rlp_bytes(&be)
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
    map: BTreeMap<Vec<u8>, Vec<u8>>,
}
impl Trie {
    /// Secure trie: 32-byte keys.
    pub fn new(entries: &[(Bytes32, Vec<u8>)]) -> Trie {
        let raw: Vec<_> = entries
            .iter()
            .map(|(k, v)| (k.to_vec(), v.clone()))
            .collect();
        Trie::new_raw(&raw)
    }
    /// Keys of any length, none a prefix of another (e.g. `index_key`).
    pub fn new_raw(entries: &[(Vec<u8>, Vec<u8>)]) -> Trie {
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
        self.prove_raw(key)
    }
    pub fn prove_raw(&self, key: &[u8]) -> Vec<Vec<u8>> {
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
