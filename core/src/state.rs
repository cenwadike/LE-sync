//! Execution-layer account and storage proofs on top of `mpt::verify_proof`
//! (`no_std`, no alloc). EIP-1186 `eth_getProof` data goes in; verified values come out.
//!
//! The storage proof is always checked against the `storageRoot` decoded from the VERIFIED
//! account leaf, never against the `storageHash` field of the RPC response, and the account
//! proof is checked against a state root the caller must have derived from a finalised header
//! (see `ExecutionPayloadHeader` and `sync::verify_execution_branch`).

use crate::keccak::{keccak256, EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};
use crate::mpt::{verify_index_proof, verify_proof};
use crate::receipt::{select_log, Log, LogFilter};
use crate::rlp::{canonical_uint, decode_exact, split_list, Item};
use crate::{Bytes32, Error};

pub type Address = [u8; 20];

/// A decoded account: RLP `[nonce, balance, storageRoot, codeHash]`.
/// `balance` is big-endian, left-padded to 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    pub balance: Bytes32,
    pub storage_root: Bytes32,
    pub code_hash: Bytes32,
}

impl Account {
    /// What Ethereum semantics give an account that is not in the trie.
    pub const ABSENT: Account = Account {
        nonce: 0,
        balance: [0u8; 32],
        storage_root: EMPTY_TRIE_ROOT,
        code_hash: EMPTY_CODE_HASH,
    };
}

fn left_pad32(b: &[u8]) -> Bytes32 {
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    out
}

fn hash32(b: &[u8]) -> Result<Bytes32, Error> {
    b.try_into().map_err(|_| Error::InvalidRlp)
}

fn decode_account(rlp: &[u8]) -> Result<Account, Error> {
    let Item::List { payload, .. } = decode_exact(rlp)? else {
        return Err(Error::InvalidRlp);
    };
    let (items, n) = split_list::<4>(payload)?;
    if n != 4 {
        return Err(Error::InvalidRlp);
    }
    let nonce = canonical_uint(items[0].as_bytes()?, 8)?;
    let balance = canonical_uint(items[1].as_bytes()?, 32)?;
    let mut nonce_be = [0u8; 8];
    nonce_be[8 - nonce.len()..].copy_from_slice(nonce);
    Ok(Account {
        nonce: u64::from_be_bytes(nonce_be),
        balance: left_pad32(balance),
        storage_root: hash32(items[2].as_bytes()?)?,
        code_hash: hash32(items[3].as_bytes()?)?,
    })
}

/// `keccak256(address)` is the key in the state trie.
pub fn account_key(address: &Address) -> Bytes32 {
    keccak256(address)
}

/// `keccak256(slot)` is the key in a storage trie (slot as a 32-byte big-endian word).
pub fn storage_key(slot: &Bytes32) -> Bytes32 {
    keccak256(slot)
}

/// Verify an account proof under `state_root`.
/// `Ok(None)` is a verified proof that the account does not exist.
pub fn verify_account<N: AsRef<[u8]>>(
    state_root: &Bytes32,
    address: &Address,
    proof: &[N],
) -> Result<Option<Account>, Error> {
    match verify_proof(state_root, &account_key(address), proof)? {
        None => Ok(None),
        Some(rlp) => decode_account(rlp).map(Some),
    }
}

/// Verify a storage proof under `storage_root`; returns the slot value as a big-endian 32-byte
/// word. An absent slot is a verified zero.
///
/// The leaf value is the RLP encoding of the value's trimmed big-endian bytes, itself stored
/// as the (byte-string) value of the trie leaf, so it is decoded twice: the trie yields the
/// leaf's byte string, which is an RLP string. Zero is never stored; a stored zero or a value
/// with leading zeros is rejected.
pub fn verify_storage<N: AsRef<[u8]>>(
    storage_root: &Bytes32,
    slot: &Bytes32,
    proof: &[N],
) -> Result<Bytes32, Error> {
    match verify_proof(storage_root, &storage_key(slot), proof)? {
        None => Ok([0u8; 32]),
        Some(leaf_value) => {
            let Item::Bytes(v) = decode_exact(leaf_value)? else {
                return Err(Error::InvalidRlp);
            };
            if v.is_empty() || v.len() > 32 || v[0] == 0 {
                return Err(Error::InvalidRlp);
            }
            Ok(left_pad32(v))
        }
    }
}

/// Verified outcome of an account + storage lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateValue {
    pub account: Account,
    pub account_present: bool,
    /// Big-endian slot value; zero when absent.
    pub value: Bytes32,
}

/// Account proof under `state_root`, then storage proof under the account's own storage root.
/// If the account does not exist the slot is zero and the storage proof is not consulted.
pub fn verify_state<N: AsRef<[u8]>, M: AsRef<[u8]>>(
    state_root: &Bytes32,
    address: &Address,
    account_proof: &[N],
    slot: &Bytes32,
    storage_proof: &[M],
) -> Result<StateValue, Error> {
    match verify_account(state_root, address, account_proof)? {
        None => Ok(StateValue {
            account: Account::ABSENT,
            account_present: false,
            value: [0u8; 32],
        }),
        Some(account) => {
            let value = verify_storage(&account.storage_root, slot, storage_proof)?;
            Ok(StateValue {
                account,
                account_present: true,
                value,
            })
        }
    }
}

/// Verify a log under `receipts_root`: the receipt at `tx_index` is proven by `proof`
/// (receipts-trie nodes, root first), then its `log_index`-th log must match `filter`.
///
/// `receipts_root` must come from an anchored header (`exec::anchor_execution`). No receipt at
/// `tx_index` is `LogMismatch`, never a success. The returned log borrows from `proof`.
pub fn verify_log<'a, N: AsRef<[u8]>>(
    receipts_root: &Bytes32,
    tx_index: u64,
    proof: &'a [N],
    log_index: usize,
    filter: &LogFilter,
) -> Result<Log<'a>, Error> {
    let receipt = verify_index_proof(receipts_root, tx_index, proof)?.ok_or(Error::LogMismatch)?;
    select_log(receipt, log_index, filter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpt::testutil::{index_key, rlp_bytes, rlp_list, Trie};

    fn trim(b: &[u8]) -> Vec<u8> {
        let i = b.iter().position(|x| *x != 0).unwrap_or(b.len());
        b[i..].to_vec()
    }
    fn be(v: u128) -> Vec<u8> {
        trim(&v.to_be_bytes())
    }
    fn account_rlp(nonce: u64, balance: u128, sroot: &Bytes32, chash: &Bytes32) -> Vec<u8> {
        rlp_list(&[
            rlp_bytes(&trim(&nonce.to_be_bytes())),
            rlp_bytes(&be(balance)),
            rlp_bytes(sroot),
            rlp_bytes(chash),
        ])
    }
    fn addr(i: u8) -> Address {
        [i; 20]
    }
    fn slot(i: u8) -> Bytes32 {
        let mut s = [0u8; 32];
        s[31] = i;
        s
    }

    struct World {
        state: Trie,
        storage: Trie,
    }
    /// Account 1 has storage {slot1: 0x1234, slot2: 5, slot9: 2^255}; accounts 2..8 are fillers.
    fn world() -> World {
        let mut big = [0u8; 32];
        big[0] = 0x80;
        let storage = Trie::new(&[
            (storage_key(&slot(1)), rlp_bytes(&[0x12, 0x34])),
            (storage_key(&slot(2)), rlp_bytes(&[5])),
            (storage_key(&slot(9)), rlp_bytes(&big)),
        ]);
        let mut es = vec![(
            account_key(&addr(1)),
            account_rlp(
                7,
                123_456_789_000_000_000_000u128,
                &storage.root,
                &[0xCC; 32],
            ),
        )];
        for i in 2..9u8 {
            es.push((
                account_key(&addr(i)),
                account_rlp(0, i as u128, &EMPTY_TRIE_ROOT, &EMPTY_CODE_HASH),
            ));
        }
        World {
            state: Trie::new(&es),
            storage,
        }
    }

    #[test]
    fn account_and_storage_verify() {
        let w = world();
        let ap = w.state.prove(&account_key(&addr(1)));
        let acct = verify_account(&w.state.root, &addr(1), &ap)
            .unwrap()
            .unwrap();
        assert_eq!(acct.nonce, 7);
        assert_eq!(acct.storage_root, w.storage.root);
        assert_eq!(acct.code_hash, [0xCC; 32]);
        let mut bal = [0u8; 32];
        bal[32 - be(123_456_789_000_000_000_000u128).len()..]
            .copy_from_slice(&be(123_456_789_000_000_000_000u128));
        assert_eq!(acct.balance, bal);

        for (s, want) in [(1u8, vec![0x12u8, 0x34]), (2, vec![5])] {
            let sp = w.storage.prove(&storage_key(&slot(s)));
            let v = verify_storage(&acct.storage_root, &slot(s), &sp).unwrap();
            let mut e = [0u8; 32];
            e[32 - want.len()..].copy_from_slice(&want);
            assert_eq!(v, e);
        }
        // full 32-byte value (no leading zero)
        let sp = w.storage.prove(&storage_key(&slot(9)));
        let v = verify_storage(&acct.storage_root, &slot(9), &sp).unwrap();
        assert_eq!(v[0], 0x80);
    }

    #[test]
    fn verify_state_end_to_end_and_exclusions() {
        let w = world();
        let ap = w.state.prove(&account_key(&addr(1)));
        let sp = w.storage.prove(&storage_key(&slot(1)));
        let r = verify_state(&w.state.root, &addr(1), &ap, &slot(1), &sp).unwrap();
        assert!(r.account_present);
        assert_eq!(&r.value[30..], &[0x12, 0x34]);

        // absent slot of a present account: verified zero
        let sp = w.storage.prove(&storage_key(&slot(77)));
        let r = verify_state(&w.state.root, &addr(1), &ap, &slot(77), &sp).unwrap();
        assert!(r.account_present);
        assert_eq!(r.value, [0u8; 32]);

        // absent account: verified absence, zero value, storage proof not consulted
        let ap = w.state.prove(&account_key(&addr(200)));
        let none: [Vec<u8>; 0] = [];
        let r = verify_state(&w.state.root, &addr(200), &ap, &slot(1), &none).unwrap();
        assert!(!r.account_present);
        assert_eq!(r.account, Account::ABSENT);
        assert_eq!(r.value, [0u8; 32]);
    }

    #[test]
    fn storage_is_checked_against_the_accounts_own_root_not_a_supplied_one() {
        let w = world();
        // another account's storage proof (a different, valid trie) must not satisfy account 1
        let other = Trie::new(&[(storage_key(&slot(1)), rlp_bytes(&[0x99]))]);
        let ap = w.state.prove(&account_key(&addr(1)));
        let forged = other.prove(&storage_key(&slot(1)));
        assert_eq!(
            verify_state(&w.state.root, &addr(1), &ap, &slot(1), &forged),
            Err(Error::InvalidTrieProof)
        );
    }

    #[test]
    fn tamper_matrix() {
        let w = world();
        let ap = w.state.prove(&account_key(&addr(1)));
        let sp = w.storage.prove(&storage_key(&slot(1)));
        let ok = verify_state(&w.state.root, &addr(1), &ap, &slot(1), &sp).unwrap();

        // wrong state root
        let mut r = w.state.root;
        r[5] ^= 1;
        assert!(verify_state(&r, &addr(1), &ap, &slot(1), &sp).is_err());
        // wrong address (proof is for addr 1): never yields account 1's data
        let bad = verify_state(&w.state.root, &addr(2), &ap, &slot(1), &sp);
        assert_ne!(bad.ok(), Some(ok));
        // wrong slot
        let bad = verify_state(&w.state.root, &addr(1), &ap, &slot(2), &sp);
        assert_ne!(bad.ok(), Some(ok));
        // every flipped byte in every account node and storage node
        for n in 0..ap.len() {
            for b in 0..ap[n].len() {
                let mut t = ap.clone();
                t[n][b] ^= 1;
                assert_ne!(
                    verify_state(&w.state.root, &addr(1), &t, &slot(1), &sp).ok(),
                    Some(ok),
                    "account node {n} byte {b}"
                );
            }
        }
        for n in 0..sp.len() {
            for b in 0..sp[n].len() {
                let mut t = sp.clone();
                t[n][b] ^= 1;
                assert_ne!(
                    verify_state(&w.state.root, &addr(1), &ap, &slot(1), &t).ok(),
                    Some(ok),
                    "storage node {n} byte {b}"
                );
            }
        }
        // truncated / extra
        assert!(verify_state(&w.state.root, &addr(1), &ap[..ap.len() - 1], &slot(1), &sp).is_err());
        assert!(verify_state(&w.state.root, &addr(1), &ap, &slot(1), &sp[..sp.len() - 1]).is_err());
        let mut extra = sp.clone();
        extra.push(sp[0].clone());
        assert!(verify_state(&w.state.root, &addr(1), &ap, &slot(1), &extra).is_err());
    }

    #[test]
    fn malformed_account_and_slot_values_are_rejected() {
        let h = [1u8; 32];
        let ok = |nonce: Vec<u8>, bal: Vec<u8>| {
            let rlp = rlp_list(&[
                rlp_bytes(&nonce),
                rlp_bytes(&bal),
                rlp_bytes(&h),
                rlp_bytes(&h),
            ]);
            decode_account(&rlp)
        };
        assert!(ok(vec![1], vec![2]).is_ok());
        assert!(ok(vec![], vec![]).is_ok()); // nonce 0, balance 0
        assert_eq!(ok(vec![0, 1], vec![2]), Err(Error::InvalidRlp)); // leading zero
        assert_eq!(ok(vec![1], vec![0, 2]), Err(Error::InvalidRlp));
        assert_eq!(ok(vec![1; 9], vec![2]), Err(Error::InvalidRlp)); // nonce > u64
        assert_eq!(ok(vec![1], vec![1; 33]), Err(Error::InvalidRlp)); // balance > 32 bytes
                                                                      // wrong arity, short hash, non-list
        assert_eq!(
            decode_account(&rlp_list(&[
                rlp_bytes(&[1]),
                rlp_bytes(&[2]),
                rlp_bytes(&h)
            ])),
            Err(Error::InvalidRlp)
        );
        assert_eq!(
            decode_account(&rlp_list(&[
                rlp_bytes(&[1]),
                rlp_bytes(&[2]),
                rlp_bytes(&h[..31]),
                rlp_bytes(&h)
            ])),
            Err(Error::InvalidRlp)
        );
        assert_eq!(decode_account(&rlp_bytes(&[1, 2])), Err(Error::InvalidRlp));
        // the largest legal nonce
        let n = ok(vec![0xff; 8], vec![]).unwrap();
        assert_eq!(n.nonce, u64::MAX);

        // storage leaf values: stored zero, leading zero, > 32 bytes, not-a-string
        let bad_leaf = |leaf_value: Vec<u8>| {
            let t = Trie::new(&[(storage_key(&slot(1)), leaf_value)]);
            let p = t.prove(&storage_key(&slot(1)));
            verify_storage(&t.root, &slot(1), &p)
        };
        assert_eq!(bad_leaf(rlp_bytes(&[])), Err(Error::InvalidRlp)); // zero must not be stored
        assert_eq!(bad_leaf(rlp_bytes(&[0, 1])), Err(Error::InvalidRlp));
        assert_eq!(bad_leaf(rlp_bytes(&[1; 33])), Err(Error::InvalidRlp));
        assert_eq!(bad_leaf(rlp_list(&[])), Err(Error::InvalidRlp));
        assert_eq!(bad_leaf(vec![0x81, 0x01]), Err(Error::InvalidRlp)); // non-canonical RLP
        assert!(bad_leaf(rlp_bytes(&[1])).is_ok());
    }

    #[test]
    fn key_derivations_are_keccak_of_address_and_slot() {
        assert_eq!(account_key(&[0u8; 20]), keccak256(&[0u8; 20]));
        assert_eq!(storage_key(&[0u8; 32]), keccak256(&[0u8; 32]));
        assert_ne!(account_key(&addr(1)), account_key(&addr(2)));
    }
    // ---- log proofs (receipts trie) ----

    fn log_rlp(a: u8, topic: u8) -> Vec<u8> {
        rlp_list(&[
            rlp_bytes(&[a; 20]),
            rlp_list(&[
                rlp_bytes(&[topic; 32]),
                rlp_bytes(&[topic.wrapping_add(1); 32]),
            ]),
            rlp_bytes(&[topic; 32]),
        ])
    }
    /// A typed (0x02) receipt whose single log is `log_rlp(a, topic)`.
    fn receipt_leaf(status: &[u8], a: u8, topic: u8) -> Vec<u8> {
        let mut v = vec![0x02];
        v.extend(rlp_list(&[
            rlp_bytes(status),
            rlp_bytes(&[0x52, 0x08]),
            rlp_bytes(&[0u8; 256]),
            rlp_list(&[log_rlp(a, topic)]),
        ]));
        v
    }
    /// A block of `n` receipts; transaction `i` logs topic `i as u8`.
    fn receipts_trie(n: u64) -> Trie {
        Trie::new_raw(
            &(0..n)
                .map(|i| (index_key(i), receipt_leaf(&[1], 0xA1, i as u8)))
                .collect::<Vec<_>>(),
        )
    }
    fn filter(a: u8, topic: u8) -> LogFilter {
        LogFilter {
            address: [a; 20],
            topics: [Some([topic; 32]), None, None, None],
        }
    }

    #[test]
    fn a_log_verifies_at_indexes_below_and_above_128() {
        let t = receipts_trie(300);
        for i in [0u64, 1, 2, 127, 128, 129, 255, 256, 299] {
            let proof = t.prove_raw(&index_key(i));
            let l = verify_log(&t.root, i, &proof, 0, &filter(0xA1, i as u8)).unwrap();
            assert_eq!(l.address, [0xA1; 20], "tx {i}");
            assert_eq!(l.topics[0], [i as u8; 32]);
            assert_eq!(l.topics[1], [(i as u8).wrapping_add(1); 32]);
            assert_eq!(l.data, &[i as u8; 32][..]);
        }
    }

    #[test]
    fn a_wrong_transaction_index_does_not_verify() {
        let t = receipts_trie(20);
        let proof = t.prove_raw(&index_key(7));
        for j in (0..20u64).filter(|j| *j != 7) {
            assert_eq!(
                verify_log(&t.root, j, &proof, 0, &filter(0xA1, 7)),
                Err(Error::InvalidTrieProof),
                "tx {j}"
            );
        }
    }

    #[test]
    fn no_receipt_at_the_index_is_logmismatch() {
        let t = receipts_trie(20);
        for i in [20u64, 21, 1000] {
            let proof = t.prove_raw(&index_key(i));
            assert_eq!(
                verify_log(&t.root, i, &proof, 0, &filter(0xA1, 0)),
                Err(Error::LogMismatch),
                "tx {i}"
            );
        }
    }

    #[test]
    fn log_filter_log_index_and_status_failures() {
        let t = receipts_trie(20);
        let proof = t.prove_raw(&index_key(7));
        // wrong address, wrong topic, log index beyond the receipt's one log
        assert_eq!(
            verify_log(&t.root, 7, &proof, 0, &filter(0xB2, 7)),
            Err(Error::LogMismatch)
        );
        assert_eq!(
            verify_log(&t.root, 7, &proof, 0, &filter(0xA1, 8)),
            Err(Error::LogMismatch)
        );
        assert_eq!(
            verify_log(&t.root, 7, &proof, 1, &filter(0xA1, 7)),
            Err(Error::LogMismatch)
        );
        // a failed transaction (status 0) in the trie
        let failed = Trie::new_raw(&[
            (index_key(0), receipt_leaf(&[1], 0xA1, 0)),
            (index_key(1), receipt_leaf(&[], 0xA1, 1)),
        ]);
        let proof = failed.prove_raw(&index_key(1));
        assert_eq!(
            verify_log(&failed.root, 1, &proof, 0, &filter(0xA1, 1)),
            Err(Error::LogMismatch)
        );
    }

    #[test]
    fn tampered_receipt_proofs_are_rejected() {
        let t = receipts_trie(20);
        let proof = t.prove_raw(&index_key(7));
        let f = filter(0xA1, 7);
        assert!(verify_log(&t.root, 7, &proof, 0, &f).is_ok());
        // wrong root
        let mut r = t.root;
        r[0] ^= 1;
        assert_eq!(
            verify_log(&r, 7, &proof, 0, &f),
            Err(Error::InvalidTrieProof)
        );
        // any flipped byte of any node: never the original log
        let good = verify_log(&t.root, 7, &proof, 0, &f).unwrap();
        for n in 0..proof.len() {
            for b in 0..proof[n].len() {
                let mut bad = proof.clone();
                bad[n][b] ^= 1;
                assert_ne!(
                    verify_log(&t.root, 7, &bad, 0, &f),
                    Ok(good),
                    "node {n} byte {b}"
                );
            }
        }
        // truncated and surplus nodes
        assert_eq!(
            verify_log(&t.root, 7, &proof[..proof.len() - 1], 0, &f),
            Err(Error::InvalidTrieProof)
        );
        let mut extra = proof.clone();
        extra.push(proof[0].clone());
        assert_eq!(
            verify_log(&t.root, 7, &extra, 0, &f),
            Err(Error::InvalidTrieProof)
        );
    }
}
