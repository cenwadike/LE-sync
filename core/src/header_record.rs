//! One record per verified finalized header (Sprint 6, M2) (`no_std`, no alloc).
//!
//! When the staged update moves the store's finalized header, `init`/`finish_update` stores a
//! `HeaderRecord` for the new header. The record carries what an attestation proves against:
//! the execution state root and receipts root, with the block number and hash. The execution
//! payload header is tied to the finalized beacon header **when the record is stored**
//! (`from_finalized`: `anchor_execution`, gindex 25 under the header's body root), so an
//! attest instruction only reads a record; it does no beacon-chain work.
//!
//! A record can only be made from the store's own finalized header, so "the header is
//! finalized and verified" is a property of the record's existence, not a check an attest
//! repeats.
//!
//! The records of an instance live in one account as a fixed number of slots
//! (`RECORD_LEN` bytes each, a blank slot is all zero). `insert_record` fills a blank slot, or
//! replaces the record with the lowest slot (the finalized header only moves forward, so that
//! is the oldest). `find_record` looks a record up by header root. The number of slots is an
//! account-scheme choice of the program; this module only requires the account length to be
//! a whole number of slots.
//!
//! Record layout, version 1 (integers little-endian, fixed width, no padding):
//!
//! ```text
//! version       u8 = 1
//! slot          u64
//! header_root   32   hash_tree_root of the finalized beacon header
//! block_number  u64
//! block_hash    32
//! state_root    32
//! receipts_root 32
//! ```
use crate::exec::{anchor_execution, ExecutionPayloadHeader};
use crate::instance::{is_blank, InstanceConfig};
use crate::sync::LightClientStore;
use crate::{Bytes32, Error};

pub const RECORD_VERSION: u8 = 1;
pub const RECORD_LEN: usize = 1 + 8 + 32 + 8 + 32 + 32 + 32;
const _: () = assert!(RECORD_LEN == 145);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderRecord {
    pub slot: u64,
    pub header_root: Bytes32,
    pub block_number: u64,
    pub block_hash: Bytes32,
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
}

/// What `insert_record` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Insert {
    /// Written to a blank slot.
    Stored,
    /// The record with the lowest slot was overwritten.
    Replaced,
    /// An identical record was already there; nothing changed.
    AlreadyPresent,
}

impl HeaderRecord {
    /// The record of the store's finalized header, with the execution fields proven from
    /// `exec` and `execution_branch` under that header (`anchor_execution`: `InvalidBranch`,
    /// `UnsupportedFork`, `BadConfig`).
    pub fn from_finalized(
        cfg: &InstanceConfig,
        store: &LightClientStore,
        exec: &ExecutionPayloadHeader,
        execution_branch: &[Bytes32],
    ) -> Result<Self, Error> {
        let header = &store.finalized_header;
        let anchored = anchor_execution(&cfg.chain(), header, exec, execution_branch)?;
        Ok(Self {
            slot: header.slot,
            header_root: header.hash_tree_root(),
            block_number: anchored.block_number,
            block_hash: anchored.block_hash,
            state_root: anchored.state_root,
            receipts_root: anchored.receipts_root,
        })
    }

    pub fn encode(&self) -> [u8; RECORD_LEN] {
        let mut b = [0u8; RECORD_LEN];
        b[0] = RECORD_VERSION;
        b[1..9].copy_from_slice(&self.slot.to_le_bytes());
        b[9..41].copy_from_slice(&self.header_root);
        b[41..49].copy_from_slice(&self.block_number.to_le_bytes());
        b[49..81].copy_from_slice(&self.block_hash);
        b[81..113].copy_from_slice(&self.state_root);
        b[113..145].copy_from_slice(&self.receipts_root);
        b
    }

    /// `HeaderRecordEncoding` for a wrong length or version.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != RECORD_LEN || bytes[0] != RECORD_VERSION {
            return Err(Error::HeaderRecordEncoding);
        }
        let u64_at = |at: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[at..at + 8]);
            u64::from_le_bytes(b)
        };
        let b32_at = |at: usize| {
            let mut b = [0u8; 32];
            b.copy_from_slice(&bytes[at..at + 32]);
            b
        };
        Ok(Self {
            slot: u64_at(1),
            header_root: b32_at(9),
            block_number: u64_at(41),
            block_hash: b32_at(49),
            state_root: b32_at(81),
            receipts_root: b32_at(113),
        })
    }
}

/// `HeaderRecordEncoding` unless the account is a non-empty whole number of slots.
fn slots(log: &[u8]) -> Result<usize, Error> {
    if log.is_empty() || log.len() % RECORD_LEN != 0 {
        return Err(Error::HeaderRecordEncoding);
    }
    Ok(log.len() / RECORD_LEN)
}

/// The record in slot `i`, `None` for a blank slot.
fn slot_at(log: &[u8], i: usize) -> Result<Option<HeaderRecord>, Error> {
    let bytes = &log[i * RECORD_LEN..(i + 1) * RECORD_LEN];
    if is_blank(bytes) {
        return Ok(None);
    }
    HeaderRecord::decode(bytes).map(Some)
}

/// The record of the header with root `header_root`. `HeaderNotFound` if there is none;
/// `HeaderRecordEncoding` if a slot is malformed or two slots hold the same header.
pub fn find_record(log: &[u8], header_root: &Bytes32) -> Result<HeaderRecord, Error> {
    let mut found = None;
    for i in 0..slots(log)? {
        if let Some(r) = slot_at(log, i)? {
            if r.header_root == *header_root {
                if found.is_some() {
                    return Err(Error::HeaderRecordEncoding);
                }
                found = Some(r);
            }
        }
    }
    found.ok_or(Error::HeaderNotFound)
}

/// Stores `record`. An identical record is `AlreadyPresent`; a different record for a header
/// that is already there is `HeaderRecordEncoding` (one header has one record). Otherwise it
/// takes the first blank slot (`Stored`), or, when none is left, the slot of the record with
/// the lowest slot number, the first of them on a tie (`Replaced`).
pub fn insert_record(log: &mut [u8], record: &HeaderRecord) -> Result<Insert, Error> {
    let n = slots(log)?;
    let mut blank = None;
    // (index, slot) of the record to replace; the first slot is the start, so a full log
    // always has an answer
    let mut lowest = (0usize, u64::MAX);
    for i in 0..n {
        match slot_at(log, i)? {
            None => {
                if blank.is_none() {
                    blank = Some(i);
                }
            }
            Some(r) => {
                if r.header_root == record.header_root {
                    return if r == *record {
                        Ok(Insert::AlreadyPresent)
                    } else {
                        Err(Error::HeaderRecordEncoding)
                    };
                }
                if r.slot < lowest.1 {
                    lowest = (i, r.slot);
                }
            }
        }
    }
    let (at, outcome) = match blank {
        Some(i) => (i, Insert::Stored),
        None => (lowest.0, Insert::Replaced),
    };
    log[at * RECORD_LEN..(at + 1) * RECORD_LEN].copy_from_slice(&record.encode());
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::sample;
    use crate::hash_pair;
    use crate::instance::{init_store, Bootstrap, Timing};
    use crate::sync::tests::{leaf_n, N};
    use crate::sync::{SyncCommittee, Version};
    use crate::{pubkeys_root, BeaconBlockHeader, BlsPubkey};

    const FV: Version = [5, 0, 0, 1];
    const TIMING: Timing = Timing {
        genesis_time: 1_606_824_023,
        seconds_per_slot: 12,
    };

    fn rec(n: u8) -> HeaderRecord {
        HeaderRecord {
            slot: 100 + n as u64,
            header_root: [n; 32],
            block_number: 1_000 + n as u64,
            block_hash: [n.wrapping_add(1); 32],
            state_root: [n.wrapping_add(2); 32],
            receipts_root: [n.wrapping_add(3); 32],
        }
    }

    /// Branch of leaf `idx` in a tree of `leaves`, and the root.
    fn tree(mut level: Vec<Bytes32>, mut idx: usize) -> (Bytes32, Vec<Bytes32>) {
        let mut branch = vec![];
        while level.len() > 1 {
            branch.push(level[idx ^ 1]);
            level = level.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
            idx /= 2;
        }
        (level[0], branch)
    }

    struct Fixture {
        cfg: InstanceConfig,
        store: LightClientStore,
        exec: ExecutionPayloadHeader,
        branch: Vec<Bytes32>,
    }

    /// A store whose finalized header (slot 8) has `exec` at field 9 of its body.
    fn fixture() -> Fixture {
        let exec = sample(3);
        let mut body: Vec<Bytes32> = (0..16u64).map(|i| leaf_n(300 + i)).collect();
        body[9] = exec.hash_tree_root().unwrap();
        let (body_root, branch) = tree(body, 9);

        let keys: Vec<BlsPubkey> = (0..N as u64)
            .map(|i| {
                let mut k = [0u8; 48];
                k[..32].copy_from_slice(&leaf_n(i));
                k
            })
            .collect();
        let keys_root = pubkeys_root(&keys).unwrap();
        let mut aggregate = [0u8; 48];
        aggregate[0] = 9;
        let committee = SyncCommittee::rooted(N, keys_root, aggregate).unwrap();
        let mut state: Vec<Bytes32> = (0..64u64).map(|i| leaf_n(700 + i)).collect();
        state[22] = committee.root().unwrap();
        let (state_root, committee_branch) = tree(state, 22);
        let header = BeaconBlockHeader {
            slot: 8,
            proposer_index: 1,
            parent_root: leaf_n(1),
            state_root,
            body_root,
        };
        let cfg = InstanceConfig::new(
            1,
            [0xAA; 32],
            8,
            8,
            N as u16,
            0,
            None,
            &[(0, FV)],
            TIMING,
            header.hash_tree_root(),
        )
        .unwrap();
        let boot = Bootstrap {
            header,
            keys_root,
            aggregate,
            branch: &committee_branch,
        };
        let store = init_store(&cfg, &boot, 8).unwrap();
        Fixture {
            cfg,
            store,
            exec,
            branch,
        }
    }

    // ---- the record ---------------------------------------------------------------------

    #[test]
    fn a_record_is_145_bytes_with_each_field_at_its_offset() {
        assert_eq!(RECORD_LEN, 145);
        let r = HeaderRecord {
            slot: 0x0102_0304_0506_0708,
            header_root: [0x11; 32],
            block_number: 0x0A0B_0C0D_0E0F_1011,
            block_hash: [0x22; 32],
            state_root: [0x33; 32],
            receipts_root: [0x44; 32],
        };
        let b = r.encode();
        assert_eq!(b[0], RECORD_VERSION);
        assert_eq!(b[1..9], 0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(b[9..41], [0x11; 32]);
        assert_eq!(b[41..49], 0x0A0B_0C0D_0E0F_1011u64.to_le_bytes());
        assert_eq!(b[49..81], [0x22; 32]);
        assert_eq!(b[81..113], [0x33; 32]);
        assert_eq!(b[113..145], [0x44; 32]);
        assert_eq!(HeaderRecord::decode(&b), Ok(r));
    }

    #[test]
    fn every_byte_is_a_field_and_a_bad_frame_is_refused() {
        let b = rec(7).encode();
        for i in 1..RECORD_LEN {
            let mut f = b;
            f[i] ^= 1;
            let d = HeaderRecord::decode(&f).unwrap();
            assert_ne!(d, rec(7), "byte {i}");
            assert_eq!(d.encode(), f, "byte {i}");
        }
        let bad = Error::HeaderRecordEncoding;
        assert_eq!(HeaderRecord::decode(&b[..RECORD_LEN - 1]), Err(bad));
        assert_eq!(HeaderRecord::decode(&[]), Err(bad));
        let mut longer = b.to_vec();
        longer.push(0);
        assert_eq!(HeaderRecord::decode(&longer), Err(bad));
        let mut v0 = b;
        v0[0] = 0;
        assert_eq!(HeaderRecord::decode(&v0), Err(bad));
        let mut v2 = b;
        v2[0] = 2;
        assert_eq!(HeaderRecord::decode(&v2), Err(bad));
    }

    // ---- made from the store's finalized header, with the execution branch checked --------

    #[test]
    fn the_record_carries_the_proven_execution_fields() {
        let f = fixture();
        let r = HeaderRecord::from_finalized(&f.cfg, &f.store, &f.exec, &f.branch).unwrap();
        assert_eq!(r.slot, 8);
        assert_eq!(r.header_root, f.store.finalized_header.hash_tree_root());
        assert_eq!(r.block_number, f.exec.block_number);
        assert_eq!(r.block_hash, f.exec.block_hash);
        assert_eq!(r.state_root, f.exec.state_root);
        assert_eq!(r.receipts_root, f.exec.receipts_root);
        // the sample's roots differ, so a swapped field would show
        assert_ne!(r.state_root, r.receipts_root);
        assert_ne!(r.block_hash, r.state_root);
        assert_ne!(r.block_hash, r.receipts_root);
    }

    #[test]
    fn a_forged_execution_header_or_branch_is_refused() {
        let f = fixture();
        let make = |e: &ExecutionPayloadHeader, br: &[Bytes32]| {
            HeaderRecord::from_finalized(&f.cfg, &f.store, e, br)
        };
        let mut e = f.exec;
        e.state_root = [0xEE; 32];
        assert_eq!(make(&e, &f.branch), Err(Error::InvalidBranch));
        let mut e = f.exec;
        e.receipts_root = [0xEE; 32];
        assert_eq!(make(&e, &f.branch), Err(Error::InvalidBranch));
        let mut e = f.exec;
        e.block_hash = [0xEE; 32];
        assert_eq!(make(&e, &f.branch), Err(Error::InvalidBranch));
        let mut e = f.exec;
        e.block_number += 1;
        assert_eq!(make(&e, &f.branch), Err(Error::InvalidBranch));
        for i in 0..f.branch.len() {
            let mut br = f.branch.clone();
            br[i][0] ^= 1;
            assert_eq!(make(&f.exec, &br), Err(Error::InvalidBranch), "{i}");
        }
        assert_eq!(make(&f.exec, &f.branch[..3]), Err(Error::InvalidBranch));
    }

    #[test]
    fn an_execution_header_of_another_beacon_header_is_refused() {
        // self-consistent execution header and branch, but under a different body root
        let f = fixture();
        let other = sample(4);
        let mut body: Vec<Bytes32> = (0..16u64).map(|i| leaf_n(300 + i)).collect();
        body[9] = other.hash_tree_root().unwrap();
        let (_, br) = tree(body, 9);
        assert_eq!(
            HeaderRecord::from_finalized(&f.cfg, &f.store, &other, &br),
            Err(Error::InvalidBranch)
        );
    }

    #[test]
    fn the_fork_of_the_header_must_be_supported() {
        let f = fixture();
        // Gloas from epoch 1: the finalized header (slot 8) is in the unsupported era
        let gloas = InstanceConfig::new(
            1,
            [0xAA; 32],
            8,
            8,
            N as u16,
            0,
            Some(1),
            &[(0, FV)],
            TIMING,
            f.cfg.trusted_root,
        )
        .unwrap();
        assert_eq!(
            HeaderRecord::from_finalized(&gloas, &f.store, &f.exec, &f.branch),
            Err(Error::UnsupportedFork)
        );
        // Electra from epoch 2: slot 8 is epoch 1, before Electra
        let early = InstanceConfig::new(
            1,
            [0xAA; 32],
            8,
            8,
            N as u16,
            2,
            None,
            &[(0, FV)],
            TIMING,
            f.cfg.trusted_root,
        )
        .unwrap();
        assert_eq!(
            HeaderRecord::from_finalized(&early, &f.store, &f.exec, &f.branch),
            Err(Error::UnsupportedFork)
        );
    }

    // ---- the log ----------------------------------------------------------------------

    fn log(n: usize) -> Vec<u8> {
        vec![0u8; n * RECORD_LEN]
    }

    #[test]
    fn an_account_must_be_a_whole_number_of_slots() {
        let bad = Error::HeaderRecordEncoding;
        assert_eq!(find_record(&[], &[1; 32]), Err(bad));
        assert_eq!(insert_record(&mut [], &rec(1)), Err(bad));
        let mut odd = vec![0u8; RECORD_LEN + 1];
        assert_eq!(find_record(&odd, &[1; 32]), Err(bad));
        assert_eq!(insert_record(&mut odd, &rec(1)), Err(bad));
        let mut short = vec![0u8; RECORD_LEN - 1];
        assert_eq!(insert_record(&mut short, &rec(1)), Err(bad));
    }

    #[test]
    fn a_blank_log_finds_nothing_not_even_the_zero_root() {
        let l = log(3);
        assert_eq!(find_record(&l, &[1; 32]), Err(Error::HeaderNotFound));
        assert_eq!(find_record(&l, &[0; 32]), Err(Error::HeaderNotFound));
    }

    #[test]
    fn records_fill_blank_slots_in_order_and_are_found_by_header_root() {
        let mut l = log(3);
        for n in 1..=3u8 {
            assert_eq!(insert_record(&mut l, &rec(n)), Ok(Insert::Stored));
            let at = (n as usize - 1) * RECORD_LEN;
            assert_eq!(l[at..at + RECORD_LEN], rec(n).encode(), "slot {n}");
        }
        for n in 1..=3u8 {
            assert_eq!(find_record(&l, &[n; 32]), Ok(rec(n)));
        }
        assert_eq!(find_record(&l, &[9; 32]), Err(Error::HeaderNotFound));
    }

    #[test]
    fn a_record_is_found_wherever_it_is_and_a_blank_slot_before_it_is_skipped() {
        let mut l = log(3);
        l[2 * RECORD_LEN..].copy_from_slice(&rec(5).encode());
        assert_eq!(find_record(&l, &[5; 32]), Ok(rec(5)));
        // a record in the middle with blanks around
        let mut l = log(3);
        l[RECORD_LEN..2 * RECORD_LEN].copy_from_slice(&rec(6).encode());
        assert_eq!(find_record(&l, &[6; 32]), Ok(rec(6)));
        // the next insert takes the first blank, which is slot 0
        assert_eq!(insert_record(&mut l, &rec(7)), Ok(Insert::Stored));
        assert_eq!(l[..RECORD_LEN], rec(7).encode());
    }

    #[test]
    fn storing_the_same_record_again_changes_nothing() {
        let mut l = log(2);
        assert_eq!(insert_record(&mut l, &rec(1)), Ok(Insert::Stored));
        let before = l.clone();
        assert_eq!(insert_record(&mut l, &rec(1)), Ok(Insert::AlreadyPresent));
        assert_eq!(l, before);
        // also when the log is full
        assert_eq!(insert_record(&mut l, &rec(2)), Ok(Insert::Stored));
        let before = l.clone();
        assert_eq!(insert_record(&mut l, &rec(2)), Ok(Insert::AlreadyPresent));
        assert_eq!(insert_record(&mut l, &rec(1)), Ok(Insert::AlreadyPresent));
        assert_eq!(l, before);
    }

    #[test]
    fn a_different_record_for_a_stored_header_is_refused() {
        let mut l = log(2);
        insert_record(&mut l, &rec(1)).unwrap();
        let before = l.clone();
        let fields: [fn(&mut HeaderRecord); 5] = [
            |r| r.slot += 1,
            |r| r.block_number += 1,
            |r| r.block_hash[0] ^= 1,
            |r| r.state_root[0] ^= 1,
            |r| r.receipts_root[0] ^= 1,
        ];
        for (i, edit) in fields.iter().enumerate() {
            let mut other = rec(1);
            edit(&mut other);
            assert_eq!(
                insert_record(&mut l, &other),
                Err(Error::HeaderRecordEncoding),
                "field {i}"
            );
            assert_eq!(l, before, "field {i}");
        }
    }

    #[test]
    fn a_full_log_replaces_the_lowest_slot() {
        let mut l = log(3);
        // slots 103, 101, 102: the lowest is in the middle
        for n in [3u8, 1, 2] {
            insert_record(&mut l, &rec(n)).unwrap();
        }
        assert_eq!(insert_record(&mut l, &rec(4)), Ok(Insert::Replaced));
        assert_eq!(find_record(&l, &[1; 32]), Err(Error::HeaderNotFound));
        for n in [2u8, 3, 4] {
            assert_eq!(find_record(&l, &[n; 32]), Ok(rec(n)));
        }
        assert_eq!(l[RECORD_LEN..2 * RECORD_LEN], rec(4).encode());
        // again: now 103, 104, 102: the lowest is the last
        assert_eq!(insert_record(&mut l, &rec(5)), Ok(Insert::Replaced));
        assert_eq!(find_record(&l, &[2; 32]), Err(Error::HeaderNotFound));
        assert_eq!(l[2 * RECORD_LEN..], rec(5).encode());
    }

    #[test]
    fn on_a_tie_the_first_lowest_slot_is_replaced() {
        let mut l = log(3);
        let mut a = rec(1);
        let mut b = rec(2);
        let mut c = rec(3);
        a.slot = 50;
        b.slot = 40;
        c.slot = 40;
        for r in [a, b, c] {
            insert_record(&mut l, &r).unwrap();
        }
        assert_eq!(insert_record(&mut l, &rec(4)), Ok(Insert::Replaced));
        assert_eq!(l[RECORD_LEN..2 * RECORD_LEN], rec(4).encode()); // b went, c stayed
        assert_eq!(find_record(&l, &[3; 32]), Ok(c));
        assert_eq!(find_record(&l, &[1; 32]), Ok(a));
    }

    #[test]
    fn a_single_slot_log_holds_the_latest() {
        let mut l = log(1);
        assert_eq!(insert_record(&mut l, &rec(1)), Ok(Insert::Stored));
        assert_eq!(insert_record(&mut l, &rec(2)), Ok(Insert::Replaced));
        assert_eq!(find_record(&l, &[1; 32]), Err(Error::HeaderNotFound));
        assert_eq!(find_record(&l, &[2; 32]), Ok(rec(2)));
    }

    #[test]
    fn a_corrupt_log_is_refused_not_skipped() {
        let bad = Error::HeaderRecordEncoding;
        // a slot with a wrong version byte but other bytes set
        let mut l = log(2);
        l[0] = 9;
        l[5] = 1;
        assert_eq!(find_record(&l, &[1; 32]), Err(bad));
        assert_eq!(insert_record(&mut l, &rec(1)), Err(bad));
        // a stray byte in a slot that is otherwise blank is not blank
        let mut l = log(2);
        l[RECORD_LEN + 100] = 1;
        assert_eq!(find_record(&l, &[1; 32]), Err(bad));
        // the same header in two slots
        let mut l = log(2);
        l[..RECORD_LEN].copy_from_slice(&rec(1).encode());
        l[RECORD_LEN..].copy_from_slice(&rec(1).encode());
        assert_eq!(find_record(&l, &[1; 32]), Err(bad));
        // ... even if one of them is not the one looked for
        assert_eq!(find_record(&l, &[2; 32]), Err(Error::HeaderNotFound));
    }

    #[test]
    fn the_record_of_a_stored_header_is_what_an_attest_reads() {
        // end to end: store from the finalized header, insert, look up by the header's root
        let f = fixture();
        let r = HeaderRecord::from_finalized(&f.cfg, &f.store, &f.exec, &f.branch).unwrap();
        let mut l = log(4);
        assert_eq!(insert_record(&mut l, &r), Ok(Insert::Stored));
        let root = f.store.finalized_header.hash_tree_root();
        assert_eq!(find_record(&l, &root), Ok(r));
        // a header the instance never finalized has no record
        let mut other = f.store.finalized_header;
        other.slot += 1;
        assert_eq!(
            find_record(&l, &other.hash_tree_root()),
            Err(Error::HeaderNotFound)
        );
    }
}
