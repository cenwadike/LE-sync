//! The synthetic world of the executor tests: a beacon chain with a real committee that signs
//! real updates, and an execution layer whose tries the claims are proven against. Pure
//! (no LEZ, no risc0), so it compiles and is reasoned about apart from the harness.
//!
//! Real BLS signatures (testkit signs; its keys are trivially guessable and must never leave
//! tests). Slots: the bootstrap header is at 8; the default update attests 40, finalizes 24
//! and is signed at 41; the clock reads slot 41. A period is 64 slots, so everything above is
//! period 0 and the store does not know its next committee, which is what lets a handoff
//! update apply and what makes an update signed in period 1 a handoff from an unknown
//! committee.
//!
//! Same helpers as `bench/src/fixture.rs` and `wire/src/statement_path.rs` (tests); an
//! integration crate cannot import those, so the few lines are repeated here.
use le_sync_core::exec::ExecutionPayloadHeader;
use le_sync_core::header_record::HeaderRecord;
use le_sync_core::instance::{Bootstrap, InstanceConfig, Timing};
use le_sync_core::keccak::{keccak256, EMPTY_TRIE_ROOT};
use le_sync_core::receipt::MAX_TOPICS;
use le_sync_core::state::{account_key, storage_key, Address};
use le_sync_core::sync::{compute_domain, compute_signing_root, DOMAIN_SYNC_COMMITTEE};
use le_sync_core::{pubkeys_root, BeaconBlockHeader, Bytes32};
use le_sync_testkit as tk;
use le_sync_testkit::trie::{index_key, rlp_bytes, rlp_list, Trie};
use le_sync_wire::bls::uncompress_g1;
use le_sync_wire::rooted::{absent_wire, to_rooted_update, AbsentWire, RootedUpdate};
use le_sync_wire::statement_path::{AccountClaim, AttestClaim, LogClaim, StorageClaim};
use le_sync_wire::{ExecWire, UpdateWire, WireHeader};

pub const GVR: Bytes32 = [0xAA; 32];
pub const FORK: [u8; 4] = [5, 0, 0, 1];
pub const SPE: u64 = 8;
pub const EPP: u64 = 8;
pub const GENESIS_TIME: u64 = 1_700_000_000;
pub const SECONDS_PER_SLOT: u64 = 12;

/// The LEZ clock (milliseconds) a moment inside `slot`.
pub fn clock_ms(slot: u64) -> u64 {
    (GENESIS_TIME + slot * SECONDS_PER_SLOT) * 1000 + 500
}

pub const ADDR: Address = [0xAB; 20];
pub const SLOT_A: Bytes32 = {
    let mut s = [0u8; 32];
    s[31] = 1;
    s
};
pub const LOG_TX: u64 = 129;
pub const LOG_ADDR: Address = [0xC0; 20];

fn trim_be(v: u128) -> Vec<u8> {
    let b = v.to_be_bytes();
    let i = b.iter().position(|x| *x != 0).unwrap_or(b.len());
    b[i..].to_vec()
}

fn hdr(slot: u64, state_root: Bytes32, salt: u64) -> WireHeader {
    WireHeader {
        slot,
        proposer_index: salt,
        parent_root: tk::leaf(100 + salt),
        state_root,
        body_root: tk::leaf(200 + salt),
    }
}

fn root_of(h: &WireHeader) -> Bytes32 {
    BeaconBlockHeader::from(h).hash_tree_root()
}

fn signing_root(att: &WireHeader) -> Bytes32 {
    compute_signing_root(
        &root_of(att),
        &compute_domain(DOMAIN_SYNC_COMMITTEE, FORK, &GVR),
    )
}

/// Who signs an update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signer {
    /// The committee the instance was started with.
    Current,
    /// The committee of the next period (which the instance does not know yet).
    Next,
}

/// One update to build.
#[derive(Clone, Copy, Debug)]
pub struct Spec {
    pub finalized: u64,
    pub attested: u64,
    pub signature: u64,
    /// Varies the filler of the headers, the state and the execution block.
    pub salt: u64,
    /// Members that sign (the first `present` bits).
    pub present: usize,
    pub signer: Signer,
    /// Carries the next committee (a handoff).
    pub carry_next: bool,
}

impl Spec {
    /// The default update: every member signs, finalized 24, attested 40, signed 41.
    pub fn new(n: usize) -> Spec {
        Spec {
            finalized: 24,
            attested: 40,
            signature: 41,
            salt: 2,
            present: n,
            signer: Signer::Current,
            carry_next: false,
        }
    }
}

/// An update as the program takes it, with what `finish_update` needs next to it.
pub struct Update {
    pub rooted: RootedUpdate,
    pub absent: AbsentWire,
    pub exec: ExecWire,
    pub exec_branch: Vec<Bytes32>,
    pub finalized_root: Bytes32,
    pub attested_root: Bytes32,
    /// The record `finish_update` stores for the finalized header.
    pub record: HeaderRecord,
}

/// The execution layer: an account with a balance and storage, and a block of receipts.
pub struct Exec {
    pub state: Trie,
    pub storage: Trie,
    pub receipts: Trie,
}

fn log_rlp(tag: u8) -> Vec<u8> {
    let mut data = vec![tag; 32];
    data.extend([tag.wrapping_add(1); 32]);
    rlp_list(&[
        rlp_bytes(&LOG_ADDR),
        rlp_list(&[
            rlp_bytes(&[tag; 32]),
            rlp_bytes(&[tag.wrapping_add(1); 32]),
            rlp_bytes(&[tag.wrapping_add(2); 32]),
        ]),
        rlp_bytes(&data),
    ])
}

fn receipt_leaf(logs: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![0x02];
    v.extend(rlp_list(&[
        rlp_bytes(&[1]),
        rlp_bytes(&[0x52, 0x08]),
        rlp_bytes(&[0u8; 256]),
        rlp_list(logs),
    ]));
    v
}

impl Exec {
    /// `ADDR`: balance 1_000_000, storage {`SLOT_A`: 0x1234}, plus filler accounts; a block of
    /// 200 receipts where transaction `LOG_TX` has two logs (tags 0x10 and 0x20).
    pub fn new() -> Exec {
        let storage = Trie::new(&[(storage_key(&SLOT_A), rlp_bytes(&[0x12, 0x34]))]);
        let code_hash = keccak256(&[]);
        let mut es = vec![(
            account_key(&ADDR),
            rlp_list(&[
                rlp_bytes(&[7]),
                rlp_bytes(&trim_be(1_000_000)),
                rlp_bytes(&storage.root),
                rlp_bytes(&[0xCC; 32]),
            ]),
        )];
        for k in 0x22..0x2au8 {
            es.push((
                account_key(&[k; 20]),
                rlp_list(&[
                    rlp_bytes(&[]),
                    rlp_bytes(&[k]),
                    rlp_bytes(&EMPTY_TRIE_ROOT),
                    rlp_bytes(&code_hash),
                ]),
            ));
        }
        let state = Trie::new(&es);
        let receipts = Trie::new_raw(
            &(0..200u64)
                .map(|n| {
                    let logs = if n == LOG_TX {
                        vec![log_rlp(0x10), log_rlp(0x20)]
                    } else {
                        vec![log_rlp(n as u8 | 0x80)]
                    };
                    (index_key(n), receipt_leaf(&logs))
                })
                .collect::<Vec<_>>(),
        );
        Exec {
            state,
            storage,
            receipts,
        }
    }

    pub fn header(&self, salt: u64) -> ExecutionPayloadHeader {
        let b = |n: u8| [(salt as u8).wrapping_add(n); 32];
        let mut extra = [0u8; 32];
        extra[..5].copy_from_slice(b"hello");
        ExecutionPayloadHeader {
            parent_hash: b(1),
            fee_recipient: [salt as u8; 20],
            state_root: self.state.root,
            receipts_root: self.receipts.root,
            logs_bloom: [0u8; 256],
            prev_randao: b(4),
            block_number: 24_000_000 + salt,
            gas_limit: 30_000_000,
            gas_used: 12_345,
            timestamp: 1_700_000_000,
            extra_data: extra,
            extra_data_len: 5,
            base_fee_per_gas: b(5),
            block_hash: b(6),
            transactions_root: b(7),
            withdrawals_root: b(8),
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }

    pub fn account(&self, address: Address) -> AttestClaim {
        AttestClaim::Account(AccountClaim {
            address,
            account_proof: self.state.prove(&account_key(&address)),
            predicate: None,
        })
    }

    pub fn storage(&self, slot: Bytes32) -> AttestClaim {
        AttestClaim::Storage(StorageClaim {
            address: ADDR,
            slot,
            account_proof: self.state.prove(&account_key(&ADDR)),
            storage_proof: self.storage.prove(&storage_key(&slot)),
            predicate: None,
        })
    }

    pub fn log(&self, tx: u64, log_index: u32) -> AttestClaim {
        AttestClaim::Log(LogClaim {
            tx_index: tx,
            log_index,
            receipt_proof: self.receipts.prove_raw(&index_key(tx)),
            address: LOG_ADDR,
            topics: [None; MAX_TOPICS],
            predicate: None,
        })
    }
}

fn exec_wire(h: &ExecutionPayloadHeader) -> ExecWire {
    ExecWire {
        parent_hash: h.parent_hash,
        fee_recipient: h.fee_recipient,
        state_root: h.state_root,
        receipts_root: h.receipts_root,
        logs_bloom: h.logs_bloom.to_vec(),
        prev_randao: h.prev_randao,
        block_number: h.block_number,
        gas_limit: h.gas_limit,
        gas_used: h.gas_used,
        timestamp: h.timestamp,
        extra_data: h.extra_data[..h.extra_data_len].to_vec(),
        base_fee_per_gas: h.base_fee_per_gas,
        block_hash: h.block_hash,
        transactions_root: h.transactions_root,
        withdrawals_root: h.withdrawals_root,
        blob_gas_used: h.blob_gas_used,
        excess_blob_gas: h.excess_blob_gas,
    }
}

/// One beacon chain: two committees, and everything an instance on it needs.
pub struct World {
    pub n: usize,
    /// `seed` of the committees: two worlds with different seeds share nothing.
    pub seed: u32,
    pub cur: tk::Committee,
    pub next: tk::Committee,
    pub exec: Exec,
    pub boot: WireHeader,
    boot_branch: Vec<Bytes32>,
    keys_root: Bytes32,
}

impl World {
    /// `n`: committee size, a power of two. `seed`: 1 for the honest chain.
    pub fn new(n: usize, seed: u32) -> World {
        let cur = tk::committee(seed * 2 - 1, n);
        let next = tk::committee(seed * 2, n);
        let boot_state = tk::state(1, &tk::leaf(1), &cur.root(), &next.root());
        let boot = hdr(8, boot_state.root, 1);
        let keys_root = pubkeys_root(&cur.pubkeys).expect("a power-of-two committee");
        World {
            n,
            seed,
            cur,
            next,
            exec: Exec::new(),
            boot,
            boot_branch: boot_state.cur_branch,
            keys_root,
        }
    }

    /// The configuration of an instance of this chain labelled `chain_id`.
    pub fn config(&self, chain_id: u64) -> InstanceConfig {
        InstanceConfig::new(
            chain_id,
            GVR,
            SPE,
            EPP,
            self.n as u16,
            0,
            None,
            &[(0, FORK)],
            Timing {
                genesis_time: GENESIS_TIME,
                seconds_per_slot: SECONDS_PER_SLOT,
            },
            root_of(&self.boot),
        )
        .expect("a valid configuration")
    }

    /// The checkpoint header, the committee as a root, and the branch, as `init_instance`
    /// takes them.
    pub fn bootstrap(&self) -> Bootstrap<'_> {
        Bootstrap {
            header: BeaconBlockHeader::from(&self.boot),
            keys_root: self.keys_root,
            aggregate: self.cur.aggregate,
            branch: &self.boot_branch,
        }
    }

    /// Build one update. The hints are those of the instance's own (current) committee, which
    /// is all an honest relayer has; an update signed by `Signer::Next` carries them too.
    pub fn update(&self, s: &Spec) -> Update {
        let exec_header = self.exec.header(s.salt);
        let exec_root = exec_header.hash_tree_root().expect("a valid header");
        // the finalized header commits the execution header (gindex 25 of the body)
        let mut leaves: Vec<Bytes32> = (0..16)
            .map(|i| tk::leaf(9_000 + s.salt * 100 + i))
            .collect();
        leaves[9] = exec_root;
        let (body_root, exec_branch) = tk::root_and_branch(leaves, 9);
        let mut fin = hdr(s.finalized, tk::leaf(300 + s.salt), s.salt);
        fin.body_root = body_root;

        let st = tk::state(s.salt, &root_of(&fin), &self.cur.root(), &self.next.root());
        let att = hdr(s.attested, st.root, s.salt + 1);
        let bits = tk::bits_set(self.n, s.present);
        let msg = signing_root(&att);
        let signature = match s.signer {
            Signer::Current => self.cur.sign(&bits, &msg),
            Signer::Next => self.next.sign(&bits, &msg),
        };
        let (next_pubkeys, next_aggregate, next_branch) = if s.carry_next {
            (
                self.next.flat(),
                self.next.aggregate.to_vec(),
                st.next_branch.clone(),
            )
        } else {
            (vec![], vec![], vec![])
        };
        let finalized_root = root_of(&fin);
        let attested_root = root_of(&att);
        let wire = UpdateWire {
            attested: att,
            next_pubkeys,
            next_aggregate,
            next_branch,
            finalized: fin,
            finality_branch: st.finality_branch,
            bits: bits.clone(),
            signature: signature.to_vec(),
            signature_slot: s.signature,
        };
        let rooted = to_rooted_update(&wire).expect("a rooted update");
        let absent = absent_wire(&self.cur.pubkeys, &bits, uncompress_g1).expect("the hints");
        let record = HeaderRecord {
            slot: s.finalized,
            header_root: finalized_root,
            block_number: exec_header.block_number,
            block_hash: exec_header.block_hash,
            state_root: exec_header.state_root,
            receipts_root: exec_header.receipts_root,
        };
        Update {
            rooted,
            absent,
            exec: exec_wire(&exec_header),
            exec_branch,
            finalized_root,
            attested_root,
            record,
        }
    }
}

/// Smallest number of signers the 2/3 gate accepts.
pub fn min_participants(n: usize) -> usize {
    (2 * n + 2) / 3
}

#[cfg(test)]
mod tests {
    use super::*;
    use le_sync_core::exec::anchor_execution;
    use le_sync_core::instance::init_store;
    use le_sync_wire::statement_path::verify_attest;

    #[test]
    fn the_bootstrap_starts_the_store_at_the_checkpoint() {
        let w = World::new(32, 1);
        let cfg = w.config(1);
        let store = init_store(&cfg, &w.bootstrap(), 41).expect("a valid bootstrap");
        assert_eq!(store.finalized_header.slot, 8);
    }

    #[test]
    fn another_chain_label_is_another_instance_of_the_same_chain() {
        let w = World::new(32, 1);
        assert_ne!(w.config(1).id(), w.config(2).id());
        assert_eq!(w.config(1).trusted_root, w.config(2).trusted_root);
        assert_ne!(
            World::new(32, 1).config(1).id(),
            World::new(32, 2).config(1).id()
        );
    }

    #[test]
    fn the_finalized_header_commits_the_execution_header_the_record_is_made_from() {
        let w = World::new(32, 1);
        let cfg = w.config(1);
        let u = w.update(&Spec::new(32));
        let fin = BeaconBlockHeader::from(&u.rooted.update.finalized);
        assert_eq!(fin.hash_tree_root(), u.finalized_root);
        let exec = u.exec.to_header().expect("a valid header");
        let a = anchor_execution(&cfg.chain(), &fin, &exec, &u.exec_branch).expect("anchored");
        assert_eq!(a.state_root, u.record.state_root);
        assert_eq!(a.receipts_root, u.record.receipts_root);
        assert_eq!(a.block_hash, u.record.block_hash);
        assert_eq!(a.block_number, u.record.block_number);
    }

    #[test]
    fn the_claims_verify_under_the_record_and_have_distinct_statement_ids() {
        let w = World::new(32, 1);
        let cfg = w.config(1);
        let u = w.update(&Spec::new(32));
        let ids: Vec<_> = [
            w.exec.account(ADDR),
            w.exec.storage(SLOT_A),
            w.exec.log(LOG_TX, 0),
            w.exec.log(LOG_TX, 1),
        ]
        .iter()
        .map(|c| {
            verify_attest(&cfg, &u.record, c)
                .expect("verifies")
                .statement_id
        })
        .collect();
        for i in 0..ids.len() {
            for j in 0..i {
                assert_ne!(ids[i], ids[j]);
            }
        }
    }

    #[test]
    fn two_updates_of_different_salts_finalize_different_headers_and_blocks() {
        let w = World::new(32, 1);
        let a = w.update(&Spec::new(32));
        let b = w.update(&Spec {
            salt: 3,
            ..Spec::new(32)
        });
        assert_ne!(a.finalized_root, b.finalized_root);
        assert_ne!(a.record.block_hash, b.record.block_hash);
    }

    #[test]
    fn min_participation_is_the_smallest_the_gate_accepts() {
        for n in [8usize, 32, 512] {
            let p = min_participants(n);
            assert!(p * 3 >= n * 2 && (p - 1) * 3 < n * 2);
        }
    }
}
