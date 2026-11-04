//! The attest path (Sprint 6, M2): a claim about an account, a storage slot or a log, checked
//! against a stored `HeaderRecord`.
//!
//! The record already holds the state root and receipts root of a finalized header, and the
//! execution branch was checked when the record was stored (`header_record::from_finalized`).
//! So `verify_attest` does no beacon-chain work: it runs the account, storage or receipt proof
//! under the record's root, evaluates the optional predicate, and derives the statement ID.
//! It reuses `state`, `receipt`, `predicate` and `statement` of the core unchanged.
//!
//! What it returns comes from the verified proof and the record, never from the claim. The
//! claim's `address`, `slot`, `tx_index` and `log_index` are echoed because the proof verified
//! exactly those keys. Nothing about who attests (a caller, a consumer) is an input, so the
//! result cannot reveal it.
//!
//! A predicate reads only what the claim's proof covers: an account claim covers the balance,
//! a storage claim the balance and the slot value, a log claim its topics and data words. A
//! predicate over anything else is `PredicateFalse`, as in the single-shot path.
use crate::{PredicateTarget, PredicateWire};
use le_sync_core::header_record::{find_record, HeaderRecord};
use le_sync_core::instance::InstanceConfig;
use le_sync_core::keccak::keccak256;
use le_sync_core::predicate::{Predicate, Subject};
use le_sync_core::receipt::{LogFilter, MAX_TOPICS};
use le_sync_core::state::{verify_account, verify_log, verify_state, Address};
use le_sync_core::statement::{statement_id, ProofKey};
use le_sync_core::{Bytes32, Error, ZERO};

/// An account claim: the account at `address`, or its proven absence.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccountClaim {
    pub address: Address,
    /// `eth_getProof` `accountProof`: RLP nodes, root first.
    pub account_proof: Vec<Vec<u8>>,
    /// Optional predicate over the balance.
    pub predicate: Option<PredicateWire>,
}

/// A storage claim: the value of `slot` in the account at `address`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StorageClaim {
    pub address: Address,
    /// 32-byte big-endian storage key.
    pub slot: Bytes32,
    pub account_proof: Vec<Vec<u8>>,
    /// `eth_getProof` `storageProof[0].proof`: RLP nodes, root first.
    pub storage_proof: Vec<Vec<u8>>,
    /// Optional predicate over the balance or the slot value.
    pub predicate: Option<PredicateWire>,
}

/// A log claim: one log of one transaction of the block.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LogClaim {
    /// Position of the transaction in the block: the key of the receipt is `rlp(tx_index)`.
    pub tx_index: u64,
    /// Position of the log within the receipt.
    pub log_index: u32,
    /// Receipts-trie nodes for `rlp(tx_index)`, root first.
    pub receipt_proof: Vec<Vec<u8>>,
    /// The log must come from this contract ...
    pub address: Address,
    /// ... and match these topics (`None` is a wildcard).
    pub topics: [Option<Bytes32>; MAX_TOPICS],
    /// Optional predicate over a topic or data word of the log.
    pub predicate: Option<PredicateWire>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AttestClaim {
    Account(AccountClaim),
    Storage(StorageClaim),
    Log(LogClaim),
}

/// What the proof established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Verified {
    Account {
        address: Address,
        /// `false` = the account is proven absent from the state trie.
        present: bool,
        /// Big-endian wei balance; zero when absent.
        balance: Bytes32,
    },
    Storage {
        address: Address,
        slot: Bytes32,
        account_present: bool,
        balance: Bytes32,
        /// Big-endian slot value; zero for an absent slot or an absent account.
        value: Bytes32,
    },
    Log {
        tx_index: u64,
        log_index: u32,
        address: Address,
        topic_count: u32,
        /// `topics[..topic_count]` are the log's; the rest are zero.
        topics: [Bytes32; MAX_TOPICS],
        data_len: u64,
        data_hash: Bytes32,
    },
}

/// The verified statement: where it holds, what it is, and its ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Attested {
    pub chain_id: u64,
    /// Root of the finalized beacon header the record was made from.
    pub header_root: Bytes32,
    pub slot: u64,
    pub block_number: u64,
    pub block_hash: Bytes32,
    /// The state root (account, storage) or receipts root (log) the proof was checked against.
    pub root: Bytes32,
    pub verified: Verified,
    /// The predicate that held, if one was supplied.
    pub predicate: Option<PredicateWire>,
    /// `statement::statement_id` of the claim in this block of this chain.
    pub statement_id: Bytes32,
}

impl AttestClaim {
    pub fn predicate(&self) -> Option<PredicateWire> {
        match self {
            AttestClaim::Account(c) => c.predicate,
            AttestClaim::Storage(c) => c.predicate,
            AttestClaim::Log(c) => c.predicate,
        }
    }
}

/// Fail closed: a predicate that does not hold means no statement.
fn check_predicate<'a>(
    p: &Option<PredicateWire>,
    subject: impl Fn(&PredicateWire) -> Subject<'a>,
) -> Result<(), Error> {
    match p {
        Some(p) => Predicate::from(p).evaluate(&subject(p)),
        None => Ok(()),
    }
}

/// Check `claim` against `record`, for the instance `cfg` (its chain ID goes into the
/// statement ID). Errors are those of the core's proof checks (trie, RLP, `LogMismatch`) and
/// `PredicateFalse`.
pub fn verify_attest(
    cfg: &InstanceConfig,
    record: &HeaderRecord,
    claim: &AttestClaim,
) -> Result<Attested, Error> {
    let chain_id = cfg.chain_id;
    let (root, verified, key) = match claim {
        AttestClaim::Account(c) => {
            let acct = verify_account(&record.state_root, &c.address, &c.account_proof)?;
            let (present, balance) = match acct {
                Some(a) => (true, a.balance),
                None => (false, ZERO),
            };
            check_predicate(&c.predicate, |_| Subject::Account { balance })?;
            (
                record.state_root,
                Verified::Account {
                    address: c.address,
                    present,
                    balance,
                },
                ProofKey::Account { address: c.address },
            )
        }
        AttestClaim::Storage(c) => {
            let s = verify_state(
                &record.state_root,
                &c.address,
                &c.account_proof,
                &c.slot,
                &c.storage_proof,
            )?;
            check_predicate(&c.predicate, |p| match p.target {
                PredicateTarget::StorageValue => Subject::Storage { value: s.value },
                // the balance; log targets read nothing in an account and fail
                _ => Subject::Account {
                    balance: s.account.balance,
                },
            })?;
            (
                record.state_root,
                Verified::Storage {
                    address: c.address,
                    slot: c.slot,
                    account_present: s.account_present,
                    balance: s.account.balance,
                    value: s.value,
                },
                ProofKey::Storage {
                    address: c.address,
                    slot: c.slot,
                },
            )
        }
        AttestClaim::Log(c) => {
            let filter = LogFilter {
                address: c.address,
                topics: c.topics,
            };
            let log = verify_log(
                &record.receipts_root,
                c.tx_index,
                &c.receipt_proof,
                c.log_index as usize,
                &filter,
            )?;
            check_predicate(&c.predicate, |_| Subject::Log(log))?;
            (
                record.receipts_root,
                Verified::Log {
                    tx_index: c.tx_index,
                    log_index: c.log_index,
                    address: c.address,
                    topic_count: log.topic_count as u32,
                    topics: log.topics,
                    data_len: log.data.len() as u64,
                    data_hash: keccak256(log.data),
                },
                ProofKey::Log {
                    tx_index: c.tx_index,
                    log_index: u64::from(c.log_index),
                },
            )
        }
    };
    Ok(Attested {
        chain_id,
        header_root: record.header_root,
        slot: record.slot,
        block_number: record.block_number,
        block_hash: record.block_hash,
        root,
        verified,
        predicate: claim.predicate(),
        statement_id: statement_id(chain_id, &record.block_hash, &key),
    })
}

/// `find_record` in the instance's record account `records`, then `verify_attest`. A header
/// the instance never stored (or has evicted) is `HeaderNotFound`, before any proof work.
pub fn attest_header(
    cfg: &InstanceConfig,
    records: &[u8],
    header_root: &Bytes32,
    claim: &AttestClaim,
) -> Result<Attested, Error> {
    let record = find_record(records, header_root)?;
    verify_attest(cfg, &record, claim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use le_sync_core::instance::Timing;
    const TIMING: Timing = Timing {
        genesis_time: 1_606_824_023,
        seconds_per_slot: 12,
    };
    use le_sync_core::header_record::{insert_record, RECORD_LEN};
    use le_sync_core::keccak::EMPTY_TRIE_ROOT;
    use le_sync_core::state::{account_key, storage_key};
    use le_sync_testkit::trie::{index_key, rlp_bytes, rlp_list, Trie};

    const CHAIN: u64 = 7;
    const ADDR: Address = [0xAB; 20];
    const SLOT: Bytes32 = {
        let mut s = [0u8; 32];
        s[31] = 1;
        s
    };
    const SLOT2: Bytes32 = {
        let mut s = [0u8; 32];
        s[31] = 2;
        s
    };
    const LOG_TX: u64 = 129; // above 127: a two-byte `rlp(index)` key
    const LOG_ADDR: Address = [0xC0; 20];

    fn cfg_with(chain_id: u64) -> InstanceConfig {
        InstanceConfig::new(
            chain_id,
            [0xAA; 32],
            8,
            8,
            32,
            0,
            None,
            &[(0, [5, 0, 0, 1])],
            TIMING,
            [1; 32],
        )
        .unwrap()
    }

    fn trim_be(v: u128) -> Vec<u8> {
        let b = v.to_be_bytes();
        let i = b.iter().position(|x| *x != 0).unwrap_or(b.len());
        b[i..].to_vec()
    }
    fn be32(v: u128) -> Bytes32 {
        let mut o = [0u8; 32];
        o[16..].copy_from_slice(&v.to_be_bytes());
        o
    }

    struct Chain {
        state: Trie,
        storage: Trie,
        receipts: Trie,
        record: HeaderRecord,
    }

    fn topic(n: u8) -> Bytes32 {
        [n; 32]
    }
    /// One log: `LOG_ADDR`, topics [tag, tag+1, tag+2], 64 bytes of data (words tag, tag+1).
    fn log_rlp(tag: u8) -> Vec<u8> {
        let mut data = vec![tag; 32];
        data.extend([tag.wrapping_add(1); 32]);
        rlp_list(&[
            rlp_bytes(&LOG_ADDR),
            rlp_list(&[
                rlp_bytes(&topic(tag)),
                rlp_bytes(&topic(tag.wrapping_add(1))),
                rlp_bytes(&topic(tag.wrapping_add(2))),
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

    /// `ADDR`: balance 1_000_000, storage {SLOT: 0x1234, SLOT2: 5}, plus filler accounts;
    /// a block of 200 receipts where transaction `LOG_TX` has two logs (tags 0x10, 0x20).
    fn chain() -> Chain {
        let storage = Trie::new(&[
            (storage_key(&SLOT), rlp_bytes(&[0x12, 0x34])),
            (storage_key(&SLOT2), rlp_bytes(&[5])),
        ]);
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
        let record = HeaderRecord {
            slot: 4_000,
            header_root: [0x71; 32],
            block_number: 24_000_123,
            block_hash: [0x72; 32],
            state_root: state.root,
            receipts_root: receipts.root,
        };
        Chain {
            state,
            storage,
            receipts,
            record,
        }
    }

    impl Chain {
        fn account(&self, address: Address, predicate: Option<PredicateWire>) -> AttestClaim {
            AttestClaim::Account(AccountClaim {
                address,
                account_proof: self.state.prove(&account_key(&address)),
                predicate,
            })
        }
        fn storage(&self, slot: Bytes32, predicate: Option<PredicateWire>) -> AttestClaim {
            AttestClaim::Storage(StorageClaim {
                address: ADDR,
                slot,
                account_proof: self.state.prove(&account_key(&ADDR)),
                storage_proof: self.storage.prove(&storage_key(&slot)),
                predicate,
            })
        }
        fn log(&self, tx: u64, log_index: u32, predicate: Option<PredicateWire>) -> AttestClaim {
            AttestClaim::Log(LogClaim {
                tx_index: tx,
                log_index,
                receipt_proof: self.receipts.prove_raw(&index_key(tx)),
                address: LOG_ADDR,
                topics: [None; MAX_TOPICS],
                predicate,
            })
        }
    }

    fn pred(target: PredicateTarget, op: crate::PredicateOp, operand: Bytes32) -> PredicateWire {
        PredicateWire {
            target,
            op,
            operand,
        }
    }
    use crate::PredicateOp::{Eq, Ne};

    // ---- account ----------------------------------------------------------------------

    #[test]
    fn an_account_claim_verifies_the_balance_under_the_records_state_root() {
        let c = chain();
        let cfg = cfg_with(CHAIN);
        let a = verify_attest(&cfg, &c.record, &c.account(ADDR, None)).unwrap();
        assert_eq!(
            a.verified,
            Verified::Account {
                address: ADDR,
                present: true,
                balance: be32(1_000_000)
            }
        );
        assert_eq!(a.chain_id, CHAIN);
        assert_eq!(a.header_root, c.record.header_root);
        assert_eq!(a.slot, c.record.slot);
        assert_eq!(a.block_number, c.record.block_number);
        assert_eq!(a.block_hash, c.record.block_hash);
        assert_eq!(a.root, c.record.state_root);
        assert_eq!(a.predicate, None);
        assert_eq!(
            a.statement_id,
            statement_id(
                CHAIN,
                &c.record.block_hash,
                &ProofKey::Account { address: ADDR }
            )
        );
    }

    #[test]
    fn an_absent_account_is_a_verified_exclusion() {
        let c = chain();
        let other: Address = [0x99; 20];
        let a = verify_attest(&cfg_with(CHAIN), &c.record, &c.account(other, None)).unwrap();
        assert_eq!(
            a.verified,
            Verified::Account {
                address: other,
                present: false,
                balance: ZERO
            }
        );
    }

    #[test]
    fn an_account_predicate_holds_over_the_balance_or_the_claim_fails() {
        let c = chain();
        let cfg = cfg_with(CHAIN);
        let p = pred(PredicateTarget::Balance, Eq, be32(1_000_000));
        let a = verify_attest(&cfg, &c.record, &c.account(ADDR, Some(p))).unwrap();
        assert_eq!(a.predicate, Some(p));
        let p = pred(PredicateTarget::Balance, Ne, be32(5));
        assert!(verify_attest(&cfg, &c.record, &c.account(ADDR, Some(p))).is_ok());
        for p in [
            pred(PredicateTarget::Balance, Eq, be32(1_000_001)),
            pred(PredicateTarget::Balance, Ne, be32(1_000_000)),
        ] {
            assert_eq!(
                verify_attest(&cfg, &c.record, &c.account(ADDR, Some(p))),
                Err(Error::PredicateFalse)
            );
        }
    }

    #[test]
    fn a_predicate_over_state_the_account_proof_does_not_cover_fails() {
        let c = chain();
        let cfg = cfg_with(CHAIN);
        // the slot value is not covered by an account proof, nor is any log word
        for target in [
            PredicateTarget::StorageValue,
            PredicateTarget::Topic(0),
            PredicateTarget::DataWord(0),
        ] {
            // an operand the (absent) word would equal if it were read as zero
            let p = pred(target, Eq, ZERO);
            assert_eq!(
                verify_attest(&cfg, &c.record, &c.account(ADDR, Some(p))),
                Err(Error::PredicateFalse),
                "{target:?}"
            );
            let p = pred(target, Ne, be32(1));
            assert_eq!(
                verify_attest(&cfg, &c.record, &c.account(ADDR, Some(p))),
                Err(Error::PredicateFalse),
                "{target:?}"
            );
        }
    }

    // ---- storage ----------------------------------------------------------------------

    #[test]
    fn a_storage_claim_verifies_the_slot_under_the_accounts_storage_root() {
        let c = chain();
        let cfg = cfg_with(CHAIN);
        let a = verify_attest(&cfg, &c.record, &c.storage(SLOT, None)).unwrap();
        assert_eq!(
            a.verified,
            Verified::Storage {
                address: ADDR,
                slot: SLOT,
                account_present: true,
                balance: be32(1_000_000),
                value: be32(0x1234)
            }
        );
        assert_eq!(a.root, c.record.state_root);
        assert_eq!(
            a.statement_id,
            statement_id(
                CHAIN,
                &c.record.block_hash,
                &ProofKey::Storage {
                    address: ADDR,
                    slot: SLOT
                }
            )
        );
        let b = verify_attest(&cfg, &c.record, &c.storage(SLOT2, None)).unwrap();
        assert_ne!(a.statement_id, b.statement_id);
        let Verified::Storage { value, .. } = b.verified else {
            panic!()
        };
        assert_eq!(value, be32(5));
    }

    #[test]
    fn an_absent_slot_is_a_verified_zero_and_an_absent_account_has_zero_everything() {
        let c = chain();
        let cfg = cfg_with(CHAIN);
        let mut absent_slot = [0u8; 32];
        absent_slot[31] = 9;
        let a = verify_attest(&cfg, &c.record, &c.storage(absent_slot, None)).unwrap();
        let Verified::Storage { value, .. } = a.verified else {
            panic!()
        };
        assert_eq!(value, ZERO);
        // account absent: the storage proof is not consulted
        let claim = AttestClaim::Storage(StorageClaim {
            address: [0x99; 20],
            slot: SLOT,
            account_proof: c.state.prove(&account_key(&[0x99; 20])),
            storage_proof: vec![],
            predicate: None,
        });
        let a = verify_attest(&cfg, &c.record, &claim).unwrap();
        assert_eq!(
            a.verified,
            Verified::Storage {
                address: [0x99; 20],
                slot: SLOT,
                account_present: false,
                balance: ZERO,
                value: ZERO
            }
        );
    }

    #[test]
    fn a_storage_predicate_reads_the_slot_or_the_balance() {
        let c = chain();
        let cfg = cfg_with(CHAIN);
        let ok = |p| verify_attest(&cfg, &c.record, &c.storage(SLOT, Some(p)));
        assert!(ok(pred(PredicateTarget::StorageValue, Eq, be32(0x1234))).is_ok());
        assert!(ok(pred(PredicateTarget::StorageValue, Ne, be32(0x1235))).is_ok());
        assert_eq!(
            ok(pred(PredicateTarget::StorageValue, Eq, be32(0x1235))),
            Err(Error::PredicateFalse)
        );
        assert!(ok(pred(PredicateTarget::Balance, Eq, be32(1_000_000))).is_ok());
        assert_eq!(
            ok(pred(PredicateTarget::Balance, Eq, be32(0x1234))),
            Err(Error::PredicateFalse)
        );
        // log words are not covered
        assert_eq!(
            ok(pred(PredicateTarget::Topic(0), Ne, be32(1))),
            Err(Error::PredicateFalse)
        );
        assert_eq!(
            ok(pred(PredicateTarget::DataWord(0), Ne, be32(1))),
            Err(Error::PredicateFalse)
        );
    }

    // ---- log --------------------------------------------------------------------------

    #[test]
    fn a_log_claim_verifies_the_log_under_the_records_receipts_root() {
        let c = chain();
        let cfg = cfg_with(CHAIN);
        let a = verify_attest(&cfg, &c.record, &c.log(LOG_TX, 1, None)).unwrap();
        let mut topics = [ZERO; MAX_TOPICS];
        topics[0] = topic(0x20);
        topics[1] = topic(0x21);
        topics[2] = topic(0x22);
        let mut data = vec![0x20u8; 32];
        data.extend([0x21u8; 32]);
        assert_eq!(
            a.verified,
            Verified::Log {
                tx_index: LOG_TX,
                log_index: 1,
                address: LOG_ADDR,
                topic_count: 3,
                topics,
                data_len: 64,
                data_hash: keccak256(&data),
            }
        );
        assert_eq!(a.root, c.record.receipts_root);
        assert_eq!(
            a.statement_id,
            statement_id(
                CHAIN,
                &c.record.block_hash,
                &ProofKey::Log {
                    tx_index: LOG_TX,
                    log_index: 1
                }
            )
        );
        // the first log of the same receipt is another statement
        let first = verify_attest(&cfg, &c.record, &c.log(LOG_TX, 0, None)).unwrap();
        assert_ne!(first.statement_id, a.statement_id);
        let Verified::Log { topics, .. } = first.verified else {
            panic!()
        };
        assert_eq!(topics[0], topic(0x10));
    }

    #[test]
    fn a_log_filter_that_does_not_match_is_refused() {
        let c = chain();
        let cfg = cfg_with(CHAIN);
        let AttestClaim::Log(mut l) = c.log(LOG_TX, 0, None) else {
            panic!()
        };
        l.topics[0] = Some(topic(0x10));
        assert!(verify_attest(&cfg, &c.record, &AttestClaim::Log(l.clone())).is_ok());
        l.topics[0] = Some(topic(0x11));
        assert_eq!(
            verify_attest(&cfg, &c.record, &AttestClaim::Log(l.clone())),
            Err(Error::LogMismatch)
        );
        l.topics[0] = None;
        l.address = [0xC1; 20];
        assert_eq!(
            verify_attest(&cfg, &c.record, &AttestClaim::Log(l)),
            Err(Error::LogMismatch)
        );
        // no such log in the receipt
        assert_eq!(
            verify_attest(&cfg, &c.record, &c.log(LOG_TX, 2, None)),
            Err(Error::LogMismatch)
        );
    }

    #[test]
    fn a_log_predicate_reads_topics_and_data_words_or_the_claim_fails() {
        let c = chain();
        let cfg = cfg_with(CHAIN);
        let ok = |p| verify_attest(&cfg, &c.record, &c.log(LOG_TX, 0, Some(p)));
        assert!(ok(pred(PredicateTarget::Topic(1), Eq, topic(0x11))).is_ok());
        assert!(ok(pred(PredicateTarget::DataWord(1), Eq, topic(0x11))).is_ok());
        assert_eq!(
            ok(pred(PredicateTarget::Topic(1), Eq, topic(0x12))),
            Err(Error::PredicateFalse)
        );
        // the log has three topics and two data words
        assert_eq!(
            ok(pred(PredicateTarget::Topic(3), Ne, ZERO)),
            Err(Error::PredicateFalse)
        );
        assert_eq!(
            ok(pred(PredicateTarget::DataWord(2), Ne, ZERO)),
            Err(Error::PredicateFalse)
        );
        // state targets are not covered by a log proof
        assert_eq!(
            ok(pred(PredicateTarget::Balance, Ne, be32(1))),
            Err(Error::PredicateFalse)
        );
        assert_eq!(
            ok(pred(PredicateTarget::StorageValue, Ne, be32(1))),
            Err(Error::PredicateFalse)
        );
        let a = ok(pred(PredicateTarget::Topic(0), Eq, topic(0x10))).unwrap();
        assert!(a.predicate.is_some());
    }

    // ---- tampering and replay -----------------------------------------------------------

    #[test]
    fn a_tampered_state_root_or_receipts_root_fails_every_claim() {
        let c = chain();
        let cfg = cfg_with(CHAIN);
        let mut r = c.record;
        r.state_root[0] ^= 1;
        assert!(verify_attest(&cfg, &r, &c.account(ADDR, None)).is_err());
        assert!(verify_attest(&cfg, &r, &c.storage(SLOT, None)).is_err());
        // a log claim does not read the state root
        assert!(verify_attest(&cfg, &r, &c.log(LOG_TX, 0, None)).is_ok());
        let mut r = c.record;
        r.receipts_root[0] ^= 1;
        assert!(verify_attest(&cfg, &r, &c.log(LOG_TX, 0, None)).is_err());
        // and an account claim does not read the receipts root
        assert!(verify_attest(&cfg, &r, &c.account(ADDR, None)).is_ok());
    }

    #[test]
    fn a_tampered_proof_node_is_refused() {
        let c = chain();
        let cfg = cfg_with(CHAIN);
        let AttestClaim::Account(mut a) = c.account(ADDR, None) else {
            panic!()
        };
        let last = a.account_proof.len() - 1;
        let n = a.account_proof[last].len();
        a.account_proof[last][n - 1] ^= 1;
        assert!(verify_attest(&cfg, &c.record, &AttestClaim::Account(a)).is_err());
        let AttestClaim::Storage(mut s) = c.storage(SLOT, None) else {
            panic!()
        };
        let n = s.storage_proof[0].len();
        s.storage_proof[0][n - 1] ^= 1;
        assert!(verify_attest(&cfg, &c.record, &AttestClaim::Storage(s)).is_err());
        let AttestClaim::Log(mut l) = c.log(LOG_TX, 0, None) else {
            panic!()
        };
        let n = l.receipt_proof[0].len();
        l.receipt_proof[0][n - 1] ^= 1;
        assert!(verify_attest(&cfg, &c.record, &AttestClaim::Log(l)).is_err());
    }

    #[test]
    fn a_proof_of_one_key_does_not_prove_another() {
        let c = chain();
        let cfg = cfg_with(CHAIN);
        // the proof for SLOT claimed for SLOT2
        let AttestClaim::Storage(mut s) = c.storage(SLOT, None) else {
            panic!()
        };
        s.slot = SLOT2;
        assert!(verify_attest(&cfg, &c.record, &AttestClaim::Storage(s)).is_err());
        // the proof of transaction 5 claimed for LOG_TX
        let AttestClaim::Log(mut l) = c.log(5, 0, None) else {
            panic!()
        };
        l.tx_index = LOG_TX;
        assert!(verify_attest(&cfg, &c.record, &AttestClaim::Log(l)).is_err());
    }

    #[test]
    fn the_statement_id_carries_the_chain_id_and_the_block() {
        let c = chain();
        let claim = c.account(ADDR, None);
        let a = verify_attest(&cfg_with(1), &c.record, &claim).unwrap();
        let b = verify_attest(&cfg_with(2), &c.record, &claim).unwrap();
        assert_ne!(a.statement_id, b.statement_id);
        assert_eq!((a.chain_id, b.chain_id), (1, 2));
        let mut other_block = c.record;
        other_block.block_hash[0] ^= 1;
        let d = verify_attest(&cfg_with(1), &other_block, &claim).unwrap();
        assert_ne!(a.statement_id, d.statement_id);
        // account, storage and log statements of one block are distinct
        let s = verify_attest(&cfg_with(1), &c.record, &c.storage(SLOT, None)).unwrap();
        let l = verify_attest(&cfg_with(1), &c.record, &c.log(LOG_TX, 0, None)).unwrap();
        assert_ne!(a.statement_id, s.statement_id);
        assert_ne!(a.statement_id, l.statement_id);
        assert_ne!(s.statement_id, l.statement_id);
    }

    #[test]
    fn the_result_has_no_input_for_who_attests() {
        // the same claim from any caller gives the same result: the only inputs are the
        // instance configuration, the record and the claim
        let c = chain();
        let cfg = cfg_with(CHAIN);
        let claim = c.storage(SLOT, None);
        let a = verify_attest(&cfg, &c.record, &claim).unwrap();
        let b = verify_attest(&cfg, &c.record, &claim.clone()).unwrap();
        assert_eq!(a, b);
    }

    // ---- through the record account -------------------------------------------------------

    #[test]
    fn attest_header_reads_the_record_by_header_root() {
        let c = chain();
        let cfg = cfg_with(CHAIN);
        let mut records = vec![0u8; 3 * RECORD_LEN];
        insert_record(&mut records, &c.record).unwrap();
        let claim = c.account(ADDR, None);
        let a = attest_header(&cfg, &records, &c.record.header_root, &claim).unwrap();
        assert_eq!(a, verify_attest(&cfg, &c.record, &claim).unwrap());
        // a header the instance never stored: no proof work, a typed error
        assert_eq!(
            attest_header(&cfg, &records, &[0x01; 32], &claim),
            Err(Error::HeaderNotFound)
        );
        // an empty or malformed record account is not a record
        assert_eq!(
            attest_header(&cfg, &[], &c.record.header_root, &claim),
            Err(Error::HeaderRecordEncoding)
        );
    }

    #[test]
    fn a_record_of_a_header_that_was_never_finalized_does_not_exist_to_attest_against() {
        // a valid proof against a header the instance did not store is HeaderNotFound, even if
        // the state it proves is real
        let c = chain();
        let cfg = cfg_with(CHAIN);
        let mut records = vec![0u8; 2 * RECORD_LEN];
        let mut other = c.record;
        other.header_root = [0x55; 32];
        insert_record(&mut records, &other).unwrap();
        assert_eq!(
            attest_header(
                &cfg,
                &records,
                &c.record.header_root,
                &c.account(ADDR, None)
            ),
            Err(Error::HeaderNotFound)
        );
    }
}
