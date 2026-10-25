//! Statement ID (`no_std`, no alloc). PROVISIONAL.
//!
//! A deterministic 32-byte identifier for what a proof attests, which a consumer can key a
//! nullifier on:
//!
//! ```text
//! id = SHA-256( DOMAIN || chain_id (8, BE) || block_hash (32) || proof_type (1) || key )
//! ```
//!
//! * `block_hash` is the hash of the EXECUTION block the proof is about, not the finalized
//!   beacon header that vouched for it. The same event or state proven under a later
//!   finalized header therefore keeps the same ID, so a nullifier on the ID cannot be
//!   replayed by re-anchoring. (An Ethereum log is identified by block hash, transaction
//!   index and log index.)
//! * `proof_type` is 1 (account), 2 (storage) or 3 (log); the key layout is fixed per type, so
//!   no two encodings collide.
//! * Key: account = address (20); storage = address (20) and slot (32);
//!   log = transaction index (8, BE) and log index (8, BE).
//! * The predicate and the value are not part of the ID: it names the attested subject.
//!
//! Provisional: what the ID binds to and the hash function are fixed by RFP-021 Func #6.
//! Both are confined to this file. The vectors below pin the current encoding.

use crate::Bytes32;
use sha2::{Digest, Sha256};

/// Domain separation tag; the version changes with the encoding.
pub const DOMAIN: &[u8] = b"le-sync/statement/v1";

/// The subject of a statement within one execution block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKey {
    Account { address: [u8; 20] },
    Storage { address: [u8; 20], slot: Bytes32 },
    Log { tx_index: u64, log_index: u64 },
}

impl ProofKey {
    const fn proof_type(&self) -> u8 {
        match self {
            ProofKey::Account { .. } => 1,
            ProofKey::Storage { .. } => 2,
            ProofKey::Log { .. } => 3,
        }
    }
}

/// The statement ID for `key` in the execution block `block_hash` of chain `chain_id`.
pub fn statement_id(chain_id: u64, block_hash: &Bytes32, key: &ProofKey) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(chain_id.to_be_bytes());
    h.update(block_hash);
    h.update([key.proof_type()]);
    match key {
        ProofKey::Account { address } => h.update(address),
        ProofKey::Storage { address, slot } => {
            h.update(address);
            h.update(slot);
        }
        ProofKey::Log {
            tx_index,
            log_index,
        } => {
            h.update(tx_index.to_be_bytes());
            h.update(log_index.to_be_bytes());
        }
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ZERO;

    const BH: Bytes32 = [0x11; 32];
    const ADDR: [u8; 20] = [0xA1; 20];
    fn slot7() -> Bytes32 {
        let mut s = [0u8; 32];
        s[31] = 7;
        s
    }
    fn hex(b: &Bytes32) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn known_answer_vectors() {
        // computed independently (Python hashlib) from the layout in the module doc
        assert_eq!(
            hex(&statement_id(1, &BH, &ProofKey::Account { address: ADDR })),
            "30897029e0a30ed695ea2f5d51b2ecae0d0cd89e98c852e0340e99d387271a07"
        );
        assert_eq!(
            hex(&statement_id(
                1,
                &BH,
                &ProofKey::Storage {
                    address: ADDR,
                    slot: slot7()
                }
            )),
            "fc03d19fa5e62c8a454880c962c79776cad744e847c3539f834bf632bdc9e2bd"
        );
        assert_eq!(
            hex(&statement_id(
                1,
                &BH,
                &ProofKey::Log {
                    tx_index: 130,
                    log_index: 2
                }
            )),
            "f4db33e8346b9cbdb1e0b75588cb728e8a3f5d448489f55f07ac265c19ae12b6"
        );
    }

    #[test]
    fn same_inputs_same_id() {
        let k = ProofKey::Log {
            tx_index: 5,
            log_index: 1,
        };
        assert_eq!(statement_id(1, &BH, &k), statement_id(1, &BH, &k));
    }

    #[test]
    fn every_input_changes_the_id() {
        let keys = [
            ProofKey::Account { address: ADDR },
            ProofKey::Storage {
                address: ADDR,
                slot: slot7(),
            },
            ProofKey::Log {
                tx_index: 130,
                log_index: 2,
            },
        ];
        for k in keys {
            let base = statement_id(1, &BH, &k);
            // chain id
            assert_ne!(statement_id(2, &BH, &k), base);
            // every byte of the block hash
            for i in 0..32 {
                let mut b = BH;
                b[i] ^= 1;
                assert_ne!(statement_id(1, &b, &k), base, "block hash byte {i}");
            }
        }
        let base = statement_id(1, &BH, &keys[0]);
        for i in 0..20 {
            let mut a = ADDR;
            a[i] ^= 1;
            assert_ne!(
                statement_id(1, &BH, &ProofKey::Account { address: a }),
                base,
                "address byte {i}"
            );
        }
        let base = statement_id(1, &BH, &keys[1]);
        for i in 0..20 {
            let mut a = ADDR;
            a[i] ^= 1;
            assert_ne!(
                statement_id(
                    1,
                    &BH,
                    &ProofKey::Storage {
                        address: a,
                        slot: slot7()
                    }
                ),
                base
            );
        }
        for i in 0..32 {
            let mut s = slot7();
            s[i] ^= 1;
            assert_ne!(
                statement_id(
                    1,
                    &BH,
                    &ProofKey::Storage {
                        address: ADDR,
                        slot: s
                    }
                ),
                base,
                "slot byte {i}"
            );
        }
        let base = statement_id(1, &BH, &keys[2]);
        assert_ne!(
            statement_id(
                1,
                &BH,
                &ProofKey::Log {
                    tx_index: 131,
                    log_index: 2
                }
            ),
            base
        );
        assert_ne!(
            statement_id(
                1,
                &BH,
                &ProofKey::Log {
                    tx_index: 130,
                    log_index: 3
                }
            ),
            base
        );
        // tx and log index are not interchangeable
        assert_ne!(
            statement_id(
                1,
                &BH,
                &ProofKey::Log {
                    tx_index: 2,
                    log_index: 130
                }
            ),
            base
        );
    }

    #[test]
    fn proof_types_never_collide() {
        // an account and a storage key over the same address, and a log over small indices
        let a = statement_id(1, &BH, &ProofKey::Account { address: ADDR });
        let s = statement_id(
            1,
            &BH,
            &ProofKey::Storage {
                address: ADDR,
                slot: [0; 32],
            },
        );
        let l = statement_id(
            1,
            &BH,
            &ProofKey::Log {
                tx_index: 0,
                log_index: 0,
            },
        );
        assert_ne!(a, s);
        assert_ne!(a, l);
        assert_ne!(s, l);
    }

    #[test]
    fn proof_type_numbers_are_pinned() {
        assert_eq!(ProofKey::Account { address: ADDR }.proof_type(), 1);
        assert_eq!(
            ProofKey::Storage {
                address: ADDR,
                slot: ZERO
            }
            .proof_type(),
            2
        );
        assert_eq!(
            ProofKey::Log {
                tx_index: 0,
                log_index: 0
            }
            .proof_type(),
            3
        );
    }
}
