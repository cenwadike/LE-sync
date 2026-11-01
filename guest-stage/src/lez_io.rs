//! The program input and output layout of LEZ v0.1.2, as far as cycle cost is concerned.
//!
//! WHY THIS EXISTS. A LEZ program does not read a `StageInput` and commit a `StageOutput`. The
//! platform (`nssa/src/program.rs`, `Program::write_inputs`) writes, in this order, with the
//! RISC Zero serde:
//!   1. the program id            `[u32; 8]`
//!   2. the caller's program id   `Option<[u32; 8]>`
//!   3. the input accounts        `Vec<AccountWithMetadata>`  (each account's data is a
//!                                `Data(Vec<u8>)`, read one element at a time)
//!   4. the instruction words     `Vec<u32>`, which the program then deserializes into its own
//!                                instruction type (`read_nssa_inputs`)
//! and the program ends with `ProgramOutput::write`, which commits ALL of: the instruction words,
//! every input account, every output account (`pre_states`, `post_states`), the chained calls and
//! the validity windows. So an account passed to a step is read once and committed twice (as a
//! pre state and as a post state), whether or not the step changes it.
//! (`nssa/core/src/program.rs`: `read_nssa_inputs`, `ProgramOutput`.)
//!
//! This file copies those shapes, with the same field order and the same `Data` visitor, from
//! the checkout `cf3639d8252040d13b3d4e933feb19b42c76e14a` (tag v0.1.2), so the bench measures
//! the real serialization work without depending on `nssa_core` (edition 2024, extra crates).
//! Where a field's exact type does not change its size it is simplified, and says so.
//!
//! It is shared by the guest (`lez_stage.rs`) and by the bench host (`#[path]` include), so
//! both sides agree by construction. It does NOT prove they agree with the platform: M2 must
//! run the real program through the real executor path and compare.
#![allow(dead_code)]

use le_sync_wire::rooted::{AbsentWire, RootedUpdate};
use le_sync_wire::UpdateWire;
use serde::{Deserialize, Serialize};

pub type ProgramId = [u32; 8];

/// `nssa_core::account::data::DATA_MAX_LENGTH` (100 KiB).
pub const DATA_MAX_LENGTH: usize = 100 * 1024;

/// An account's data. Serializes as a sequence of bytes, one serde element per byte, and
/// deserializes with the platform's visitor (a bound check per element), like `nssa_core`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct Data(Vec<u8>);

impl Data {
    /// `None` if `v` is longer than `DATA_MAX_LENGTH`.
    pub fn new(v: Vec<u8>) -> Option<Self> {
        (v.len() <= DATA_MAX_LENGTH).then_some(Self(v))
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DataVisitor;

        impl<'de> serde::de::Visitor<'de> for DataVisitor {
            type Value = Data;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a byte array of at most {DATA_MAX_LENGTH} bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(DATA_MAX_LENGTH));
                while let Some(value) = seq.next_element()? {
                    if vec.len() >= DATA_MAX_LENGTH {
                        return Err(serde::de::Error::custom("data too long"));
                    }
                    vec.push(value);
                }
                Ok(Data(vec))
            }
        }

        deserializer.deserialize_seq(DataVisitor)
    }
}

/// `nssa_core::account::Account`. The nonce is a `u128` on the wire.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub program_owner: ProgramId,
    pub balance: u128,
    pub data: Data,
    pub nonce: u128,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountId {
    pub value: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountWithMetadata {
    pub account: Account,
    pub is_authorized: bool,
    pub account_id: AccountId,
}

/// `claim` is `Option<Claim>` in the platform; `None` (what a step that claims nothing writes)
/// is one word either way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPostState {
    pub account: Account,
    pub claim: Option<u8>,
}

/// `ValidityWindow<u64>`: `from` and `to`, both `None` when unbounded.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidityWindow {
    pub from: Option<u64>,
    pub to: Option<u64>,
}

/// `nssa_core::program::ProgramOutput`. `chained_calls` is always empty here, and an empty
/// sequence is one word whatever its element type, so it is typed as bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramOutput {
    pub self_program_id: ProgramId,
    pub caller_program_id: Option<ProgramId>,
    pub instruction_data: Vec<u32>,
    pub pre_states: Vec<AccountWithMetadata>,
    pub post_states: Vec<AccountPostState>,
    pub chained_calls: Vec<u8>,
    pub block_validity_window: ValidityWindow,
    pub timestamp_validity_window: ValidityWindow,
}

/// What the staged steps take as the program's own instruction. The store and the job are not
/// in it: they are account data (`pre_states`).
///   Begin  : accounts [store, job slot (empty)]   Miller: [job]   Finish: [store, job]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LezOp {
    Begin { update: UpdateWire },
    Miller,
    Finish { update: UpdateWire },
}

impl LezOp {
    pub fn mode(&self) -> &'static str {
        match self {
            LezOp::Begin { .. } => "begin",
            LezOp::Miller => "miller",
            LezOp::Finish { .. } => "finish",
        }
    }
}

/// The rooted design's instruction (`lez_rooted.rs`): the same three steps over a store that
/// holds the committee as a root (`store_codec` v2). Begin carries the hints for the absent
/// keys; the committee's keys are not in the account and not in the update.
///   Begin  : accounts [store, job slot (empty)]   Miller: [job]   Finish: [store, job]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootedOp {
    Begin {
        update: RootedUpdate,
        absent: AbsentWire,
    },
    Miller,
    Finish {
        update: RootedUpdate,
    },
}

impl RootedOp {
    pub fn mode(&self) -> &'static str {
        match self {
            RootedOp::Begin { .. } => "begin",
            RootedOp::Miller => "miller",
            RootedOp::Finish { .. } => "finish",
        }
    }
}

/// A program-owned account holding `data`, as an input account (`tag` makes the id differ).
pub fn meta(tag: u8, data: Vec<u8>) -> AccountWithMetadata {
    AccountWithMetadata {
        account: Account {
            program_owner: [7; 8],
            balance: 0,
            data: Data::new(data).expect("account data within DATA_MAX_LENGTH"),
            nonce: 0,
        },
        is_authorized: false,
        account_id: AccountId { value: [tag; 32] },
    }
}

/// The post state of `like` with `data` in place of its data.
pub fn post(like: &AccountWithMetadata, data: Vec<u8>) -> AccountPostState {
    AccountPostState {
        account: Account {
            data: Data::new(data).expect("account data within DATA_MAX_LENGTH"),
            ..like.account.clone()
        },
        claim: None,
    }
}

/// Instruction of the `agg` measurement: the committee keys an update needs, each as the 96-byte
/// uncompressed point (the y-hint), their positions in the 512-leaf committee tree (ascending),
/// and the Merkle multiproof siblings (32 bytes each) that bind them to the stored root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggInput {
    pub keys: Vec<Vec<u8>>,
    pub index: Vec<u16>,
    pub proof: Vec<Vec<u8>>,
}

/// The same instruction with the bytes packed four to a `u32`. The platform serializes a
/// `Vec<u8>` as one serde element per byte, so the cost of an instruction is per element, not per
/// byte; four bytes per element should cost about a quarter. `keys` is 24 words per key, `proof`
/// 8 words per sibling (little-endian).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggPacked {
    pub keys: Vec<u32>,
    pub index: Vec<u16>,
    pub proof: Vec<u32>,
}

fn words_of(chunks: &[Vec<u8>]) -> Vec<u32> {
    chunks
        .iter()
        .flat_map(|c| c.chunks_exact(4))
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
        .collect()
}

fn chunks_of(words: &[u32], words_per_chunk: usize) -> Vec<Vec<u8>> {
    words
        .chunks_exact(words_per_chunk)
        .map(|c| c.iter().flat_map(|w| w.to_le_bytes()).collect())
        .collect()
}

impl AggPacked {
    /// Pack `i` (96-byte keys, 32-byte siblings).
    pub fn pack(i: &AggInput) -> Self {
        Self {
            keys: words_of(&i.keys),
            index: i.index.clone(),
            proof: words_of(&i.proof),
        }
    }

    /// The bytes form, or `None` if the word counts do not fit 96-byte keys and 32-byte siblings.
    pub fn unpack(&self) -> Option<AggInput> {
        if self.keys.len() % 24 != 0 || self.proof.len() % 8 != 0 {
            return None;
        }
        Some(AggInput {
            keys: chunks_of(&self.keys, 24),
            index: self.index.clone(),
            proof: chunks_of(&self.proof, 8),
        })
    }
}

/// What the `agg` program is sent: either form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggMsg {
    Bytes(AggInput),
    Packed(AggPacked),
}
