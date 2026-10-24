//! Guest input/output types and `verify`, the whole of what the zkVM guest executes
//! (bootstrap, finality branches, sync-update validation incl. BLS, chain-binding commitment,
//! and, Sprint 4, the execution anchor plus account/storage proofs under the finalized header).
//! Kept free of risc0 so it runs natively in tests; the guest is a 3-line wrapper.
//!
//! serde note: `[u8; 48]` has no serde impl, so pubkeys travel as one flat `Vec<u8>`.
pub mod bls;

use le_sync_core::exec::{verify_execution_anchor, ExecutionPayloadHeader};
use le_sync_core::state::{verify_account, verify_storage, Account, Address};
use le_sync_core::sync::{
    has_supermajority, initialize_light_client_store, process_light_client_update, Bls,
    ChainBinding, ForkSchedule, LightClientStore, LightClientUpdate, SyncCommittee, SyncConfig,
};
use le_sync_core::{
    is_branch_present, verify_bootstrap, verify_finality_branch, BeaconBlockHeader, BlsPubkey,
    Bytes32, ChainConfig, Error, ZERO,
};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WireHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: Bytes32,
    pub state_root: Bytes32,
    pub body_root: Bytes32,
}

impl From<&BeaconBlockHeader> for WireHeader {
    fn from(h: &BeaconBlockHeader) -> Self {
        Self {
            slot: h.slot,
            proposer_index: h.proposer_index,
            parent_root: h.parent_root,
            state_root: h.state_root,
            body_root: h.body_root,
        }
    }
}
impl From<&WireHeader> for BeaconBlockHeader {
    fn from(h: &WireHeader) -> Self {
        Self {
            slot: h.slot,
            proposer_index: h.proposer_index,
            parent_root: h.parent_root,
            state_root: h.state_root,
            body_root: h.body_root,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FinalityItem {
    pub attested: WireHeader,
    pub finalized: WireHeader,
    pub branch: Vec<Bytes32>,
}

/// One `LightClientUpdate` (or `finality_update`, which has no next committee).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdateWire {
    pub attested: WireHeader,
    /// `committee_size * 48` bytes, or empty when the update has no next committee.
    pub next_pubkeys: Vec<u8>,
    pub next_aggregate: Vec<u8>,
    /// Empty = no next committee branch.
    pub next_branch: Vec<Bytes32>,
    pub finalized: WireHeader,
    pub finality_branch: Vec<Bytes32>,
    pub bits: Vec<u8>,
    /// 96 bytes.
    pub signature: Vec<u8>,
    pub signature_slot: u64,
}

/// Sprint 2 section: full update validation incl. BLS.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SyncInput {
    /// Declared chain label (`DEPOSIT_CHAIN_ID`). NOT signed by anything: it is committed in
    /// the journal's chain binding, and only a verifier-side `check_chain_binding` against an
    /// expected binding gives it meaning.
    pub chain_id: u64,
    pub genesis_validators_root: Bytes32,
    pub epochs_per_period: u64,
    /// Ascending `(fork_epoch, fork_version)`, genesis first.
    pub forks: Vec<(u64, [u8; 4])>,
    /// Chosen by the host (guest has no clock). It is part of what the proof is about.
    pub current_slot: u64,
    pub updates: Vec<UpdateWire>,
}

/// `ExecutionPayloadHeader` on the wire (Deneb layout, 17 fields). `logs_bloom` (256 bytes) and
/// `extra_data` (at most 32 bytes) are `Vec`s because `[u8; N]` has no serde impl above 32.
/// `base_fee_per_gas` is the SSZ (little-endian) uint256 encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExecWire {
    pub parent_hash: Bytes32,
    pub fee_recipient: [u8; 20],
    pub state_root: Bytes32,
    pub receipts_root: Bytes32,
    pub logs_bloom: Vec<u8>,
    pub prev_randao: Bytes32,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub base_fee_per_gas: Bytes32,
    pub block_hash: Bytes32,
    pub transactions_root: Bytes32,
    pub withdrawals_root: Bytes32,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

impl ExecWire {
    /// `None` if `logs_bloom` is not 256 bytes or `extra_data` exceeds 32 bytes (not a valid
    /// header). The result is only a CLAIM: nothing in it is trusted until
    /// `verify_execution_anchor` has tied its root to the finalized beacon header.
    pub fn to_header(&self) -> Option<ExecutionPayloadHeader> {
        if self.logs_bloom.len() != le_sync_core::exec::BLOOM_LEN
            || self.extra_data.len() > le_sync_core::exec::MAX_EXTRA_DATA
        {
            return None;
        }
        let mut logs_bloom = [0u8; le_sync_core::exec::BLOOM_LEN];
        logs_bloom.copy_from_slice(&self.logs_bloom);
        let mut extra_data = [0u8; le_sync_core::exec::MAX_EXTRA_DATA];
        extra_data[..self.extra_data.len()].copy_from_slice(&self.extra_data);
        Some(ExecutionPayloadHeader {
            parent_hash: self.parent_hash,
            fee_recipient: self.fee_recipient,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            logs_bloom,
            prev_randao: self.prev_randao,
            block_number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data,
            extra_data_len: self.extra_data.len(),
            base_fee_per_gas: self.base_fee_per_gas,
            block_hash: self.block_hash,
            transactions_root: self.transactions_root,
            withdrawals_root: self.withdrawals_root,
            blob_gas_used: self.blob_gas_used,
            excess_blob_gas: self.excess_blob_gas,
        })
    }
}

impl From<&ExecutionPayloadHeader> for ExecWire {
    fn from(h: &ExecutionPayloadHeader) -> Self {
        Self {
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
}

/// Sprint 4 section: one account and one storage slot under the execution state root of the
/// store's FINAL finalized header. There is deliberately no `state_root` field: the root is
/// read out of `exec` only after `exec` has been proven (via `exec_branch`, gindex 25) to be the
/// execution payload header of that finalized beacon header. Requires a `sync` section.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StateInput {
    pub exec: ExecWire,
    pub exec_branch: Vec<Bytes32>,
    pub address: Address,
    /// 32-byte big-endian storage key.
    pub slot: Bytes32,
    /// `eth_getProof` `accountProof`: RLP nodes, root first.
    pub account_proof: Vec<Vec<u8>>,
    /// `eth_getProof` `storageProof[0].proof`: RLP nodes, root first.
    pub storage_proof: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GuestInput {
    pub slots_per_epoch: u64,
    pub electra_fork_epoch: u64,
    pub gloas_fork_epoch: Option<u64>,
    pub trusted_root: Bytes32,
    pub boot_header: WireHeader,
    /// `committee_size * 48` bytes, concatenated.
    pub pubkeys: Vec<u8>,
    /// 48 bytes.
    pub aggregate: Vec<u8>,
    pub boot_branch: Vec<Bytes32>,
    pub finality: Vec<FinalityItem>,
    pub sync: Option<SyncInput>,
    /// Sprint 4: account + storage inclusion under the final finalized header. Needs `sync`.
    pub state: Option<StateInput>,
}

/// Committed to the journal. The host trusts only this, not its own re-computation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GuestOutput {
    pub trusted_root: Bytes32,
    pub bootstrap_ok: bool,
    pub finality_pass: u32,
    pub finality_fail: u32,
    pub finality_skip: u32,
    /// Sprint 2: updates that passed `validate_light_client_update` (incl. BLS).
    pub sync_validated: u32,
    /// Older than the store (spec: not relevant) - not an attack, not counted as failure.
    pub sync_not_relevant: u32,
    /// Every update not counted as validated or not-relevant (includes `sync_below_threshold`).
    pub sync_rejected: u32,
    /// Subset of `sync_rejected`: participation below 2/3, rejected by the strict gate
    /// before any signature work. Project-defined (not an Altair spec error).
    pub sync_below_threshold: u32,
    pub finalized_slot: u64,
    pub finalized_root: Bytes32,
    /// Advances only from supermajority (>= 2/3) updates under the strict gate.
    pub optimistic_slot: u64,
    /// Chain identity, populated whenever the input had a `sync` section (even if bootstrap
    /// failed), zero otherwise. `chain_id` is a declared label; `genesis_validators_root` and
    /// the fork versions are the cryptographically bound parts (via the signing domain).
    pub chain_id: u64,
    pub genesis_validators_root: Bytes32,
    /// `ChainBinding::digest()` over chain id, gvr, fork-schedule hash and preset timing.
    /// Zero when there is no sync section or the fork schedule is malformed (fail closed).
    pub chain_binding: Bytes32,
    /// Sprint 4. `true` once a state section was evaluated against the store's final finalized
    /// header (needs a `sync` section whose bootstrap and setup succeeded). Every field below is
    /// zero / false unless `state_ok`: a failed state check commits nothing about the state.
    pub state_checked: bool,
    /// Anchor, account proof and storage proof all verified.
    pub state_ok: bool,
    /// `Error::code()` of the failing stage when `state_checked && !state_ok`, else 0.
    pub state_error_code: u16,
    /// Execution block the verified state belongs to (from the proven execution header).
    pub exec_block_number: u64,
    pub exec_block_hash: Bytes32,
    /// The state root the account proof was checked against. Derived in the guest, never input.
    pub exec_state_root: Bytes32,
    pub state_address: [u8; 20],
    pub state_slot: Bytes32,
    /// Big-endian slot value; zero for an absent slot (a verified zero) or an absent account.
    pub state_value: Bytes32,
    /// `false` = the account is proven absent from the state trie.
    pub account_present: bool,
    /// Big-endian wei balance of the account; zero when absent.
    pub account_balance: Bytes32,
}

impl GuestOutput {
    /// Sprint 1 rule. `tamper`: bootstrap + all branches must be rejected.
    pub fn success(&self, tamper: bool) -> bool {
        if tamper {
            !self.bootstrap_ok && self.finality_pass == 0 && self.finality_fail > 0
        } else {
            self.bootstrap_ok && self.finality_fail == 0 && self.finality_pass > 0
        }
    }

    /// Sprint 2 rule (only meaningful when the input had a `sync` section):
    /// normal run -> something validated, and the only rejections are below-threshold ones
    /// (a live finality update with < 2/3 participation is expected, not an attack);
    /// `expect_reject` (bad signature / other chain) -> nothing validated, something rejected.
    pub fn sync_success(&self, expect_reject: bool) -> bool {
        if expect_reject {
            self.sync_validated == 0 && self.sync_rejected > 0
        } else {
            self.sync_validated > 0 && self.sync_rejected == self.sync_below_threshold
        }
    }
}

/// Per-update verdict, for tests, the CLI dry run and anything that needs the typed error
/// code (Usability #2). NOT committed to the journal: the proof format is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    Validated,
    /// Older than the store (spec: not relevant).
    NotRelevant,
    /// Rejected with the typed error (`Error::code()` is the stable public code).
    Rejected(Error),
    /// The update's own bytes could not be parsed (bad signature length, bad next committee).
    Malformed,
    /// The run never reached this update: bootstrap or sync setup failed.
    SetupFailed(Error),
}

/// `verify`'s journal plus one `UpdateOutcome` per update, in input order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    pub output: GuestOutput,
    pub updates: Vec<UpdateOutcome>,
}

fn note(t: &mut Option<&mut Vec<UpdateOutcome>>, o: UpdateOutcome) {
    if let Some(v) = t.as_mut() {
        v.push(o);
    }
}

/// Build the chain binding from raw configuration. Used by `verify` to fill the journal and by
/// verifiers/hosts to build the binding they EXPECT, so both sides share one code path.
/// `Err(BadConfig)` if the fork schedule is malformed.
pub fn build_chain_binding(
    slots_per_epoch: u64,
    epochs_per_period: u64,
    chain_id: u64,
    genesis_validators_root: &Bytes32,
    forks: &[(u64, [u8; 4])],
) -> Result<ChainBinding, Error> {
    Ok(ChainBinding {
        chain_id,
        genesis_validators_root: *genesis_validators_root,
        fork_schedule_hash: ForkSchedule::new(forks)?.hash(),
        slots_per_epoch,
        epochs_per_period,
    })
}

/// Consumer-side chain check. Call it FIRST, before trusting anything else in the journal.
///
/// 1. The committed digest must equal the digest of the expected binding.
/// 2. The readable `chain_id` and `genesis_validators_root` must equal the expected ones, so
///    the plain fields cannot be forged against a correct digest (or vice versa).
///
/// Returns `Error::ChainMismatch` otherwise, including for a journal with no sync section
/// (zero binding). Limit: the guest cannot tell whether `chain_id` is the true label for the
/// gvr; that assurance exists only because the verifier supplies the expected binding.
pub fn check_chain_binding(out: &GuestOutput, expected: &ChainBinding) -> Result<(), Error> {
    expected.check_digest(&out.chain_binding)?;
    if out.chain_id != expected.chain_id
        || out.genesis_validators_root != expected.genesis_validators_root
    {
        return Err(Error::ChainMismatch);
    }
    Ok(())
}

/// Strict gate for the guest and host. Updates with participation below 2/3 are rejected as
/// `Error::BelowThreshold` BEFORE any other validation or BLS work, leaving the store
/// untouched (no optimistic move, no `best_valid_update`). `le_sync_core` stays spec-faithful
/// (the official vectors call it directly); only this wrapper is stricter.
///
/// Trade-off: rejection is classified by participation alone, so a sub-2/3 update that is also
/// stale, malformed or badly signed reports `BelowThreshold`, not its other defect.
pub fn process_update_strict<B: Bls>(
    store: &mut LightClientStore,
    update: &LightClientUpdate,
    current_slot: u64,
    cfg: &SyncConfig,
    bls: &B,
) -> Result<(), Error> {
    if !has_supermajority(update.sync_committee_bits) {
        return Err(Error::BelowThreshold);
    }
    process_light_client_update(store, update, current_slot, cfg, bls)
}

#[inline(always)]
fn cc() -> u64 {
    #[cfg(feature = "cycle-trace")]
    {
        risc0_zkvm::guest::env::cycle_count()
    }
    #[cfg(not(feature = "cycle-trace"))]
    {
        0
    }
}

#[allow(unused_variables)]
fn log(s: &str) {
    #[cfg(feature = "cycle-trace")]
    risc0_zkvm::guest::env::log(s);
}

fn pubkeys(flat: &[u8]) -> Option<Vec<BlsPubkey>> {
    if flat.is_empty() || flat.len() % 48 != 0 {
        return None;
    }
    Some(flat.chunks(48).map(|c| c.try_into().unwrap()).collect())
}

fn committee_from(flat: &[u8], agg: &[u8], size: usize) -> Option<SyncCommittee> {
    if flat.is_empty() && agg.is_empty() {
        return Some(SyncCommittee::empty(size));
    }
    let keys = pubkeys(flat)?;
    SyncCommittee::new(&keys, agg.try_into().ok()?).ok()
}

fn run_sync<B: Bls>(
    i: &GuestInput,
    s: &SyncInput,
    cfg: ChainConfig,
    bls: &B,
    out: &mut GuestOutput,
    mut trace: Option<&mut Vec<UpdateOutcome>>,
) -> Option<BeaconBlockHeader> {
    let ta = cc();
    let n_updates = s.updates.len() as u32;
    let header = BeaconBlockHeader::from(&i.boot_header);
    let setup = (|| -> Result<_, Error> {
        let forks = ForkSchedule::new(&s.forks)?;
        // The size argument only matters when both the keys and the aggregate are empty, and
        // `verify` has already rejected such a bootstrap before `run_sync` is reached.
        let c = committee_from(&i.pubkeys, &i.aggregate, 0).ok_or(Error::BadSyncCommitteeSize)?;
        Ok((forks, c))
    })();
    let (forks, committee) = match setup {
        Ok(v) => v,
        Err(e) => {
            out.sync_rejected = n_updates;
            for _ in &s.updates {
                note(&mut trace, UpdateOutcome::SetupFailed(e));
            }
            return None;
        }
    };
    let tb = cc();
    let size = committee.len;
    let scfg = SyncConfig {
        chain: cfg,
        epochs_per_period: s.epochs_per_period,
        genesis_validators_root: s.genesis_validators_root,
        forks,
    };
    let mut store = match initialize_light_client_store(
        &scfg,
        &i.trusted_root,
        &header,
        committee,
        &i.boot_branch,
    ) {
        Ok(st) => st,
        Err(e) => {
            out.sync_rejected = n_updates;
            for _ in &s.updates {
                note(&mut trace, UpdateOutcome::SetupFailed(e));
            }
            return None;
        }
    };
    let tc = cc();

    for u in &s.updates {
        let parsed = (|| {
            let next = committee_from(&u.next_pubkeys, &u.next_aggregate, size)?;
            let sig: [u8; 96] = u.signature.as_slice().try_into().ok()?;
            Some((next, sig))
        })();
        let Some((next, sig)) = parsed else {
            out.sync_rejected += 1;
            note(&mut trace, UpdateOutcome::Malformed);
            continue;
        };
        let zeros6;
        let next_branch: &[Bytes32] = if u.next_branch.is_empty() {
            zeros6 = [ZERO; 6];
            &zeros6
        } else {
            &u.next_branch
        };
        let lcu = LightClientUpdate {
            attested_header: (&u.attested).into(),
            next_sync_committee: &next,
            next_sync_committee_branch: next_branch,
            finalized_header: (&u.finalized).into(),
            finality_branch: &u.finality_branch,
            sync_committee_bits: &u.bits,
            sync_committee_signature: sig,
            signature_slot: u.signature_slot,
        };
        match process_update_strict(&mut store, &lcu, s.current_slot, &scfg, bls) {
            Ok(()) => {
                out.sync_validated += 1;
                note(&mut trace, UpdateOutcome::Validated);
            }
            Err(Error::UpdateNotRelevant) => {
                out.sync_not_relevant += 1;
                note(&mut trace, UpdateOutcome::NotRelevant);
            }
            Err(Error::BelowThreshold) => {
                out.sync_rejected += 1;
                out.sync_below_threshold += 1;
                note(&mut trace, UpdateOutcome::Rejected(Error::BelowThreshold));
            }
            Err(e) => {
                out.sync_rejected += 1;
                note(&mut trace, UpdateOutcome::Rejected(e));
            }
        }
    }
    let td = cc();
    out.finalized_slot = store.finalized_header.slot;
    out.finalized_root = store.finalized_header.hash_tree_root();
    out.optimistic_slot = store.optimistic_header.slot;
    log(&format!(
        "run_sync cycles: setup={} init_store={} updates_loop={} (includes BLS)",
        tb - ta,
        tc - tb,
        td - tc
    ));
    // The state section anchors to exactly this header: it is the store's trusted head.
    Some(store.finalized_header)
}

/// Sprint 4: the execution anchor, then the account proof, then the storage proof, all under
/// `finalized` (the store's final finalized header, already trusted by the sync run).
///
/// Fail closed: on any error only `state_checked` and `state_error_code` are set. On success the
/// committed values come from the verified header and the verified tries, never from the input
/// (the input's `address` and `slot` are echoed because the proofs verified exactly those keys).
fn verify_state_section(
    cfg: &ChainConfig,
    finalized: &BeaconBlockHeader,
    st: &StateInput,
    out: &mut GuestOutput,
) {
    out.state_checked = true;
    let t0 = cc();
    let run = || -> Result<_, Error> {
        // A malformed header cannot hash to anything the beacon header vouches for.
        let exec = st.exec.to_header().ok_or(Error::InvalidBranch)?;
        let state_root = verify_execution_anchor(cfg, finalized, &exec, &st.exec_branch)?;
        let t1 = cc();
        let acct = verify_account(&state_root, &st.address, &st.account_proof)?;
        let t2 = cc();
        // Same semantics as `le_sync_core::state::verify_state` (a test pins the equivalence);
        // split here only so each proof gets its own cycle marker.
        let (account, present, value) = match acct {
            None => (Account::ABSENT, false, ZERO),
            Some(a) => {
                let v = verify_storage(&a.storage_root, &st.slot, &st.storage_proof)?;
                (a, true, v)
            }
        };
        let t3 = cc();
        log(&format!(
            "state cycles: anchor={} account_proof={} storage_proof={}",
            t1 - t0,
            t2 - t1,
            t3 - t2
        ));
        Ok((exec, state_root, account, present, value))
    };
    match run() {
        Ok((exec, state_root, account, present, value)) => {
            out.state_ok = true;
            out.exec_block_number = exec.block_number;
            out.exec_block_hash = exec.block_hash;
            out.exec_state_root = state_root;
            out.state_address = st.address;
            out.state_slot = st.slot;
            out.state_value = value;
            out.account_present = present;
            out.account_balance = account.balance;
        }
        Err(e) => out.state_error_code = e.code(),
    }
}

/// Never panics on malformed input: it just reports `bootstrap_ok = false` / rejections.
/// This is the guest's entry point; the journal it returns is exactly what gets committed.
pub fn verify<B: Bls>(i: &GuestInput, bls: &B) -> GuestOutput {
    verify_inner(i, bls, None)
}

/// Same run as `verify` (identical `output`), plus the typed per-update verdicts. Host/test
/// side only: the guest calls `verify`, so the journal format and cycle profile are unchanged.
pub fn verify_trace<B: Bls>(i: &GuestInput, bls: &B) -> Trace {
    let mut updates = Vec::new();
    let output = verify_inner(i, bls, Some(&mut updates));
    Trace { output, updates }
}

fn verify_inner<B: Bls>(
    i: &GuestInput,
    bls: &B,
    mut trace: Option<&mut Vec<UpdateOutcome>>,
) -> GuestOutput {
    let cfg = ChainConfig {
        slots_per_epoch: i.slots_per_epoch,
        electra_fork_epoch: i.electra_fork_epoch,
        gloas_fork_epoch: i.gloas_fork_epoch,
    };
    let mut out = GuestOutput {
        trusted_root: i.trusted_root,
        ..Default::default()
    };
    // Chain identity first, so even a run whose bootstrap fails states which chain it was about.
    if let Some(s) = &i.sync {
        out.chain_id = s.chain_id;
        out.genesis_validators_root = s.genesis_validators_root;
        if let Ok(b) = build_chain_binding(
            i.slots_per_epoch,
            s.epochs_per_period,
            s.chain_id,
            &s.genesis_validators_root,
            &s.forks,
        ) {
            out.chain_binding = b.digest();
        }
    }
    let header = BeaconBlockHeader::from(&i.boot_header);
    let agg: Option<BlsPubkey> = i.aggregate.as_slice().try_into().ok();
    let t0 = cc();
    let boot: Result<(), Error> = match (pubkeys(&i.pubkeys), agg) {
        (Some(keys), Some(agg)) => {
            verify_bootstrap(&cfg, &i.trusted_root, &header, &keys, &agg, &i.boot_branch)
        }
        (None, _) => Err(Error::BadSyncCommitteeSize),
        (_, None) => Err(Error::BadConfig),
    };
    out.bootstrap_ok = boot.is_ok();
    let t1 = cc();
    // Spec: no further trust in anything if the anchor is not the trusted root.
    if let Err(e) = boot {
        out.finality_fail = i.finality.len() as u32;
        if let Some(s) = &i.sync {
            out.sync_rejected = s.updates.len() as u32;
            for _ in &s.updates {
                note(&mut trace, UpdateOutcome::SetupFailed(e));
            }
        }
        return out;
    }

    for f in &i.finality {
        if !is_branch_present(&f.branch) {
            out.finality_skip += 1;
            continue;
        }
        let r = verify_finality_branch(
            &cfg,
            &(&f.attested).into(),
            &(&f.finalized).into(),
            &f.branch,
        );
        if r.is_ok() {
            out.finality_pass += 1;
        } else {
            out.finality_fail += 1;
        }
    }
    let t2 = cc();
    log(&format!(
        "verify cycles: bootstrap={} finality={}",
        t1 - t0,
        t2 - t1
    ));
    if let Some(s) = &i.sync {
        let final_header = run_sync(i, s, cfg, bls, &mut out, trace);
        // Sprint 4. Only against the store's final finalized header; if the sync setup failed
        // there is no such header and the state section is not evaluated (`state_checked` stays
        // false), so nothing about the state is committed.
        if let (Some(st), Some(fh)) = (&i.state, final_header) {
            verify_state_section(&cfg, &fh, st, &mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use le_sync_core::{hash_pair, sync::Version, sync_committee_root, ZERO};

    const N: usize = 32;
    const GVR: Bytes32 = [0xAA; 32];
    const FV: Version = [5, 0, 0, 1];
    const CHAIN_ID: u64 = 1;

    /// Accepts iff the signature starts with 7 and the signing root is the one for `GVR`/`FV`.
    struct Mock;
    impl Bls for Mock {
        fn fast_aggregate_verify(
            &self,
            c: &[BlsPubkey],
            _agg: &BlsPubkey,
            bits: &[u8],
            root: &Bytes32,
            sig: &le_sync_core::sync::BlsSignature,
        ) -> bool {
            assert_eq!(c.len(), bits.len() * 8);
            let want = le_sync_core::sync::compute_signing_root(
                &Mock::att_root(),
                &le_sync_core::sync::compute_domain(
                    le_sync_core::sync::DOMAIN_SYNC_COMMITTEE,
                    FV,
                    &GVR,
                ),
            );
            sig[0] == 7 && *root == want
        }
    }
    impl Mock {
        fn att_root() -> Bytes32 {
            BeaconBlockHeader::from(&fixture().finality[0].attested).hash_tree_root()
        }
    }
    fn leaf(i: u8) -> Bytes32 {
        hash_pair(&[i; 32], &ZERO)
    }
    fn root_and_branch(mut leaves: Vec<Bytes32>, mut i: usize) -> (Bytes32, Vec<Bytes32>) {
        let mut br = vec![];
        while leaves.len() > 1 {
            br.push(leaves[i ^ 1]);
            leaves = leaves.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
            i /= 2;
        }
        (leaves[0], br)
    }
    fn hdr(slot: u64, state_root: Bytes32) -> WireHeader {
        WireHeader {
            slot,
            proposer_index: 1,
            parent_root: leaf(1),
            state_root,
            body_root: leaf(2),
        }
    }
    fn fixture() -> GuestInput {
        fixture_seeded(0)
    }
    /// `seed` changes the committee keys (and so the bootstrap state root and trusted root);
    /// seed 0 is the honest fixture.
    fn fixture_seeded(seed: u8) -> GuestInput {
        fixture_with_body(seed, leaf(2))
    }
    /// `fin_body`: body root of the finalized header (the execution anchor hangs off it).
    fn fixture_with_body(seed: u8, fin_body: Bytes32) -> GuestInput {
        let keys: Vec<BlsPubkey> = (0..N)
            .map(|i| {
                let mut k = [0u8; 48];
                k[0] = i as u8 + 1;
                k[1] = seed;
                k
            })
            .collect();
        let agg = [9u8; 48];
        let mut f: Vec<Bytes32> = (0..64).map(|i| leaf(100 + i as u8)).collect();
        f[22] = sync_committee_root(&keys, &agg).unwrap();
        let (sroot, boot_branch) = root_and_branch(f, 22);
        let boot = hdr(8, sroot);
        let boot_root = BeaconBlockHeader::from(&boot).hash_tree_root();

        let mut fin = hdr(24, leaf(9));
        fin.body_root = fin_body;
        let epoch_chunk = leaf(77);
        let mut g: Vec<Bytes32> = (0..64).map(|i| leaf(150 + i as u8)).collect();
        g[20] = hash_pair(
            &epoch_chunk,
            &BeaconBlockHeader::from(&fin).hash_tree_root(),
        );
        let (aroot, mut fb) = root_and_branch(g, 20);
        fb.insert(0, epoch_chunk);
        GuestInput {
            slots_per_epoch: 8,
            electra_fork_epoch: 0,
            gloas_fork_epoch: None,
            trusted_root: boot_root,
            boot_header: boot,
            pubkeys: keys.concat(),
            aggregate: agg.to_vec(),
            boot_branch,
            finality: vec![
                FinalityItem {
                    attested: hdr(40, aroot),
                    finalized: fin.clone(),
                    branch: fb.clone(),
                },
                FinalityItem {
                    attested: hdr(40, aroot),
                    finalized: hdr(0, ZERO),
                    branch: vec![ZERO; 7],
                },
            ],
            sync: None,
            state: None,
        }
    }

    /// Adds one finality-only update (no next committee) at slots 40/41 signed (per Mock) by sig[0]==7.
    fn with_sync(mut i: GuestInput) -> GuestInput {
        let f = i.finality[0].clone();
        i.sync = Some(SyncInput {
            chain_id: CHAIN_ID,
            genesis_validators_root: GVR,
            epochs_per_period: 8,
            forks: vec![(0, FV)],
            current_slot: 41,
            updates: vec![UpdateWire {
                attested: f.attested,
                next_pubkeys: vec![],
                next_aggregate: vec![],
                next_branch: vec![],
                finalized: f.finalized,
                finality_branch: f.branch,
                bits: vec![0xFF; N / 8],
                signature: vec![7; 96],
                signature_slot: 41,
            }],
        });
        i
    }

    #[test]
    fn valid_input_passes_and_empty_branch_is_skipped() {
        let o = verify(&fixture(), &Mock);
        assert_eq!(
            (
                o.bootstrap_ok,
                o.finality_pass,
                o.finality_fail,
                o.finality_skip
            ),
            (true, 1, 0, 1)
        );
        assert!(o.success(false));
    }

    #[test]
    fn tampered_input_is_rejected_everywhere() {
        let mut i = fixture();
        i.boot_branch[0][0] ^= 1;
        let o = verify(&i, &Mock);
        assert!(!o.bootstrap_ok && o.finality_pass == 0 && o.finality_fail == 2);
        assert!(o.success(true));

        let mut i = fixture();
        i.finality[0].branch[6][0] ^= 1;
        let o = verify(&i, &Mock);
        assert!(o.bootstrap_ok && o.finality_fail == 1 && !o.success(false));
    }

    #[test]
    fn wrong_trusted_root_and_malformed_keys_do_not_panic() {
        let mut i = fixture();
        i.trusted_root = [0; 32];
        assert!(!verify(&i, &Mock).bootstrap_ok);
        let mut i = fixture();
        i.pubkeys.pop();
        assert!(!verify(&i, &Mock).bootstrap_ok);
        let mut i = fixture();
        i.aggregate.clear();
        assert!(!verify(&i, &Mock).bootstrap_ok);
    }

    #[test]
    fn sync_valid_applies_and_reports_store() {
        let o = verify(&with_sync(fixture()), &Mock);
        assert_eq!(
            (o.sync_validated, o.sync_rejected, o.sync_not_relevant),
            (1, 0, 0),
            "{o:?}"
        );
        assert_eq!((o.finalized_slot, o.optimistic_slot), (24, 40));
        assert!(o.sync_success(false));
    }

    #[test]
    fn sync_bad_signature_and_other_chain_are_rejected() {
        let mut i = with_sync(fixture());
        i.sync.as_mut().unwrap().updates[0].signature[0] ^= 1;
        let o = verify(&i, &Mock);
        assert_eq!((o.sync_validated, o.sync_rejected), (0, 1));
        assert!(o.sync_success(true) && !o.sync_success(false));

        let mut i = with_sync(fixture());
        i.sync.as_mut().unwrap().genesis_validators_root = [0xBB; 32];
        let o = verify(&i, &Mock);
        assert_eq!((o.sync_validated, o.sync_rejected), (0, 1));
    }

    #[test]
    fn sync_old_update_is_not_relevant_not_rejected() {
        let mut i = with_sync(fixture());
        let u = &mut i.sync.as_mut().unwrap().updates[0];
        u.attested.slot = 8;
        u.finalized = hdr(0, ZERO);
        u.finality_branch = vec![ZERO; 7];
        let o = verify(&i, &Mock);
        assert_eq!((o.sync_not_relevant, o.sync_rejected), (1, 0), "{o:?}");
    }

    #[test]
    fn sync_not_run_when_bootstrap_fails() {
        let mut i = with_sync(fixture());
        i.trusted_root = [0; 32];
        let o = verify(&i, &Mock);
        assert_eq!((o.sync_validated, o.sync_rejected), (0, 1));
    }

    #[test]
    fn fabricated_bootstrap_rejected() {
        let honest = with_sync(fixture());
        let attacker = fixture_seeded(1);
        let mut i = honest.clone();
        i.boot_header = attacker.boot_header.clone();
        i.pubkeys = attacker.pubkeys.clone();
        i.aggregate = attacker.aggregate.clone();
        i.boot_branch = attacker.boot_branch.clone();
        assert_eq!(
            i.trusted_root, honest.trusted_root,
            "trusted root is unchanged"
        );

        let own = verify_bootstrap(
            &ChainConfig {
                slots_per_epoch: 8,
                electra_fork_epoch: 0,
                gloas_fork_epoch: None,
            },
            &attacker.trusted_root,
            &(&i.boot_header).into(),
            &pubkeys(&i.pubkeys).unwrap(),
            &i.aggregate.as_slice().try_into().unwrap(),
            &i.boot_branch,
        );
        assert_eq!(own, Ok(()));

        let o = verify(&i, &Mock);
        assert!(!o.bootstrap_ok);
        assert_eq!((o.sync_validated, o.sync_rejected), (0, 1));
        assert_eq!((o.finalized_slot, o.finalized_root), (0, ZERO));
        assert_eq!(o.trusted_root, honest.trusted_root);
    }

    struct Counting(std::cell::Cell<u32>);
    impl Bls for Counting {
        fn fast_aggregate_verify(
            &self,
            c: &[BlsPubkey],
            a: &BlsPubkey,
            bits: &[u8],
            root: &Bytes32,
            sig: &le_sync_core::sync::BlsSignature,
        ) -> bool {
            self.0.set(self.0.get() + 1);
            Mock.fast_aggregate_verify(c, a, bits, root, sig)
        }
    }

    fn low_bits() -> Vec<u8> {
        vec![0xFF, 0x0F, 0x00, 0x00] // 12 of 32 set
    }

    #[test]
    fn below_threshold_rejected_and_store_untouched() {
        let mut i = with_sync(fixture());
        i.sync.as_mut().unwrap().updates[0].bits = low_bits();
        let bls = Counting(Default::default());
        let o = verify(&i, &bls);
        assert_eq!(
            (o.sync_validated, o.sync_rejected, o.sync_below_threshold),
            (0, 1, 1),
            "{o:?}"
        );
        assert_eq!(bls.0.get(), 0, "no pairing work for a sub-2/3 update");
        assert_eq!(o.finalized_root, i.trusted_root);
        assert_eq!((o.finalized_slot, o.optimistic_slot), (8, 8));
        assert!(o.sync_success(true) && !o.sync_success(false));
    }

    #[test]
    fn exactly_two_thirds_is_not_below_threshold() {
        let mut i = with_sync(fixture());
        i.sync.as_mut().unwrap().updates[0].bits = vec![0xFF, 0xFF, 0x3F, 0x00];
        let o = verify(&i, &Mock);
        assert_eq!((o.sync_validated, o.sync_below_threshold), (1, 0), "{o:?}");
    }

    #[test]
    fn sync_success_tolerates_only_below_threshold_rejections() {
        let mut i = with_sync(fixture());
        let mut low = i.sync.as_ref().unwrap().updates[0].clone();
        low.bits = low_bits();
        i.sync.as_mut().unwrap().updates.push(low);
        let o = verify(&i, &Mock);
        assert_eq!(
            (o.sync_validated, o.sync_rejected, o.sync_below_threshold),
            (1, 1, 1)
        );
        assert!(
            o.sync_success(false),
            "below-threshold alone is not a failure"
        );
        assert!(!o.sync_success(true));

        let mut i = with_sync(fixture());
        let mut bad = i.sync.as_ref().unwrap().updates[0].clone();
        bad.signature[0] ^= 1;
        i.sync.as_mut().unwrap().updates.push(bad);
        let o = verify(&i, &Mock);
        assert_eq!(
            (o.sync_validated, o.sync_rejected, o.sync_below_threshold),
            (1, 1, 0)
        );
        assert!(!o.sync_success(false));
    }

    fn expected_binding(chain_id: u64, gvr: &Bytes32) -> ChainBinding {
        build_chain_binding(8, 8, chain_id, gvr, &[(0, FV)]).unwrap()
    }

    #[test]
    fn journal_commits_chain_config() {
        let i = with_sync(fixture());
        let o = verify(&i, &Mock);
        let s = i.sync.as_ref().unwrap();
        assert_eq!(o.chain_id, s.chain_id);
        assert_eq!(o.genesis_validators_root, s.genesis_validators_root);
        assert_eq!(o.chain_binding, expected_binding(CHAIN_ID, &GVR).digest());
        assert_ne!(o.chain_binding, ZERO);

        let mut bad = i.clone();
        bad.trusted_root = [0; 32];
        let ob = verify(&bad, &Mock);
        assert!(!ob.bootstrap_ok);
        assert_eq!(ob.chain_binding, o.chain_binding);

        let n = verify(&fixture(), &Mock);
        assert_eq!(
            (n.chain_id, n.genesis_validators_root, n.chain_binding),
            (0, ZERO, ZERO)
        );

        let mut mf = i.clone();
        mf.sync.as_mut().unwrap().forks = vec![];
        let om = verify(&mf, &Mock);
        assert_eq!((om.chain_id, om.chain_binding), (CHAIN_ID, ZERO));
        assert_eq!((om.sync_validated, om.sync_rejected), (0, 1));
    }

    #[test]
    fn journals_differ_when_only_gvr_differs() {
        let a = with_sync(fixture());
        let mut b = a.clone();
        b.sync.as_mut().unwrap().genesis_validators_root = [0xBB; 32];
        let (oa, ob) = (verify(&a, &Mock), verify(&b, &Mock));
        assert_ne!(oa, ob);
        assert_ne!(oa.chain_binding, ob.chain_binding);
        assert_ne!(oa.genesis_validators_root, ob.genesis_validators_root);
    }

    #[test]
    fn verify_is_deterministic() {
        let i = with_sync(fixture());
        let (a, b) = (verify(&i, &Mock), verify(&i, &Mock));
        assert_eq!(a, b);
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    #[test]
    fn check_chain_binding_accepts_match() {
        let o = verify(&with_sync(fixture()), &Mock);
        assert_eq!(
            check_chain_binding(&o, &expected_binding(CHAIN_ID, &GVR)),
            Ok(())
        );
    }

    #[test]
    fn check_chain_binding_rejects_wrong_chain_id() {
        let o = verify(&with_sync(fixture()), &Mock);
        assert_eq!(
            check_chain_binding(&o, &expected_binding(CHAIN_ID + 1, &GVR)),
            Err(Error::ChainMismatch)
        );
    }

    #[test]
    fn check_chain_binding_rejects_wrong_gvr() {
        let o = verify(&with_sync(fixture()), &Mock);
        assert_eq!(
            check_chain_binding(&o, &expected_binding(CHAIN_ID, &[0xBB; 32])),
            Err(Error::ChainMismatch)
        );
    }

    #[test]
    fn check_chain_binding_rejects_other_fork_schedule_and_preset() {
        let o = verify(&with_sync(fixture()), &Mock);
        let other_fork = build_chain_binding(8, 8, CHAIN_ID, &GVR, &[(0, [6, 0, 0, 1])]).unwrap();
        assert_eq!(
            check_chain_binding(&o, &other_fork),
            Err(Error::ChainMismatch)
        );
        let other_preset = build_chain_binding(32, 256, CHAIN_ID, &GVR, &[(0, FV)]).unwrap();
        assert_eq!(
            check_chain_binding(&o, &other_preset),
            Err(Error::ChainMismatch)
        );
    }

    #[test]
    fn check_chain_binding_rejects_readable_fields_forged_against_digest() {
        let exp = expected_binding(CHAIN_ID, &GVR);
        let other = verify(&with_sync(fixture()), &Mock);
        let mut forged = GuestOutput {
            chain_binding: expected_binding(CHAIN_ID + 1, &GVR).digest(),
            ..other.clone()
        };
        forged.chain_id = CHAIN_ID;
        assert_eq!(
            check_chain_binding(&forged, &exp),
            Err(Error::ChainMismatch)
        );
        let mut tampered = other.clone();
        tampered.chain_id = 999;
        assert_eq!(
            check_chain_binding(&tampered, &exp),
            Err(Error::ChainMismatch)
        );
        let mut tampered = other;
        tampered.genesis_validators_root = [0xCC; 32];
        assert_eq!(
            check_chain_binding(&tampered, &exp),
            Err(Error::ChainMismatch)
        );
    }

    #[test]
    fn check_chain_binding_rejects_journal_without_sync_section() {
        let o = verify(&fixture(), &Mock);
        assert_eq!(
            check_chain_binding(&o, &expected_binding(CHAIN_ID, &GVR)),
            Err(Error::ChainMismatch)
        );
    }

    #[test]
    fn mislabeled_chain_id_passes_guest_but_fails_consumer_check() {
        let mut i = with_sync(fixture());
        i.sync.as_mut().unwrap().chain_id = 999;
        let o = verify(&i, &Mock);
        assert_eq!(
            (o.sync_validated, o.sync_rejected),
            (1, 0),
            "guest accepts: {o:?}"
        );
        assert!(o.sync_success(false));
        assert_eq!(
            check_chain_binding(&o, &expected_binding(CHAIN_ID, &GVR)),
            Err(Error::ChainMismatch),
            "consumer expecting chain 1 rejects the mislabel"
        );
        assert_eq!(
            check_chain_binding(&o, &expected_binding(999, &GVR)),
            Ok(())
        );
    }

    // ---- success / sync_success matrix (cargo-mutants hardening) ----------------------------

    fn go(
        bootstrap_ok: bool,
        finality_pass: u32,
        finality_fail: u32,
        sync_validated: u32,
        sync_rejected: u32,
        sync_below_threshold: u32,
    ) -> GuestOutput {
        GuestOutput {
            bootstrap_ok,
            finality_pass,
            finality_fail,
            sync_validated,
            sync_rejected,
            sync_below_threshold,
            ..Default::default()
        }
    }

    #[test]
    fn success_non_tamper_requires_all_three_conjuncts() {
        assert!(go(true, 1, 0, 0, 0, 0).success(false));
        assert!(!go(false, 1, 0, 0, 0, 0).success(false));
        assert!(!go(true, 0, 0, 0, 0, 0).success(false));
        assert!(!go(true, 1, 1, 0, 0, 0).success(false));
        assert!(!go(true, 2, 1, 0, 0, 0).success(false));
    }

    #[test]
    fn success_tamper_requires_all_three_conjuncts() {
        assert!(go(false, 0, 1, 0, 0, 0).success(true));
        assert!(!go(true, 0, 1, 0, 0, 0).success(true));
        assert!(!go(false, 1, 1, 0, 0, 0).success(true));
        assert!(!go(false, 0, 0, 0, 0, 0).success(true));
        assert!(go(false, 0, 3, 0, 0, 0).success(true));
    }

    #[test]
    fn success_tamper_flag_selects_opposite_rules() {
        let good_normal = go(true, 1, 0, 0, 0, 0);
        let good_tamper = go(false, 0, 1, 0, 0, 0);
        assert!(good_normal.success(false));
        assert!(!good_normal.success(true));
        assert!(good_tamper.success(true));
        assert!(!good_tamper.success(false));
    }

    #[test]
    fn sync_success_normal_requires_validated_and_only_below_threshold_rejects() {
        assert!(go(true, 1, 0, 1, 0, 0).sync_success(false));
        assert!(go(true, 1, 0, 2, 1, 1).sync_success(false));
        assert!(!go(true, 1, 0, 0, 0, 0).sync_success(false));
        assert!(!go(true, 1, 0, 1, 1, 0).sync_success(false));
        assert!(!go(true, 1, 0, 1, 2, 1).sync_success(false));
        assert!(!go(true, 1, 0, 0, 1, 1).sync_success(false));
    }

    #[test]
    fn sync_success_expect_reject_requires_zero_validated_and_some_rejected() {
        assert!(go(true, 1, 0, 0, 1, 0).sync_success(true));
        assert!(go(true, 1, 0, 0, 1, 1).sync_success(true));
        assert!(!go(true, 1, 0, 1, 1, 0).sync_success(true));
        assert!(!go(true, 1, 0, 0, 0, 0).sync_success(true));
        assert!(!go(true, 1, 0, 1, 0, 0).sync_success(true));
    }

    #[test]
    fn sync_success_flag_selects_opposite_rules() {
        let normal_ok = go(true, 1, 0, 1, 0, 0);
        let reject_ok = go(true, 1, 0, 0, 1, 0);
        assert!(normal_ok.sync_success(false));
        assert!(!normal_ok.sync_success(true));
        assert!(reject_ok.sync_success(true));
        assert!(!reject_ok.sync_success(false));
    }

    #[test]
    fn sync_success_is_independent_of_sprint1_fields() {
        // Mutants that mix success() and sync_success() die here.
        let sprint1_fail = go(false, 0, 0, 1, 0, 0);
        assert!(!sprint1_fail.success(false));
        assert!(sprint1_fail.sync_success(false));

        let sprint1_ok = go(true, 1, 0, 0, 1, 0);
        assert!(sprint1_ok.success(false));
        assert!(sprint1_ok.sync_success(true));
        assert!(!sprint1_ok.sync_success(false));
    }

    // ---- Phase C: committee_from, parse failures, verify_trace -------------------------------

    #[test]
    fn committee_from_requires_both_or_neither() {
        let k = vec![7u8; 48 * 2];
        let a = [9u8; 48];
        // neither: an empty committee of the requested size
        let e = committee_from(&[], &[], 8).unwrap();
        assert_eq!(e.len, 8);
        // aggregate alone, or keys alone, is malformed (kills `&&` -> `||`)
        assert!(committee_from(&[], &a, 8).is_none());
        assert!(committee_from(&k, &[], 8).is_none());
        // both present
        assert_eq!(committee_from(&k, &a, 8).unwrap().len, 2);
        // wrong lengths
        assert!(committee_from(&k[..47], &a, 8).is_none());
        assert!(committee_from(&k, &a[..47], 8).is_none());
    }

    #[test]
    fn malformed_signature_is_counted_per_update_and_traced() {
        let mut i = with_sync(fixture());
        let good = i.sync.as_ref().unwrap().updates[0].clone();
        let mut short = good.clone();
        short.signature.truncate(95);
        i.sync.as_mut().unwrap().updates = vec![short.clone(), good, short];
        let t = verify_trace(&i, &Mock);
        assert_eq!((t.output.sync_validated, t.output.sync_rejected), (1, 2));
        assert_eq!(
            t.updates,
            vec![
                UpdateOutcome::Malformed,
                UpdateOutcome::Validated,
                UpdateOutcome::Malformed
            ]
        );
    }

    #[test]
    fn verify_trace_reports_a_typed_outcome_per_update() {
        let mut i = with_sync(fixture());
        let valid = i.sync.as_ref().unwrap().updates[0].clone();
        let mut bad_sig = valid.clone();
        bad_sig.signature[0] ^= 1;
        let mut low = valid.clone();
        low.bits = low_bits();
        let mut old = valid.clone();
        old.attested.slot = 8;
        old.finalized = hdr(0, ZERO);
        old.finality_branch = vec![ZERO; 7];
        i.sync.as_mut().unwrap().updates = vec![valid, bad_sig, low, old];
        let t = verify_trace(&i, &Mock);
        assert_eq!(
            t.updates,
            vec![
                UpdateOutcome::Validated,
                UpdateOutcome::Rejected(Error::BadSignature),
                UpdateOutcome::Rejected(Error::BelowThreshold),
                UpdateOutcome::NotRelevant,
            ]
        );
        let o = &t.output;
        assert_eq!(
            (
                o.sync_validated,
                o.sync_rejected,
                o.sync_below_threshold,
                o.sync_not_relevant
            ),
            (1, 2, 1, 1)
        );
    }

    #[test]
    fn verify_trace_output_equals_verify_and_setup_failures_are_typed() {
        let i = with_sync(fixture());
        assert_eq!(verify_trace(&i, &Mock).output, verify(&i, &Mock));

        let mut bad_root = with_sync(fixture());
        bad_root.trusted_root = [0; 32];
        let t = verify_trace(&bad_root, &Mock);
        assert_eq!(
            t.updates,
            vec![UpdateOutcome::SetupFailed(Error::TrustedRootMismatch)]
        );

        let mut bad_forks = with_sync(fixture());
        bad_forks.sync.as_mut().unwrap().forks = vec![];
        let t = verify_trace(&bad_forks, &Mock);
        assert_eq!(
            t.updates,
            vec![UpdateOutcome::SetupFailed(Error::BadConfig)]
        );
        assert!(t.output.bootstrap_ok);
        assert_eq!(t.output.sync_rejected, 1);
    }

    // ==== Sprint 4: execution anchor + account/storage proofs ===================================

    use le_sync_core::keccak::{EMPTY_CODE_HASH, EMPTY_TRIE_ROOT};
    use le_sync_core::state::{account_key, storage_key, verify_state};
    use le_sync_testkit::trie::{rlp_bytes, rlp_list, Trie};

    /// Like `Mock`, but accepts the signing root of an arbitrary attested header (the Sprint 4
    /// fixtures change the finalized header, so the attested header differs from `fixture()`'s).
    struct MockAt(Bytes32);
    impl Bls for MockAt {
        fn fast_aggregate_verify(
            &self,
            c: &[BlsPubkey],
            _agg: &BlsPubkey,
            bits: &[u8],
            root: &Bytes32,
            sig: &le_sync_core::sync::BlsSignature,
        ) -> bool {
            assert_eq!(c.len(), bits.len() * 8);
            let want = le_sync_core::sync::compute_signing_root(
                &self.0,
                &le_sync_core::sync::compute_domain(
                    le_sync_core::sync::DOMAIN_SYNC_COMMITTEE,
                    FV,
                    &GVR,
                ),
            );
            sig[0] == 7 && *root == want
        }
    }

    const ADDR: Address = [0x11; 20];
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

    fn trim_be(v: u128) -> Vec<u8> {
        let b = v.to_be_bytes();
        let i = b.iter().position(|x| *x != 0).unwrap_or(b.len());
        b[i..].to_vec()
    }
    fn be32(bytes: &[u8]) -> Bytes32 {
        let mut o = [0u8; 32];
        o[32 - bytes.len()..].copy_from_slice(bytes);
        o
    }

    struct World {
        state: Trie,
        storage: Trie,
    }

    /// `ADDR`: nonce 7, balance 1_000_000, storage {SLOT: 0x1234, SLOT2: 5}; plus filler accounts.
    fn world(balance: u128) -> World {
        let storage = Trie::new(&[
            (storage_key(&SLOT), rlp_bytes(&[0x12, 0x34])),
            (storage_key(&SLOT2), rlp_bytes(&[5])),
        ]);
        let mut es = vec![(
            account_key(&ADDR),
            rlp_list(&[
                rlp_bytes(&[7]),
                rlp_bytes(&trim_be(balance)),
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
                    rlp_bytes(&EMPTY_CODE_HASH),
                ]),
            ));
        }
        World {
            state: Trie::new(&es),
            storage,
        }
    }

    fn exec_for(state_root: Bytes32) -> ExecutionPayloadHeader {
        ExecutionPayloadHeader {
            parent_hash: [0x51; 32],
            fee_recipient: [0x52; 20],
            state_root,
            receipts_root: [0x53; 32],
            logs_bloom: [0x54; 256],
            prev_randao: [0x55; 32],
            block_number: 24_000_123,
            gas_limit: 36_000_000,
            gas_used: 777,
            timestamp: 1_700_000_000,
            extra_data: {
                let mut e = [0u8; 32];
                e[..3].copy_from_slice(b"le!");
                e
            },
            extra_data_len: 3,
            base_fee_per_gas: [0x56; 32],
            block_hash: [0x57; 32],
            transactions_root: [0x58; 32],
            withdrawals_root: [0x59; 32],
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }

    /// BeaconBlockBody: 16 padded leaves, `execution_payload` at index 9 (gindex 25, depth 4).
    fn body_tree(exec_root: Bytes32) -> (Bytes32, Vec<Bytes32>) {
        let mut level: Vec<Bytes32> = (0..16u8).map(|i| [0x40 + i; 32]).collect();
        level[9] = exec_root;
        let (mut idx, mut branch) = (9usize, vec![]);
        while level.len() > 1 {
            branch.push(level[idx ^ 1]);
            level = level.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
            idx /= 2;
        }
        (level[0], branch)
    }

    fn state_input(w: &World, exec: &ExecutionPayloadHeader, branch: Vec<Bytes32>) -> StateInput {
        StateInput {
            exec: ExecWire::from(exec),
            exec_branch: branch,
            address: ADDR,
            slot: SLOT,
            account_proof: w.state.prove(&account_key(&ADDR)),
            storage_proof: w.storage.prove(&storage_key(&SLOT)),
        }
    }

    /// A full honest run: bootstrap, one validated finality update whose finalized header's body
    /// holds `exec`, and a state section for (`ADDR`, `SLOT`).
    fn state_fixture() -> (GuestInput, World) {
        let w = world(1_000_000);
        let exec = exec_for(w.state.root);
        let (body_root, branch) = body_tree(exec.hash_tree_root().unwrap());
        let mut i = with_sync(fixture_with_body(0, body_root));
        i.state = Some(state_input(&w, &exec, branch));
        (i, w)
    }

    fn run(i: &GuestInput) -> GuestOutput {
        let att = BeaconBlockHeader::from(&i.finality[0].attested).hash_tree_root();
        verify(i, &MockAt(att))
    }

    /// A rejected state check commits nothing about the state except the error code.
    fn assert_state_rejected(o: &GuestOutput, e: Error) {
        assert!(o.state_checked && !o.state_ok, "{o:?}");
        assert_eq!(o.state_error_code, e.code(), "{o:?}");
        assert_eq!(
            (
                o.exec_block_number,
                o.exec_block_hash,
                o.exec_state_root,
                o.state_address,
                o.state_slot,
                o.state_value,
                o.account_present,
                o.account_balance
            ),
            (0, ZERO, ZERO, [0; 20], ZERO, ZERO, false, ZERO),
            "{o:?}"
        );
    }

    #[test]
    fn state_proof_verifies_and_the_journal_commits_the_values() {
        let (i, w) = state_fixture();
        let o = run(&i);
        assert_eq!((o.sync_validated, o.sync_rejected), (1, 0), "{o:?}");
        assert!(o.state_checked && o.state_ok, "{o:?}");
        assert_eq!(o.state_error_code, 0);
        let st = i.state.as_ref().unwrap();
        // every committed value comes from the proven header / verified tries
        assert_eq!(o.exec_block_number, 24_000_123);
        assert_eq!(o.exec_block_hash, [0x57; 32]);
        assert_eq!(o.exec_state_root, w.state.root);
        assert_eq!((o.state_address, o.state_slot), (ADDR, SLOT));
        assert_eq!(o.state_value, be32(&[0x12, 0x34]));
        assert!(o.account_present);
        assert_eq!(o.account_balance, be32(&trim_be(1_000_000)));
        // the state hangs off the finalized header the same journal commits
        assert_eq!(o.finalized_slot, 24);
        // same answer as the core one-shot `verify_state`
        let c = verify_state(
            &w.state.root,
            &st.address,
            &st.account_proof,
            &st.slot,
            &st.storage_proof,
        )
        .unwrap();
        assert_eq!(
            (c.value, c.account.balance, c.account_present),
            (o.state_value, o.account_balance, o.account_present)
        );
        // the proof format and everything above is unchanged by the trace variant
        assert_eq!(
            verify_trace(
                &i,
                &MockAt(BeaconBlockHeader::from(&i.finality[0].attested).hash_tree_root())
            )
            .output,
            o
        );
    }

    #[test]
    fn absent_slot_and_absent_account_are_verified_exclusions() {
        let (mut i, w) = state_fixture();
        // absent slot of a present account: a verified zero
        let s = i.state.as_mut().unwrap();
        s.slot = [0x77; 32];
        s.storage_proof = w.storage.prove(&storage_key(&[0x77; 32]));
        let o = run(&i);
        assert!(o.state_ok && o.account_present, "{o:?}");
        assert_eq!((o.state_slot, o.state_value), ([0x77; 32], ZERO));
        assert_eq!(o.account_balance, be32(&trim_be(1_000_000)));

        // absent account: zero balance, zero value, storage proof not consulted
        let (mut i, w) = state_fixture();
        let s = i.state.as_mut().unwrap();
        s.address = [0x99; 20];
        s.account_proof = w.state.prove(&account_key(&[0x99; 20]));
        s.storage_proof = vec![];
        let o = run(&i);
        assert!(o.state_ok && !o.account_present, "{o:?}");
        assert_eq!(
            (o.state_address, o.state_value, o.account_balance),
            ([0x99; 20], ZERO, ZERO)
        );
        assert_eq!(o.exec_state_root, w.state.root);
    }

    #[test]
    fn beacon_part_verifies_but_tampered_execution_branch_is_rejected() {
        let (i, _) = state_fixture();
        let n_nodes = i.state.as_ref().unwrap().exec_branch.len();
        assert_eq!(n_nodes, 4);
        for n in 0..n_nodes {
            let mut t = i.clone();
            t.state.as_mut().unwrap().exec_branch[n][0] ^= 1;
            let o = run(&t);
            // Sprint 1-3 verdicts are untouched: only the state section fails
            assert_eq!(
                (o.bootstrap_ok, o.sync_validated, o.sync_rejected),
                (true, 1, 0)
            );
            assert_state_rejected(&o, Error::InvalidBranch);
        }
    }

    #[test]
    fn a_forged_state_root_is_rejected_even_with_matching_proofs() {
        // The attacker builds a self-consistent fake world (a huge balance) and an execution
        // header carrying ITS state root. Both tries verify against each other, but the header
        // is not the one the finalized beacon header commits to.
        let (honest, _) = state_fixture();
        let fake = world(999_999_999_999);
        let fake_exec = exec_for(fake.state.root);
        let mut i = honest.clone();
        let branch = i.state.as_ref().unwrap().exec_branch.clone();
        i.state = Some(state_input(&fake, &fake_exec, branch));
        assert_state_rejected(&run(&i), Error::InvalidBranch);

        // just swapping the state root inside the honest header
        let mut i = honest.clone();
        i.state.as_mut().unwrap().exec.state_root = [0xEE; 32];
        assert_state_rejected(&run(&i), Error::InvalidBranch);

        // any other field of the execution header is covered by the same root
        let mut i = honest.clone();
        i.state.as_mut().unwrap().exec.block_number += 1;
        assert_state_rejected(&run(&i), Error::InvalidBranch);
        let mut i = honest;
        i.state.as_mut().unwrap().exec.logs_bloom[255] ^= 1;
        assert_state_rejected(&run(&i), Error::InvalidBranch);
    }

    #[test]
    fn malformed_execution_header_is_rejected_not_a_panic() {
        let (honest, _) = state_fixture();
        let mut i = honest.clone();
        i.state.as_mut().unwrap().exec.logs_bloom.pop();
        assert_state_rejected(&run(&i), Error::InvalidBranch);
        let mut i = honest.clone();
        i.state.as_mut().unwrap().exec.extra_data = vec![1; 33];
        assert_state_rejected(&run(&i), Error::InvalidBranch);
        let mut i = honest;
        i.state.as_mut().unwrap().exec_branch = vec![];
        assert_state_rejected(&run(&i), Error::InvalidBranch);
    }

    #[test]
    fn tampered_account_proof_is_rejected() {
        let (honest, _) = state_fixture();
        let nodes = honest.state.as_ref().unwrap().account_proof.len();
        assert!(nodes >= 2);
        for n in 0..nodes {
            let len = honest.state.as_ref().unwrap().account_proof[n].len();
            for b in [0, len / 2, len - 1] {
                let mut i = honest.clone();
                i.state.as_mut().unwrap().account_proof[n][b] ^= 1;
                assert_state_rejected(&run(&i), Error::InvalidTrieProof);
            }
        }
        // truncated, extra, empty
        let mut i = honest.clone();
        i.state.as_mut().unwrap().account_proof.pop();
        assert_state_rejected(&run(&i), Error::InvalidTrieProof);
        let mut i = honest.clone();
        let extra = i.state.as_ref().unwrap().account_proof[0].clone();
        i.state.as_mut().unwrap().account_proof.push(extra);
        assert_state_rejected(&run(&i), Error::InvalidTrieProof);
        let mut i = honest;
        i.state.as_mut().unwrap().account_proof.clear();
        assert_state_rejected(&run(&i), Error::InvalidTrieProof);
    }

    #[test]
    fn tampered_storage_proof_is_rejected() {
        let (honest, _) = state_fixture();
        let nodes = honest.state.as_ref().unwrap().storage_proof.len();
        assert!(nodes >= 2);
        for n in 0..nodes {
            let len = honest.state.as_ref().unwrap().storage_proof[n].len();
            for b in [0, len / 2, len - 1] {
                let mut i = honest.clone();
                i.state.as_mut().unwrap().storage_proof[n][b] ^= 1;
                assert_state_rejected(&run(&i), Error::InvalidTrieProof);
            }
        }
        let mut i = honest.clone();
        i.state.as_mut().unwrap().storage_proof.pop();
        assert_state_rejected(&run(&i), Error::InvalidTrieProof);
        let mut i = honest.clone();
        let extra = i.state.as_ref().unwrap().storage_proof[0].clone();
        i.state.as_mut().unwrap().storage_proof.push(extra);
        assert_state_rejected(&run(&i), Error::InvalidTrieProof);
        // a storage proof from another account's trie does not satisfy this account's root
        let mut i = honest;
        let other = Trie::new(&[(storage_key(&SLOT), rlp_bytes(&[0x99]))]);
        i.state.as_mut().unwrap().storage_proof = other.prove(&storage_key(&SLOT));
        assert_state_rejected(&run(&i), Error::InvalidTrieProof);
    }

    #[test]
    fn a_proof_for_one_key_never_proves_another() {
        let (honest, _) = state_fixture();
        // wrong slot: SLOT2 exists with value 5, so SLOT's proof cannot prove it (or its absence)
        let mut i = honest.clone();
        i.state.as_mut().unwrap().slot = SLOT2;
        assert_state_rejected(&run(&i), Error::InvalidTrieProof);
        // wrong address: either a (truthful) exclusion or a rejection, never ADDR's data
        let mut i = honest;
        i.state.as_mut().unwrap().address = [0x12; 20];
        let o = run(&i);
        if o.state_ok {
            assert!(!o.account_present, "{o:?}");
            assert_eq!((o.state_value, o.account_balance), (ZERO, ZERO));
            assert_eq!(o.state_address, [0x12; 20]);
        } else {
            assert_state_rejected(&o, Error::InvalidTrieProof);
        }
    }

    #[test]
    fn the_anchor_must_be_the_stores_final_finalized_header() {
        // No update applied: the store's finalized header is the bootstrap header, so an
        // execution header that hangs off the (never applied) update's header cannot vouch.
        let (mut i, _) = state_fixture();
        i.sync.as_mut().unwrap().updates.clear();
        let o = run(&i);
        assert_eq!(o.sync_validated, 0);
        assert_state_rejected(&o, Error::InvalidBranch);

        // An update below the 2/3 threshold is rejected, so it cannot move the store either.
        let (mut i, _) = state_fixture();
        i.sync.as_mut().unwrap().updates[0].bits = low_bits();
        let o = run(&i);
        assert_eq!((o.sync_validated, o.sync_below_threshold), (0, 1));
        assert_state_rejected(&o, Error::InvalidBranch);

        // A badly signed update likewise.
        let (mut i, _) = state_fixture();
        i.sync.as_mut().unwrap().updates[0].signature[0] ^= 1;
        let o = run(&i);
        assert_eq!(o.sync_validated, 0);
        assert_state_rejected(&o, Error::InvalidBranch);
    }

    #[test]
    fn state_is_not_evaluated_without_a_trusted_sync_run() {
        let nothing = |o: &GuestOutput| {
            assert!(!o.state_checked && !o.state_ok, "{o:?}");
            assert_eq!(o.state_error_code, 0);
            assert_eq!(
                (o.exec_state_root, o.state_value, o.account_present),
                (ZERO, ZERO, false)
            );
        };
        // no sync section: there is no trusted finalized header to anchor to
        let (mut i, _) = state_fixture();
        i.sync = None;
        nothing(&run(&i));
        // bootstrap fails
        let (mut i, _) = state_fixture();
        i.trusted_root = [0; 32];
        nothing(&run(&i));
        // sync setup fails (malformed fork schedule)
        let (mut i, _) = state_fixture();
        i.sync.as_mut().unwrap().forks = vec![];
        nothing(&run(&i));
        // and a run with no state section commits an all-default state block
        let o = verify(&with_sync(fixture()), &Mock);
        nothing(&o);
        assert_eq!(o.exec_block_number, 0);
    }

    #[test]
    fn exec_wire_conversion_is_exact_and_length_checked() {
        let e = exec_for([0x01; 32]);
        let w = ExecWire::from(&e);
        assert_eq!(w.logs_bloom.len(), 256);
        assert_eq!(w.extra_data, b"le!".to_vec());
        assert_eq!(w.to_header(), Some(e));
        assert_eq!(w.to_header().unwrap().hash_tree_root(), e.hash_tree_root());
        let mut bad = w.clone();
        bad.logs_bloom = vec![0; 255];
        assert_eq!(bad.to_header(), None);
        let mut bad = w.clone();
        bad.logs_bloom = vec![0; 257];
        assert_eq!(bad.to_header(), None);
        let mut ok = w.clone();
        ok.extra_data = vec![9; 32];
        assert!(ok.to_header().is_some());
        let mut bad = w;
        bad.extra_data = vec![9; 33];
        assert_eq!(bad.to_header(), None);
    }
}
