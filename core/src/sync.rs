//! Sprint 2: light-client store + update validation, `no_std`, no alloc.

use super::*;

pub type BlsSignature = [u8; 96];
pub type Version = [u8; 4];

pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];
pub const MIN_SYNC_COMMITTEE_PARTICIPANTS: u64 = 1;
/// Operator-level guideline only (NOT part of the light-client spec). Used by
/// `LightClientStore::assert_within_weak_subjectivity_period`, which is no longer
/// called from `validate_light_client_update`.
pub const WEAK_SUBJECTIVITY_PERIOD_LIMIT: u64 = 4;

/// Spec: `UPDATE_TIMEOUT = SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD`
/// (used only in `process_light_client_store_force_update`).
fn update_timeout(cfg: &SyncConfig) -> u64 {
    cfg.chain
        .slots_per_epoch
        .saturating_mul(cfg.epochs_per_period)
}

pub fn compute_fork_data_root(version: Version, genesis_validators_root: &Bytes32) -> Bytes32 {
    let mut v = ZERO;
    v[..4].copy_from_slice(&version);
    hash_pair(&v, genesis_validators_root)
}

/// First 4 bytes of the fork data root (Electra and earlier; Fulu XORs in blob parameters,
/// which affects p2p digests only, not signing domains).
pub fn compute_fork_digest(version: Version, genesis_validators_root: &Bytes32) -> [u8; 4] {
    let r = compute_fork_data_root(version, genesis_validators_root);
    [r[0], r[1], r[2], r[3]]
}

pub fn compute_domain(
    domain_type: [u8; 4],
    version: Version,
    genesis_validators_root: &Bytes32,
) -> Bytes32 {
    let r = compute_fork_data_root(version, genesis_validators_root);
    let mut d = ZERO;
    d[..4].copy_from_slice(&domain_type);
    d[4..].copy_from_slice(&r[..28]);
    d
}

pub fn compute_signing_root(object_root: &Bytes32, domain: &Bytes32) -> Bytes32 {
    hash_pair(object_root, domain)
}

pub const MAX_FORKS: usize = 8;
/// Max Merkle branch length we store for best-update (Electra finality depth 7).
pub const MAX_BRANCH_LEN: usize = 8;
/// Bitfield capacity for `MAX_SYNC_COMMITTEE_SIZE`.
pub const MAX_BITS_LEN: usize = MAX_SYNC_COMMITTEE_SIZE / 8;

#[derive(Clone, Copy, Debug)]
pub struct ForkSchedule {
    entries: [(u64, Version); MAX_FORKS],
    len: usize,
}

impl ForkSchedule {
    pub fn new(list: &[(u64, Version)]) -> Result<Self, Error> {
        if list.is_empty() || list.len() > MAX_FORKS {
            return Err(Error::BadConfig);
        }
        let mut entries = [(0u64, [0u8; 4]); MAX_FORKS];
        for (i, e) in list.iter().enumerate() {
            if i > 0 && e.0 < list[i - 1].0 {
                return Err(Error::BadConfig);
            }
            entries[i] = *e;
        }
        Ok(Self {
            entries,
            len: list.len(),
        })
    }

    pub fn single(version: Version) -> Self {
        let mut entries = [(0u64, [0u8; 4]); MAX_FORKS];
        entries[0] = (0, version);
        Self { entries, len: 1 }
    }

    /// The populated schedule entries, in epoch order.
    pub fn entries(&self) -> &[(u64, Version)] {
        &self.entries[..self.len]
    }

    /// Fixed-layout, domain-separated digest of the schedule:
    /// `SHA256("LE_SYNC_FORK_SCHEDULE_V1" || len:u64le || (epoch:u64le || version:4)*)`.
    /// The count is committed so padding or a trailing `(0, [0;4])` entry cannot collide.
    pub fn hash(&self) -> Bytes32 {
        let mut h = Sha256::new();
        h.update(b"LE_SYNC_FORK_SCHEDULE_V1");
        h.update((self.len as u64).to_le_bytes());
        for (epoch, version) in self.entries() {
            h.update(epoch.to_le_bytes());
            h.update(version);
        }
        h.finalize().into()
    }

    pub fn version_at_epoch(&self, epoch: u64) -> Version {
        let mut v = self.entries[0].1;
        for e in &self.entries[..self.len] {
            if e.0 <= epoch {
                v = e.1;
            }
        }
        v
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SyncConfig {
    pub chain: ChainConfig,
    pub epochs_per_period: u64,
    pub genesis_validators_root: Bytes32,
    pub forks: ForkSchedule,
}

impl SyncConfig {
    fn check(&self) -> Result<(), Error> {
        if self.chain.slots_per_epoch == 0 || self.epochs_per_period == 0 {
            return Err(Error::BadConfig);
        }
        Ok(())
    }

    pub fn period_at_slot(&self, slot: u64) -> u64 {
        slot / self.chain.slots_per_epoch / self.epochs_per_period
    }

    /// The chain binding this configuration implies. `chain_id` is supplied by the caller:
    /// it is a declared label (e.g. `DEPOSIT_CHAIN_ID`), not something the signatures cover.
    pub fn binding(&self, chain_id: u64) -> ChainBinding {
        ChainBinding {
            chain_id,
            genesis_validators_root: self.genesis_validators_root,
            fork_schedule_hash: self.forks.hash(),
            slots_per_epoch: self.chain.slots_per_epoch,
            epochs_per_period: self.epochs_per_period,
        }
    }
}

/// Everything that identifies the chain a proof is about, committed as one digest.
///
/// Cryptographic status of each field: `genesis_validators_root` and the fork versions in
/// `fork_schedule_hash` feed the BLS signing domain, so a forged value makes signatures fail.
/// `chain_id`, `slots_per_epoch` and `epochs_per_period` are NOT signed by anything; they are
/// declared labels whose integrity rests on the verifier comparing the committed binding with
/// an expected one (`check` / `check_digest`, returning `Error::ChainMismatch`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainBinding {
    pub chain_id: u64,
    pub genesis_validators_root: Bytes32,
    pub fork_schedule_hash: Bytes32,
    pub slots_per_epoch: u64,
    pub epochs_per_period: u64,
}

impl ChainBinding {
    /// `SHA256("LE_SYNC_CHAIN_BINDING_V1" || chain_id:u64le || gvr:32 || fork_schedule_hash:32
    /// || slots_per_epoch:u64le || epochs_per_period:u64le)`. Every field is fixed-width, so
    /// the encoding is unambiguous. Intended for reuse by statement-ID derivation.
    pub fn digest(&self) -> Bytes32 {
        let mut h = Sha256::new();
        h.update(b"LE_SYNC_CHAIN_BINDING_V1");
        h.update(self.chain_id.to_le_bytes());
        h.update(self.genesis_validators_root);
        h.update(self.fork_schedule_hash);
        h.update(self.slots_per_epoch.to_le_bytes());
        h.update(self.epochs_per_period.to_le_bytes());
        h.finalize().into()
    }

    /// Consumer-side check: `self` is the binding the verifier expects, `committed` is the one
    /// found in the proof.
    pub fn check(&self, committed: &ChainBinding) -> Result<(), Error> {
        if self == committed {
            Ok(())
        } else {
            Err(Error::ChainMismatch)
        }
    }

    /// Same as `check`, against a committed digest (what a journal carries).
    pub fn check_digest(&self, committed: &Bytes32) -> Result<(), Error> {
        if self.digest() == *committed {
            Ok(())
        } else {
            Err(Error::ChainMismatch)
        }
    }
}

pub trait Bls {
    fn fast_aggregate_verify(
        &self,
        committee: &[BlsPubkey],
        aggregate_pubkey: &BlsPubkey,
        bits: &[u8],
        signing_root: &Bytes32,
        signature: &BlsSignature,
    ) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncCommittee {
    pub pubkeys: [BlsPubkey; MAX_SYNC_COMMITTEE_SIZE],
    pub len: usize,
    pub aggregate_pubkey: BlsPubkey,
}

impl SyncCommittee {
    pub fn empty(len: usize) -> Self {
        Self {
            pubkeys: [[0u8; 48]; MAX_SYNC_COMMITTEE_SIZE],
            len: len.min(MAX_SYNC_COMMITTEE_SIZE),
            aggregate_pubkey: [0u8; 48],
        }
    }

    pub fn new(keys: &[BlsPubkey], aggregate_pubkey: BlsPubkey) -> Result<Self, Error> {
        if keys.is_empty() || keys.len() > MAX_SYNC_COMMITTEE_SIZE {
            return Err(Error::BadSyncCommitteeSize);
        }
        let mut c = Self::empty(keys.len());
        c.pubkeys[..keys.len()].copy_from_slice(keys);
        c.aggregate_pubkey = aggregate_pubkey;
        Ok(c)
    }

    pub fn keys(&self) -> &[BlsPubkey] {
        &self.pubkeys[..self.len]
    }

    pub fn is_empty(&self) -> bool {
        self.aggregate_pubkey == [0u8; 48] && self.keys().iter().all(|k| *k == [0u8; 48])
    }

    pub fn root(&self) -> Result<Bytes32, Error> {
        sync_committee_root(self.keys(), &self.aggregate_pubkey)
    }
}

#[derive(Debug, Clone)]
pub struct LightClientUpdate<'a> {
    pub attested_header: BeaconBlockHeader,
    pub next_sync_committee: &'a SyncCommittee,
    pub next_sync_committee_branch: &'a [Bytes32],
    pub finalized_header: BeaconBlockHeader,
    pub finality_branch: &'a [Bytes32],
    pub sync_committee_bits: &'a [u8],
    pub sync_committee_signature: BlsSignature,
    pub signature_slot: u64,
}

impl LightClientUpdate<'_> {
    pub fn is_sync_committee_update(&self) -> bool {
        is_branch_present(self.next_sync_committee_branch)
    }
    pub fn is_finality_update(&self) -> bool {
        is_branch_present(self.finality_branch)
    }
}

/// Owned copy of an update for `best_valid_update` (spec name). Fixed buffers → no alloc.
#[derive(Clone, Debug)]
pub struct OwnedLightClientUpdate {
    pub attested_header: BeaconBlockHeader,
    pub next_sync_committee: SyncCommittee,
    pub next_sync_committee_branch: [Bytes32; MAX_BRANCH_LEN],
    pub next_branch_len: usize,
    pub finalized_header: BeaconBlockHeader,
    pub finality_branch: [Bytes32; MAX_BRANCH_LEN],
    pub finality_branch_len: usize,
    pub sync_committee_bits: [u8; MAX_BITS_LEN],
    pub bits_len: usize,
    pub sync_committee_signature: BlsSignature,
    pub signature_slot: u64,
}

impl OwnedLightClientUpdate {
    pub fn from_borrowed(u: &LightClientUpdate<'_>) -> Result<Self, Error> {
        if u.next_sync_committee_branch.len() > MAX_BRANCH_LEN
            || u.finality_branch.len() > MAX_BRANCH_LEN
            || u.sync_committee_bits.len() > MAX_BITS_LEN
        {
            return Err(Error::BadConfig);
        }
        let mut next_br = [ZERO; MAX_BRANCH_LEN];
        next_br[..u.next_sync_committee_branch.len()].copy_from_slice(u.next_sync_committee_branch);
        let mut fin_br = [ZERO; MAX_BRANCH_LEN];
        fin_br[..u.finality_branch.len()].copy_from_slice(u.finality_branch);
        let mut bits = [0u8; MAX_BITS_LEN];
        bits[..u.sync_committee_bits.len()].copy_from_slice(u.sync_committee_bits);
        Ok(Self {
            attested_header: u.attested_header,
            next_sync_committee: u.next_sync_committee.clone(),
            next_sync_committee_branch: next_br,
            next_branch_len: u.next_sync_committee_branch.len(),
            finalized_header: u.finalized_header,
            finality_branch: fin_br,
            finality_branch_len: u.finality_branch.len(),
            sync_committee_bits: bits,
            bits_len: u.sync_committee_bits.len(),
            sync_committee_signature: u.sync_committee_signature,
            signature_slot: u.signature_slot,
        })
    }

    pub fn view(&self) -> LightClientUpdate<'_> {
        LightClientUpdate {
            attested_header: self.attested_header,
            next_sync_committee: &self.next_sync_committee,
            next_sync_committee_branch: &self.next_sync_committee_branch[..self.next_branch_len],
            finalized_header: self.finalized_header,
            finality_branch: &self.finality_branch[..self.finality_branch_len],
            sync_committee_bits: &self.sync_committee_bits[..self.bits_len],
            sync_committee_signature: self.sync_committee_signature,
            signature_slot: self.signature_slot,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LightClientStore {
    pub finalized_header: BeaconBlockHeader,
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: SyncCommittee,
    pub optimistic_header: BeaconBlockHeader,
    pub previous_max_active_participants: u64,
    pub current_max_active_participants: u64,
    /// Spec: `best_valid_update`.
    pub best_valid_update: Option<OwnedLightClientUpdate>,
}

impl LightClientStore {
    pub fn is_next_sync_committee_known(&self) -> bool {
        !self.next_sync_committee.is_empty()
    }

    pub fn safety_threshold(&self) -> u64 {
        self.previous_max_active_participants
            .max(self.current_max_active_participants)
            / 2
    }

    /// Operator-level guideline (not a spec assert). Not called by validation.
    pub fn assert_within_weak_subjectivity_period(
        &self,
        current_slot: u64,
        slots_per_epoch: u64,
        epochs_per_sync_committee_period: u64,
    ) -> Result<(), Error> {
        let period_length = slots_per_epoch.saturating_mul(epochs_per_sync_committee_period);
        if period_length == 0 {
            return Err(Error::BadConfig);
        }
        let current_period = current_slot / period_length;
        let finalized_period = self.finalized_header.slot / period_length;

        if current_period > finalized_period.saturating_add(WEAK_SUBJECTIVITY_PERIOD_LIMIT) {
            return Err(Error::CheckpointStale);
        }
        Ok(())
    }

    /// Spec `process_light_client_store_force_update`.
    pub fn force_update(&mut self, current_slot: u64, cfg: &SyncConfig) -> Result<(), Error> {
        cfg.check()?;
        let timeout = update_timeout(cfg);
        let Some(best) = self.best_valid_update.as_ref() else {
            return Ok(());
        };
        if current_slot <= self.finalized_header.slot.saturating_add(timeout) {
            return Ok(());
        }
        let mut best = best.clone();
        // Extended non-finality: treat attested as finalized so the period can advance.
        if best.finalized_header.slot <= self.finalized_header.slot {
            best.finalized_header = best.attested_header;
        }
        apply_light_client_update(self, &best.view(), cfg)?;
        self.best_valid_update = None;
        Ok(())
    }

    pub fn upgrade_store(&mut self, _target_fork_version: Version) {}
}

pub fn count_bits(bits: &[u8]) -> u64 {
    bits.iter().map(|b| b.count_ones() as u64).sum()
}

/// Spec supermajority test: `sum(bits) * 3 >= len(bits) * 2` (bitfield length in bits).
/// The single home of the 2/3 arithmetic: used by `is_better_update`,
/// `process_light_client_update` and the `wire` strict gate. An empty bitfield is not a
/// supermajority (fail closed; unreachable through validation, which rejects size 0).
pub fn has_supermajority(bits: &[u8]) -> bool {
    let n = (bits.len() * 8) as u64;
    n != 0 && count_bits(bits) * 3 >= n * 2
}

/// Spec `is_better_update` (Altair; unchanged through Fulu).
pub fn is_better_update(
    new: &LightClientUpdate,
    old: &LightClientUpdate,
    cfg: &SyncConfig,
) -> bool {
    let new_active = count_bits(new.sync_committee_bits);
    let old_active = count_bits(old.sync_committee_bits);
    // Both updates were validated against the same committee, so their bitfield lengths match.
    let new_super = has_supermajority(new.sync_committee_bits);
    let old_super = has_supermajority(old.sync_committee_bits);
    if new_super != old_super {
        return new_super;
    }
    if !new_super && new_active != old_active {
        return new_active > old_active;
    }

    let relevant = |u: &LightClientUpdate| {
        u.is_sync_committee_update()
            && cfg.period_at_slot(u.attested_header.slot) == cfg.period_at_slot(u.signature_slot)
    };
    let (new_rel, old_rel) = (relevant(new), relevant(old));
    if new_rel != old_rel {
        return new_rel;
    }

    let (new_fin, old_fin) = (new.is_finality_update(), old.is_finality_update());
    if new_fin != old_fin {
        return new_fin;
    }

    if new_fin {
        let correct = |u: &LightClientUpdate| {
            cfg.period_at_slot(u.finalized_header.slot)
                == cfg.period_at_slot(u.attested_header.slot)
        };
        let (new_ok, old_ok) = (correct(new), correct(old));
        if new_ok != old_ok {
            return new_ok;
        }
    }

    if new_active != old_active {
        return new_active > old_active;
    }
    if new.attested_header.slot != old.attested_header.slot {
        return new.attested_header.slot < old.attested_header.slot;
    }
    new.signature_slot < old.signature_slot
}

pub fn verify_execution_branch(
    header: &BeaconBlockHeader,
    execution_branch: &[Bytes32],
    execution_payload_root: &Bytes32,
) -> Result<(), Error> {
    const EXECUTION_PAYLOAD_GINDEX: u64 = 25;
    if !is_valid_normalized_merkle_branch(
        execution_payload_root,
        execution_branch,
        EXECUTION_PAYLOAD_GINDEX,
        &header.body_root,
    ) {
        return Err(Error::InvalidBranch);
    }
    Ok(())
}

pub fn initialize_light_client_store(
    cfg: &SyncConfig,
    trusted_block_root: &Bytes32,
    header: &BeaconBlockHeader,
    current_sync_committee: SyncCommittee,
    current_sync_committee_branch: &[Bytes32],
) -> Result<LightClientStore, Error> {
    cfg.check()?;
    verify_bootstrap(
        &cfg.chain,
        trusted_block_root,
        header,
        current_sync_committee.keys(),
        &current_sync_committee.aggregate_pubkey,
        current_sync_committee_branch,
    )?;
    let len = current_sync_committee.len;
    Ok(LightClientStore {
        finalized_header: *header,
        current_sync_committee,
        next_sync_committee: SyncCommittee::empty(len),
        optimistic_header: *header,
        previous_max_active_participants: 0,
        current_max_active_participants: 0,
        best_valid_update: None,
    })
}

pub fn validate_light_client_update<B: Bls>(
    store: &LightClientStore,
    update: &LightClientUpdate,
    current_slot: u64,
    cfg: &SyncConfig,
    bls: &B,
) -> Result<(), Error> {
    cfg.check()?;

    let n = update.sync_committee_bits.len() * 8;
    if n == 0 || n != store.current_sync_committee.len || n != update.next_sync_committee.len {
        return Err(Error::CommitteeSizeMismatch);
    }

    if count_bits(update.sync_committee_bits) < MIN_SYNC_COMMITTEE_PARTICIPANTS {
        return Err(Error::InsufficientParticipants);
    }

    let attested_slot = update.attested_header.slot;
    let finalized_slot = update.finalized_header.slot;
    if !(current_slot >= update.signature_slot
        && update.signature_slot > attested_slot
        && attested_slot >= finalized_slot)
    {
        return Err(Error::BadSlotOrder);
    }

    let store_period = cfg.period_at_slot(store.finalized_header.slot);
    let signature_period = cfg.period_at_slot(update.signature_slot);
    if store.is_next_sync_committee_known() {
        if signature_period != store_period && signature_period != store_period + 1 {
            return Err(Error::PeriodSkipped);
        }
    } else if signature_period != store_period {
        return Err(Error::PeriodSkipped);
    }

    let attested_period = cfg.period_at_slot(attested_slot);
    let has_next = !store.is_next_sync_committee_known()
        && update.is_sync_committee_update()
        && attested_period == store_period;
    if !(attested_slot > store.finalized_header.slot || has_next) {
        return Err(Error::UpdateNotRelevant);
    }

    if !update.is_finality_update() {
        if !update.finalized_header.is_empty() {
            return Err(Error::FinalizedHeaderNotEmpty);
        }
    } else {
        verify_finality_branch(
            &cfg.chain,
            &update.attested_header,
            &update.finalized_header,
            update.finality_branch,
        )?;
    }

    if !update.is_sync_committee_update() {
        if !update.next_sync_committee.is_empty() {
            return Err(Error::NextCommitteeNotEmpty);
        }
    } else {
        if attested_period == store_period
            && store.is_next_sync_committee_known()
            && *update.next_sync_committee != store.next_sync_committee
        {
            return Err(Error::NextCommitteeMismatch);
        }
        let gindex = cfg
            .chain
            .gindices_at_slot(attested_slot)?
            .next_sync_committee;
        let leaf = update.next_sync_committee.root()?;
        if !is_valid_normalized_merkle_branch(
            &leaf,
            update.next_sync_committee_branch,
            gindex,
            &update.attested_header.state_root,
        ) {
            return Err(Error::InvalidBranch);
        }
    }

    let committee = if signature_period == store_period {
        &store.current_sync_committee
    } else {
        &store.next_sync_committee
    };
    let fork_version_slot = update.signature_slot.saturating_sub(1);
    let fork_version = cfg
        .forks
        .version_at_epoch(fork_version_slot / cfg.chain.slots_per_epoch);
    let domain = compute_domain(
        DOMAIN_SYNC_COMMITTEE,
        fork_version,
        &cfg.genesis_validators_root,
    );
    let signing_root = compute_signing_root(&update.attested_header.hash_tree_root(), &domain);
    if !bls.fast_aggregate_verify(
        committee.keys(),
        &committee.aggregate_pubkey,
        update.sync_committee_bits,
        &signing_root,
        &update.sync_committee_signature,
    ) {
        return Err(Error::BadSignature);
    }
    Ok(())
}

pub fn apply_light_client_update(
    store: &mut LightClientStore,
    update: &LightClientUpdate,
    cfg: &SyncConfig,
) -> Result<(), Error> {
    cfg.check()?;
    let store_period = cfg.period_at_slot(store.finalized_header.slot);
    let update_finalized_period = cfg.period_at_slot(update.finalized_header.slot);
    if !store.is_next_sync_committee_known() {
        if update_finalized_period != store_period {
            return Err(Error::PeriodSkipped);
        }
        store.next_sync_committee = update.next_sync_committee.clone();
    } else if update_finalized_period == store_period + 1 {
        store.current_sync_committee = core::mem::replace(
            &mut store.next_sync_committee,
            update.next_sync_committee.clone(),
        );
        store.previous_max_active_participants = store.current_max_active_participants;
        store.current_max_active_participants = 0;
    }
    if update.finalized_header.slot > store.finalized_header.slot {
        store.finalized_header = update.finalized_header;
        if store.finalized_header.slot > store.optimistic_header.slot {
            store.optimistic_header = store.finalized_header;
        }
    }
    Ok(())
}

pub fn process_light_client_update<B: Bls>(
    store: &mut LightClientStore,
    update: &LightClientUpdate,
    current_slot: u64,
    cfg: &SyncConfig,
    bls: &B,
) -> Result<(), Error> {
    validate_light_client_update(store, update, current_slot, cfg, bls)?;

    let active = count_bits(update.sync_committee_bits);

    // Track the best valid update (spec ranking) for a later force-update.
    let replace = match store.best_valid_update.as_ref() {
        None => true,
        Some(best) => is_better_update(update, &best.view(), cfg),
    };
    if replace {
        store.best_valid_update = Some(OwnedLightClientUpdate::from_borrowed(update)?);
    }

    store.current_max_active_participants = store.current_max_active_participants.max(active);
    if active > store.safety_threshold()
        && update.attested_header.slot > store.optimistic_header.slot
    {
        store.optimistic_header = update.attested_header;
    }

    let update_has_finalized_next_sync_committee = !store.is_next_sync_committee_known()
        && update.is_sync_committee_update()
        && update.is_finality_update()
        && cfg.period_at_slot(update.finalized_header.slot)
            == cfg.period_at_slot(update.attested_header.slot);

    if has_supermajority(update.sync_committee_bits)
        && (update.finalized_header.slot > store.finalized_header.slot
            || update_has_finalized_next_sync_committee)
    {
        apply_light_client_update(store, update, cfg)?;
        store.best_valid_update = None;
    }
    Ok(())
}

// -------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const SPE: u64 = 8;
    const EPP: u64 = 8; // period = 64 slots (minimal preset)
    const N: usize = 32; // minimal SYNC_COMMITTEE_SIZE
    const FORK_V: Version = [0x05, 0, 0, 1];
    const GVR_A: Bytes32 = [0xAA; 32];
    const GVR_B: Bytes32 = [0xBB; 32];

    fn cfg(gvr: Bytes32) -> SyncConfig {
        SyncConfig {
            chain: ChainConfig {
                slots_per_epoch: SPE,
                electra_fork_epoch: 0,
                gloas_fork_epoch: None,
            },
            epochs_per_period: EPP,
            genesis_validators_root: gvr,
            forks: ForkSchedule::single(FORK_V),
        }
    }

    // ---- tree helpers (same oracle style as lib tests) ----
    fn leaf_n(i: u64) -> Bytes32 {
        let mut h = Sha256::new();
        h.update(b"sync-test");
        h.update(i.to_le_bytes());
        h.finalize().into()
    }
    fn levels(leaves: Vec<Bytes32>) -> Vec<Vec<Bytes32>> {
        let mut l = vec![leaves];
        while l.last().unwrap().len() > 1 {
            let n = l
                .last()
                .unwrap()
                .chunks(2)
                .map(|p| hash_pair(&p[0], &p[1]))
                .collect();
            l.push(n);
        }
        l
    }
    fn branch(l: &[Vec<Bytes32>], mut i: usize) -> Vec<Bytes32> {
        let mut out = vec![];
        for lv in &l[..l.len() - 1] {
            out.push(lv[i ^ 1]);
            i /= 2;
        }
        out
    }
    fn committee(seed: u64) -> SyncCommittee {
        let keys: Vec<BlsPubkey> = (0..N as u64)
            .map(|i| {
                let mut k = [0u8; 48];
                k[..32].copy_from_slice(&leaf_n(seed * 1000 + i));
                k
            })
            .collect();
        let mut agg = [0u8; 48];
        agg[..32].copy_from_slice(&leaf_n(seed * 1000 + 999));
        SyncCommittee::new(&keys, agg).unwrap()
    }

    /// A BeaconState-shaped tree (64 field leaves): field 20 = Checkpoint{epoch, root},
    /// 22 = current_sync_committee, 23 = next_sync_committee.
    struct State {
        root: Bytes32,
        finality_branch: Vec<Bytes32>, // 7
        cur_branch: Vec<Bytes32>,      // 6
        next_branch: Vec<Bytes32>,     // 6
    }
    fn state(finalized_root: Bytes32, cur: &SyncCommittee, next: &SyncCommittee) -> State {
        let epoch_chunk = leaf_n(77_777);
        let mut f: Vec<Bytes32> = (0..64).map(|i| leaf_n(5000 + i)).collect();
        f[20] = hash_pair(&epoch_chunk, &finalized_root);
        f[22] = cur.root().unwrap();
        f[23] = next.root().unwrap();
        let l = levels(f);
        let mut fin = vec![epoch_chunk];
        fin.extend(branch(&l, 20));
        State {
            root: l.last().unwrap()[0],
            finality_branch: fin,
            cur_branch: branch(&l, 22),
            next_branch: branch(&l, 23),
        }
    }
    fn hdr(slot: u64, state_root: Bytes32, salt: u64) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot,
            proposer_index: salt,
            parent_root: leaf_n(100 + salt),
            state_root,
            body_root: leaf_n(200 + salt),
        }
    }

    struct Mock {
        /// None = accept anything; Some(root) = accept only that signing root.
        expect: Option<Bytes32>,
        result: bool,
        seen: RefCell<Vec<(Bytes32, usize)>>,
        /// First pubkey of the committee each call was verified against (which committee?).
        keys: RefCell<Vec<BlsPubkey>>,
    }
    impl Mock {
        fn ok() -> Self {
            Self {
                expect: None,
                result: true,
                seen: RefCell::new(vec![]),
                keys: RefCell::new(vec![]),
            }
        }
        fn expecting(r: Bytes32) -> Self {
            Self {
                expect: Some(r),
                result: true,
                seen: RefCell::new(vec![]),
                keys: RefCell::new(vec![]),
            }
        }
        fn reject() -> Self {
            Self {
                expect: None,
                result: false,
                seen: RefCell::new(vec![]),
                keys: RefCell::new(vec![]),
            }
        }
    }
    impl Bls for Mock {
        fn fast_aggregate_verify(
            &self,
            c: &[BlsPubkey],
            _agg: &BlsPubkey,
            bits: &[u8],
            root: &Bytes32,
            _s: &BlsSignature,
        ) -> bool {
            assert_eq!(c.len(), bits.len() * 8);
            self.seen.borrow_mut().push((*root, c.len()));
            self.keys.borrow_mut().push(c[0]);
            self.result && self.expect.map_or(true, |e| e == *root)
        }
    }

    fn bits(set: usize) -> Vec<u8> {
        let mut b = vec![0u8; N / 8];
        for i in 0..set {
            b[i / 8] |= 1 << (i % 8);
        }
        b
    }

    /// Store at finalized slot 8 (period 0) + an Electra update that finalizes slot 24 and
    /// carries committee B; attested slot 40, signature slot 41.
    struct Fx {
        store: LightClientStore,
        next: SyncCommittee,
        fin_hdr: BeaconBlockHeader,
        att: BeaconBlockHeader,
        finality_branch: Vec<Bytes32>,
        next_branch: Vec<Bytes32>,
        bits: Vec<u8>,
    }
    fn fixture() -> Fx {
        let (a, b) = (committee(1), committee(2));
        // bootstrap
        let boot_state = state(leaf_n(1), &a, &committee(9));
        let boot_hdr = hdr(8, boot_state.root, 1);
        let store = initialize_light_client_store(
            &cfg(GVR_A),
            &boot_hdr.hash_tree_root(),
            &boot_hdr,
            a.clone(),
            &boot_state.cur_branch,
        )
        .unwrap();
        // update
        let fin_hdr = hdr(24, leaf_n(300), 2);
        let st = state(fin_hdr.hash_tree_root(), &a, &b);
        let att = hdr(40, st.root, 3);
        Fx {
            store,
            next: b,
            fin_hdr,
            att,
            finality_branch: st.finality_branch,
            next_branch: st.next_branch,
            bits: bits(N),
        }
    }
    fn upd<'a>(f: &'a Fx, sig_slot: u64) -> LightClientUpdate<'a> {
        LightClientUpdate {
            attested_header: f.att,
            next_sync_committee: &f.next,
            next_sync_committee_branch: &f.next_branch,
            finalized_header: f.fin_hdr,
            finality_branch: &f.finality_branch,
            sync_committee_bits: &f.bits,
            sync_committee_signature: [7u8; 96],
            signature_slot: sig_slot,
        }
    }

    // ---- Arithmetic & Edge-Case Boundary Assertions (Mutation Hardening) ----

    #[test]
    fn test_slot_and_epoch_arithmetic_boundaries() {
        let c = cfg(GVR_A);
        let slots_per_epoch = c.chain.slots_per_epoch; // 8
        let epochs_per_period = c.epochs_per_period; // 8
        let period_length = slots_per_epoch * epochs_per_period; // 64

        // Exact slot rollovers and period boundary checks
        assert_eq!(c.period_at_slot(0), 0);
        assert_eq!(c.period_at_slot(period_length - 1), 0);
        assert_eq!(c.period_at_slot(period_length), 1);
        assert_eq!(c.period_at_slot(period_length + 1), 1);

        // Verify division versus modulo mutations (e.g., slot / slots_per_epoch)
        // Choose a slot where quotient != remainder so the assert_ne is meaningful.
        let test_slot = 26;
        let expected_epoch = test_slot / slots_per_epoch; // 3
        assert_eq!(test_slot / slots_per_epoch, expected_epoch);
        assert_ne!(test_slot % slots_per_epoch, expected_epoch); // 2 != 3
    }

    #[test]
    fn test_bitmask_boundary_and_chunk_lengths() {
        // Test exact bitmask sizing, trailing bits, and boundary evaluations for has_supermajority
        // Committee size N = 32 elements (4 bytes). 2/3 threshold is 22 bits set (66 >= 64).

        // Exactly 21 bits set (< 2/3 threshold)
        let bits_21 = vec![0xFF, 0xFF, 0x1F, 0x00];
        assert_eq!(bits_21.len() * 8, 32);
        assert!(
            !has_supermajority(&bits_21),
            "21 bits must fail supermajority check"
        );

        // Exactly 22 bits set (>= 2/3 threshold)
        let bits_22 = vec![0xFF, 0xFF, 0x3F, 0x00];
        assert!(
            has_supermajority(&bits_22),
            "22 bits must pass supermajority check"
        );

        // Trailing bits outside committee range or mismatched chunk lengths
        let mismatched_bits = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF]; // 40 bits for a 32-element committee
        let f = fixture();
        let store = f.store.clone();
        let mut u = upd(&f, 41);
        u.sync_committee_bits = &mismatched_bits;

        // Fixed: changed `c(GVR_A)` to `cfg(GVR_A)`
        let validation_result =
            validate_light_client_update(&store, &u, 41, &cfg(GVR_A), &Mock::ok());
        assert_eq!(
            validation_result,
            Err(Error::CommitteeSizeMismatch),
            "Mismatched bitfield lengths must be rejected"
        );
    }

    #[test]
    fn test_safety_threshold_arithmetic_precision() {
        let store = LightClientStore {
            finalized_header: BeaconBlockHeader::default(),
            current_sync_committee: committee(1),
            next_sync_committee: committee(2),
            optimistic_header: BeaconBlockHeader::default(),
            previous_max_active_participants: 30,
            current_max_active_participants: 50,
            best_valid_update: None,
        };

        // max(30, 50) / 2 = 25. Guards against integer division or operator mutations.
        assert_eq!(store.safety_threshold(), 25);
    }

    #[test]
    fn fork_digests_match_known_mainnet_values() {
        let gvr: Bytes32 = [
            0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f,
            0xdd, 0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f,
            0x51, 0x1b, 0xfe, 0x95,
        ];
        assert_eq!(
            compute_fork_digest([3, 0, 0, 0], &gvr),
            [0xbb, 0xa4, 0xda, 0x96]
        ); // capella
        assert_eq!(
            compute_fork_digest([4, 0, 0, 0], &gvr),
            [0x6a, 0x95, 0xa1, 0xa9]
        ); // deneb
        assert_eq!(
            compute_fork_digest([5, 0, 0, 0], &gvr),
            [0xad, 0x53, 0x2c, 0xeb]
        ); // electra
    }

    #[test]
    fn fork_schedule_picks_latest_fork_at_epoch() {
        let s = ForkSchedule::new(&[(0, [0, 0, 0, 0]), (10, [1, 0, 0, 0]), (20, [2, 0, 0, 0])])
            .unwrap();
        assert_eq!(s.version_at_epoch(0), [0, 0, 0, 0]);
        assert_eq!(s.version_at_epoch(9), [0, 0, 0, 0]);
        assert_eq!(s.version_at_epoch(10), [1, 0, 0, 0]);
        assert_eq!(s.version_at_epoch(1_000), [2, 0, 0, 0]);
        assert!(ForkSchedule::new(&[]).is_err());
        assert!(ForkSchedule::new(&[(5, [0; 4]), (1, [1; 4])]).is_err());
    }

    #[test]
    fn valid_finality_and_committee_update_applies() {
        let f = fixture();
        let mut store = f.store.clone();
        let bls = Mock::ok();
        process_light_client_update(&mut store, &upd(&f, 41), 41, &cfg(GVR_A), &bls).unwrap();
        assert_eq!(store.finalized_header.slot, 24);
        assert_eq!(store.optimistic_header.slot, 40);
        assert!(store.is_next_sync_committee_known());
        assert_eq!(store.next_sync_committee, f.next);
        assert_eq!(store.current_max_active_participants, N as u64);
        assert_eq!(bls.seen.borrow().len(), 1);
        // same period => verified against the CURRENT committee, not the (empty) next one
        assert_eq!(
            bls.keys.borrow()[0],
            f.store.current_sync_committee.keys()[0]
        );
        // spec: best_valid_update is cleared after a normal apply
        assert!(store.best_valid_update.is_none());
    }

    #[test]
    fn signature_failure_is_rejected_and_store_untouched() {
        let f = fixture();
        let mut store = f.store.clone();
        let e =
            process_light_client_update(&mut store, &upd(&f, 41), 41, &cfg(GVR_A), &Mock::reject())
                .unwrap_err();
        assert_eq!(e, Error::BadSignature);
        assert_eq!(store.finalized_header, f.store.finalized_header);
        assert!(!store.is_next_sync_committee_known());
    }

    #[test]
    fn chain_binding_changes_the_signing_root() {
        let f = fixture();
        // Signing root a verifier configured for chain A would accept:
        let dom_a = compute_domain(DOMAIN_SYNC_COMMITTEE, FORK_V, &GVR_A);
        let want_a = compute_signing_root(&f.att.hash_tree_root(), &dom_a);
        let mut s = f.store.clone();
        assert!(process_light_client_update(
            &mut s,
            &upd(&f, 41),
            41,
            &cfg(GVR_A),
            &Mock::expecting(want_a)
        )
        .is_ok());
        // same update, verifier configured for another genesis_validators_root => rejected
        let mut s = f.store.clone();
        assert_eq!(
            process_light_client_update(
                &mut s,
                &upd(&f, 41),
                41,
                &cfg(GVR_B),
                &Mock::expecting(want_a)
            )
            .unwrap_err(),
            Error::BadSignature
        );
        // same update, other fork version => rejected
        let mut c = cfg(GVR_A);
        c.forks = ForkSchedule::single([0x06, 0, 0, 1]);
        let mut s = f.store.clone();
        assert_eq!(
            process_light_client_update(&mut s, &upd(&f, 41), 41, &c, &Mock::expecting(want_a))
                .unwrap_err(),
            Error::BadSignature
        );
    }

    #[test]
    fn fork_version_comes_from_signature_slot_minus_one() {
        let f = fixture();
        let mut c = cfg(GVR_A);
        // fork boundary at epoch 5 (slot 40): signature_slot 41 -> slot 40 -> epoch 5 => new version
        c.forks = ForkSchedule::new(&[(0, [1, 0, 0, 1]), (5, [2, 0, 0, 1]), (100, [3, 0, 0, 1])])
            .unwrap();
        let bls = Mock::ok();
        let mut s = f.store.clone();
        process_light_client_update(&mut s, &upd(&f, 41), 41, &c, &bls).unwrap();
        let want = compute_signing_root(
            &f.att.hash_tree_root(),
            &compute_domain(DOMAIN_SYNC_COMMITTEE, [2, 0, 0, 1], &GVR_A),
        );
        assert_eq!(bls.seen.borrow()[0].0, want);
    }

    // ---- one named rejection per spec assert; all start from the same passing baseline ----

    fn validate_fx(f: &Fx, u: &LightClientUpdate, current_slot: u64) -> Result<(), Error> {
        validate_light_client_update(&f.store, u, current_slot, &cfg(GVR_A), &Mock::ok())
    }

    #[test]
    fn baseline_validates() {
        // Guards every rejection test below: if the baseline stops passing, a "rejection"
        // could be a broken fixture rather than the check under test.
        let f = fixture();
        assert_eq!(validate_fx(&f, &upd(&f, 41), 41), Ok(()));
    }

    #[test]
    fn zero_participants_rejected() {
        let f = fixture();
        let zero = vec![0u8; N / 8];
        let mut u = upd(&f, 41);
        u.sync_committee_bits = &zero;
        assert_eq!(
            validate_fx(&f, &u, 41),
            Err(Error::InsufficientParticipants)
        );
    }

    #[test]
    fn committee_size_mismatch_rejected() {
        let f = fixture();
        let short = vec![0xFFu8; 2];
        let mut u = upd(&f, 41);
        u.sync_committee_bits = &short;
        assert_eq!(validate_fx(&f, &u, 41), Err(Error::CommitteeSizeMismatch));
    }

    #[test]
    fn signature_slot_not_after_attested_rejected() {
        let f = fixture();
        // signature_slot == attested_slot
        assert_eq!(validate_fx(&f, &upd(&f, 40), 41), Err(Error::BadSlotOrder));
    }

    #[test]
    fn current_slot_before_signature_slot_rejected() {
        let f = fixture();
        assert_eq!(validate_fx(&f, &upd(&f, 41), 40), Err(Error::BadSlotOrder));
    }

    #[test]
    fn finalized_after_attested_rejected() {
        let f = fixture();
        let mut u = upd(&f, 41);
        u.finalized_header.slot = 41;
        assert_eq!(validate_fx(&f, &u, 41), Err(Error::BadSlotOrder));
    }

    #[test]
    fn skipped_period_rejected() {
        // signature in period 2 (slot 128+) while store period is 0 and next committee unknown
        let f = fixture();
        assert_eq!(
            validate_fx(&f, &upd(&f, 130), 130),
            Err(Error::PeriodSkipped)
        );
    }

    #[test]
    fn stale_update_not_relevant_rejected() {
        // attested slot == store finalized slot (8), no next committee on offer
        let f = fixture();
        let empty = SyncCommittee::empty(N);
        let zeros7 = vec![ZERO; 7];
        let zeros6 = vec![ZERO; 6];
        let u = LightClientUpdate {
            attested_header: hdr(8, leaf_n(400), 8),
            next_sync_committee: &empty,
            next_sync_committee_branch: &zeros6,
            finalized_header: BeaconBlockHeader::default(),
            finality_branch: &zeros7,
            sync_committee_bits: &f.bits,
            sync_committee_signature: [7u8; 96],
            signature_slot: 41,
        };
        assert_eq!(validate_fx(&f, &u, 41), Err(Error::UpdateNotRelevant));
    }

    #[test]
    fn bad_finality_branch_rejected() {
        let f = fixture();
        let mut bad = f.finality_branch.clone();
        bad[3][0] ^= 1;
        let mut u = upd(&f, 41);
        u.finality_branch = &bad;
        assert_eq!(validate_fx(&f, &u, 41), Err(Error::InvalidBranch));
    }

    #[test]
    fn bad_next_committee_branch_rejected() {
        let f = fixture();
        let mut bad = f.next_branch.clone();
        bad[0][0] ^= 1;
        let mut u = upd(&f, 41);
        u.next_sync_committee_branch = &bad;
        assert_eq!(validate_fx(&f, &u, 41), Err(Error::InvalidBranch));
    }

    #[test]
    fn swapped_next_committee_rejected() {
        // right branch, wrong committee: the root no longer matches the attested state
        let f = fixture();
        let other = committee(5);
        let mut u = upd(&f, 41);
        u.next_sync_committee = &other;
        assert_eq!(validate_fx(&f, &u, 41), Err(Error::InvalidBranch));
    }

    #[test]
    fn finalized_header_not_empty_rejected() {
        // no finality branch but a non-empty finalized header
        let f = fixture();
        let zeros = vec![ZERO; 7];
        let mut u = upd(&f, 41);
        u.finality_branch = &zeros;
        assert_eq!(validate_fx(&f, &u, 41), Err(Error::FinalizedHeaderNotEmpty));
    }

    #[test]
    fn next_committee_not_empty_rejected() {
        // no next-committee branch but a non-empty next committee
        let f = fixture();
        let zeros6 = vec![ZERO; 6];
        let mut u = upd(&f, 41);
        u.next_sync_committee_branch = &zeros6;
        assert_eq!(validate_fx(&f, &u, 41), Err(Error::NextCommitteeNotEmpty));
    }

    #[test]
    fn replayed_update_does_not_double_apply() {
        // Spec behaviour: a replay whose attested slot is still newer than the store's
        // finalized header is *valid* (so it is NOT UpdateNotRelevant), but it must change
        // nothing that matters: no second apply, no committee rotation, no finalized move.
        let f = fixture();
        let c = cfg(GVR_A);
        let mut store = f.store.clone();
        process_light_client_update(&mut store, &upd(&f, 41), 41, &c, &Mock::ok()).unwrap();
        let (fin, cur, next, opt, max) = (
            store.finalized_header,
            store.current_sync_committee.clone(),
            store.next_sync_committee.clone(),
            store.optimistic_header,
            store.current_max_active_participants,
        );
        assert_eq!(
            process_light_client_update(&mut store, &upd(&f, 41), 41, &c, &Mock::ok()),
            Ok(())
        );
        assert_eq!(store.finalized_header, fin);
        assert_eq!(store.current_sync_committee, cur);
        assert_eq!(store.next_sync_committee, next);
        assert_eq!(store.optimistic_header, opt);
        assert_eq!(store.current_max_active_participants, max);
    }

    #[test]
    fn has_supermajority_boundaries() {
        // 24-bit field: exactly 2/3 = 16 set bits
        let at = |set: usize| {
            let mut b = vec![0u8; 3];
            for i in 0..set {
                b[i / 8] |= 1 << (i % 8);
            }
            b
        };
        assert!(has_supermajority(&at(16)), "exactly 2/3 counts");
        assert!(!has_supermajority(&at(15)), "one short of 2/3 does not");
        assert!(has_supermajority(&at(24)));
        assert!(!has_supermajority(&at(0)));
        // 32-bit minimal committee: 22 -> 66 >= 64, 21 -> 63 < 64
        assert!(has_supermajority(&bits(22)));
        assert!(!has_supermajority(&bits(21)));
        // fail closed on an empty bitfield
        assert!(!has_supermajority(&[]));
    }

    #[test]
    fn weak_subjectivity_period_returns_checkpoint_stale() {
        let f = fixture(); // store finalized at slot 8 => period 0 (64-slot periods)
        let (spe, epp) = (SPE, EPP);
        // limit is 4 periods
        assert_eq!(
            f.store
                .assert_within_weak_subjectivity_period(4 * 64, spe, epp),
            Ok(())
        );
        assert_eq!(
            f.store
                .assert_within_weak_subjectivity_period(5 * 64, spe, epp),
            Err(Error::CheckpointStale)
        );
        // a zero period length is a config error, not a divide-by-zero panic
        assert_eq!(
            f.store.assert_within_weak_subjectivity_period(100, 0, epp),
            Err(Error::BadConfig)
        );
    }

    // ---- chain binding -------------------------------------------------------------------

    #[test]
    fn chain_binding_digest_changes_with_each_field() {
        let base = cfg(GVR_A).binding(1);
        assert_eq!(
            base.digest(),
            cfg(GVR_A).binding(1).digest(),
            "deterministic"
        );

        let mut v = vec![];
        v.push(cfg(GVR_A).binding(2)); // chain_id only
        v.push(cfg(GVR_B).binding(1)); // gvr only
        let mut c = cfg(GVR_A);
        c.forks = ForkSchedule::single([0x06, 0, 0, 1]);
        v.push(c.binding(1)); // fork version only
        let mut c = cfg(GVR_A);
        c.chain.slots_per_epoch = SPE + 1;
        v.push(c.binding(1)); // slots_per_epoch only
        let mut c = cfg(GVR_A);
        c.epochs_per_period = EPP + 1;
        v.push(c.binding(1)); // epochs_per_period only
        for (i, b) in v.iter().enumerate() {
            assert_ne!(
                b.digest(),
                base.digest(),
                "field {i} not covered by the digest"
            );
        }
    }

    #[test]
    fn chain_binding_check_flags_mismatch() {
        let expected = cfg(GVR_A).binding(1);
        assert_eq!(expected.check(&cfg(GVR_A).binding(1)), Ok(()));
        assert_eq!(
            expected.check_digest(&cfg(GVR_A).binding(1).digest()),
            Ok(())
        );
        // a label-only change (chain_id) is invisible to the guest but caught here
        assert_eq!(
            expected.check(&cfg(GVR_A).binding(2)),
            Err(Error::ChainMismatch)
        );
        assert_eq!(
            expected.check_digest(&cfg(GVR_A).binding(2).digest()),
            Err(Error::ChainMismatch)
        );
        assert_eq!(
            expected.check_digest(&cfg(GVR_B).binding(1).digest()),
            Err(Error::ChainMismatch)
        );
    }

    #[test]
    fn fork_schedule_hash_and_entries() {
        let a = ForkSchedule::new(&[(0, [0, 0, 0, 0]), (10, [1, 0, 0, 0])]).unwrap();
        assert_eq!(a.entries(), &[(0, [0, 0, 0, 0]), (10, [1, 0, 0, 0])]);
        assert_eq!(a.hash(), a.hash());
        let b = ForkSchedule::new(&[(0, [0, 0, 0, 0]), (11, [1, 0, 0, 0])]).unwrap();
        let c = ForkSchedule::new(&[(0, [0, 0, 0, 0]), (10, [2, 0, 0, 0])]).unwrap();
        assert_ne!(a.hash(), b.hash(), "epoch");
        assert_ne!(a.hash(), c.hash(), "version");
        // a trailing all-zero entry must not collide with a shorter schedule
        let s1 = ForkSchedule::single([1, 0, 0, 0]);
        let s2 = ForkSchedule::new(&[(0, [1, 0, 0, 0]), (0, [0, 0, 0, 0])]).unwrap();
        assert_ne!(s1.hash(), s2.hash(), "length");
        assert_eq!(s1.entries().len(), 1);
    }

    #[test]
    fn below_two_thirds_updates_optimistic_but_not_finalized() {
        let f = fixture();
        let mut store = f.store.clone();
        let b = bits(12); // 12/32 < 2/3 but > safety threshold (12/2 = 6)
        let mut u = upd(&f, 41);
        u.sync_committee_bits = &b;
        process_light_client_update(&mut store, &u, 41, &cfg(GVR_A), &Mock::ok()).unwrap();
        assert_eq!(store.finalized_header.slot, 8);
        assert_eq!(store.optimistic_header.slot, 40);
        assert_eq!(store.current_max_active_participants, 12);
        assert!(!store.is_next_sync_committee_known());
        assert!(store.best_valid_update.is_some());
    }

    #[test]
    fn force_update_waits_for_update_timeout_then_applies_best() {
        let f = fixture();
        let c = cfg(GVR_A);
        let mut store = f.store.clone();
        let b = bits(12); // below 2/3 => not applied, but tracked as best
        let mut u = upd(&f, 41);
        u.sync_committee_bits = &b;
        process_light_client_update(&mut store, &u, 41, &c, &Mock::ok()).unwrap();
        assert_eq!(store.finalized_header.slot, 8);

        // UPDATE_TIMEOUT = 8 * 8 = 64; finalized 8 + 64 = 72 -> not yet (strictly greater)
        store.force_update(72, &c).unwrap();
        assert_eq!(store.finalized_header.slot, 8);
        assert!(store.best_valid_update.is_some());

        store.force_update(73, &c).unwrap();
        assert_eq!(store.finalized_header.slot, 24);
        assert!(store.is_next_sync_committee_known());
        assert!(store.best_valid_update.is_none());
    }

    #[test]
    fn force_update_treats_attested_as_finalized_when_no_progress() {
        let f = fixture();
        let c = cfg(GVR_A);
        let mut store = f.store.clone();
        // best whose finalized header is not newer than the store's
        let mut best = OwnedLightClientUpdate::from_borrowed(&upd(&f, 41)).unwrap();
        best.finalized_header = store.finalized_header;
        store.best_valid_update = Some(best);
        store.force_update(8 + 64 + 1, &c).unwrap();
        assert_eq!(store.finalized_header.slot, 40); // attested became finalized
    }

    #[test]
    fn is_better_update_follows_spec_order() {
        let f = fixture();
        let c = cfg(GVR_A);
        let full = upd(&f, 41);
        let few_bits = bits(12);
        let mut few = upd(&f, 41);
        few.sync_committee_bits = &few_bits;
        // supermajority beats non-supermajority, never the reverse
        assert!(is_better_update(&full, &few, &c));
        assert!(!is_better_update(&few, &full, &c));
        // identical updates: not strictly better
        assert!(!is_better_update(&full, &full, &c));
        // same everything but older signature slot wins the final tie-break
        assert!(is_better_update(&upd(&f, 41), &upd(&f, 42), &c));
        // finality beats no finality (both supermajority, both "relevant")
        let zeros = vec![ZERO; 7];
        let mut nofin = upd(&f, 41);
        nofin.finality_branch = &zeros;
        nofin.finalized_header = BeaconBlockHeader::default();
        assert!(is_better_update(&full, &nofin, &c));
        assert!(!is_better_update(&nofin, &full, &c));
    }

    #[test]
    fn known_next_committee_must_match_and_period_handoff_rotates() {
        let f = fixture();
        let c = cfg(GVR_A);
        let mut store = f.store.clone();
        process_light_client_update(&mut store, &upd(&f, 41), 41, &c, &Mock::ok()).unwrap();

        // a later update in the same period offering a DIFFERENT next committee is rejected
        let other = committee(6);
        let fin2 = hdr(40, leaf_n(301), 4);
        let st2 = state(fin2.hash_tree_root(), &committee(1), &other);
        let att2 = hdr(56, st2.root, 5);
        let b = bits(N);
        let u2 = LightClientUpdate {
            attested_header: att2,
            next_sync_committee: &other,
            next_sync_committee_branch: &st2.next_branch,
            finalized_header: fin2,
            finality_branch: &st2.finality_branch,
            sync_committee_bits: &b,
            sync_committee_signature: [0; 96],
            signature_slot: 57,
        };
        assert_eq!(
            validate_light_client_update(&store, &u2, 57, &c, &Mock::ok()),
            Err(Error::NextCommitteeMismatch)
        );

        // handoff: attested/finalized in period 1 (slots 64..127), signed by `next` (committee B)
        let c3 = committee(7);
        let fin3 = hdr(72, leaf_n(302), 6);
        let st3 = state(fin3.hash_tree_root(), &f.next, &c3);
        let att3 = hdr(88, st3.root, 7);
        let u3 = LightClientUpdate {
            attested_header: att3,
            next_sync_committee: &c3,
            next_sync_committee_branch: &st3.next_branch,
            finalized_header: fin3,
            finality_branch: &st3.finality_branch,
            sync_committee_bits: &b,
            sync_committee_signature: [0; 96],
            signature_slot: 89,
        };
        let bls = Mock::ok();
        process_light_client_update(&mut store, &u3, 89, &c, &bls).unwrap();
        assert_eq!(store.finalized_header.slot, 72);
        assert_eq!(store.current_sync_committee, f.next); // B became current
        assert_eq!(store.next_sync_committee, c3);
        assert_eq!(store.previous_max_active_participants, N as u64);
        assert_eq!(store.current_max_active_participants, 0);
        // and it was verified against committee B's keys (signature period 1 => store.next at check time)
        assert_eq!(bls.seen.borrow()[0].1, N);
        assert_eq!(
            bls.keys.borrow()[0],
            f.next.keys()[0],
            "must be committee B, not A"
        );
    }

    #[test]
    fn bad_config_is_refused() {
        let f = fixture();
        let mut c = cfg(GVR_A);
        c.epochs_per_period = 0;
        assert_eq!(
            validate_light_client_update(&f.store, &upd(&f, 41), 41, &c, &Mock::ok()),
            Err(Error::BadConfig)
        );
    }

    // ---- mutation hardening, round 2 (each test names the mutants it exists to kill) ----------

    #[test]
    fn capacity_constants_are_pinned() {
        // `MAX_SYNC_COMMITTEE_SIZE / 8` -> `* 8` still compiles and only loosens a bound.
        assert_eq!(MAX_BITS_LEN, 64);
        assert_eq!(MAX_BRANCH_LEN, 8);
    }

    fn from_borrowed_with(
        f: &Fx,
        next_br: &[Bytes32],
        fin_br: &[Bytes32],
        bits: &[u8],
    ) -> Result<(), Error> {
        let mut u = upd(f, 41);
        u.next_sync_committee_branch = next_br;
        u.finality_branch = fin_br;
        u.sync_committee_bits = bits;
        OwnedLightClientUpdate::from_borrowed(&u).map(|_| ())
    }

    #[test]
    fn from_borrowed_accepts_exact_capacity_and_rejects_one_over_per_field() {
        let f = fixture();
        let (br_ok, br_big) = ([ZERO; 8], [ZERO; 9]);
        let (bits_ok, bits_big) = ([0u8; 64], [0u8; 65]);
        assert_eq!(from_borrowed_with(&f, &br_ok, &br_ok, &bits_ok), Ok(()));
        // exactly one operand over its limit, the other two at theirs
        assert_eq!(
            from_borrowed_with(&f, &br_big, &br_ok, &bits_ok),
            Err(Error::BadConfig)
        );
        assert_eq!(
            from_borrowed_with(&f, &br_ok, &br_big, &bits_ok),
            Err(Error::BadConfig)
        );
        assert_eq!(
            from_borrowed_with(&f, &br_ok, &br_ok, &bits_big),
            Err(Error::BadConfig)
        );
    }

    #[test]
    fn committee_is_empty_only_when_aggregate_and_every_key_are_zero() {
        assert!(SyncCommittee::empty(N).is_empty());
        let mut only_agg = SyncCommittee::empty(N);
        only_agg.aggregate_pubkey = [1u8; 48];
        assert!(!only_agg.is_empty(), "non-zero aggregate, zero keys");
        let mut only_key = SyncCommittee::empty(N);
        only_key.pubkeys[N - 1] = [1u8; 48];
        assert!(!only_key.is_empty(), "zero aggregate, one non-zero key");
        assert!(!committee(1).is_empty());
    }

    #[test]
    fn execution_branch_verifies_against_body_root_and_rejects_tamper() {
        // BeaconBlockBody (Capella+): 16 field chunks, execution_payload = field 9 => gindex 25.
        let payload = leaf_n(9_001);
        let mut fields: Vec<Bytes32> = (0..16).map(|i| leaf_n(7_000 + i)).collect();
        fields[9] = payload;
        let l = levels(fields);
        let br = branch(&l, 9);
        assert_eq!(br.len(), 4);
        let mut h = hdr(1, leaf_n(1), 1);
        h.body_root = l.last().unwrap()[0];
        assert_eq!(verify_execution_branch(&h, &br, &payload), Ok(()));
        let mut bad = br.clone();
        bad[0][0] ^= 1;
        assert_eq!(
            verify_execution_branch(&h, &bad, &payload),
            Err(Error::InvalidBranch)
        );
        assert_eq!(
            verify_execution_branch(&h, &br, &leaf_n(9_002)),
            Err(Error::InvalidBranch)
        );
    }

    #[test]
    fn size_check_rejects_each_mismatching_operand_independently() {
        let f = fixture(); // store committees: N = 32
        let next64 = SyncCommittee::empty(64);
        let b64 = vec![0xFFu8; 8];
        // bits and next agree with each other (64) but not with the store
        let mut u = upd(&f, 41);
        u.sync_committee_bits = &b64;
        u.next_sync_committee = &next64;
        assert_eq!(validate_fx(&f, &u, 41), Err(Error::CommitteeSizeMismatch));
        // bits agree with the store (32) but not with the update's next committee
        let mut u = upd(&f, 41);
        u.next_sync_committee = &next64;
        assert_eq!(validate_fx(&f, &u, 41), Err(Error::CommitteeSizeMismatch));
        // empty bitfield
        let mut u = upd(&f, 41);
        u.sync_committee_bits = &[];
        assert_eq!(validate_fx(&f, &u, 41), Err(Error::CommitteeSizeMismatch));
    }

    #[test]
    fn a_single_participant_meets_the_minimum() {
        let f = fixture();
        let b = bits(1);
        let mut u = upd(&f, 41);
        u.sync_committee_bits = &b;
        assert_eq!(validate_fx(&f, &u, 41), Ok(()));
    }

    /// A sync-committee-only update (no finality), attested at `att_slot`, carrying `f.next`.
    fn next_only<'a>(f: &'a Fx, st: &'a State, att_slot: u64) -> LightClientUpdate<'a> {
        static ZEROS: [Bytes32; 7] = [ZERO; 7];
        LightClientUpdate {
            attested_header: hdr(att_slot, st.root, 5),
            next_sync_committee: &f.next,
            next_sync_committee_branch: &st.next_branch,
            finalized_header: BeaconBlockHeader::default(),
            finality_branch: &ZEROS,
            sync_committee_bits: &f.bits,
            sync_committee_signature: [7u8; 96],
            signature_slot: att_slot + 1,
        }
    }

    #[test]
    fn first_update_carrying_the_next_committee_is_relevant_even_if_not_newer() {
        let f = fixture(); // store finalized at 8, next committee unknown
        let st = state(leaf_n(1), &committee(1), &f.next);
        // attested slot 8 is NOT newer than the store's finalized slot 8; only `has_next` admits it
        let u = next_only(&f, &st, 8);
        assert_eq!(validate_fx(&f, &u, 9), Ok(()));
    }

    #[test]
    fn once_the_next_committee_is_known_a_non_newer_update_is_not_relevant() {
        let f = fixture();
        let c = cfg(GVR_A);
        let mut store = f.store.clone();
        process_light_client_update(&mut store, &upd(&f, 41), 41, &c, &Mock::ok()).unwrap();
        assert!(store.is_next_sync_committee_known());
        assert_eq!(store.finalized_header.slot, 24);
        // attested slot 24 == store finalized 24, same next committee, same period
        let st = state(leaf_n(1), &committee(1), &f.next);
        let u = next_only(&f, &st, 24);
        assert_eq!(
            validate_light_client_update(&store, &u, 25, &c, &Mock::ok()),
            Err(Error::UpdateNotRelevant)
        );
    }

    #[test]
    fn fork_version_uses_epoch_division_not_multiplication() {
        // Covered by the 3-fork schedule in `fork_version_comes_from_signature_slot_minus_one`;
        // this asserts the same property at a second slot so the two cannot drift together.
        let f = fixture();
        let mut c = cfg(GVR_A);
        c.forks = ForkSchedule::new(&[(0, [1, 0, 0, 1]), (5, [2, 0, 0, 1]), (100, [3, 0, 0, 1])])
            .unwrap();
        let bls = Mock::ok();
        let mut s = f.store.clone();
        process_light_client_update(&mut s, &upd(&f, 41), 41, &c, &bls).unwrap();
        let v2 = compute_signing_root(
            &f.att.hash_tree_root(),
            &compute_domain(DOMAIN_SYNC_COMMITTEE, [2, 0, 0, 1], &GVR_A),
        );
        let v3 = compute_signing_root(
            &f.att.hash_tree_root(),
            &compute_domain(DOMAIN_SYNC_COMMITTEE, [3, 0, 0, 1], &GVR_A),
        );
        assert_eq!(bls.seen.borrow()[0].0, v2);
        assert_ne!(bls.seen.borrow()[0].0, v3);
    }

    #[test]
    fn apply_advances_finalized_strictly_and_drags_optimistic_only_when_behind() {
        let f = fixture();
        let c = cfg(GVR_A);
        // (a) finalized moves 8 -> 24 and optimistic (8) is behind it: both advance
        let mut s = f.store.clone();
        apply_light_client_update(&mut s, &upd(&f, 41), &c).unwrap();
        assert_eq!(s.finalized_header.slot, 24);
        assert_eq!(s.optimistic_header.slot, 24);
        assert!(s.is_next_sync_committee_known());
        // (b) optimistic already AT the new finalized slot (different header): left alone
        let other_opt = hdr(24, leaf_n(999), 77);
        let mut s = f.store.clone();
        s.optimistic_header = other_opt;
        apply_light_client_update(&mut s, &upd(&f, 41), &c).unwrap();
        assert_eq!(s.finalized_header.slot, 24);
        assert_eq!(s.optimistic_header, other_opt);
        // (c) store already finalized AT slot 24 (different header): not replaced
        let other_fin = hdr(24, leaf_n(998), 78);
        let mut s = f.store.clone();
        s.finalized_header = other_fin;
        apply_light_client_update(&mut s, &upd(&f, 41), &c).unwrap();
        assert_eq!(s.finalized_header, other_fin);
    }

    #[test]
    fn optimistic_header_needs_strictly_more_than_the_safety_threshold_and_a_newer_slot() {
        let f = fixture();
        let c = cfg(GVR_A);
        // (a) active == safety threshold: current_max = 24 => threshold 12; 12 is not > 12
        let mut s = f.store.clone();
        s.current_max_active_participants = 24;
        let b12 = bits(12);
        let mut u = upd(&f, 41);
        u.sync_committee_bits = &b12;
        process_light_client_update(&mut s, &u, 41, &c, &Mock::ok()).unwrap();
        assert_eq!(
            s.optimistic_header.slot, 8,
            "12 active is not > threshold 12"
        );
        // (b) plenty of participants but the attested header is OLDER than the optimistic one
        let mut s = f.store.clone();
        s.optimistic_header = hdr(50, leaf_n(1), 5);
        process_light_client_update(&mut s, &upd(&f, 41), 41, &c, &Mock::ok()).unwrap();
        assert_eq!(s.optimistic_header.slot, 50);
        // (c) same slot, different header: not replaced (strictly newer only)
        let same_slot = hdr(40, leaf_n(55), 56);
        let mut s = f.store.clone();
        s.optimistic_header = same_slot;
        process_light_client_update(&mut s, &upd(&f, 41), 41, &c, &Mock::ok()).unwrap();
        assert_eq!(s.optimistic_header, same_slot);
    }

    /// Builds an update from `st`, attested at 40 / signature 41, with the given pieces.
    fn finality_only<'a>(
        f: &'a Fx,
        fin: BeaconBlockHeader,
        st: &'a State,
        empty_next: &'a SyncCommittee,
    ) -> LightClientUpdate<'a> {
        static ZEROS6: [Bytes32; 6] = [ZERO; 6];
        let _ = f;
        LightClientUpdate {
            attested_header: hdr(40, st.root, 12),
            next_sync_committee: empty_next,
            next_sync_committee_branch: &ZEROS6,
            finalized_header: fin,
            finality_branch: &st.finality_branch,
            sync_committee_bits: &f.bits,
            sync_committee_signature: [7u8; 96],
            signature_slot: 41,
        }
    }

    #[test]
    fn apply_gate_when_next_committee_is_already_known_and_finalized_does_not_advance() {
        let f = fixture();
        let c = cfg(GVR_A);
        let mut store = f.store.clone();
        process_light_client_update(&mut store, &upd(&f, 41), 41, &c, &Mock::ok()).unwrap();
        assert!(store.is_next_sync_committee_known());
        // same period, sync-committee + finality update, finalized slot (24) == store's (24)
        let st = state(f.fin_hdr.hash_tree_root(), &committee(1), &f.next);
        let u = LightClientUpdate {
            attested_header: hdr(48, st.root, 9),
            next_sync_committee: &f.next,
            next_sync_committee_branch: &st.next_branch,
            finalized_header: f.fin_hdr,
            finality_branch: &st.finality_branch,
            sync_committee_bits: &f.bits,
            sync_committee_signature: [7u8; 96],
            signature_slot: 49,
        };
        process_light_client_update(&mut store, &u, 49, &c, &Mock::ok()).unwrap();
        // nothing to apply: the update stays as best_valid_update, it is NOT cleared
        assert!(store.best_valid_update.is_some());
        assert_eq!(store.finalized_header.slot, 24);
    }

    #[test]
    fn apply_gate_finality_only_update_that_does_not_advance_is_not_applied() {
        let f = fixture(); // next unknown, store finalized at slot 8
        let c = cfg(GVR_A);
        let fin8 = hdr(8, leaf_n(310), 11); // == store's finalized slot, different header
        let st = state(fin8.hash_tree_root(), &committee(1), &committee(2));
        let empty = SyncCommittee::empty(N);
        let u = finality_only(&f, fin8, &st, &empty);
        let mut store = f.store.clone();
        process_light_client_update(&mut store, &u, 41, &c, &Mock::ok()).unwrap();
        assert!(
            store.best_valid_update.is_some(),
            "must not be applied/cleared"
        );
        assert!(!store.is_next_sync_committee_known());
        assert_eq!(store.finalized_header.slot, 8);
    }

    #[test]
    fn apply_gate_committee_update_without_finality_is_not_applied() {
        let f = fixture(); // next unknown
        let c = cfg(GVR_A);
        let st = state(leaf_n(1), &committee(1), &f.next);
        let u = next_only(&f, &st, 40); // finalized header empty (slot 0, period 0 == att period)
        let mut store = f.store.clone();
        process_light_client_update(&mut store, &u, 41, &c, &Mock::ok()).unwrap();
        assert!(
            !store.is_next_sync_committee_known(),
            "no finality => nothing finalized"
        );
        assert!(store.best_valid_update.is_some());
    }

    #[test]
    fn apply_gate_finalized_next_committee_in_same_period_applies_without_slot_advance() {
        let f = fixture(); // next unknown, store finalized at slot 8 (period 0)
        let c = cfg(GVR_A);
        let fin8 = hdr(8, leaf_n(310), 11); // finalized slot == store's: only the flag can apply it
        let st = state(fin8.hash_tree_root(), &committee(1), &f.next);
        let u = LightClientUpdate {
            attested_header: hdr(40, st.root, 12),
            next_sync_committee: &f.next,
            next_sync_committee_branch: &st.next_branch,
            finalized_header: fin8,
            finality_branch: &st.finality_branch,
            sync_committee_bits: &f.bits,
            sync_committee_signature: [7u8; 96],
            signature_slot: 41,
        };
        let mut store = f.store.clone();
        process_light_client_update(&mut store, &u, 41, &c, &Mock::ok()).unwrap();
        assert!(store.is_next_sync_committee_known());
        assert_eq!(store.next_sync_committee, f.next);
        assert!(store.best_valid_update.is_none());
        assert_eq!(store.finalized_header.slot, 8);
    }

    fn drop_finality<'a>(u: &mut LightClientUpdate<'a>) {
        static ZEROS7: [Bytes32; 7] = [ZERO; 7];
        u.finality_branch = &ZEROS7;
        u.finalized_header = BeaconBlockHeader::default();
    }

    #[test]
    fn is_better_update_each_criterion_decides_on_its_own() {
        let f = fixture();
        let c = cfg(GVR_A);
        let (b12, b10, b30, b32) = (bits(12), bits(10), bits(30), bits(32));

        // 1. neither has a supermajority: more participants wins even over finality
        let mut few12 = upd(&f, 41);
        few12.sync_committee_bits = &b12;
        drop_finality(&mut few12);
        let mut few10 = upd(&f, 41);
        few10.sync_committee_bits = &b10;
        assert!(is_better_update(&few12, &few10, &c));
        assert!(!is_better_update(&few10, &few12, &c));

        // 2. both have a supermajority: participant count is NOT the first criterion
        //    (finality outranks it); 30 active + finality beats 32 active without
        let mut sm30 = upd(&f, 41);
        sm30.sync_committee_bits = &b30;
        let mut sm32_nofin = upd(&f, 41);
        sm32_nofin.sync_committee_bits = &b32;
        drop_finality(&mut sm32_nofin);
        assert!(is_better_update(&sm30, &sm32_nofin, &c));
        assert!(!is_better_update(&sm32_nofin, &sm30, &c));

        // 3. equal otherwise: more participants wins
        let mut sm32 = upd(&f, 41);
        sm32.sync_committee_bits = &b32;
        assert!(is_better_update(&sm32, &sm30, &c));
        assert!(!is_better_update(&sm30, &sm32, &c));

        // 4. relevance: sync-committee update with attested/signature in one period
        //    beats a non-sync-committee update, even if the latter signed earlier
        let mut nosync = upd(&f, 41);
        let zeros6 = vec![ZERO; 6];
        nosync.next_sync_committee_branch = &zeros6;
        let sync42 = upd(&f, 42);
        assert!(!is_better_update(&nosync, &sync42, &c));
        assert!(is_better_update(&sync42, &nosync, &c));
        //    and the period test itself: signature slot 65 is period 1, attested (40) period 0
        assert!(is_better_update(&upd(&f, 41), &upd(&f, 65), &c));
        assert!(!is_better_update(&upd(&f, 65), &upd(&f, 41), &c));

        // 5. finalized header in the attested period beats one that is not
        let mut off = upd(&f, 71);
        off.attested_header = hdr(70, f.att.state_root, 3); // period 1; finalized (24) is period 0
        assert!(is_better_update(&upd(&f, 41), &off, &c));
        assert!(!is_better_update(&off, &upd(&f, 41), &c));

        // 6. everything else equal: the OLDER attested header wins (signature slot equal)
        let x = upd(&f, 42);
        let mut y = upd(&f, 42);
        y.attested_header = hdr(41, f.att.state_root, 3);
        assert!(is_better_update(&x, &y, &c));
        assert!(!is_better_update(&y, &x, &c));
    }
}
