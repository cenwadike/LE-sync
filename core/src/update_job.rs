//! Staged light-client update (`no_std`, no alloc): one update, three steps, one job record
//! in between.
//!
//! The BLS check of an update (aggregate the participating keys, hash the message, two
//! pairings, final exponentiation) is the expensive part. This module splits it across three
//! transactions so each fits a per-transaction cycle cap:
//!
//! 1. `begin_update`: every non-BLS validity rule (`check_light_client_update`), then
//!    `StagedBls::prepare`. Produces an `UpdateJob` at `STEP_PREPARED`.
//! 2. `miller_update`: `StagedBls::miller` on the job's state. `STEP_PREPARED` ->
//!    `STEP_MILLER`.
//! 3. `finish_update`: the checks again, `StagedBls::finish` (final exponentiation and the
//!    comparison), then `accept_validated_update`. Returns the new store; on any error the
//!    caller's store is unchanged.
//!
//! The job binds the update (`update_digest`: the update's fields and the configuration it
//! was checked under) and the store (`store_digest`: the canonical `store_codec` bytes), so
//! `finish_update` refuses a different update (`JobMismatch`) or a store that moved on
//! (`StoreChanged`). Steps run in order or not at all (`WrongStep`).
//!
//! SECURITY: the job's `state` is NOT authenticated. The digests bind the job to its inputs
//! but nothing proves the bytes in `state` came from `prepare` / `miller`. A caller who can
//! write the job can make `finish` accept a forged signature. The job MUST live where only
//! this code can write it (a program-owned account), and every step MUST read it from there,
//! never from instruction data.
//!
//! ROOTED committees. A store whose committees are rooted (`store_codec` v2) keeps no keys. Its
//! update is begun with `begin_update_rooted`: the caller supplies the keys of the members that
//! did NOT sign (`AbsentKeys`), the backend checks each is a point on the curve and proves all
//! of them against the committee's keys root (`multiproof`), and the aggregate of the signers
//! is the committee's aggregate minus those keys. `miller_update` and `finish_update` are the
//! same for both kinds of store. The positions must be exactly the zero bits of the update's
//! participation bits (`multiproof::absent_matches_bits`), checked here, not left to a backend.
//!
//! The 2/3 participation gate is a `wire` policy (`process_update_strict`), not a spec rule,
//! so it is applied by the caller before `begin_update`. `best_valid_update` is not part of
//! the staged flow (see `store_codec`).

use crate::multiproof::absent_matches_bits;
use crate::store_codec::write_store;
use crate::sync::{
    accept_validated_update, check_light_client_update, Bls, BlsSignature, LightClientStore,
    LightClientUpdate, SignatureInputs, SyncCommittee, SyncConfig,
};
use crate::{BlsPubkey, Bytes32, Error, MAX_SYNC_COMMITTEE_SIZE};
use sha2::{Digest, Sha256};

/// Size of the opaque pairing state: 12 base-field elements of 48 bytes (an `Fp12`).
/// `prepare` stores its own, smaller, intermediate values in the same buffer.
pub const STATE_LEN: usize = 576;

/// Serialized `UpdateJob`: `step:1 || store_digest:32 || update_digest:32 || state:576`.
pub const JOB_LEN: usize = 1 + 32 + 32 + STATE_LEN;
const _: () = assert!(JOB_LEN == 641);

/// After `begin_update`.
pub const STEP_PREPARED: u8 = 1;
/// After `miller_update`.
pub const STEP_MILLER: u8 = 2;

/// Opaque pairing state shared by the three steps.
pub type StageState = [u8; STATE_LEN];

/// Words per supplied key: its uncompressed 96-byte point (the form `blst_p1_affine_serialize`
/// writes), cut into 4-byte groups, each read little-endian.
pub const KEY_WORDS: usize = 24;
/// Words per multiproof sibling: 32 bytes, in the same word order.
pub const NODE_WORDS: usize = 8;

/// The keys of the committee members that did not sign, as a rooted update supplies them.
/// Words, not bytes: an instruction is read and echoed per element, and four bytes to a word
/// costs a quarter as much.
#[derive(Clone, Copy, Debug)]
pub struct AbsentKeys<'a> {
    /// `KEY_WORDS` words per entry of `index`.
    pub keys: &'a [u32],
    /// Positions in the committee, strictly ascending: the zero bits of the update's bits.
    pub index: &'a [u16],
    /// Multiproof siblings, `NODE_WORDS` words each, in the order `multiproof` requires.
    pub proof: &'a [u32],
}

fn words_to_bytes<const N: usize>(words: &[u32]) -> [u8; N] {
    let mut b = [0u8; N];
    for (chunk, w) in b.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&w.to_le_bytes());
    }
    b
}

impl<'a> AbsentKeys<'a> {
    /// `keys` has `KEY_WORDS` words for every position and `proof` is whole siblings.
    pub fn well_formed(&self) -> bool {
        self.index.len().checked_mul(KEY_WORDS) == Some(self.keys.len())
            && self.proof.chunks_exact(NODE_WORDS).remainder().is_empty()
    }

    /// The uncompressed point of the `i`-th supplied key, `None` if there is none.
    pub fn key_bytes(&self, i: usize) -> Option<[u8; 96]> {
        let start = i.checked_mul(KEY_WORDS)?;
        let w = self.keys.get(start..start.checked_add(KEY_WORDS)?)?;
        Some(words_to_bytes(w))
    }

    /// The proof siblings in order. A trailing partial sibling is not returned.
    pub fn siblings(&self) -> impl Iterator<Item = Bytes32> + 'a {
        let proof = self.proof;
        proof.chunks_exact(NODE_WORDS).map(words_to_bytes::<32>)
    }
}

/// `Bls::fast_aggregate_verify` cut into three resumable stages. All three read and write
/// only `state`, so a stage can run in a different process from the one before it. Unused
/// bytes of `state` should be zero.
pub trait StagedBls {
    /// Decode the signature, aggregate the participating keys, hash the signing root to the
    /// curve; write what `miller` needs into `state`. `false` rejects the update.
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        &self,
        committee: &[BlsPubkey],
        aggregate_pubkey: &BlsPubkey,
        bits: &[u8],
        signing_root: &Bytes32,
        signature: &BlsSignature,
        state: &mut StageState,
    ) -> bool;

    /// The Miller loops: replace the prepared values in `state` with the Miller result.
    /// `false` rejects the update.
    fn miller(&self, state: &mut StageState) -> bool;

    /// Final exponentiation and the comparison with the identity. `true` only if the
    /// signature verifies.
    fn finish(&self, state: &StageState) -> bool;

    /// `prepare` for a ROOTED committee: no keys, only the root of the key tree, the committee
    /// size and the aggregate key, plus the keys of the members that did not sign. The caller
    /// (`begin_update_rooted`) has already checked that `absent` is well formed and lists
    /// exactly the zero bits of `bits`. The backend must (1) check every supplied key is a
    /// valid point, (2) prove the keys against `keys_root` with `multiproof::verify_multiproof`
    /// (leaf = `pubkey_root` of the key's compressed form), (3) aggregate: the committee's
    /// aggregate minus the supplied keys, and from there do what `prepare` does.
    /// `AbsentKeys` if the keys or proof are not acceptable, `BadSignature` for anything about
    /// the signature. Backends without rooted support keep this default and reject.
    #[allow(clippy::too_many_arguments)]
    fn prepare_rooted(
        &self,
        _keys_root: &Bytes32,
        _len: usize,
        _aggregate_pubkey: &BlsPubkey,
        _absent: &AbsentKeys,
        _bits: &[u8],
        _signing_root: &Bytes32,
        _signature: &BlsSignature,
        _state: &mut StageState,
    ) -> Result<(), Error> {
        Err(Error::AbsentKeys)
    }
}

/// Runs the three stages back to back, so a `StagedBls` also serves wherever a `Bls` is
/// expected (differential tests against the single-shot path).
pub struct Chained<'a, S: StagedBls>(pub &'a S);

impl<S: StagedBls> Bls for Chained<'_, S> {
    fn fast_aggregate_verify(
        &self,
        committee: &[BlsPubkey],
        aggregate_pubkey: &BlsPubkey,
        bits: &[u8],
        signing_root: &Bytes32,
        signature: &BlsSignature,
    ) -> bool {
        let mut state = [0u8; STATE_LEN];
        self.0.prepare(
            committee,
            aggregate_pubkey,
            bits,
            signing_root,
            signature,
            &mut state,
        ) && self.0.miller(&mut state)
            && self.0.finish(&state)
    }
}

/// The record carried between steps. See the module docs for the trust model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateJob {
    pub step: u8,
    pub store_digest: Bytes32,
    pub update_digest: Bytes32,
    pub state: StageState,
}

impl UpdateJob {
    pub fn to_bytes(&self) -> [u8; JOB_LEN] {
        let mut b = [0u8; JOB_LEN];
        b[0] = self.step;
        b[1..33].copy_from_slice(&self.store_digest);
        b[33..65].copy_from_slice(&self.update_digest);
        b[65..].copy_from_slice(&self.state);
        b
    }

    /// `JobMismatch` unless `bytes` is exactly `JOB_LEN` long and at a known step.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != JOB_LEN || !(bytes[0] == STEP_PREPARED || bytes[0] == STEP_MILLER) {
            return Err(Error::JobMismatch);
        }
        let mut store_digest = [0u8; 32];
        store_digest.copy_from_slice(&bytes[1..33]);
        let mut update_digest = [0u8; 32];
        update_digest.copy_from_slice(&bytes[33..65]);
        let mut state = [0u8; STATE_LEN];
        state.copy_from_slice(&bytes[65..]);
        Ok(Self {
            step: bytes[0],
            store_digest,
            update_digest,
            state,
        })
    }
}

/// `SHA256("LE_SYNC_STORE_V1" || store_codec v1 bytes)`. `StoreEncoding` if the store is not
/// encodable.
pub fn store_digest(store: &LightClientStore) -> Result<Bytes32, Error> {
    let mut h = Sha256::new();
    h.update(b"LE_SYNC_STORE_V1");
    write_store(store, |piece| h.update(piece))?;
    Ok(h.finalize().into())
}

fn put_header(h: &mut Sha256, x: &crate::BeaconBlockHeader) {
    h.update(x.slot.to_le_bytes());
    h.update(x.proposer_index.to_le_bytes());
    h.update(x.parent_root);
    h.update(x.state_root);
    h.update(x.body_root);
}

fn put_nodes(h: &mut Sha256, nodes: &[Bytes32]) {
    h.update((nodes.len() as u32).to_le_bytes());
    for n in nodes {
        h.update(n);
    }
}

fn put_committee(h: &mut Sha256, c: &SyncCommittee) {
    // a rooted committee has no keys: marker (a length no full committee has), len, root, aggregate
    if let Some(root) = c.stored_keys_root() {
        h.update(u32::MAX.to_le_bytes());
        h.update((c.len as u32).to_le_bytes());
        h.update(root);
        h.update(c.aggregate_pubkey);
        return;
    }
    // `len` is a public field: clamp so a bogus value cannot index out of range.
    let n = c.len.min(MAX_SYNC_COMMITTEE_SIZE);
    h.update((c.len as u32).to_le_bytes());
    for k in &c.pubkeys[..n] {
        h.update(k);
    }
    h.update(c.aggregate_pubkey);
}

/// Digest of an update together with the configuration it is checked under:
///
/// ```text
/// SHA256("LE_SYNC_UPDATE_V1"
///   || SyncConfig::binding(0).digest():32 || electra_fork_epoch:u64
///   || gloas_tag:u8 (0 none, 1 some) || gloas_fork_epoch:u64 (0 if none)
///   || attested_header:112
///   || next_sync_committee: len:u32, len*pubkey:48, aggregate:48
///        (a rooted committee: 0xFFFFFFFF:u32, len:u32, keys_root:32, aggregate:48)
///   || next_sync_committee_branch: n:u32, n*32
///   || finalized_header:112
///   || finality_branch: n:u32, n*32
///   || bits: n:u32, n bytes
///   || signature:96 || signature_slot:u64)
/// ```
///
/// Integers are little-endian. `current_slot` is not included: it is a clock reading, and
/// every step re-checks it against the signature slot.
pub fn update_digest(update: &LightClientUpdate, cfg: &SyncConfig) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(b"LE_SYNC_UPDATE_V1");
    h.update(cfg.binding(0).digest());
    h.update(cfg.chain.electra_fork_epoch.to_le_bytes());
    h.update([cfg.chain.gloas_fork_epoch.is_some() as u8]);
    h.update(cfg.chain.gloas_fork_epoch.unwrap_or(0).to_le_bytes());
    put_header(&mut h, &update.attested_header);
    put_committee(&mut h, update.next_sync_committee);
    put_nodes(&mut h, update.next_sync_committee_branch);
    put_header(&mut h, &update.finalized_header);
    put_nodes(&mut h, update.finality_branch);
    h.update((update.sync_committee_bits.len() as u32).to_le_bytes());
    h.update(update.sync_committee_bits);
    h.update(update.sync_committee_signature);
    h.update(update.signature_slot.to_le_bytes());
    h.finalize().into()
}

/// Step 1. Runs every non-BLS rule against `store`, then `prepare`. Errors are those of
/// `validate_light_client_update`, with `BadSignature` if `prepare` rejects.
///
/// A store with rooted committees has no keys to aggregate: `AbsentKeys` (use
/// `begin_update_rooted`).
pub fn begin_update<B: StagedBls>(
    store: &LightClientStore,
    update: &LightClientUpdate,
    current_slot: u64,
    cfg: &SyncConfig,
    bls: &B,
) -> Result<UpdateJob, Error> {
    begin_with(store, update, current_slot, cfg, |inputs, state| {
        if inputs.committee.is_rooted() {
            return Err(Error::AbsentKeys);
        }
        if !bls.prepare(
            inputs.committee.keys(),
            &inputs.committee.aggregate_pubkey,
            update.sync_committee_bits,
            &inputs.signing_root,
            &update.sync_committee_signature,
            state,
        ) {
            return Err(Error::BadSignature);
        }
        Ok(())
    })
}

/// Step 1 for a store with ROOTED committees. The same rules as `begin_update`, then:
/// `AbsentKeys` unless the signing committee is rooted, `absent` is well formed and its
/// positions are exactly the zero bits of the update's participation bits; then
/// `StagedBls::prepare_rooted`, whose verdict (`AbsentKeys` or `BadSignature`) is returned.
pub fn begin_update_rooted<B: StagedBls>(
    store: &LightClientStore,
    update: &LightClientUpdate,
    absent: &AbsentKeys,
    current_slot: u64,
    cfg: &SyncConfig,
    bls: &B,
) -> Result<UpdateJob, Error> {
    begin_with(store, update, current_slot, cfg, |inputs, state| {
        let committee = inputs.committee;
        let Some(keys_root) = committee.stored_keys_root() else {
            return Err(Error::AbsentKeys);
        };
        if !absent.well_formed() || !absent_matches_bits(update.sync_committee_bits, absent.index) {
            return Err(Error::AbsentKeys);
        }
        bls.prepare_rooted(
            &keys_root,
            committee.len,
            &committee.aggregate_pubkey,
            absent,
            update.sync_committee_bits,
            &inputs.signing_root,
            &update.sync_committee_signature,
            state,
        )
    })
}

/// What both `begin_update` variants share: every non-BLS rule, the store digest, then
/// `prepare` (which fills `state` or fails), then the job.
fn begin_with(
    store: &LightClientStore,
    update: &LightClientUpdate,
    current_slot: u64,
    cfg: &SyncConfig,
    prepare: impl FnOnce(&SignatureInputs, &mut StageState) -> Result<(), Error>,
) -> Result<UpdateJob, Error> {
    let inputs = check_light_client_update(store, update, current_slot, cfg)?;
    let store_digest = store_digest(store)?;
    let mut state = [0u8; STATE_LEN];
    prepare(&inputs, &mut state)?;
    Ok(UpdateJob {
        step: STEP_PREPARED,
        store_digest,
        update_digest: update_digest(update, cfg),
        state,
    })
}

/// Step 2. `WrongStep` unless `job` is at `STEP_PREPARED`; `BadSignature` if `miller`
/// rejects. Needs neither the store nor the update: it only advances the pairing state.
pub fn miller_update<B: StagedBls>(job: &UpdateJob, bls: &B) -> Result<UpdateJob, Error> {
    if job.step != STEP_PREPARED {
        return Err(Error::WrongStep);
    }
    let mut state = job.state;
    if !bls.miller(&mut state) {
        return Err(Error::BadSignature);
    }
    Ok(UpdateJob {
        step: STEP_MILLER,
        state,
        ..job.clone()
    })
}

/// Step 3. In order: `WrongStep` unless `job` is at `STEP_MILLER`; `JobMismatch` if `update`
/// (or `cfg`) is not what the job was begun with; `StoreChanged` if `store` is not the store
/// it was begun against; then every non-BLS rule again (it may have been a while:
/// `current_slot` is re-checked); then `finish` (`BadSignature` if it rejects); then the
/// spec's apply step on a copy of `store`. The copy is returned; `store` is never modified.
pub fn finish_update<B: StagedBls>(
    job: &UpdateJob,
    store: &LightClientStore,
    update: &LightClientUpdate,
    current_slot: u64,
    cfg: &SyncConfig,
    bls: &B,
) -> Result<LightClientStore, Error> {
    if job.step != STEP_MILLER {
        return Err(Error::WrongStep);
    }
    if job.update_digest != update_digest(update, cfg) {
        return Err(Error::JobMismatch);
    }
    if job.store_digest != store_digest(store)? {
        return Err(Error::StoreChanged);
    }
    check_light_client_update(store, update, current_slot, cfg)?;
    if !bls.finish(&job.state) {
        return Err(Error::BadSignature);
    }
    let mut next = store.clone();
    accept_validated_update(&mut next, update, cfg)?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store_codec::{encode_store, MAX_ENCODED_LEN};
    use crate::sync::tests::{cfg, committee, fixture, upd, Fx, GVR_A, GVR_B, N};
    use crate::sync::{process_light_client_update, validate_light_client_update};
    use std::cell::RefCell;

    /// Which stage the mock rejects at (1 prepare, 2 miller, 3 finish), and a call log.
    struct Mock {
        fail_at: u8,
        calls: RefCell<Vec<&'static str>>,
        seen_root: RefCell<Option<Bytes32>>,
        seen_first_key: RefCell<Option<BlsPubkey>>,
        seen_bits: RefCell<Vec<u8>>,
        seen_sig: RefCell<Option<BlsSignature>>,
        seen_agg: RefCell<Option<BlsPubkey>>,
    }
    impl Mock {
        fn new(fail_at: u8) -> Self {
            Self {
                fail_at,
                calls: RefCell::new(vec![]),
                seen_root: RefCell::new(None),
                seen_first_key: RefCell::new(None),
                seen_bits: RefCell::new(vec![]),
                seen_sig: RefCell::new(None),
                seen_agg: RefCell::new(None),
            }
        }
        fn ok() -> Self {
            Self::new(0)
        }
        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }
    impl StagedBls for Mock {
        fn prepare(
            &self,
            committee: &[BlsPubkey],
            aggregate_pubkey: &BlsPubkey,
            bits: &[u8],
            signing_root: &Bytes32,
            signature: &BlsSignature,
            state: &mut StageState,
        ) -> bool {
            self.calls.borrow_mut().push("prepare");
            *self.seen_root.borrow_mut() = Some(*signing_root);
            *self.seen_first_key.borrow_mut() = Some(committee[0]);
            *self.seen_bits.borrow_mut() = bits.to_vec();
            *self.seen_sig.borrow_mut() = Some(*signature);
            *self.seen_agg.borrow_mut() = Some(*aggregate_pubkey);
            assert_eq!(committee.len(), bits.len() * 8);
            state[..32].copy_from_slice(signing_root);
            state[575] = 0x11;
            self.fail_at != 1
        }
        fn miller(&self, state: &mut StageState) -> bool {
            self.calls.borrow_mut().push("miller");
            // proves the state written by `prepare` reached this stage through the job bytes
            assert_eq!(state[575], 0x11);
            assert_eq!(&state[..32], self.seen_root.borrow().unwrap());
            state[575] = 0x22;
            state[100] = 0x77;
            self.fail_at != 2
        }
        fn finish(&self, state: &StageState) -> bool {
            self.calls.borrow_mut().push("finish");
            assert_eq!(state[575], 0x22);
            assert_eq!(state[100], 0x77);
            self.fail_at != 3
        }
    }

    fn enc(store: &LightClientStore) -> Vec<u8> {
        let mut out = vec![0u8; MAX_ENCODED_LEN];
        let n = encode_store(store, &mut out).unwrap();
        out.truncate(n);
        out
    }

    /// begin -> (through bytes) -> miller -> (through bytes) -> finish
    fn run_all(f: &Fx, bls: &Mock) -> Result<LightClientStore, Error> {
        let c = cfg(GVR_A);
        let u = upd(f, 41);
        let j1 = begin_update(&f.store, &u, 41, &c, bls)?;
        let j1 = UpdateJob::from_bytes(&j1.to_bytes())?;
        let j2 = miller_update(&j1, bls)?;
        let j2 = UpdateJob::from_bytes(&j2.to_bytes())?;
        finish_update(&j2, &f.store, &u, 41, &c, bls)
    }

    fn job_at_miller(f: &Fx) -> UpdateJob {
        let b = Mock::ok();
        let j = begin_update(&f.store, &upd(f, 41), 41, &cfg(GVR_A), &b).unwrap();
        miller_update(&j, &b).unwrap()
    }

    // ---- job record ---------------------------------------------------------------------

    #[test]
    fn job_is_641_bytes_with_a_fixed_layout() {
        assert_eq!(JOB_LEN, 641);
        assert_eq!(STATE_LEN, 576);
        let mut state = [0u8; STATE_LEN];
        for (i, b) in state.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let j = UpdateJob {
            step: STEP_MILLER,
            store_digest: [0xA1; 32],
            update_digest: [0xB2; 32],
            state,
        };
        let b = j.to_bytes();
        assert_eq!(b.len(), 641);
        assert_eq!(b[0], 2);
        assert_eq!(&b[1..33], &[0xA1; 32]);
        assert_eq!(&b[33..65], &[0xB2; 32]);
        assert_eq!(&b[65..], &state[..]);
        assert_eq!(UpdateJob::from_bytes(&b), Ok(j));
    }

    #[test]
    fn job_bytes_with_a_wrong_length_or_step_are_rejected() {
        let f = fixture();
        let j = job_at_miller(&f);
        let b = j.to_bytes();
        assert_eq!(UpdateJob::from_bytes(&b).unwrap().step, STEP_MILLER);
        assert_eq!(UpdateJob::from_bytes(&b[..640]), Err(Error::JobMismatch));
        assert_eq!(UpdateJob::from_bytes(&[]), Err(Error::JobMismatch));
        let mut longer = b.to_vec();
        longer.push(0);
        assert_eq!(UpdateJob::from_bytes(&longer), Err(Error::JobMismatch));
        for bad in [0u8, 3, 0xFF] {
            let mut c = b;
            c[0] = bad;
            assert_eq!(
                UpdateJob::from_bytes(&c),
                Err(Error::JobMismatch),
                "step {bad}"
            );
        }
        let mut c = b;
        c[0] = STEP_PREPARED;
        assert_eq!(UpdateJob::from_bytes(&c).unwrap().step, STEP_PREPARED);
    }

    // ---- the staged path equals the single-shot path -------------------------------------

    #[test]
    fn three_steps_equal_process_light_client_update() {
        let f = fixture();
        let mock = Mock::ok();
        let staged = run_all(&f, &mock).unwrap();
        assert_eq!(mock.calls(), ["prepare", "miller", "finish"]);

        let mut direct = f.store.clone();
        let one = Mock::ok();
        process_light_client_update(&mut direct, &upd(&f, 41), 41, &cfg(GVR_A), &Chained(&one))
            .unwrap();
        assert_eq!(enc(&staged), enc(&direct));
        assert_eq!(staged.finalized_header.slot, 24);
        assert_eq!(staged.optimistic_header.slot, 40);
        assert!(staged.is_next_sync_committee_known());
        assert_eq!(staged.next_sync_committee, f.next);
        assert_eq!(staged.current_max_active_participants, N as u64);
        assert!(staged.best_valid_update.is_none());
        // both paths hand the same inputs to the signature check
        assert_eq!(one.calls(), ["prepare", "miller", "finish"]);
        assert_eq!(*one.seen_root.borrow(), *mock.seen_root.borrow());
        assert_eq!(*one.seen_first_key.borrow(), *mock.seen_first_key.borrow());
        assert_eq!(*one.seen_bits.borrow(), *mock.seen_bits.borrow());
        assert_eq!(*one.seen_sig.borrow(), *mock.seen_sig.borrow());
        assert_eq!(*one.seen_agg.borrow(), *mock.seen_agg.borrow());
    }

    #[test]
    fn prepare_gets_the_current_committee_and_the_update_signature_inputs() {
        let f = fixture();
        let mock = Mock::ok();
        run_all(&f, &mock).unwrap();
        assert_eq!(
            *mock.seen_first_key.borrow(),
            Some(f.store.current_sync_committee.keys()[0])
        );
        assert_eq!(
            *mock.seen_agg.borrow(),
            Some(f.store.current_sync_committee.aggregate_pubkey)
        );
        assert_eq!(*mock.seen_bits.borrow(), f.bits);
        assert_eq!(*mock.seen_sig.borrow(), Some([7u8; 96]));
        let want = check_light_client_update(&f.store, &upd(&f, 41), 41, &cfg(GVR_A))
            .unwrap()
            .signing_root;
        assert_eq!(*mock.seen_root.borrow(), Some(want));
    }

    #[test]
    fn finish_does_not_modify_the_store_it_was_given() {
        let f = fixture();
        let before = enc(&f.store);
        let _ = run_all(&f, &Mock::ok()).unwrap();
        assert_eq!(enc(&f.store), before);
    }

    #[test]
    fn miller_keeps_the_digests_and_changes_only_step_and_state() {
        let f = fixture();
        let b = Mock::ok();
        let j1 = begin_update(&f.store, &upd(&f, 41), 41, &cfg(GVR_A), &b).unwrap();
        assert_eq!(j1.step, STEP_PREPARED);
        let j2 = miller_update(&j1, &b).unwrap();
        assert_eq!(j2.step, STEP_MILLER);
        assert_eq!(j2.store_digest, j1.store_digest);
        assert_eq!(j2.update_digest, j1.update_digest);
        assert_ne!(j2.state, j1.state);
        assert_eq!(j1.store_digest, store_digest(&f.store).unwrap());
        assert_eq!(j1.update_digest, update_digest(&upd(&f, 41), &cfg(GVR_A)));
    }

    // ---- begin: non-BLS rules first, and no BLS work for a rejected update -----------------

    #[test]
    fn begin_rejects_non_signature_failures_without_any_bls_work() {
        let f = fixture();
        let c = cfg(GVR_A);
        type Edit = fn(&mut LightClientUpdate);
        let cases: [(&str, Error, Edit); 3] = [
            ("zero participants", Error::InsufficientParticipants, |u| {
                u.sync_committee_bits = &[0, 0, 0, 0]
            }),
            ("wrong bitfield size", Error::CommitteeSizeMismatch, |u| {
                u.sync_committee_bits = &[0xFF, 0xFF]
            }),
            (
                "signature slot not after attested",
                Error::BadSlotOrder,
                |u| u.signature_slot = u.attested_header.slot,
            ),
        ];
        for (name, want, edit) in cases {
            let mut u = upd(&f, 41);
            edit(&mut u);
            let b = Mock::ok();
            assert_eq!(
                begin_update(&f.store, &u, 41, &c, &b).err(),
                Some(want),
                "{name}"
            );
            assert!(b.calls().is_empty(), "{name}: BLS ran");
            // and it is the very error the single-shot validation reports
            assert_eq!(
                validate_light_client_update(&f.store, &u, 41, &c, &Chained(&Mock::ok())),
                Err(want),
                "{name}"
            );
        }
        let mut bad_branch = f.finality_branch.clone();
        bad_branch[0][0] ^= 1;
        let mut u = upd(&f, 41);
        u.finality_branch = &bad_branch;
        let b = Mock::ok();
        assert_eq!(
            begin_update(&f.store, &u, 41, &c, &b).err(),
            Some(Error::InvalidBranch)
        );
        assert!(b.calls().is_empty());
    }

    #[test]
    fn begin_refuses_a_store_that_cannot_be_encoded() {
        let mut f = fixture();
        f.store.next_sync_committee.len = 16; // not the length of the current committee
        let b = Mock::ok();
        assert_eq!(
            begin_update(&f.store, &upd(&f, 41), 41, &cfg(GVR_A), &b).err(),
            Some(Error::StoreEncoding)
        );
        assert!(b.calls().is_empty());
    }

    // ---- ordering -------------------------------------------------------------------------

    #[test]
    fn steps_out_of_order_are_wrong_step_and_run_no_bls() {
        let f = fixture();
        let c = cfg(GVR_A);
        let b = Mock::ok();
        let prepared = begin_update(&f.store, &upd(&f, 41), 41, &c, &b).unwrap();
        let milled = miller_update(&prepared, &b).unwrap();
        let before = b.calls().len();
        // finish on a PREPARED job, miller on a MILLER job
        assert_eq!(
            finish_update(&prepared, &f.store, &upd(&f, 41), 41, &c, &b).err(),
            Some(Error::WrongStep)
        );
        assert_eq!(miller_update(&milled, &b).err(), Some(Error::WrongStep));
        assert_eq!(b.calls().len(), before);
        // a step byte nobody produces
        let mut odd = prepared.clone();
        odd.step = 9;
        assert_eq!(miller_update(&odd, &b).err(), Some(Error::WrongStep));
        assert_eq!(
            finish_update(&odd, &f.store, &upd(&f, 41), 41, &c, &b).err(),
            Some(Error::WrongStep)
        );
        // the right order still works
        assert!(finish_update(&milled, &f.store, &upd(&f, 41), 41, &c, &b).is_ok());
    }

    // ---- binding to the update and the configuration --------------------------------------

    #[test]
    fn finish_refuses_any_other_update() {
        let f = fixture();
        let c = cfg(GVR_A);
        let job = job_at_miller(&f);
        let b = Mock::ok();
        let ok = upd(&f, 41);
        assert!(finish_update(&job, &f.store, &ok, 41, &c, &b).is_ok());

        let other_branch = vec![[0x55u8; 32]; f.finality_branch.len()];
        let other_next_branch = vec![[0x56u8; 32]; f.next_branch.len()];
        let other_committee = committee(7);
        let other_bits = crate::sync::tests::bits(N - 1);
        let mut variants: Vec<(&str, LightClientUpdate)> = vec![];
        let mut v = upd(&f, 41);
        v.attested_header.proposer_index ^= 1;
        variants.push(("attested header", v));
        let mut v = upd(&f, 41);
        v.finalized_header.proposer_index ^= 1;
        variants.push(("finalized header", v));
        let mut v = upd(&f, 41);
        v.finality_branch = &other_branch;
        variants.push(("finality branch", v));
        let mut v = upd(&f, 41);
        v.next_sync_committee_branch = &other_next_branch;
        variants.push(("next committee branch", v));
        let mut v = upd(&f, 41);
        v.next_sync_committee = &other_committee;
        variants.push(("next committee", v));
        let mut v = upd(&f, 41);
        v.sync_committee_bits = &other_bits;
        variants.push(("bits", v));
        let mut v = upd(&f, 41);
        v.sync_committee_signature[95] ^= 1;
        variants.push(("signature", v));
        variants.push(("signature slot", upd(&f, 42)));
        for (name, v) in &variants {
            assert_eq!(
                finish_update(&job, &f.store, v, 42, &c, &b).err(),
                Some(Error::JobMismatch),
                "{name}"
            );
        }
    }

    #[test]
    fn finish_refuses_another_configuration() {
        let f = fixture();
        let job = job_at_miller(&f);
        let b = Mock::ok();
        let u = upd(&f, 41);
        let ok = cfg(GVR_A);
        assert!(finish_update(&job, &f.store, &u, 41, &ok, &b).is_ok());
        let mut others = vec![("genesis validators root", cfg(GVR_B))];
        let mut c = ok;
        c.chain.slots_per_epoch += 1;
        others.push(("slots per epoch", c));
        let mut c = ok;
        c.epochs_per_period += 1;
        others.push(("epochs per period", c));
        let mut c = ok;
        c.chain.electra_fork_epoch += 1;
        others.push(("electra epoch", c));
        let mut c = ok;
        c.chain.gloas_fork_epoch = Some(0);
        others.push(("gloas epoch some(0)", c));
        let mut c = ok;
        c.chain.gloas_fork_epoch = Some(1_000_000);
        others.push(("gloas epoch", c));
        let mut c = ok;
        c.forks = crate::sync::ForkSchedule::single([9, 9, 9, 9]);
        others.push(("fork schedule", c));
        for (name, c) in others {
            assert_eq!(
                finish_update(&job, &f.store, &u, 41, &c, &b).err(),
                Some(Error::JobMismatch),
                "{name}"
            );
        }
    }

    // ---- binding to the store ---------------------------------------------------------------

    #[test]
    fn finish_refuses_a_store_that_moved_on() {
        let f = fixture();
        let c = cfg(GVR_A);
        let job = job_at_miller(&f);
        let b = Mock::ok();
        let u = upd(&f, 41);
        // one store at a time: they are large, and a test thread's stack is small
        type StoreEdit = fn(&mut LightClientStore);
        let edits: [(&str, StoreEdit); 7] = [
            ("finalized header", |s| s.finalized_header.slot += 1),
            ("optimistic header", |s| s.optimistic_header.slot += 1),
            ("previous max", |s| s.previous_max_active_participants += 1),
            ("current max", |s| s.current_max_active_participants += 1),
            ("current committee key", |s| {
                s.current_sync_committee.pubkeys[3][0] ^= 1
            }),
            ("current committee aggregate", |s| {
                s.current_sync_committee.aggregate_pubkey[0] ^= 1
            }),
            ("next committee", |s| s.next_sync_committee = committee(9)),
        ];
        for (name, edit) in edits {
            let mut s = f.store.clone();
            edit(&mut s);
            assert_eq!(
                finish_update(&job, &s, &u, 41, &c, &b).err(),
                Some(Error::StoreChanged),
                "{name}"
            );
        }
        // the very same job cannot be finished twice: the first finish moved the store
        let after = finish_update(&job, &f.store, &u, 41, &c, &b).unwrap();
        assert_eq!(
            finish_update(&job, &after, &u, 41, &c, &b).err(),
            Some(Error::StoreChanged)
        );
    }

    #[test]
    fn finish_with_a_store_that_cannot_be_encoded_is_a_store_encoding_error() {
        let f = fixture();
        let job = job_at_miller(&f);
        let mut s = f.store.clone();
        s.current_sync_committee.len = 0;
        assert_eq!(
            finish_update(&job, &s, &upd(&f, 41), 41, &cfg(GVR_A), &Mock::ok()).err(),
            Some(Error::StoreEncoding)
        );
    }

    // ---- failures ---------------------------------------------------------------------------

    #[test]
    fn each_stage_can_reject_and_a_rejected_finish_returns_no_store() {
        let f = fixture();
        for (at, name) in [(1u8, "prepare"), (2, "miller"), (3, "finish")] {
            let b = Mock::new(at);
            assert_eq!(run_all(&f, &b).err(), Some(Error::BadSignature), "{name}");
            let calls = b.calls();
            assert_eq!(calls.len(), at as usize, "{name}: stages run");
            assert_eq!(calls[at as usize - 1], name);
        }
    }

    #[test]
    fn finish_repeats_the_non_bls_checks() {
        let f = fixture();
        let c = cfg(GVR_A);
        let job = job_at_miller(&f);
        let b = Mock::ok();
        // the clock reads before the signature slot: BadSlotOrder, and `finish` never ran
        assert_eq!(
            finish_update(&job, &f.store, &upd(&f, 41), 40, &c, &b).err(),
            Some(Error::BadSlotOrder)
        );
        assert!(!b.calls().contains(&"finish"));
        assert!(finish_update(&job, &f.store, &upd(&f, 41), 41, &c, &b).is_ok());
    }

    // ---- digests ----------------------------------------------------------------------------

    #[test]
    fn store_digest_is_domain_separated_codec_bytes() {
        let f = fixture();
        let mut h = Sha256::new();
        h.update(b"LE_SYNC_STORE_V1");
        h.update(enc(&f.store));
        let want: Bytes32 = h.finalize().into();
        assert_eq!(store_digest(&f.store), Ok(want));
    }

    #[test]
    fn store_digest_ignores_best_valid_update_and_padding() {
        let f = fixture();
        let mut s = f.store.clone();
        s.best_valid_update =
            Some(crate::sync::OwnedLightClientUpdate::from_borrowed(&upd(&f, 41)).unwrap());
        s.current_sync_committee.pubkeys[N + 5] = [3u8; 48];
        assert_eq!(store_digest(&s), store_digest(&f.store));
    }

    #[test]
    fn update_digest_matches_the_documented_layout() {
        let f = fixture();
        let c = cfg(GVR_A);
        let u = upd(&f, 41);
        let mut want = Sha256::new();
        want.update(b"LE_SYNC_UPDATE_V1");
        want.update(c.binding(0).digest());
        want.update(c.chain.electra_fork_epoch.to_le_bytes());
        want.update([0u8]);
        want.update(0u64.to_le_bytes());
        let hd = &u.attested_header;
        want.update(hd.slot.to_le_bytes());
        want.update(hd.proposer_index.to_le_bytes());
        want.update(hd.parent_root);
        want.update(hd.state_root);
        want.update(hd.body_root);
        want.update((N as u32).to_le_bytes());
        for k in u.next_sync_committee.keys() {
            want.update(k);
        }
        want.update(u.next_sync_committee.aggregate_pubkey);
        want.update((u.next_sync_committee_branch.len() as u32).to_le_bytes());
        for n in u.next_sync_committee_branch {
            want.update(n);
        }
        let hd = &u.finalized_header;
        want.update(hd.slot.to_le_bytes());
        want.update(hd.proposer_index.to_le_bytes());
        want.update(hd.parent_root);
        want.update(hd.state_root);
        want.update(hd.body_root);
        want.update((u.finality_branch.len() as u32).to_le_bytes());
        for n in u.finality_branch {
            want.update(n);
        }
        want.update((u.sync_committee_bits.len() as u32).to_le_bytes());
        want.update(u.sync_committee_bits);
        want.update(u.sync_committee_signature);
        want.update(41u64.to_le_bytes());
        let want: Bytes32 = want.finalize().into();
        assert_eq!(update_digest(&u, &c), want);

        // the gloas field is length-and-tag framed
        let mut g = c;
        g.chain.gloas_fork_epoch = Some(5);
        assert_ne!(update_digest(&u, &g), want);
    }

    #[test]
    fn update_digest_survives_a_bogus_committee_length() {
        let f = fixture();
        let mut c = committee(7);
        c.len = usize::MAX;
        let mut u = upd(&f, 41);
        u.next_sync_committee = &c;
        let d = update_digest(&u, &cfg(GVR_A)); // must not panic
        assert_ne!(d, update_digest(&upd(&f, 41), &cfg(GVR_A)));
    }

    // ---- the single-shot adaptor --------------------------------------------------------------

    #[test]
    fn chained_runs_all_three_stages_in_order_and_needs_all_three_to_pass() {
        let committee_keys = committee(1);
        let args = |b: &Mock| {
            Chained(b).fast_aggregate_verify(
                committee_keys.keys(),
                &committee_keys.aggregate_pubkey,
                &[0xFF; N / 8],
                &[0x42; 32],
                &[1u8; 96],
            )
        };
        let b = Mock::ok();
        assert!(args(&b));
        assert_eq!(b.calls(), ["prepare", "miller", "finish"]);
        assert_eq!(*b.seen_root.borrow(), Some([0x42; 32]));
        assert_eq!(*b.seen_sig.borrow(), Some([1u8; 96]));
        for (at, ran) in [(1u8, 1usize), (2, 2), (3, 3)] {
            let b = Mock::new(at);
            assert!(!args(&b), "stage {at}");
            assert_eq!(b.calls().len(), ran, "stage {at}");
        }
    }

    // ---- rooted committees --------------------------------------------------------------

    #[derive(Clone, Debug, PartialEq)]
    struct Seen {
        keys_root: Bytes32,
        len: usize,
        agg: BlsPubkey,
        keys: Vec<u32>,
        index: Vec<u16>,
        proof: Vec<u32>,
        bits: Vec<u8>,
        root: Bytes32,
        sig: BlsSignature,
    }

    /// A backend with rooted support: records what `prepare_rooted` saw, answers as told.
    struct RootedMock {
        answer: Result<(), Error>,
        calls: RefCell<Vec<&'static str>>,
        seen: RefCell<Option<Seen>>,
    }
    impl RootedMock {
        fn new(answer: Result<(), Error>) -> Self {
            Self {
                answer,
                calls: RefCell::new(vec![]),
                seen: RefCell::new(None),
            }
        }
        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }
    impl StagedBls for RootedMock {
        fn prepare(
            &self,
            _: &[BlsPubkey],
            _: &BlsPubkey,
            _: &[u8],
            _: &Bytes32,
            _: &BlsSignature,
            _: &mut StageState,
        ) -> bool {
            self.calls.borrow_mut().push("prepare");
            false
        }
        fn prepare_rooted(
            &self,
            keys_root: &Bytes32,
            len: usize,
            aggregate_pubkey: &BlsPubkey,
            absent: &AbsentKeys,
            bits: &[u8],
            signing_root: &Bytes32,
            signature: &BlsSignature,
            state: &mut StageState,
        ) -> Result<(), Error> {
            self.calls.borrow_mut().push("prepare_rooted");
            *self.seen.borrow_mut() = Some(Seen {
                keys_root: *keys_root,
                len,
                agg: *aggregate_pubkey,
                keys: absent.keys.to_vec(),
                index: absent.index.to_vec(),
                proof: absent.proof.to_vec(),
                bits: bits.to_vec(),
                root: *signing_root,
                sig: *signature,
            });
            state[..32].copy_from_slice(signing_root);
            state[575] = 0x11;
            self.answer
        }
        fn miller(&self, state: &mut StageState) -> bool {
            self.calls.borrow_mut().push("miller");
            assert_eq!(state[575], 0x11);
            state[575] = 0x22;
            true
        }
        fn finish(&self, state: &StageState) -> bool {
            self.calls.borrow_mut().push("finish");
            assert_eq!(state[575], 0x22);
            true
        }
    }

    /// A fixture signed by the first `signers` of the N members, with its stores' committees
    /// rooted: the full fixture, the rooted store, the rooted next committee.
    fn rooted_fx(signers: usize) -> (Fx, LightClientStore, SyncCommittee) {
        let mut f = fixture();
        f.bits = crate::sync::tests::bits(signers);
        let store = f.store.to_rooted().unwrap();
        let next = f.next.to_rooted().unwrap();
        (f, store, next)
    }

    fn rooted_upd<'a>(f: &'a Fx, next: &'a SyncCommittee) -> LightClientUpdate<'a> {
        let mut u = upd(f, 41);
        u.next_sync_committee = next;
        u
    }

    /// Hints for the members `signers..N`: distinguishable words, and two siblings.
    fn hints(signers: usize) -> (Vec<u32>, Vec<u16>, Vec<u32>) {
        let index: Vec<u16> = (signers as u16..N as u16).collect();
        let keys: Vec<u32> = (0..index.len() * KEY_WORDS)
            .map(|i| i as u32 * 7 + 1)
            .collect();
        let proof: Vec<u32> = (0..2 * NODE_WORDS).map(|i| 0xA000 + i as u32).collect();
        (keys, index, proof)
    }

    #[test]
    fn rooted_begin_hands_the_backend_the_root_the_aggregate_and_the_absent_keys() {
        let (f, store, next) = rooted_fx(22);
        let (keys, index, proof) = hints(22);
        let a = AbsentKeys {
            keys: &keys,
            index: &index,
            proof: &proof,
        };
        let m = RootedMock::new(Ok(()));
        let u = rooted_upd(&f, &next);
        let c = cfg(GVR_A);
        let job = begin_update_rooted(&store, &u, &a, 41, &c, &m).unwrap();
        assert_eq!(m.calls(), ["prepare_rooted"]);
        let seen = m.seen.borrow().clone().unwrap();
        let inputs = check_light_client_update(&store, &u, 41, &c).unwrap();
        assert_eq!(
            seen,
            Seen {
                keys_root: store.current_sync_committee.stored_keys_root().unwrap(),
                len: N,
                agg: store.current_sync_committee.aggregate_pubkey,
                keys: keys.clone(),
                index: index.clone(),
                proof: proof.clone(),
                bits: f.bits.clone(),
                root: inputs.signing_root,
                sig: [7u8; 96],
            }
        );
        assert_eq!(job.step, STEP_PREPARED);
        assert_eq!(job.store_digest, store_digest(&store).unwrap());
        assert_eq!(job.update_digest, update_digest(&u, &c));
        assert_eq!(&job.state[..32], &seen.root);
        assert_eq!(job.state[575], 0x11);
    }

    #[test]
    fn rooted_three_steps_end_in_the_store_the_full_flow_ends_in() {
        let (f, store, next) = rooted_fx(22);
        let (keys, index, proof) = hints(22);
        let a = AbsentKeys {
            keys: &keys,
            index: &index,
            proof: &proof,
        };
        let m = RootedMock::new(Ok(()));
        let u = rooted_upd(&f, &next);
        let c = cfg(GVR_A);
        let j = begin_update_rooted(&store, &u, &a, 41, &c, &m).unwrap();
        let j = UpdateJob::from_bytes(&j.to_bytes()).unwrap();
        let j = miller_update(&j, &m).unwrap();
        let j = UpdateJob::from_bytes(&j.to_bytes()).unwrap();
        let rooted = finish_update(&j, &store, &u, 41, &c, &m).unwrap();
        assert_eq!(m.calls(), ["prepare_rooted", "miller", "finish"]);
        assert!(rooted.current_sync_committee.is_rooted());
        assert!(rooted.next_sync_committee.is_rooted());
        assert_eq!(rooted.finalized_header.slot, 24);

        let full = run_all(&f, &Mock::ok()).unwrap();
        assert_eq!(enc(&rooted), enc(&full.to_rooted().unwrap()));
    }

    #[test]
    fn rooted_begin_with_everyone_present_needs_no_keys() {
        let (f, store, next) = rooted_fx(N);
        let a = AbsentKeys {
            keys: &[],
            index: &[],
            proof: &[],
        };
        let m = RootedMock::new(Ok(()));
        let u = rooted_upd(&f, &next);
        assert!(begin_update_rooted(&store, &u, &a, 41, &cfg(GVR_A), &m).is_ok());
    }

    #[test]
    fn rooted_begin_refuses_hints_that_do_not_match_the_bits_before_any_bls_work() {
        let (f, store, next) = rooted_fx(22);
        let u = rooted_upd(&f, &next);
        let words = |n: usize| vec![1u32; n * KEY_WORDS];
        let wrong: Vec<Vec<u16>> = vec![
            (21..32).collect(),                               // lists a member that signed
            (23..32).collect(),                               // leaves out one that did not
            (22..31).collect(),                               // leaves out the last
            vec![],                                           // lists none of the ten
            (22..32).rev().collect(),                         // right members, wrong order
            vec![22, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31], // a repeat
            (22..33).collect(),                               // one past the end
        ];
        for index in wrong {
            let keys = words(index.len());
            let a = AbsentKeys {
                keys: &keys,
                index: &index,
                proof: &[],
            };
            let m = RootedMock::new(Ok(()));
            assert_eq!(
                begin_update_rooted(&store, &u, &a, 41, &cfg(GVR_A), &m).err(),
                Some(Error::AbsentKeys),
                "{index:?}"
            );
            assert!(m.calls().is_empty(), "{index:?}");
        }
        // right positions, malformed words
        let (keys, index, proof) = hints(22);
        for (k, p) in [
            (&keys[..keys.len() - 1], &proof[..]),
            (&keys[..], &proof[..NODE_WORDS + 1]),
        ] {
            let a = AbsentKeys {
                keys: k,
                index: &index,
                proof: p,
            };
            let m = RootedMock::new(Ok(()));
            assert_eq!(
                begin_update_rooted(&store, &u, &a, 41, &cfg(GVR_A), &m).err(),
                Some(Error::AbsentKeys)
            );
            assert!(m.calls().is_empty());
        }
    }

    #[test]
    fn rooted_begin_returns_the_backends_verdict() {
        let (f, store, next) = rooted_fx(22);
        let (keys, index, proof) = hints(22);
        let a = AbsentKeys {
            keys: &keys,
            index: &index,
            proof: &proof,
        };
        let u = rooted_upd(&f, &next);
        for verdict in [Error::AbsentKeys, Error::BadSignature] {
            let m = RootedMock::new(Err(verdict));
            assert_eq!(
                begin_update_rooted(&store, &u, &a, 41, &cfg(GVR_A), &m).err(),
                Some(verdict)
            );
            assert_eq!(m.calls(), ["prepare_rooted"]);
        }
    }

    #[test]
    fn rooted_begin_reports_a_non_signature_failure_before_the_hints() {
        let (f, store, next) = rooted_fx(22);
        let u = rooted_upd(&f, &next);
        let a = AbsentKeys {
            keys: &[],
            index: &[],
            proof: &[],
        }; // wrong for these bits too
        let m = RootedMock::new(Ok(()));
        // the clock reads before the signature slot
        assert_eq!(
            begin_update_rooted(&store, &u, &a, 40, &cfg(GVR_A), &m).err(),
            Some(Error::BadSlotOrder)
        );
        assert!(m.calls().is_empty());
    }

    #[test]
    fn rooted_and_full_begin_each_refuse_the_other_kind_of_store() {
        let (f, rooted_store, next) = rooted_fx(22);
        let (keys, index, proof) = hints(22);
        let a = AbsentKeys {
            keys: &keys,
            index: &index,
            proof: &proof,
        };
        // rooted begin on a full store
        let m = RootedMock::new(Ok(()));
        assert_eq!(
            begin_update_rooted(&f.store, &upd(&f, 41), &a, 41, &cfg(GVR_A), &m).err(),
            Some(Error::AbsentKeys)
        );
        assert!(m.calls().is_empty());
        // full begin on a rooted store: the keys are not there
        let mock = Mock::ok();
        let u = rooted_upd(&f, &next);
        assert_eq!(
            begin_update(&rooted_store, &u, 41, &cfg(GVR_A), &mock).err(),
            Some(Error::AbsentKeys)
        );
        assert!(mock.calls().is_empty());
    }

    #[test]
    fn a_backend_without_rooted_support_rejects_by_default() {
        let (f, store, next) = rooted_fx(N);
        let a = AbsentKeys {
            keys: &[],
            index: &[],
            proof: &[],
        };
        let mock = Mock::ok();
        let u = rooted_upd(&f, &next);
        assert_eq!(
            begin_update_rooted(&store, &u, &a, 41, &cfg(GVR_A), &mock).err(),
            Some(Error::AbsentKeys)
        );
        assert!(mock.calls().is_empty());
    }

    #[test]
    fn absent_keys_words_are_little_endian_groups_of_four_bytes() {
        let mut keys = vec![0u32; 2 * KEY_WORDS];
        keys[0] = 0x0403_0201;
        keys[KEY_WORDS - 1] = 0xDDCC_BBAA;
        keys[KEY_WORDS] = 0x0000_00FE;
        let proof: Vec<u32> = (0..2 * NODE_WORDS as u32 + 3).collect();
        let a = AbsentKeys {
            keys: &keys,
            index: &[3, 9],
            proof: &proof,
        };
        assert!(!a.well_formed(), "a trailing partial sibling");
        let k0 = a.key_bytes(0).unwrap();
        assert_eq!(&k0[..4], &[1, 2, 3, 4]);
        assert_eq!(&k0[92..], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(a.key_bytes(1).unwrap()[0], 0xFE);
        assert_eq!(a.key_bytes(2), None);
        assert_eq!(a.key_bytes(usize::MAX), None);
        let sib: Vec<Bytes32> = a.siblings().collect();
        assert_eq!(sib.len(), 2, "the partial sibling is not returned");
        assert_eq!(&sib[0][..8], &[0, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(sib[1][0], NODE_WORDS as u8);

        let ok = AbsentKeys {
            keys: &keys,
            index: &[3, 9],
            proof: &proof[..2 * NODE_WORDS],
        };
        assert!(ok.well_formed());
        let short = AbsentKeys {
            keys: &keys[..keys.len() - 1],
            index: &[3, 9],
            proof: &[],
        };
        assert!(!short.well_formed());
        let long = AbsentKeys {
            keys: &keys,
            index: &[3],
            proof: &[],
        };
        assert!(!long.well_formed());
    }

    #[test]
    fn a_rooted_next_committee_has_its_own_digest_framing() {
        let f = fixture();
        let c = cfg(GVR_A);
        let next = f.next.to_rooted().unwrap();
        let mut u = upd(&f, 41);
        let full_digest = update_digest(&u, &c);
        u.next_sync_committee = &next;
        let got = update_digest(&u, &c);
        assert_ne!(got, full_digest);

        // the documented layout, with the committee part spelled out
        let mut want = Sha256::new();
        want.update(b"LE_SYNC_UPDATE_V1");
        want.update(c.binding(0).digest());
        want.update(c.chain.electra_fork_epoch.to_le_bytes());
        want.update([0u8]);
        want.update(0u64.to_le_bytes());
        let hd = &u.attested_header;
        want.update(hd.slot.to_le_bytes());
        want.update(hd.proposer_index.to_le_bytes());
        want.update(hd.parent_root);
        want.update(hd.state_root);
        want.update(hd.body_root);
        want.update(u32::MAX.to_le_bytes());
        want.update((N as u32).to_le_bytes());
        want.update(next.stored_keys_root().unwrap());
        want.update(next.aggregate_pubkey);
        want.update((u.next_sync_committee_branch.len() as u32).to_le_bytes());
        for n in u.next_sync_committee_branch {
            want.update(n);
        }
        let hd = &u.finalized_header;
        want.update(hd.slot.to_le_bytes());
        want.update(hd.proposer_index.to_le_bytes());
        want.update(hd.parent_root);
        want.update(hd.state_root);
        want.update(hd.body_root);
        want.update((u.finality_branch.len() as u32).to_le_bytes());
        for n in u.finality_branch {
            want.update(n);
        }
        want.update((u.sync_committee_bits.len() as u32).to_le_bytes());
        want.update(u.sync_committee_bits);
        want.update(u.sync_committee_signature);
        want.update(41u64.to_le_bytes());
        let want: Bytes32 = want.finalize().into();
        assert_eq!(got, want);

        // the root and the aggregate both matter
        let other_root = SyncCommittee::rooted(N, [9; 32], next.aggregate_pubkey).unwrap();
        u.next_sync_committee = &other_root;
        assert_ne!(update_digest(&u, &c), got);
        let other_agg =
            SyncCommittee::rooted(N, next.stored_keys_root().unwrap(), [9; 48]).unwrap();
        u.next_sync_committee = &other_agg;
        assert_ne!(update_digest(&u, &c), got);
    }
}
