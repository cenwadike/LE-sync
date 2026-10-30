//! Staged update, wire side (Sprint 6, M1): the three transactions of `le_sync_core::update_job`
//! over serialisable inputs.
//!
//! `run_stage` is the whole of what one step executes. Like `verify`, it is free of risc0 and
//! runs natively in tests; a guest or a LEZ program is a thin wrapper that reads the inputs,
//! calls it and writes the output.
//!
//! * `Begin { store, update }`: the same strict 2/3 participation gate as `process_update_strict`
//!   (`BelowThreshold`, before any other rule and before any BLS work), then every non-BLS rule,
//!   then `StagedBls::prepare`. Output: the job bytes (`JOB_LEN` = 641).
//! * `Miller { job }`: advances the job. Reads neither the store nor the update, and does not
//!   look at the configuration.
//! * `Finish { job, store, update }`: the gate and the checks again, then the final
//!   exponentiation and the apply step. Output: the new store bytes. On any error there is no
//!   output, so the caller's saved store stays as it was.
//!
//! Everything fails closed. Malformed inputs are typed errors, never panics: bad store bytes are
//! `StoreEncoding`, bad job bytes `JobMismatch`, a next committee that does not decode
//! `BadSyncCommitteeSize`, a signature that is not 96 bytes `BadSignature`, an empty or
//! unordered fork list `BadConfig`.
//!
//! SECURITY: the job and the store passed in must come from storage only this program can write
//! (see `le_sync_core::update_job`). `update` and `cfg` are the caller's claims; the job binds
//! them (`JobMismatch`), the store digest binds the store (`StoreChanged`).
//!
//! `best_valid_update` is not carried between steps (see `le_sync_core::store_codec`).
use crate::{committee_from, GuestInput, SyncInput, UpdateWire};
use le_sync_core::store_codec::{decode_store, encode_store, MAX_ENCODED_LEN};
use le_sync_core::sync::{
    has_supermajority, initialize_light_client_store, ForkSchedule, LightClientStore,
    LightClientUpdate, SyncCommittee, SyncConfig,
};
use le_sync_core::update_job::{begin_update, finish_update, miller_update, StagedBls, UpdateJob};
use le_sync_core::{BeaconBlockHeader, Bytes32, ChainConfig, Error, ZERO};

/// The configuration every step runs under. It is part of what a job binds to.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StageConfig {
    pub slots_per_epoch: u64,
    pub electra_fork_epoch: u64,
    pub gloas_fork_epoch: Option<u64>,
    pub epochs_per_period: u64,
    pub genesis_validators_root: Bytes32,
    /// Ascending `(fork_epoch, fork_version)`, genesis first.
    pub forks: Vec<(u64, [u8; 4])>,
    /// The caller's clock reading, as in `SyncInput::current_slot`. Every step that checks
    /// the update re-checks it against the signature slot.
    pub current_slot: u64,
}

impl StageConfig {
    /// The configuration a `GuestInput` with a `sync` section implies.
    pub fn from_input(i: &GuestInput, s: &SyncInput) -> Self {
        Self {
            slots_per_epoch: i.slots_per_epoch,
            electra_fork_epoch: i.electra_fork_epoch,
            gloas_fork_epoch: i.gloas_fork_epoch,
            epochs_per_period: s.epochs_per_period,
            genesis_validators_root: s.genesis_validators_root,
            forks: s.forks.clone(),
            current_slot: s.current_slot,
        }
    }

    /// `BadConfig` for an empty, over-long or unordered fork list.
    fn sync_config(&self) -> Result<SyncConfig, Error> {
        Ok(SyncConfig {
            chain: ChainConfig {
                slots_per_epoch: self.slots_per_epoch,
                electra_fork_epoch: self.electra_fork_epoch,
                gloas_fork_epoch: self.gloas_fork_epoch,
            },
            epochs_per_period: self.epochs_per_period,
            genesis_validators_root: self.genesis_validators_root,
            forks: ForkSchedule::new(&self.forks)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum StageInput {
    Begin {
        /// `store_codec` v1 bytes.
        store: Vec<u8>,
        update: UpdateWire,
    },
    Miller {
        /// `UpdateJob` bytes, read from the program's own account.
        job: Vec<u8>,
    },
    Finish {
        /// `UpdateJob` bytes, read from the program's own account.
        job: Vec<u8>,
        /// `store_codec` v1 bytes: the store the job was begun against.
        store: Vec<u8>,
        update: UpdateWire,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum StageOutput {
    /// `UpdateJob` bytes (`JOB_LEN`), from `Begin` and `Miller`.
    Job(Vec<u8>),
    /// `store_codec` v1 bytes of the updated store, from `Finish`.
    Store(Vec<u8>),
}

/// Parse the wire update against a store whose committees have `size` keys, and hand the
/// borrowed `LightClientUpdate` to `f` (it borrows the parsed committee, so it cannot be
/// returned). The same parsing as `run_sync`, with typed errors instead of `Malformed`.
fn with_update<R>(
    u: &UpdateWire,
    size: usize,
    f: impl FnOnce(&LightClientUpdate) -> Result<R, Error>,
) -> Result<R, Error> {
    let next: SyncCommittee = committee_from(&u.next_pubkeys, &u.next_aggregate, size)
        .ok_or(Error::BadSyncCommitteeSize)?;
    let sig: [u8; 96] = u
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| Error::BadSignature)?;
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
    f(&lcu)
}

/// The strict gate of `process_update_strict`: below 2/3 participation is `BelowThreshold`.
fn strict_gate(u: &LightClientUpdate) -> Result<(), Error> {
    if !has_supermajority(u.sync_committee_bits) {
        return Err(Error::BelowThreshold);
    }
    Ok(())
}

fn encode(store: &LightClientStore) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; MAX_ENCODED_LEN];
    let n = encode_store(store, &mut out)?;
    out.truncate(n);
    Ok(out)
}

/// The store `run_sync` builds from the bootstrap section of `i`, as `store_codec` bytes: the
/// starting point of a staged run. Same errors as the bootstrap of `verify`.
pub fn initial_store_bytes(i: &GuestInput, s: &SyncInput) -> Result<Vec<u8>, Error> {
    let cfg = StageConfig::from_input(i, s).sync_config()?;
    let committee =
        committee_from(&i.pubkeys, &i.aggregate, 0).ok_or(Error::BadSyncCommitteeSize)?;
    let header = BeaconBlockHeader::from(&i.boot_header);
    let store =
        initialize_light_client_store(&cfg, &i.trusted_root, &header, committee, &i.boot_branch)?;
    encode(&store)
}

/// Run one step. See the module docs for what each input does and which errors it returns.
pub fn run_stage<B: StagedBls>(
    cfg: &StageConfig,
    input: &StageInput,
    bls: &B,
) -> Result<StageOutput, Error> {
    match input {
        StageInput::Begin { store, update } => {
            let scfg = cfg.sync_config()?;
            let store = Box::new(decode_store(store)?);
            let job = with_update(update, store.current_sync_committee.len, |u| {
                strict_gate(u)?;
                begin_update(&store, u, cfg.current_slot, &scfg, bls)
            })?;
            Ok(StageOutput::Job(job.to_bytes().to_vec()))
        }
        StageInput::Miller { job } => {
            let job = UpdateJob::from_bytes(job)?;
            let job = miller_update(&job, bls)?;
            Ok(StageOutput::Job(job.to_bytes().to_vec()))
        }
        StageInput::Finish { job, store, update } => {
            let scfg = cfg.sync_config()?;
            let job = UpdateJob::from_bytes(job)?;
            let store = Box::new(decode_store(store)?);
            let next = with_update(update, store.current_sync_committee.len, |u| {
                strict_gate(u)?;
                finish_update(&job, &store, u, cfg.current_slot, &scfg, bls)
            })?;
            Ok(StageOutput::Store(encode(&next)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{fixture, with_sync, Mock, FV, GVR, N};
    use crate::verify;
    use le_sync_core::store_codec::{encoded_len, STORE_CODEC_VERSION};
    use le_sync_core::sync::{Bls, BlsSignature};
    use le_sync_core::update_job::{
        Chained, StageState, JOB_LEN, STATE_LEN, STEP_MILLER, STEP_PREPARED,
    };
    use le_sync_core::BlsPubkey;
    use std::cell::RefCell;

    /// A staged backend with the verdicts of the wire `Mock` (signature starts with 7 and the
    /// signing root is the fixture's). It records the stages that ran and can fail one.
    struct Staged {
        fail_at: u8,
        calls: RefCell<Vec<&'static str>>,
    }
    impl Staged {
        fn new(fail_at: u8) -> Self {
            Self {
                fail_at,
                calls: RefCell::new(vec![]),
            }
        }
        fn ok() -> Self {
            Self::new(0)
        }
        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }
    impl StagedBls for Staged {
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
            let verdict = Mock.fast_aggregate_verify(
                committee,
                aggregate_pubkey,
                bits,
                signing_root,
                signature,
            );
            state[0] = verdict as u8;
            state[STATE_LEN - 1] = 0x11;
            verdict && self.fail_at != 1
        }
        fn miller(&self, state: &mut StageState) -> bool {
            self.calls.borrow_mut().push("miller");
            assert_eq!(state[STATE_LEN - 1], 0x11, "state from prepare");
            state[STATE_LEN - 1] = 0x22;
            self.fail_at != 2
        }
        fn finish(&self, state: &StageState) -> bool {
            self.calls.borrow_mut().push("finish");
            assert_eq!(state[STATE_LEN - 1], 0x22, "state from miller");
            state[0] == 1 && self.fail_at != 3
        }
    }

    struct Setup {
        input: GuestInput,
        cfg: StageConfig,
        store: Vec<u8>,
        update: UpdateWire,
    }
    fn setup() -> Setup {
        setup_from(with_sync(fixture()))
    }
    fn setup_from(input: GuestInput) -> Setup {
        let s = input.sync.as_ref().unwrap();
        Setup {
            cfg: StageConfig::from_input(&input, s),
            store: initial_store_bytes(&input, s).unwrap(),
            update: s.updates[0].clone(),
            input,
        }
    }
    fn job_bytes(o: Result<StageOutput, Error>) -> Vec<u8> {
        match o.unwrap() {
            StageOutput::Job(j) => j,
            other => panic!("expected a job, got {other:?}"),
        }
    }
    fn store_bytes(o: Result<StageOutput, Error>) -> Vec<u8> {
        match o.unwrap() {
            StageOutput::Store(s) => s,
            other => panic!("expected a store, got {other:?}"),
        }
    }
    fn begin(s: &Setup, b: &Staged) -> Result<StageOutput, Error> {
        run_stage(
            &s.cfg,
            &StageInput::Begin {
                store: s.store.clone(),
                update: s.update.clone(),
            },
            b,
        )
    }
    fn miller(s: &Setup, job: &[u8], b: &Staged) -> Result<StageOutput, Error> {
        run_stage(&s.cfg, &StageInput::Miller { job: job.to_vec() }, b)
    }
    fn finish(s: &Setup, job: &[u8], store: &[u8], b: &Staged) -> Result<StageOutput, Error> {
        run_stage(
            &s.cfg,
            &StageInput::Finish {
                job: job.to_vec(),
                store: store.to_vec(),
                update: s.update.clone(),
            },
            b,
        )
    }
    /// The two jobs and the bytes of the finished store, for tests that start from a good run.
    fn good_run(s: &Setup) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let b = Staged::ok();
        let j1 = job_bytes(begin(s, &b));
        let j2 = job_bytes(miller(s, &j1, &b));
        let out = store_bytes(finish(s, &j2, &s.store, &b));
        (j1, j2, out)
    }

    // ---- the staged run equals `verify` ---------------------------------------------------

    #[test]
    fn three_stages_give_the_finalized_and_optimistic_state_of_verify() {
        let s = setup();
        let b = Staged::ok();
        let (j1, j2, out) = good_run(&s);
        assert_eq!(j1.len(), JOB_LEN);
        assert_eq!(j2.len(), JOB_LEN);
        assert_eq!(j1[0], STEP_PREPARED);
        assert_eq!(j2[0], STEP_MILLER);
        assert_ne!(j1, j2);

        let want = verify(&s.input, &Mock);
        assert_eq!((want.sync_validated, want.sync_rejected), (1, 0));
        let st = decode_store(&out).unwrap();
        assert_eq!(st.finalized_header.slot, want.finalized_slot);
        assert_eq!(st.finalized_header.hash_tree_root(), want.finalized_root);
        assert_eq!(st.optimistic_header.slot, want.optimistic_slot);
        assert_eq!((want.finalized_slot, want.optimistic_slot), (24, 40));
        assert_ne!(out, s.store);
        assert_eq!(out.len(), encoded_len(N));
        // the three stages, run on one backend, call it once each and in order
        let j = job_bytes(begin(&s, &b));
        let j = job_bytes(miller(&s, &j, &b));
        store_bytes(finish(&s, &j, &s.store, &b));
        assert_eq!(b.calls(), ["prepare", "miller", "finish"]);
    }

    #[test]
    fn chained_stages_are_the_single_shot_check() {
        // `Chained` makes the staged backend a `Bls`: the whole input verifies the same way.
        let b = Staged::ok();
        let i = with_sync(fixture());
        assert_eq!(verify(&i, &Chained(&b)), verify(&i, &Mock));
        assert_eq!(b.calls(), ["prepare", "miller", "finish"]);
    }

    #[test]
    fn bootstrap_store_bytes_match_the_bootstrap_of_verify() {
        let s = setup();
        assert_eq!(s.store.len(), 3_413);
        assert_eq!(s.store[0], STORE_CODEC_VERSION);
        let st = decode_store(&s.store).unwrap();
        assert_eq!(st.finalized_header.slot, 8);
        assert_eq!(st.finalized_header.hash_tree_root(), s.input.trusted_root);
        assert!(!st.is_next_sync_committee_known());
        assert!(st.best_valid_update.is_none());
        assert_eq!(s.cfg.current_slot, 41);
        assert_eq!(s.cfg.genesis_validators_root, GVR);
        assert_eq!(s.cfg.forks, vec![(0, FV)]);
        assert_eq!(s.cfg.slots_per_epoch, 8);
        assert_eq!(s.cfg.epochs_per_period, 8);
        assert_eq!(s.cfg.electra_fork_epoch, 0);
        assert_eq!(s.cfg.gloas_fork_epoch, None);
    }

    #[test]
    fn a_bad_bootstrap_has_no_initial_store() {
        let mut i = with_sync(fixture());
        i.trusted_root[0] ^= 1;
        let s = i.sync.clone().unwrap();
        assert_eq!(initial_store_bytes(&i, &s), Err(Error::TrustedRootMismatch));
        let mut i = with_sync(fixture());
        i.sync.as_mut().unwrap().forks.clear();
        let s = i.sync.clone().unwrap();
        assert_eq!(initial_store_bytes(&i, &s), Err(Error::BadConfig));
        let mut i = with_sync(fixture());
        i.pubkeys.truncate(47);
        let s = i.sync.clone().unwrap();
        assert_eq!(
            initial_store_bytes(&i, &s),
            Err(Error::BadSyncCommitteeSize)
        );
    }

    // ---- the strict gate ------------------------------------------------------------------

    #[test]
    fn below_threshold_does_no_bls_work_and_returns_no_job() {
        let mut s = setup();
        s.update.bits = vec![0xFF, 0xFF, 0x1F, 0x00]; // 21 of 32: 63 < 64
        let b = Staged::ok();
        assert_eq!(begin(&s, &b), Err(Error::BelowThreshold));
        assert!(b.calls().is_empty());
        s.update.bits = vec![0xFF, 0xFF, 0x3F, 0x00]; // 22 of 32: exactly 2/3 and over
        assert!(begin(&s, &b).is_ok());
        assert_eq!(b.calls(), ["prepare"]);
    }

    #[test]
    fn the_gate_comes_before_the_other_rules() {
        // below 2/3 AND a stale signature slot: the strict path reports BelowThreshold first
        let mut s = setup();
        s.update.bits = vec![0xFF, 0x0F, 0x00, 0x00];
        s.update.signature_slot = 0;
        assert_eq!(begin(&s, &Staged::ok()), Err(Error::BelowThreshold));
    }

    #[test]
    fn finish_applies_the_gate_to_a_job_that_began_elsewhere() {
        // A job begun through the core (no gate) for a 12-of-32 update must not finish here.
        let mut s = setup();
        s.update.bits = vec![0xFF, 0x0F, 0x00, 0x00];
        let b = Staged::ok();
        let scfg = s.cfg.sync_config().unwrap();
        let store = decode_store(&s.store).unwrap();
        let j1 = with_update(&s.update, N, |u| {
            begin_update(&store, u, s.cfg.current_slot, &scfg, &b)
        })
        .unwrap();
        let j2 = miller_update(&j1, &b).unwrap();
        let before = b.calls().len();
        assert_eq!(
            finish(&s, &j2.to_bytes(), &s.store, &b),
            Err(Error::BelowThreshold)
        );
        assert_eq!(b.calls().len(), before, "finish did not run");
    }

    // ---- order, corruption, binding -------------------------------------------------------

    #[test]
    fn steps_out_of_order_are_wrong_step() {
        let s = setup();
        let (j1, j2, _) = good_run(&s);
        let b = Staged::ok();
        assert_eq!(miller(&s, &j2, &b), Err(Error::WrongStep));
        assert_eq!(finish(&s, &j1, &s.store, &b), Err(Error::WrongStep));
        assert!(b.calls().is_empty());
        assert!(miller(&s, &j1, &Staged::ok()).is_ok());
    }

    #[test]
    fn corrupt_job_bytes_are_job_mismatch() {
        let s = setup();
        let (j1, j2, _) = good_run(&s);
        let b = Staged::ok();
        for bad in [vec![], j1[..JOB_LEN - 1].to_vec(), {
            let mut l = j1.clone();
            l.push(0);
            l
        }] {
            assert_eq!(miller(&s, &bad, &b), Err(Error::JobMismatch));
            assert_eq!(finish(&s, &bad, &s.store, &b), Err(Error::JobMismatch));
        }
        let mut unknown_step = j2.clone();
        unknown_step[0] = 9;
        assert_eq!(miller(&s, &unknown_step, &b), Err(Error::JobMismatch));
        assert_eq!(
            finish(&s, &unknown_step, &s.store, &b),
            Err(Error::JobMismatch)
        );
        assert!(b.calls().is_empty());
    }

    #[test]
    fn corrupt_store_bytes_are_store_encoding() {
        let s = setup();
        let (_, j2, _) = good_run(&s);
        let b = Staged::ok();
        let mut garbage = s.store.clone();
        garbage[0] = 2; // version
        for bad in [vec![], garbage, s.store[..s.store.len() - 1].to_vec()] {
            let r = run_stage(
                &s.cfg,
                &StageInput::Begin {
                    store: bad.clone(),
                    update: s.update.clone(),
                },
                &b,
            );
            assert_eq!(r, Err(Error::StoreEncoding));
            assert_eq!(finish(&s, &j2, &bad, &b), Err(Error::StoreEncoding));
        }
        assert!(b.calls().is_empty());
    }

    #[test]
    fn a_changed_store_is_store_changed() {
        let s = setup();
        let (_, j2, out) = good_run(&s);
        let b = Staged::ok();
        // a store that is a valid encoding but not the one the job was begun against:
        // the proposer index of the finalized header (bytes 9..17)
        let mut other = s.store.clone();
        other[9] ^= 1;
        assert!(decode_store(&other).is_ok());
        assert_eq!(finish(&s, &j2, &other, &b), Err(Error::StoreChanged));
        // and the store after the update (the same job cannot be finished twice)
        assert_eq!(finish(&s, &j2, &out, &b), Err(Error::StoreChanged));
        assert!(b.calls().is_empty());
    }

    #[test]
    fn a_different_update_or_configuration_is_job_mismatch() {
        let s = setup();
        let (_, j2, _) = good_run(&s);
        let b = Staged::ok();
        let mut other = Setup {
            cfg: s.cfg.clone(),
            store: s.store.clone(),
            update: s.update.clone(),
            input: s.input.clone(),
        };
        other.update.signature[1] ^= 1;
        assert_eq!(finish(&other, &j2, &s.store, &b), Err(Error::JobMismatch));
        other.update = s.update.clone();
        other.update.signature_slot += 1;
        assert_eq!(finish(&other, &j2, &s.store, &b), Err(Error::JobMismatch));
        other.update = s.update.clone();
        other.cfg.genesis_validators_root[0] ^= 1;
        assert_eq!(finish(&other, &j2, &s.store, &b), Err(Error::JobMismatch));
        assert!(b.calls().is_empty());
    }

    // ---- failures return nothing ----------------------------------------------------------

    #[test]
    fn a_rejected_signature_at_any_stage_returns_no_output() {
        let s = setup();
        for at in 1u8..=3 {
            let b = Staged::new(at);
            let r = begin(&s, &b)
                .and_then(|o| match o {
                    StageOutput::Job(j) => miller(&s, &j, &b),
                    other => Ok(other),
                })
                .and_then(|o| match o {
                    StageOutput::Job(j) => finish(&s, &j, &s.store, &b),
                    other => Ok(other),
                });
            assert_eq!(r, Err(Error::BadSignature), "stage {at}");
            assert_eq!(b.calls().len(), at as usize, "stage {at}");
        }
        // a signature the verdict rejects outright (first byte is not 7) stops at prepare
        let mut bad = setup();
        bad.update.signature[0] = 6;
        let b = Staged::ok();
        assert_eq!(begin(&bad, &b), Err(Error::BadSignature));
        assert_eq!(b.calls(), ["prepare"]);
    }

    // ---- malformed input ------------------------------------------------------------------

    #[test]
    fn an_empty_or_unordered_fork_list_is_bad_config() {
        let s = setup();
        let (j1, j2, _) = good_run(&s);
        let b = Staged::ok();
        let mut cfg = s.cfg.clone();
        cfg.forks.clear();
        let bad = Setup {
            cfg,
            store: s.store.clone(),
            update: s.update.clone(),
            input: s.input.clone(),
        };
        assert_eq!(begin(&bad, &b), Err(Error::BadConfig));
        assert_eq!(finish(&bad, &j2, &s.store, &b), Err(Error::BadConfig));
        let mut unordered = s.cfg.clone();
        unordered.forks = vec![(5, FV), (1, FV)];
        let bad = Setup {
            cfg: unordered,
            ..bad
        };
        assert_eq!(begin(&bad, &b), Err(Error::BadConfig));
        // `Miller` never reads the configuration
        assert!(miller(&bad, &j1, &b).is_ok());
        // and a zero epoch length is refused by the update check
        let mut zero = s.cfg.clone();
        zero.epochs_per_period = 0;
        let bad = Setup { cfg: zero, ..bad };
        assert_eq!(begin(&bad, &Staged::ok()), Err(Error::BadConfig));
    }

    #[test]
    fn malformed_update_bytes_are_typed_errors() {
        let b = Staged::ok();
        for len in [0usize, 95, 97] {
            let mut s = setup();
            s.update.signature = vec![7; len];
            assert_eq!(begin(&s, &b), Err(Error::BadSignature), "signature {len}");
        }
        // keys without an aggregate, a partial key, an aggregate without keys
        for (keys, agg) in [
            (vec![1u8; 48], vec![]),
            (vec![1u8; 47], vec![2u8; 48]),
            (vec![], vec![2u8; 48]),
        ] {
            let mut s = setup();
            s.update.next_pubkeys = keys;
            s.update.next_aggregate = agg;
            assert_eq!(begin(&s, &b), Err(Error::BadSyncCommitteeSize));
        }
        assert!(b.calls().is_empty());
    }

    #[test]
    fn a_non_signature_rule_failure_is_the_core_error_and_runs_no_bls() {
        let mut s = setup();
        s.update.finality_branch[0][0] ^= 1;
        let b = Staged::ok();
        assert_eq!(begin(&s, &b), Err(Error::InvalidBranch));
        let mut s = setup();
        s.cfg.current_slot = 40; // before the signature slot (41)
        assert_eq!(begin(&s, &b), Err(Error::BadSlotOrder));
        assert!(b.calls().is_empty());
    }

    #[test]
    fn finish_rechecks_the_clock() {
        let s = setup();
        let (_, j2, _) = good_run(&s);
        let b = Staged::ok();
        let mut early = Setup {
            cfg: s.cfg.clone(),
            store: s.store.clone(),
            update: s.update.clone(),
            input: s.input.clone(),
        };
        early.cfg.current_slot = 40;
        assert_eq!(finish(&early, &j2, &s.store, &b), Err(Error::BadSlotOrder));
        assert!(b.calls().is_empty());
    }

    #[test]
    fn replaying_the_run_on_the_new_store_applies_nothing_new() {
        // As in the core (`replayed_update_does_not_double_apply`): the replay is valid, because
        // its attested slot is still newer than the finalized header, but it moves nothing.
        let s = setup();
        let (_, _, out) = good_run(&s);
        let again = Setup {
            store: out.clone(),
            cfg: s.cfg.clone(),
            update: s.update.clone(),
            input: s.input.clone(),
        };
        let (_, _, out2) = good_run(&again);
        let (a, b) = (decode_store(&out).unwrap(), decode_store(&out2).unwrap());
        assert_eq!(a.finalized_header, b.finalized_header);
        assert_eq!(a.optimistic_header, b.optimistic_header);
        assert_eq!(a.current_sync_committee, b.current_sync_committee);
        assert_eq!(a.next_sync_committee, b.next_sync_committee);
    }
}
