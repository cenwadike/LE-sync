//! Staged update over a ROOTED store (Sprint 6, M1): the same three transactions as `stage`,
//! but the store keeps each committee as its 32-byte keys root and its 48-byte aggregate
//! (`store_codec` v2, 403 bytes) instead of 512 keys.
//!
//! WHY. Reading and writing the full store in an account costs about 454 cycles per byte per
//! step in a LEZ program, so a 49 KiB store alone exceeds the 32M-cycle cap. The keys an update
//! needs are supplied with it instead: the keys of the members that did NOT sign, as
//! uncompressed points, with one Merkle multiproof against the keys root (`AbsentWire`). The
//! signing aggregate is the committee's aggregate minus those keys. See
//! `le_sync_core::update_job::begin_update_rooted` and `le_sync_core::multiproof`.
//!
//! * `Begin { store, update, absent }`: the strict 2/3 gate, every non-BLS rule, then
//!   `StagedBls::prepare_rooted` (the hints are checked against the keys root and the
//!   participation bits). Output: the job bytes.
//! * `Miller { job }`: identical to `stage`; `run_rooted` hands it to `run_stage`.
//! * `Finish { job, store, update }`: the gate and the checks again, the final exponentiation,
//!   the apply step. Output: the new rooted store bytes. The hints are not needed here: the job
//!   already holds the result of the aggregation and binds the update and the store.
//!
//! A next committee the update carries (a handoff) travels as its keys root and its aggregate
//! (`RootedUpdate`): the update's next-committee branch proves
//! `committee_root_from(keys_root, aggregate)`, so a wrong root fails `InvalidBranch`.
//!
//! The host side (`prove_multiproof`, `absent_wire`, `to_rooted_update`,
//! `initial_rooted_store_bytes`) builds these inputs from full data. It is not part of what a
//! program runs.
//!
//! SECURITY: as in `stage`, the job and the store must come from storage only the program can
//! write. The hints (`absent`) and the update are the caller's claims; the multiproof and the
//! participation bits bind the hints, the job binds the update and the store.
use crate::stage::{encode, initial_store, run_stage, strict_gate, with_next};
use crate::stage::{StageConfig, StageInput, StageOutput};
use crate::{pubkeys, GuestInput, SyncInput, UpdateWire};
use le_sync_core::pubkey_root;
use le_sync_core::pubkeys_root;
use le_sync_core::store_codec::decode_store;
use le_sync_core::sync::SyncCommittee;
use le_sync_core::update_job::{
    begin_update_rooted, finish_update, AbsentKeys, StagedBls, UpdateJob, KEY_WORDS,
};
use le_sync_core::{hash_pair, BlsPubkey, Bytes32, Error};

/// An update for a rooted store: `update` with no next-committee keys, plus the keys root of
/// the next committee it carries (if any). `update.next_aggregate` is the next committee's
/// aggregate (48 bytes) or empty; `update.next_pubkeys` must be empty.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RootedUpdate {
    pub update: UpdateWire,
    pub next_keys_root: Option<Bytes32>,
}

/// The hints of one `Begin`, in the words the program reads them (`AbsentKeys`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AbsentWire {
    /// `KEY_WORDS` (24) little-endian words per entry of `index`: the key's uncompressed
    /// 96-byte point.
    pub keys: Vec<u32>,
    /// Committee positions, strictly ascending: the zero bits of the update's bits.
    pub index: Vec<u16>,
    /// Multiproof siblings, 8 words each, in the order `multiproof` requires.
    pub proof: Vec<u32>,
}

impl AbsentWire {
    pub fn view(&self) -> AbsentKeys<'_> {
        AbsentKeys {
            keys: &self.keys,
            index: &self.index,
            proof: &self.proof,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RootedInput {
    Begin {
        /// `store_codec` v2 bytes.
        store: Vec<u8>,
        update: RootedUpdate,
        absent: AbsentWire,
    },
    Miller {
        /// `UpdateJob` bytes, read from the program's own account.
        job: Vec<u8>,
    },
    Finish {
        /// `UpdateJob` bytes, read from the program's own account.
        job: Vec<u8>,
        /// `store_codec` v2 bytes: the store the job was begun against.
        store: Vec<u8>,
        update: RootedUpdate,
    },
}

/// The next committee of `u`, for a store whose committees have `size` keys: unknown when the
/// update carries none, else rooted. `BadSyncCommitteeSize` for keys on the wire, a root
/// without an aggregate (or the reverse), or an aggregate that is not 48 bytes.
fn next_committee(u: &RootedUpdate, size: usize) -> Result<SyncCommittee, Error> {
    if !u.update.next_pubkeys.is_empty() {
        return Err(Error::BadSyncCommitteeSize);
    }
    match (u.next_keys_root, u.update.next_aggregate.as_slice()) {
        (None, []) => Ok(SyncCommittee::empty(size)),
        (Some(root), agg) => {
            let agg: BlsPubkey = agg.try_into().map_err(|_| Error::BadSyncCommitteeSize)?;
            SyncCommittee::rooted(size, root, agg)
        }
        (None, _) => Err(Error::BadSyncCommitteeSize),
    }
}

/// Run one step over a rooted store. See the module docs.
pub fn run_rooted<B: StagedBls>(
    cfg: &StageConfig,
    input: &RootedInput,
    bls: &B,
) -> Result<StageOutput, Error> {
    match input {
        RootedInput::Begin {
            store,
            update,
            absent,
        } => {
            let scfg = cfg.sync_config()?;
            let store = Box::new(decode_store(store)?);
            let next = next_committee(update, store.current_sync_committee.len)?;
            let job = with_next(&update.update, &next, |u| {
                strict_gate(u)?;
                begin_update_rooted(&store, u, &absent.view(), cfg.current_slot, &scfg, bls)
            })?;
            Ok(StageOutput::Job(job.to_bytes().to_vec()))
        }
        RootedInput::Miller { job } => {
            run_stage(cfg, &StageInput::Miller { job: job.clone() }, bls)
        }
        RootedInput::Finish { job, store, update } => {
            let scfg = cfg.sync_config()?;
            let job = UpdateJob::from_bytes(job)?;
            let store = Box::new(decode_store(store)?);
            let next = next_committee(update, store.current_sync_committee.len)?;
            let new = with_next(&update.update, &next, |u| {
                strict_gate(u)?;
                finish_update(&job, &store, u, cfg.current_slot, &scfg, bls)
            })?;
            Ok(StageOutput::Store(encode(&new)?))
        }
    }
}

// ---- host side: build the inputs from full data ---------------------------------------------

/// The store of `initial_store_bytes`, rooted, as `store_codec` v2 bytes.
pub fn initial_rooted_store_bytes(i: &GuestInput, s: &SyncInput) -> Result<Vec<u8>, Error> {
    encode(&initial_store(i, s)?.to_rooted()?)
}

/// A full `UpdateWire` as a `RootedUpdate`: the next committee's keys become their root.
/// `BadSyncCommitteeSize` if the next committee's keys or aggregate are malformed.
pub fn to_rooted_update(u: &UpdateWire) -> Result<RootedUpdate, Error> {
    let mut update = u.clone();
    let next_keys_root = if u.next_pubkeys.is_empty() && u.next_aggregate.is_empty() {
        None
    } else {
        let keys = pubkeys(&u.next_pubkeys).ok_or(Error::BadSyncCommitteeSize)?;
        if u.next_aggregate.len() != 48 {
            return Err(Error::BadSyncCommitteeSize);
        }
        Some(pubkeys_root(&keys)?)
    };
    update.next_pubkeys = vec![];
    Ok(RootedUpdate {
        update,
        next_keys_root,
    })
}

/// The multiproof for the leaves at `index` of the tree over `leaves` (a power of two of them):
/// the siblings in the order `le_sync_core::multiproof::verify_multiproof` consumes them, level
/// by level from the leaves up and left to right inside a level.
pub fn prove_multiproof(leaves: &[Bytes32], index: &[u16]) -> Vec<Bytes32> {
    let mut levels = vec![leaves.to_vec()];
    while levels.last().is_some_and(|l| l.len() > 1) {
        let next: Vec<Bytes32> = levels
            .last()
            .into_iter()
            .flat_map(|l| l.chunks(2).map(|p| hash_pair(&p[0], &p[1])))
            .collect();
        levels.push(next);
    }
    let mut pos: Vec<usize> = index.iter().map(|&i| i as usize).collect();
    let mut out = vec![];
    for level in &levels[..levels.len() - 1] {
        let mut parents = vec![];
        let mut i = 0;
        while i < pos.len() {
            let p = pos[i];
            if p & 1 == 1 {
                out.push(level[p - 1]);
                i += 1;
            } else if i + 1 < pos.len() && pos[i + 1] == p + 1 {
                i += 2;
            } else {
                out.push(level[p + 1]);
                i += 1;
            }
            parents.push(p >> 1);
        }
        pos = parents;
    }
    out
}

fn words(bytes: &[u8]) -> impl Iterator<Item = u32> + '_ {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
}

/// The hints for an update with participation `bits` over the committee `keys`: the keys of the
/// members whose bit is zero, their positions, and the multiproof. `uncompress` gives a key's
/// 96-byte uncompressed point (`bls::uncompress_g1` with `bls-blst`). `None` if a key does not
/// uncompress, `keys` is not a power of two in length, or `bits` does not cover `keys`.
pub fn absent_wire(
    keys: &[BlsPubkey],
    bits: &[u8],
    uncompress: impl Fn(&BlsPubkey) -> Option<[u8; 96]>,
) -> Option<AbsentWire> {
    if keys.is_empty() || !keys.len().is_power_of_two() || bits.len() * 8 != keys.len() {
        return None;
    }
    let index: Vec<u16> = (0..keys.len())
        .filter(|&i| (bits[i / 8] >> (i % 8)) & 1 == 0)
        .map(|i| i as u16)
        .collect();
    let mut packed = vec![];
    for &i in &index {
        packed.extend(words(&uncompress(&keys[i as usize])?));
    }
    debug_assert_eq!(packed.len(), index.len() * KEY_WORDS);
    let leaves: Vec<Bytes32> = keys.iter().map(pubkey_root).collect();
    let proof: Vec<u32> = prove_multiproof(&leaves, &index)
        .iter()
        .flat_map(|n| words(n).collect::<Vec<_>>())
        .collect();
    Some(AbsentWire {
        keys: packed,
        index,
        proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stage::initial_store_bytes;
    use crate::tests::{fixture, with_sync, Mock, N};
    use le_sync_core::multiproof::verify_multiproof;
    use le_sync_core::sync::{Bls, BlsSignature};
    use le_sync_core::update_job::{StageState, JOB_LEN, STATE_LEN};
    use std::cell::RefCell;

    /// The fake point of a key: the key twice. The mock "decompresses" by taking the first 48
    /// bytes, so a test can check that the hints carry the keys they should.
    fn fake_point(k: &BlsPubkey) -> Option<[u8; 96]> {
        let mut p = [0u8; 96];
        p[..48].copy_from_slice(k);
        p[48..].copy_from_slice(k);
        Some(p)
    }

    /// A rooted backend with the verdicts of the wire `Mock`. `prepare_rooted` does what the
    /// real one does short of the curve: the hinted keys must hash to leaves that the
    /// multiproof ties to the keys root.
    struct Backend {
        calls: RefCell<Vec<&'static str>>,
        absent_seen: RefCell<Vec<u16>>,
    }
    impl Backend {
        fn new() -> Self {
            Self {
                calls: RefCell::new(vec![]),
                absent_seen: RefCell::new(vec![]),
            }
        }
        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }
    impl StagedBls for Backend {
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
            let ok = Mock.fast_aggregate_verify(
                committee,
                aggregate_pubkey,
                bits,
                signing_root,
                signature,
            );
            state[0] = ok as u8;
            state[STATE_LEN - 1] = 0x11;
            ok
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
            let mut leaves = vec![];
            for i in 0..absent.index.len() {
                let p = absent.key_bytes(i).ok_or(Error::AbsentKeys)?;
                if p[..48] != p[48..] {
                    return Err(Error::AbsentKeys);
                }
                let mut k = [0u8; 48];
                k.copy_from_slice(&p[..48]);
                leaves.push(pubkey_root(&k));
            }
            if !verify_multiproof(keys_root, len, absent.index, &leaves, absent.siblings()) {
                return Err(Error::AbsentKeys);
            }
            *self.absent_seen.borrow_mut() = absent.index.to_vec();
            let dummy = vec![[0u8; 48]; len];
            let ok =
                Mock.fast_aggregate_verify(&dummy, aggregate_pubkey, bits, signing_root, signature);
            state[0] = ok as u8;
            state[STATE_LEN - 1] = 0x11;
            if ok {
                Ok(())
            } else {
                Err(Error::BadSignature)
            }
        }
        fn miller(&self, state: &mut StageState) -> bool {
            self.calls.borrow_mut().push("miller");
            assert_eq!(state[STATE_LEN - 1], 0x11, "state from prepare");
            state[STATE_LEN - 1] = 0x22;
            true
        }
        fn finish(&self, state: &StageState) -> bool {
            self.calls.borrow_mut().push("finish");
            assert_eq!(state[STATE_LEN - 1], 0x22, "state from miller");
            state[0] == 1
        }
    }

    struct Setup {
        cfg: StageConfig,
        full: Vec<u8>,
        rooted: Vec<u8>,
        update: UpdateWire,
        keys: Vec<BlsPubkey>,
    }
    fn setup() -> Setup {
        let input = with_sync(fixture());
        let s = input.sync.as_ref().unwrap();
        Setup {
            cfg: StageConfig::from_input(&input, s),
            full: initial_store_bytes(&input, s).unwrap(),
            rooted: initial_rooted_store_bytes(&input, s).unwrap(),
            update: s.updates[0].clone(),
            keys: pubkeys(&input.pubkeys).unwrap(),
        }
    }
    impl Setup {
        fn absent(&self, bits: &[u8]) -> AbsentWire {
            absent_wire(&self.keys, bits, fake_point).unwrap()
        }
        fn begin_input(&self, bits: &[u8]) -> RootedInput {
            let mut u = self.update.clone();
            u.bits = bits.to_vec();
            RootedInput::Begin {
                store: self.rooted.clone(),
                update: to_rooted_update(&u).unwrap(),
                absent: self.absent(bits),
            }
        }
        /// begin, miller, finish over the rooted store with `bits`; the new store bytes.
        fn rooted_run(&self, bits: &[u8], b: &Backend) -> Result<Vec<u8>, Error> {
            let job = job_of(run_rooted(&self.cfg, &self.begin_input(bits), b))?;
            let job = job_of(run_rooted(&self.cfg, &RootedInput::Miller { job }, b))?;
            let mut u = self.update.clone();
            u.bits = bits.to_vec();
            match run_rooted(
                &self.cfg,
                &RootedInput::Finish {
                    job,
                    store: self.rooted.clone(),
                    update: to_rooted_update(&u).unwrap(),
                },
                b,
            )? {
                StageOutput::Store(s) => Ok(s),
                other => panic!("expected a store, got {other:?}"),
            }
        }
        /// The same update through the full-store path.
        fn full_run(&self, bits: &[u8], b: &Backend) -> Result<Vec<u8>, Error> {
            let mut u = self.update.clone();
            u.bits = bits.to_vec();
            let job = job_of(run_stage(
                &self.cfg,
                &StageInput::Begin {
                    store: self.full.clone(),
                    update: u.clone(),
                },
                b,
            ))?;
            let job = job_of(run_stage(&self.cfg, &StageInput::Miller { job }, b))?;
            match run_stage(
                &self.cfg,
                &StageInput::Finish {
                    job,
                    store: self.full.clone(),
                    update: u,
                },
                b,
            )? {
                StageOutput::Store(s) => Ok(s),
                other => panic!("expected a store, got {other:?}"),
            }
        }
    }
    /// The v2 bytes of a v1 store. A store is tens of KB and a debug test thread's stack is
    /// small, so each conversion has a frame of its own and the stores live on the heap.
    #[inline(never)]
    fn rooted_form(full: &[u8]) -> Vec<u8> {
        let s = Box::new(decode_store(full).unwrap());
        let r = Box::new(s.to_rooted().unwrap());
        encode(&r).unwrap()
    }
    fn job_of(o: Result<StageOutput, Error>) -> Result<Vec<u8>, Error> {
        match o? {
            StageOutput::Job(j) => Ok(j),
            other => panic!("expected a job, got {other:?}"),
        }
    }

    fn bits_of(n: usize, absent: &[usize]) -> Vec<u8> {
        let mut b = vec![0xFFu8; n / 8];
        for &i in absent {
            b[i / 8] &= !(1 << (i % 8));
        }
        b
    }

    // ---- the rooted run equals the full run -------------------------------------------------

    #[test]
    fn rooted_store_is_the_403_byte_v2_form_of_the_bootstrap_store() {
        let s = setup();
        assert_eq!(s.rooted.len(), 403);
        assert_eq!(s.rooted[0], 2);
        assert_eq!(s.rooted, rooted_form(&s.full));
        let rooted = Box::new(decode_store(&s.rooted).unwrap());
        assert!(rooted.current_sync_committee.is_rooted());
        assert!(!rooted.is_next_sync_committee_known());
    }

    #[test]
    fn the_rooted_run_ends_in_the_rooted_form_of_the_full_run() {
        let s = setup();
        let cases: [(&str, Vec<usize>); 4] = [
            ("full participation", vec![]),
            ("22 of 32, the last ten absent", (22..32).collect()),
            (
                "scattered, 0xEE bytes",
                (0..32).filter(|i| i % 8 == 0 || i % 8 == 4).collect(),
            ),
            ("one absent", vec![17]),
        ];
        for (name, absent) in cases {
            let bits = bits_of(N, &absent);
            let b = Backend::new();
            let got = s.rooted_run(&bits, &b).unwrap();
            assert_eq!(b.calls(), ["prepare_rooted", "miller", "finish"], "{name}");
            assert_eq!(
                *b.absent_seen.borrow(),
                absent.iter().map(|&i| i as u16).collect::<Vec<_>>(),
                "{name}"
            );
            let want = rooted_form(&s.full_run(&bits, &Backend::new()).unwrap());
            assert_eq!(got, want, "{name}");
            assert_eq!(got.len(), 403, "{name}");
            assert_ne!(got, s.rooted, "{name}: the store moved");
        }
    }

    #[test]
    fn jobs_are_the_same_size_as_the_full_path() {
        let s = setup();
        let b = Backend::new();
        let bits = bits_of(N, &[3, 4]);
        let j = job_of(run_rooted(&s.cfg, &s.begin_input(&bits), &b)).unwrap();
        assert_eq!(j.len(), JOB_LEN);
    }

    // ---- the hints are checked --------------------------------------------------------------

    fn begin_with(s: &Setup, bits: &[u8], edit: impl FnOnce(&mut AbsentWire)) -> Result<(), Error> {
        let RootedInput::Begin {
            store,
            update,
            mut absent,
        } = s.begin_input(bits)
        else {
            unreachable!()
        };
        edit(&mut absent);
        run_rooted(
            &s.cfg,
            &RootedInput::Begin {
                store,
                update,
                absent,
            },
            &Backend::new(),
        )
        .map(|_| ())
    }

    #[test]
    fn hints_that_are_not_exactly_the_absent_members_are_refused() {
        let s = setup();
        let bits = bits_of(N, &[22, 25, 30]);
        assert_eq!(begin_with(&s, &bits, |_| {}), Ok(()));
        // a member dropped, one added, one swapped for a present member
        assert_eq!(
            begin_with(&s, &bits, |a| {
                a.index.pop();
                a.keys.truncate(a.keys.len() - KEY_WORDS);
            }),
            Err(Error::AbsentKeys)
        );
        assert_eq!(
            begin_with(&s, &bits, |a| {
                a.index.push(31);
                a.keys.extend([0u32; KEY_WORDS]);
            }),
            Err(Error::AbsentKeys)
        );
        assert_eq!(
            begin_with(&s, &bits, |a| a.index[1] = 24),
            Err(Error::AbsentKeys)
        );
        // positions out of order
        assert_eq!(
            begin_with(&s, &bits, |a| {
                a.index.swap(0, 1);
            }),
            Err(Error::AbsentKeys)
        );
        // keys that do not fit the positions
        assert_eq!(
            begin_with(&s, &bits, |a| {
                a.keys.pop();
            }),
            Err(Error::AbsentKeys)
        );
    }

    #[test]
    fn a_wrong_key_or_a_wrong_proof_is_refused() {
        let s = setup();
        let bits = bits_of(N, &[22, 25, 30]);
        // another member's key in place of the first absent one
        assert_eq!(
            begin_with(&s, &bits, |a| {
                let other = fake_point(&s.keys[1]).unwrap();
                a.keys[..KEY_WORDS].copy_from_slice(&words(&other).collect::<Vec<_>>());
            }),
            Err(Error::AbsentKeys)
        );
        // a key from nowhere
        assert_eq!(
            begin_with(&s, &bits, |a| a.keys[0] ^= 1),
            Err(Error::AbsentKeys)
        );
        // every word of the proof matters, and a proof that is too long or too short
        let n_proof = s.absent(&bits).proof.len();
        assert!(n_proof > 0);
        for i in 0..n_proof {
            assert_eq!(
                begin_with(&s, &bits, |a| a.proof[i] ^= 1),
                Err(Error::AbsentKeys),
                "proof word {i}"
            );
        }
        assert_eq!(
            begin_with(&s, &bits, |a| a.proof.extend([0u32; 8])),
            Err(Error::AbsentKeys)
        );
        assert_eq!(
            begin_with(&s, &bits, |a| a.proof.truncate(a.proof.len() - 8)),
            Err(Error::AbsentKeys)
        );
        assert_eq!(
            begin_with(&s, &bits, |a| a.proof.truncate(a.proof.len() - 1)),
            Err(Error::AbsentKeys)
        );
    }

    #[test]
    fn full_participation_takes_no_hints_and_refuses_any() {
        let s = setup();
        let bits = bits_of(N, &[]);
        assert_eq!(begin_with(&s, &bits, |_| {}), Ok(()));
        assert!(s.absent(&bits).proof.is_empty());
        assert_eq!(
            begin_with(&s, &bits, |a| {
                a.index.push(0);
                a.keys.extend([0u32; KEY_WORDS]);
            }),
            Err(Error::AbsentKeys)
        );
    }

    // ---- the two store forms do not mix -----------------------------------------------------

    #[test]
    fn a_full_store_is_refused_by_the_rooted_path_and_a_rooted_store_by_the_full_one() {
        let s = setup();
        let bits = bits_of(N, &[22]);
        let b = Backend::new();
        let RootedInput::Begin { update, absent, .. } = s.begin_input(&bits) else {
            unreachable!()
        };
        assert_eq!(
            run_rooted(
                &s.cfg,
                &RootedInput::Begin {
                    store: s.full.clone(),
                    update,
                    absent,
                },
                &b
            ),
            Err(Error::AbsentKeys)
        );
        assert_eq!(
            run_stage(
                &s.cfg,
                &StageInput::Begin {
                    store: s.rooted.clone(),
                    update: s.update.clone(),
                },
                &b
            ),
            Err(Error::AbsentKeys)
        );
        assert!(b.calls().is_empty());
    }

    // ---- the gate, the job, the store -------------------------------------------------------

    #[test]
    fn below_two_thirds_is_refused_before_any_hint_is_read() {
        let s = setup();
        let bits = bits_of(N, &(21..32).collect::<Vec<_>>()); // 21 of 32
        let b = Backend::new();
        assert_eq!(
            run_rooted(&s.cfg, &s.begin_input(&bits), &b),
            Err(Error::BelowThreshold)
        );
        assert!(b.calls().is_empty());
        let ok = bits_of(N, &(22..32).collect::<Vec<_>>()); // 22 of 32
        assert!(run_rooted(&s.cfg, &s.begin_input(&ok), &b).is_ok());
    }

    #[test]
    fn finish_is_bound_to_the_store_the_update_and_the_job_step() {
        let s = setup();
        let bits = bits_of(N, &[22, 25]);
        let b = Backend::new();
        let j1 = job_of(run_rooted(&s.cfg, &s.begin_input(&bits), &b)).unwrap();
        let j2 = job_of(run_rooted(
            &s.cfg,
            &RootedInput::Miller { job: j1.clone() },
            &b,
        ))
        .unwrap();
        let mut u = s.update.clone();
        u.bits = bits.clone();
        let fin = |job: &[u8], store: &[u8], update: &RootedUpdate| {
            run_rooted(
                &s.cfg,
                &RootedInput::Finish {
                    job: job.to_vec(),
                    store: store.to_vec(),
                    update: update.clone(),
                },
                &b,
            )
        };
        let ru = to_rooted_update(&u).unwrap();
        assert!(fin(&j2, &s.rooted, &ru).is_ok());
        // a job that has not been through Miller
        assert_eq!(fin(&j1, &s.rooted, &ru), Err(Error::WrongStep));
        // a store that moved on
        let mut other = s.rooted.clone();
        other[9] ^= 1;
        assert_eq!(fin(&j2, &other, &ru), Err(Error::StoreChanged));
        // another update
        let mut u2 = ru.clone();
        u2.update.signature[1] ^= 1;
        assert_eq!(fin(&j2, &s.rooted, &u2), Err(Error::JobMismatch));
        let mut u3 = ru.clone();
        u3.update.bits = bits_of(N, &[22]);
        assert_eq!(fin(&j2, &s.rooted, &u3), Err(Error::JobMismatch));
        // Miller works on bytes alone and refuses corrupt ones
        assert_eq!(
            run_rooted(
                &s.cfg,
                &RootedInput::Miller {
                    job: j1[..10].to_vec()
                },
                &b
            ),
            Err(Error::JobMismatch)
        );
    }

    #[test]
    fn corrupt_store_bytes_are_store_encoding() {
        let s = setup();
        let bits = bits_of(N, &[22]);
        for bad in [vec![], s.rooted[..402].to_vec(), {
            let mut v = s.rooted.clone();
            v.push(0);
            v
        }] {
            let RootedInput::Begin { update, absent, .. } = s.begin_input(&bits) else {
                unreachable!()
            };
            assert_eq!(
                run_rooted(
                    &s.cfg,
                    &RootedInput::Begin {
                        store: bad,
                        update,
                        absent
                    },
                    &Backend::new()
                ),
                Err(Error::StoreEncoding)
            );
        }
    }

    // ---- the next committee as a root -------------------------------------------------------

    #[test]
    fn a_next_committee_travels_as_its_keys_root() {
        let s = setup();
        let keys: Vec<BlsPubkey> = (0..N)
            .map(|i| {
                let mut k = [0u8; 48];
                k[0] = 100 + i as u8;
                k
            })
            .collect();
        let mut u = s.update.clone();
        u.next_pubkeys = keys.concat();
        u.next_aggregate = vec![5u8; 48];
        let r = to_rooted_update(&u).unwrap();
        assert!(r.update.next_pubkeys.is_empty());
        assert_eq!(r.update.next_aggregate, vec![5u8; 48]);
        assert_eq!(r.next_keys_root, Some(pubkeys_root(&keys).unwrap()));
        // the committee the program builds has the same root as the full one
        let rooted = next_committee(&r, N).unwrap();
        let full = SyncCommittee::new(&keys, [5u8; 48]).unwrap();
        assert!(rooted.is_rooted());
        assert_eq!(rooted.root(), full.root());
        // no next committee: unknown
        let none = to_rooted_update(&s.update).unwrap();
        assert_eq!(none.next_keys_root, None);
        assert_eq!(next_committee(&none, N), Ok(SyncCommittee::empty(N)));
    }

    #[test]
    fn malformed_next_committees_are_typed_errors() {
        let s = setup();
        let ok = to_rooted_update(&s.update).unwrap();
        let bad = Error::BadSyncCommitteeSize;
        // keys left on the wire
        let mut r = ok.clone();
        r.update.next_pubkeys = vec![1u8; 48 * N];
        assert_eq!(next_committee(&r, N), Err(bad));
        // a root without an aggregate, an aggregate without a root, a short aggregate
        let mut r = ok.clone();
        r.next_keys_root = Some([1u8; 32]);
        assert_eq!(next_committee(&r, N), Err(bad));
        let mut r = ok.clone();
        r.update.next_aggregate = vec![1u8; 48];
        assert_eq!(next_committee(&r, N), Err(bad));
        let mut r = ok.clone();
        r.next_keys_root = Some([1u8; 32]);
        r.update.next_aggregate = vec![1u8; 47];
        assert_eq!(next_committee(&r, N), Err(bad));
        // a size that is not a committee size
        let mut r = ok;
        r.next_keys_root = Some([1u8; 32]);
        r.update.next_aggregate = vec![1u8; 48];
        assert_eq!(next_committee(&r, 24), Err(bad));
        // host side: keys without an aggregate, a partial key, an aggregate of the wrong size
        let mut u = s.update.clone();
        u.next_pubkeys = vec![1u8; 48 * N];
        assert_eq!(to_rooted_update(&u), Err(bad));
        u.next_aggregate = vec![1u8; 47];
        assert_eq!(to_rooted_update(&u), Err(bad));
        u.next_aggregate = vec![1u8; 48];
        u.next_pubkeys = vec![1u8; 47];
        assert_eq!(to_rooted_update(&u), Err(bad));
        let mut u = s.update.clone();
        u.next_aggregate = vec![1u8; 48];
        assert_eq!(to_rooted_update(&u), Err(bad));
    }

    // ---- the host helpers -------------------------------------------------------------------

    fn leaf(i: usize) -> Bytes32 {
        let mut l = [0u8; 32];
        l[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        l[31] = 0x77;
        l
    }

    /// A tiny deterministic generator, so the index sets are spread without a dependency.
    fn lcg(seed: &mut u64) -> u64 {
        *seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *seed >> 33
    }

    #[test]
    fn the_prover_and_the_core_verifier_agree_on_many_index_sets() {
        let mut seed = 7u64;
        for n in [1usize, 2, 4, 32, 512] {
            let leaves: Vec<Bytes32> = (0..n).map(leaf).collect();
            let mut level = leaves.clone();
            while level.len() > 1 {
                level = level.chunks(2).map(|p| hash_pair(&p[0], &p[1])).collect();
            }
            let root = level[0];
            let mut sets: Vec<Vec<u16>> =
                vec![vec![], (0..n as u16).collect(), vec![0], vec![n as u16 - 1]];
            if n >= 4 {
                sets.push(vec![0, 1]);
                sets.push(vec![1, 2]);
                sets.push(vec![n as u16 - 2, n as u16 - 1]);
            }
            for _ in 0..12 {
                let take = lcg(&mut seed) as usize % (n + 1);
                let set: Vec<u16> = (0..n as u16)
                    .filter(|_| lcg(&mut seed) as usize % n < take)
                    .collect();
                sets.push(set);
            }
            for set in sets {
                let proof = prove_multiproof(&leaves, &set);
                let picked: Vec<Bytes32> = set.iter().map(|&i| leaves[i as usize]).collect();
                assert!(
                    verify_multiproof(&root, n, &set, &picked, proof.iter().copied()),
                    "n={n} set={set:?}"
                );
                // one sibling less or more is refused
                if !proof.is_empty() {
                    assert!(!verify_multiproof(
                        &root,
                        n,
                        &set,
                        &picked,
                        proof[1..].iter().copied()
                    ));
                }
                assert!(!verify_multiproof(
                    &root,
                    n,
                    &set,
                    &picked,
                    proof.iter().copied().chain([ZERO_NODE])
                ));
            }
        }
    }
    const ZERO_NODE: Bytes32 = [0u8; 32];

    #[test]
    fn a_proof_is_much_smaller_than_the_keys_it_replaces() {
        // 170 of 512 absent, spread out: the proof is a few hundred nodes, not 512 keys
        let leaves: Vec<Bytes32> = (0..512).map(leaf).collect();
        let set: Vec<u16> = (0..512u16).filter(|i| i % 3 == 0).collect();
        let p = prove_multiproof(&leaves, &set);
        assert!(p.len() < 512, "{}", p.len());
        assert!(!p.is_empty());
    }

    #[test]
    fn absent_wire_packs_each_key_as_24_little_endian_words() {
        let s = setup();
        let bits = bits_of(N, &[2, 5]);
        let a = s.absent(&bits);
        assert_eq!(a.index, vec![2, 5]);
        assert_eq!(a.keys.len(), 2 * KEY_WORDS);
        let expect = fake_point(&s.keys[2]).unwrap();
        for (w, c) in a.keys[..KEY_WORDS].iter().zip(expect.chunks(4)) {
            assert_eq!(*w, u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
        }
        // the view reads them back to the same bytes
        assert_eq!(a.view().key_bytes(0), Some(expect));
        assert_eq!(a.view().key_bytes(1), fake_point(&s.keys[5]));
        assert_eq!(a.view().key_bytes(2), None);
        assert!(a.view().well_formed());
        // 8 words per sibling
        assert_eq!(a.proof.len() % 8, 0);
        assert_eq!(a.view().siblings().count(), a.proof.len() / 8);
    }

    #[test]
    fn absent_wire_refuses_what_it_cannot_serve() {
        let s = setup();
        let bits = bits_of(N, &[2]);
        // a key that does not uncompress
        assert_eq!(absent_wire(&s.keys, &bits, |_| None), None);
        // bits that do not cover the keys, a committee that is not a power of two
        assert_eq!(absent_wire(&s.keys, &bits[..3], fake_point), None);
        assert_eq!(
            absent_wire(&s.keys[..24], &bits_of(24, &[]), fake_point),
            None
        );
        assert_eq!(absent_wire(&[], &[], fake_point), None);
        // with nobody absent no key is needed, so none is asked for
        let all = bits_of(N, &[]);
        assert_eq!(
            absent_wire(&s.keys, &all, |_| None),
            Some(AbsentWire::default())
        );
    }
}
