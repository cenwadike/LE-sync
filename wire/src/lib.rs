//! Guest input/output types and `verify`, the whole of what the zkVM guest executes
//! (Sprint 1 scope: bootstrap + finality branches; Sprint 2 `sync` goes here next).
//! Kept free of risc0 so it runs natively in tests; the guest is a 3-line wrapper.
//!
//! serde note: `[u8; 48]` has no serde impl, so pubkeys travel as one flat `Vec<u8>`.
pub mod bls;

use le_sync_core::sync::{
    initialize_light_client_store, process_light_client_update, Bls, ForkSchedule,
    LightClientUpdate, SyncCommittee, SyncConfig,
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
    pub genesis_validators_root: Bytes32,
    pub epochs_per_period: u64,
    /// Ascending `(fork_epoch, fork_version)`, genesis first.
    pub forks: Vec<(u64, [u8; 4])>,
    /// Chosen by the host (guest has no clock). It is part of what the proof is about.
    pub current_slot: u64,
    pub updates: Vec<UpdateWire>,
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
    pub sync_rejected: u32,
    pub finalized_slot: u64,
    pub finalized_root: Bytes32,
    pub optimistic_slot: u64,
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
    /// normal run -> something validated, nothing rejected;
    /// `expect_reject` (bad signature / other chain) -> nothing validated, something rejected.
    pub fn sync_success(&self, expect_reject: bool) -> bool {
        if expect_reject {
            self.sync_validated == 0 && self.sync_rejected > 0
        } else {
            self.sync_validated > 0 && self.sync_rejected == 0
        }
    }
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
) {
    let ta = cc();
    let n_updates = s.updates.len() as u32;
    let header = BeaconBlockHeader::from(&i.boot_header);
    let setup = (|| {
        let forks = ForkSchedule::new(&s.forks).ok()?;
        let c = committee_from(&i.pubkeys, &i.aggregate, i.pubkeys.len() / 48)?;
        Some((forks, c))
    })();
    let Some((forks, committee)) = setup else {
        out.sync_rejected = n_updates;
        return;
    };
    let tb = cc();
    let size = committee.len;
    let scfg = SyncConfig {
        chain: cfg,
        epochs_per_period: s.epochs_per_period,
        genesis_validators_root: s.genesis_validators_root,
        forks,
    };
    let Ok(mut store) =
        initialize_light_client_store(&scfg, &i.trusted_root, &header, committee, &i.boot_branch)
    else {
        out.sync_rejected = n_updates;
        return;
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
        match process_light_client_update(&mut store, &lcu, s.current_slot, &scfg, bls) {
            Ok(()) => out.sync_validated += 1,
            Err(Error::UpdateNotRelevant) => out.sync_not_relevant += 1,
            Err(_) => out.sync_rejected += 1,
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
}

/// Never panics on malformed input: it just reports `bootstrap_ok = false` / rejections.
pub fn verify<B: Bls>(i: &GuestInput, bls: &B) -> GuestOutput {
    let cfg = ChainConfig {
        slots_per_epoch: i.slots_per_epoch,
        electra_fork_epoch: i.electra_fork_epoch,
        gloas_fork_epoch: i.gloas_fork_epoch,
    };
    let mut out = GuestOutput {
        trusted_root: i.trusted_root,
        ..Default::default()
    };
    let header = BeaconBlockHeader::from(&i.boot_header);
    let agg: Option<BlsPubkey> = i.aggregate.as_slice().try_into().ok();
    let t0 = cc();
    out.bootstrap_ok = match (pubkeys(&i.pubkeys), agg) {
        (Some(keys), Some(agg)) => {
            verify_bootstrap(&cfg, &i.trusted_root, &header, &keys, &agg, &i.boot_branch).is_ok()
        }
        _ => false,
    };
    let t1 = cc();
    // Spec: no further trust in anything if the anchor is not the trusted root.
    if !out.bootstrap_ok {
        out.finality_fail = i.finality.len() as u32;
        if let Some(s) = &i.sync {
            out.sync_rejected = s.updates.len() as u32;
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
        run_sync(i, s, cfg, bls, &mut out);
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
        let keys: Vec<BlsPubkey> = (0..N)
            .map(|i| {
                let mut k = [0u8; 48];
                k[0] = i as u8 + 1;
                k
            })
            .collect();
        let agg = [9u8; 48];
        let mut f: Vec<Bytes32> = (0..64).map(|i| leaf(100 + i as u8)).collect();
        f[22] = sync_committee_root(&keys, &agg).unwrap();
        let (sroot, boot_branch) = root_and_branch(f, 22);
        let boot = hdr(8, sroot);
        let boot_root = BeaconBlockHeader::from(&boot).hash_tree_root();

        let fin = hdr(24, leaf(9));
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
            // (sync section is attached by `with_sync`)
        }
    }

    /// Adds one finality-only update (no next committee) at slots 40/41 signed (per Mock) by sig[0]==7.
    fn with_sync(mut i: GuestInput) -> GuestInput {
        let f = i.finality[0].clone();
        i.sync = Some(SyncInput {
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
        i.sync.as_mut().unwrap().updates[0].signature[0] ^= 1; // tampered signature
        let o = verify(&i, &Mock);
        assert_eq!((o.sync_validated, o.sync_rejected), (0, 1));
        assert!(o.sync_success(true) && !o.sync_success(false));

        let mut i = with_sync(fixture());
        i.sync.as_mut().unwrap().genesis_validators_root = [0xBB; 32]; // other chain config
        let o = verify(&i, &Mock);
        assert_eq!((o.sync_validated, o.sync_rejected), (0, 1));
    }

    #[test]
    fn sync_old_update_is_not_relevant_not_rejected() {
        let mut i = with_sync(fixture());
        let u = &mut i.sync.as_mut().unwrap().updates[0];
        u.attested.slot = 8; // not newer than the bootstrap's finalized slot
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
}
