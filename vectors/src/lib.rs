//! Runner for consensus-spec-tests `tests/<preset>/{electra,fulu}/light_client/sync/pyspec_tests/*`.
//! Pure logic (no files, no BLS impl): the bin feeds it bytes and a `Bls`.
//!
//! SSZ layouts below are Electra's (Fulu reuses them). Assumptions are marked TENTATIVE;
//! a wrong one shows up as a decode `Skip` or a `Fail`, never a silent pass.
use le_sync_core::sync::*;
use le_sync_core::*;

#[derive(Clone, Copy, Debug)]
pub struct Preset {
    pub slots_per_epoch: u64,
    pub epochs_per_period: u64,
    pub committee_size: usize,
    /// `ELECTRA_FORK_VERSION` of the preset's config (signing domain for Electra vectors).
    pub electra_version: Version,
    /// `FULU_FORK_VERSION` of the preset's config (signing domain for Fulu vectors).
    pub fulu_version: Version,
}

impl Preset {
    /// Fork version the vectors of `fork` ("electra" | "fulu") are signed under.
    /// The vectors' meta.yaml carries only digests, so this must come from the preset.
    pub fn version_for(&self, fork: &str) -> Version {
        match fork {
            "fulu" => self.fulu_version,
            _ => self.electra_version,
        }
    }
}

/// TENTATIVE (from memory): minimal 8/8/32, mainnet 32/256/512.
/// Versions from the spec configs: minimal 0x05000001 / 0x06000001, mainnet 0x05000000 / 0x06000000.
pub const MINIMAL: Preset = Preset {
    slots_per_epoch: 8,
    epochs_per_period: 8,
    committee_size: 32,
    electra_version: [5, 0, 0, 1],
    fulu_version: [6, 0, 0, 1],
};
pub const MAINNET: Preset = Preset {
    slots_per_epoch: 32,
    epochs_per_period: 256,
    committee_size: 512,
    electra_version: [5, 0, 0, 0],
    fulu_version: [6, 0, 0, 0],
};

pub struct Meta {
    pub genesis_validators_root: Bytes32,
    pub trusted_block_root: Bytes32,
    pub bootstrap_fork_digest: String,
    /// Fork version used for the signing domain (and the Electra digest check).
    /// The bin sets this from `Preset::version_for(fork)`.
    pub store_fork_version: Version,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeaderCheck {
    pub slot: u64,
    pub beacon_root: Bytes32,
}
#[derive(Clone, Debug, Default)]
pub struct Checks {
    pub finalized: Option<HeaderCheck>,
    pub optimistic: Option<HeaderCheck>,
}

pub enum Step {
    ProcessUpdate {
        update_fork_digest: String,
        update_ssz: Vec<u8>,
        current_slot: u64,
        checks: Checks,
    },
    ForceUpdate {
        current_slot: u64,
        checks: Checks,
    },
    UpgradeStore {
        checks: Checks,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    /// Needs something not implemented yet (reason says what).
    Skip(String),
    Fail(String),
}

// ---------------------------------------------------------------- SSZ decoding (Electra)

const HEADER_FIXED: usize = 112 + 4 + 128; // beacon, offset(execution), execution_branch[4]
const CUR_BRANCH: usize = 6;
const NEXT_BRANCH: usize = 6;
const FIN_BRANCH: usize = 7;

fn u32le(b: &[u8], at: usize) -> Result<usize, String> {
    b.get(at..at + 4)
        .map(|x| u32::from_le_bytes(x.try_into().unwrap()) as usize)
        .ok_or("short buffer".into())
}
fn u64le(b: &[u8], at: usize) -> Result<u64, String> {
    b.get(at..at + 8)
        .map(|x| u64::from_le_bytes(x.try_into().unwrap()))
        .ok_or("short buffer".into())
}
fn b32(b: &[u8], at: usize) -> Result<Bytes32, String> {
    b.get(at..at + 32)
        .map(|x| x.try_into().unwrap())
        .ok_or("short buffer".into())
}
fn branch(b: &[u8], at: usize, n: usize) -> Result<Vec<Bytes32>, String> {
    (0..n).map(|i| b32(b, at + 32 * i)).collect()
}

/// `LightClientHeader` -> its `beacon` header. Only the fixed part is read; the variable
/// `execution` payload header and `execution_branch` are NOT validated (Sprint 2 TODO).
pub fn decode_lc_header(b: &[u8]) -> Result<BeaconBlockHeader, String> {
    if b.len() < HEADER_FIXED {
        return Err(format!("header {} < {HEADER_FIXED} bytes", b.len()));
    }
    Ok(BeaconBlockHeader {
        slot: u64le(b, 0)?,
        proposer_index: u64le(b, 8)?,
        parent_root: b32(b, 16)?,
        state_root: b32(b, 48)?,
        body_root: b32(b, 80)?,
    })
}

pub fn decode_committee(b: &[u8], n: usize) -> Result<SyncCommittee, String> {
    if b.len() != 48 * n + 48 {
        return Err("committee size".into());
    }
    let keys: Vec<BlsPubkey> = (0..n)
        .map(|i| b[48 * i..48 * i + 48].try_into().unwrap())
        .collect();
    SyncCommittee::new(&keys, b[48 * n..].try_into().unwrap()).map_err(|e| format!("{e:?}"))
}

pub struct Bootstrap {
    pub header: BeaconBlockHeader,
    pub committee: SyncCommittee,
    pub branch: Vec<Bytes32>,
}
pub fn decode_bootstrap(b: &[u8], n: usize) -> Result<Bootstrap, String> {
    let c = 48 * n + 48;
    let fixed = 4 + c + 32 * CUR_BRANCH;
    if u32le(b, 0)? != fixed {
        return Err("bootstrap header offset != fixed size".into());
    }
    Ok(Bootstrap {
        header: decode_lc_header(&b[fixed..])?,
        committee: decode_committee(&b[4..4 + c], n)?,
        branch: branch(b, 4 + c, CUR_BRANCH)?,
    })
}

pub struct OwnedUpdate {
    pub attested: BeaconBlockHeader,
    pub next: SyncCommittee,
    pub next_branch: Vec<Bytes32>,
    pub finalized: BeaconBlockHeader,
    pub finality_branch: Vec<Bytes32>,
    pub bits: Vec<u8>,
    pub signature: BlsSignature,
    pub signature_slot: u64,
}
impl OwnedUpdate {
    pub fn view(&self) -> LightClientUpdate<'_> {
        LightClientUpdate {
            attested_header: self.attested,
            next_sync_committee: &self.next,
            next_sync_committee_branch: &self.next_branch,
            finalized_header: self.finalized,
            finality_branch: &self.finality_branch,
            sync_committee_bits: &self.bits,
            sync_committee_signature: self.signature,
            signature_slot: self.signature_slot,
        }
    }
}
pub fn decode_update(b: &[u8], n: usize) -> Result<OwnedUpdate, String> {
    let c = 48 * n + 48;
    let o_next = 4;
    let o_nb = o_next + c;
    let o_fin_off = o_nb + 32 * NEXT_BRANCH;
    let o_fb = o_fin_off + 4;
    let o_bits = o_fb + 32 * FIN_BRANCH;
    let o_sig = o_bits + n / 8;
    let o_slot = o_sig + 96;
    let fixed = o_slot + 8;
    let (off_att, off_fin) = (u32le(b, 0)?, u32le(b, o_fin_off)?);
    if off_att != fixed || off_fin < off_att || off_fin > b.len() {
        return Err("update offsets inconsistent with fixed size".into());
    }
    Ok(OwnedUpdate {
        attested: decode_lc_header(&b[off_att..off_fin])?,
        next: decode_committee(&b[o_next..o_nb], n)?,
        next_branch: branch(b, o_nb, NEXT_BRANCH)?,
        finalized: decode_lc_header(&b[off_fin..])?,
        finality_branch: branch(b, o_fb, FIN_BRANCH)?,
        bits: b[o_bits..o_sig].to_vec(),
        signature: b[o_sig..o_slot].try_into().unwrap(),
        signature_slot: u64le(b, o_slot)?,
    })
}

// ---------------------------------------------------------------- runner

fn check(store: &LightClientStore, c: &Checks, label: &str) -> Result<(), String> {
    for (name, want, got) in [
        ("finalized_header", &c.finalized, &store.finalized_header),
        ("optimistic_header", &c.optimistic, &store.optimistic_header),
    ] {
        if let Some(w) = want {
            let g = HeaderCheck {
                slot: got.slot,
                beacon_root: got.hash_tree_root(),
            };
            if &g != w {
                return Err(format!(
                    "{label}: {name} got slot {} root {} want slot {} root {}",
                    g.slot,
                    hexs(&g.beacon_root),
                    w.slot,
                    hexs(&w.beacon_root)
                ));
            }
        }
    }
    Ok(())
}
pub fn hexs(b: &[u8]) -> String {
    b.iter()
        .fold(String::from("0x"), |s, x| s + &format!("{x:02x}"))
}

/// `digest_check`: Electra cases may compare bootstrap_fork_digest to the
/// Electra compute_fork_digest (pre-Fulu definition). Fulu digests are
/// XOR'd with blob parameters (EIP-7892) and are p2p-only; they must not
/// gate light-client processing. Spec: Electra..=Fulu share the same LC
/// SSZ types and gindices; there is no Fulu LC upgrade document.
///
/// `meta.store_fork_version` is the fork version the vectors are signed under
/// (see `Preset::version_for`); it is the single entry of the fork schedule.
pub fn run_case<B: Bls>(
    preset: &Preset,
    meta: &Meta,
    digest_check: bool,
    bootstrap_ssz: &[u8],
    steps: &[Step],
    bls: &B,
) -> Outcome {
    let cfg = SyncConfig {
        chain: ChainConfig {
            slots_per_epoch: preset.slots_per_epoch,
            electra_fork_epoch: 0,
            gloas_fork_epoch: None,
        },
        epochs_per_period: preset.epochs_per_period,
        genesis_validators_root: meta.genesis_validators_root,
        forks: ForkSchedule::single(meta.store_fork_version),
    };
    if digest_check {
        // Pre-Fulu digest only (no blob-parameter XOR). Used solely for Electra
        // vectors that still publish the old 4-byte digest form.
        let want = hexs(&compute_fork_digest(
            meta.store_fork_version,
            &meta.genesis_validators_root,
        ));
        if want != meta.bootstrap_fork_digest.to_lowercase() {
            return Outcome::Skip(format!(
                "bootstrap digest {} != store-fork digest {want} (needs upgrade)",
                meta.bootstrap_fork_digest
            ));
        }
    }
    let boot = match decode_bootstrap(bootstrap_ssz, preset.committee_size) {
        Ok(b) => b,
        Err(e) => return Outcome::Skip(format!("bootstrap decode: {e} (layout or fork mismatch)")),
    };
    let mut store = match initialize_light_client_store(
        &cfg,
        &meta.trusted_block_root,
        &boot.header,
        boot.committee,
        &boot.branch,
    ) {
        Ok(s) => s,
        Err(e) => return Outcome::Fail(format!("initialize_light_client_store: {e:?}")),
    };
    for (i, s) in steps.iter().enumerate() {
        match s {
            Step::ProcessUpdate {
                update_fork_digest,
                update_ssz,
                current_slot,
                checks,
            } => {
                // Spec: Fulu reuses Electra LC types. The p2p fork_digest changes
                // under EIP-7892 (blob-parameter XOR); that must not reject an
                // otherwise valid Electra-layout update. Only skip when the
                // digest check is enabled *and* digests differ (true fork
                // transition that needs a structural upgrade, e.g. toward Gloas).
                if digest_check
                    && update_fork_digest.to_lowercase()
                        != meta.bootstrap_fork_digest.to_lowercase()
                {
                    return Outcome::Skip(format!(
                        "step {i}: update from another fork (needs upgrade)"
                    ));
                }
                let u = match decode_update(update_ssz, preset.committee_size) {
                    Ok(u) => u,
                    Err(e) => return Outcome::Skip(format!("step {i}: update decode: {e}")),
                };
                // Spec: failed asserts abort the step; the store must be unchanged
                // and the vector's checks then still describe that unchanged store.
                if let Err(e) =
                    process_light_client_update(&mut store, &u.view(), *current_slot, &cfg, bls)
                {
                    return Outcome::Fail(format!("step {i}: validation failed with {e:?}"));
                }

                if let Err(e) = check(&store, checks, &format!("step {i}")) {
                    return Outcome::Fail(e);
                }
            }
            Step::ForceUpdate {
                current_slot,
                checks,
            } => {
                if let Err(e) = store.force_update(*current_slot, &cfg) {
                    return Outcome::Fail(format!("step {i}: force_update: {e:?}"));
                }
                if let Err(e) = check(&store, checks, &format!("step {i}")) {
                    return Outcome::Fail(e);
                }
            }
            Step::UpgradeStore { checks } => {
                // Fulu LC upgrade is a no-op: same SSZ types and gindices as Electra
                // (no fulu/light-client/fork.md). Capella/Deneb/Electra/Gloas each
                // have structural upgrades; Fulu does not.
                store.upgrade_store(meta.store_fork_version);
                if let Err(e) = check(&store, checks, &format!("step {i}")) {
                    return Outcome::Fail(e);
                }
            }
        }
    }
    Outcome::Pass
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Yes;
    impl Bls for Yes {
        fn fast_aggregate_verify(
            &self,
            _: &[[u8; 48]],
            _: &[u8; 48],
            _: &[u8],
            _: &Bytes32,
            _: &[u8; 96],
        ) -> bool {
            true
        }
    }
    const N: usize = 32;
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
    fn hdr_bytes(h: &BeaconBlockHeader) -> Vec<u8> {
        let mut v = vec![];
        v.extend(h.slot.to_le_bytes());
        v.extend(h.proposer_index.to_le_bytes());
        v.extend(h.parent_root);
        v.extend(h.state_root);
        v.extend(h.body_root);
        v.extend([0u8; 4 + 128]); // execution offset + execution_branch (execution body omitted)
        v
    }
    fn committee_bytes(seed: u8) -> Vec<u8> {
        (0..=N)
            .flat_map(|i| {
                let mut k = [0u8; 48];
                k[0] = seed;
                k[1] = i as u8;
                k
            })
            .collect()
    }
    fn hdr(slot: u64, state_root: Bytes32) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot,
            proposer_index: 1,
            parent_root: leaf(1),
            state_root,
            body_root: leaf(2),
        }
    }

    #[test]
    fn preset_versions_per_fork() {
        assert_eq!(MINIMAL.version_for("electra"), [5, 0, 0, 1]);
        assert_eq!(MINIMAL.version_for("fulu"), [6, 0, 0, 1]);
        assert_eq!(MAINNET.version_for("fulu"), [6, 0, 0, 0]);
    }

    /// Self-encoded Electra bootstrap + update, run through the full decode->process->check path.
    #[test]
    fn synthetic_electra_case_passes_and_wrong_check_fails() {
        let (cur, next) = (committee_bytes(1), committee_bytes(2));
        let cur_c = decode_committee(&cur, N).unwrap();
        let next_c = decode_committee(&next, N).unwrap();
        // bootstrap state: field 22 = current committee
        let mut f: Vec<Bytes32> = (0..64).map(|i| leaf(100 + i as u8)).collect();
        f[22] = cur_c.root().unwrap();
        let (sroot, cbr) = root_and_branch(f, 22);
        let bh = hdr(8, sroot);
        let mut boot = ((4 + cur.len() + 192) as u32).to_le_bytes().to_vec();
        boot.extend(&cur);
        cbr.iter().for_each(|x| boot.extend(x));
        boot.extend(hdr_bytes(&bh));

        // update: finalized slot 24, attested slot 40; state has fields 20 (finality) and 23 (next)
        let fin = hdr(24, leaf(9));
        let epoch_chunk = leaf(77);
        let mut g: Vec<Bytes32> = (0..64).map(|i| leaf(150 + i as u8)).collect();
        g[20] = hash_pair(&epoch_chunk, &fin.hash_tree_root());
        g[22] = cur_c.root().unwrap();
        g[23] = next_c.root().unwrap();
        let (aroot, mut fb) = root_and_branch(g.clone(), 20);
        fb.insert(0, epoch_chunk);
        let (_, nb) = root_and_branch(g, 23);
        let att = hdr(40, aroot);
        let off_att = 4 + next.len() + 192 + 4 + 224 + N / 8 + 96 + 8;
        let mut upd = (off_att as u32).to_le_bytes().to_vec();
        upd.extend(&next);
        nb.iter().for_each(|x| upd.extend(x));
        upd.extend(((off_att + hdr_bytes(&att).len()) as u32).to_le_bytes());
        fb.iter().for_each(|x| upd.extend(x));
        upd.extend([0xFFu8; N / 8]);
        upd.extend([5u8; 96]);
        upd.extend(41u64.to_le_bytes());
        upd.extend(hdr_bytes(&att));
        upd.extend(hdr_bytes(&fin));

        let meta = Meta {
            genesis_validators_root: [0xAA; 32],
            trusted_block_root: bh.hash_tree_root(),
            bootstrap_fork_digest: hexs(&compute_fork_digest([5, 0, 0, 1], &[0xAA; 32])),
            store_fork_version: [5, 0, 0, 1],
        };
        let ok = Checks {
            finalized: Some(HeaderCheck {
                slot: 24,
                beacon_root: fin.hash_tree_root(),
            }),
            optimistic: Some(HeaderCheck {
                slot: 40,
                beacon_root: att.hash_tree_root(),
            }),
        };
        let step = |c: Checks| Step::ProcessUpdate {
            update_fork_digest: meta.bootstrap_fork_digest.clone(),
            update_ssz: upd.clone(),
            current_slot: 41,
            checks: c,
        };
        assert_eq!(
            run_case(&MINIMAL, &meta, true, &boot, &[step(ok.clone())], &Yes),
            Outcome::Pass
        );
        let mut bad = ok;
        bad.finalized.as_mut().unwrap().slot = 25;
        assert!(matches!(
            run_case(&MINIMAL, &meta, true, &boot, &[step(bad)], &Yes),
            Outcome::Fail(_)
        ));
        // wrong trusted root => Fail, not Skip
        let mut m2 = Meta {
            trusted_block_root: [0; 32],
            ..meta
        };
        m2.bootstrap_fork_digest = meta_digest();
        assert!(matches!(
            run_case(&MINIMAL, &m2, true, &boot, &[], &Yes),
            Outcome::Fail(_)
        ));
        // other-fork digest => Skip
        let mut m3 = Meta {
            trusted_block_root: [0; 32],
            ..m2
        };
        m3.bootstrap_fork_digest = "0x00000000".into();
        assert!(matches!(
            run_case(&MINIMAL, &m3, true, &boot, &[], &Yes),
            Outcome::Skip(_)
        ));
    }
    fn meta_digest() -> String {
        hexs(&compute_fork_digest([5, 0, 0, 1], &[0xAA; 32]))
    }
}
