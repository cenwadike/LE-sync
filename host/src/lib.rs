//! Host side of LE-Sync Sprint 1: fetch `bootstrap` / `updates` / `finality_update` from a
//! beacon API (or a saved directory of the same JSON) and verify the SSZ Merkle branches with
//! `le-sync-core`.
//!
//! Endpoints (Beacon API, light-client section):
//!   GET /eth/v1/config/spec
//!   GET /eth/v1/beacon/light_client/bootstrap/{block_root}
//!   GET /eth/v1/beacon/light_client/updates?start_period=P&count=N
//!   GET /eth/v1/beacon/light_client/finality_update
//!
//! Gindex/depth are chosen by the *attested/bootstrap header's slot* against the chain's
//! `ELECTRA_FORK_EPOCH` (spec `*_gindex_at_slot`), never from the length of a branch the
//! server sent.

use le_sync_core::{
    is_branch_present, verify_bootstrap, verify_finality_branch, BeaconBlockHeader, Bytes32,
    ChainConfig,
};
use le_sync_wire::{FinalityItem, GuestInput, SyncInput, UpdateWire, WireHeader};
use serde_json::Value;
use std::{fs, path::PathBuf};

const FAR_FUTURE_EPOCH: u64 = u64::MAX;
const SUPPORTED_VERSIONS: &[&str] = &[
    "phase0",
    "altair",
    "bellatrix",
    "capella",
    "deneb",
    "electra",
    "fulu",
];

pub struct Opts {
    pub source: String,
    pub trusted_root: Bytes32,
    pub count: u64,
    pub save_dir: Option<PathBuf>,
    pub tamper: bool,
    pub sync: bool,
    pub tamper_sig: bool,
    pub other_chain: bool,
    /// With `sync`: hand the guest only the newest `finality_update` (cost isolation).
    /// The `/updates` items are fetched (so `--save-dir` stays complete) but not sent.
    pub latest_only: bool,
}

#[derive(Default, Debug)]
pub struct Report {
    pub bootstrap_ok: bool,
    pub finality_pass: u32,
    pub finality_fail: u32,
    pub finality_skip: u32,
}

impl Report {
    pub fn success(&self, tamper: bool) -> bool {
        if tamper {
            !self.bootstrap_ok && self.finality_pass == 0 && self.finality_fail > 0
        } else {
            self.bootstrap_ok && self.finality_fail == 0 && self.finality_pass > 0
        }
    }
}

struct Source<'a> {
    base: &'a str,
    save_dir: Option<&'a PathBuf>,
}

impl Source<'_> {
    fn is_http(&self) -> bool {
        self.base.starts_with("http://") || self.base.starts_with("https://")
    }

    fn get(&self, endpoint: &str, file: &str) -> Result<Value, String> {
        let bytes: Vec<u8> = if self.is_http() {
            let url = format!("{}{}", self.base.trim_end_matches('/'), endpoint);
            let resp = ureq::get(&url)
                .set("Accept", "application/json")
                .call()
                .map_err(|e| format!("GET {url}: {e}"))?;
            resp.into_string()
                .map_err(|e| format!("read body of {url}: {e}"))?
                .into_bytes()
        } else {
            let p = PathBuf::from(self.base).join(file);
            fs::read(&p).map_err(|e| format!("read {}: {e}", p.display()))?
        };
        if let Some(dir) = self.save_dir {
            fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            fs::write(dir.join(file), &bytes).map_err(|e| format!("save {file}: {e}"))?;
        }
        serde_json::from_slice::<Value>(&bytes).map_err(|e| format!("{file}: bad JSON: {e}"))
    }
}

fn data(v: &Value) -> &Value {
    v.get("data").unwrap_or(v)
}

fn field<'a>(v: &'a Value, k: &str) -> Result<&'a Value, String> {
    v.get(k).ok_or_else(|| format!("missing field `{k}`"))
}

fn as_u64(v: &Value, k: &str) -> Result<u64, String> {
    let f = field(v, k)?;
    if let Some(s) = f.as_str() {
        s.parse::<u64>().map_err(|e| format!("`{k}`: {e}"))
    } else {
        f.as_u64().ok_or_else(|| format!("`{k}`: not a u64"))
    }
}

fn hex_n<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let raw = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| format!("hex: {e}"))?;
    if raw.len() != N {
        return Err(format!("expected {N} bytes, got {}", raw.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn hex_field<const N: usize>(v: &Value, k: &str) -> Result<[u8; N], String> {
    let s = field(v, k)?
        .as_str()
        .ok_or_else(|| format!("`{k}`: not a string"))?;
    hex_n::<N>(s).map_err(|e| format!("`{k}`: {e}"))
}

fn hex_array<const N: usize>(v: &Value, k: &str) -> Result<Vec<[u8; N]>, String> {
    field(v, k)?
        .as_array()
        .ok_or_else(|| format!("`{k}`: not an array"))?
        .iter()
        .map(|e| {
            e.as_str()
                .ok_or_else(|| format!("`{k}`: element not a string"))
                .and_then(|s| hex_n::<N>(s).map_err(|e| format!("`{k}`: {e}")))
        })
        .collect()
}

fn beacon_header(v: &Value) -> Result<BeaconBlockHeader, String> {
    let b = v.get("beacon").unwrap_or(v);
    Ok(BeaconBlockHeader {
        slot: as_u64(b, "slot")?,
        proposer_index: as_u64(b, "proposer_index")?,
        parent_root: hex_field::<32>(b, "parent_root")?,
        state_root: hex_field::<32>(b, "state_root")?,
        body_root: hex_field::<32>(b, "body_root")?,
    })
}

fn check_version(top: &Value, what: &str) -> Result<String, String> {
    let v = top
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    if v != "unknown" && !SUPPORTED_VERSIONS.contains(&v.as_str()) {
        return Err(format!("{what}: version `{v}` is not supported"));
    }
    Ok(v)
}

fn flip_last(branch: &mut [Bytes32]) {
    if let Some(last) = branch.last_mut() {
        last[0] ^= 0x01;
    }
}

struct Params {
    cfg: ChainConfig,
    epochs_per_period: u64,
}

fn load_params(src: &Source) -> Result<Params, String> {
    let spec = src.get("/eth/v1/config/spec", "config_spec.json")?;
    let d = data(&spec);
    let gloas = match d.get("GLOAS_FORK_EPOCH") {
        Some(_) => {
            let e = as_u64(d, "GLOAS_FORK_EPOCH")?;
            (e != FAR_FUTURE_EPOCH).then_some(e)
        }
        None => None,
    };
    let cfg = ChainConfig {
        slots_per_epoch: as_u64(d, "SLOTS_PER_EPOCH")?,
        electra_fork_epoch: as_u64(d, "ELECTRA_FORK_EPOCH")?,
        gloas_fork_epoch: gloas,
    };
    let epochs_per_period = as_u64(d, "EPOCHS_PER_SYNC_COMMITTEE_PERIOD")?;
    Ok(Params {
        cfg,
        epochs_per_period,
    })
}

fn check_finality(
    cfg: &ChainConfig,
    obj: &Value,
    tamper: bool,
    rep: &mut Report,
) -> Result<(), String> {
    let attested = beacon_header(field(obj, "attested_header")?)?;
    let finalized = beacon_header(field(obj, "finalized_header")?)?;
    let mut branch = hex_array::<32>(obj, "finality_branch")?;
    if !is_branch_present(&branch) {
        rep.finality_skip += 1;
        return Ok(());
    }
    if tamper {
        flip_last(&mut branch);
    }
    let r = verify_finality_branch(cfg, &attested, &finalized, &branch);
    if r.is_ok() {
        rep.finality_pass += 1;
    } else {
        rep.finality_fail += 1;
    }
    Ok(())
}

pub fn run(o: &Opts) -> Result<Report, String> {
    let src = Source {
        base: &o.source,
        save_dir: o.save_dir.as_ref(),
    };
    let p = load_params(&src)?;
    let mut rep = Report::default();

    let root_hex = format!("0x{}", hex::encode(o.trusted_root));
    let top = src.get(
        &format!("/eth/v1/beacon/light_client/bootstrap/{root_hex}"),
        "bootstrap.json",
    )?;
    let _version = check_version(&top, "bootstrap")?;
    let b = data(&top);
    let header = beacon_header(field(b, "header")?)?;
    let sc = field(b, "current_sync_committee")?;
    let pubkeys = hex_array::<48>(sc, "pubkeys")?;
    let aggregate = hex_field::<48>(sc, "aggregate_pubkey")?;
    let mut branch = hex_array::<32>(b, "current_sync_committee_branch")?;
    if o.tamper {
        flip_last(&mut branch);
    }
    let r = verify_bootstrap(
        &p.cfg,
        &o.trusted_root,
        &header,
        &pubkeys,
        &aggregate,
        &branch,
    );
    rep.bootstrap_ok = r.is_ok();
    if let Err(e) = r {
        if !o.tamper {
            return Err(format!("bootstrap rejected ({e:?})"));
        }
    }

    let period = header.slot / (p.cfg.slots_per_epoch * p.epochs_per_period);
    let top = src.get(
        &format!(
            "/eth/v1/beacon/light_client/updates?start_period={period}&count={}",
            o.count
        ),
        "updates.json",
    )?;
    let items = top
        .as_array()
        .or_else(|| top.get("data").and_then(|d| d.as_array()))
        .ok_or("updates: expected a JSON array")?;
    for (_, item) in items.iter().enumerate() {
        let _ = check_version(item, "update")?;
        check_finality(&p.cfg, data(item), o.tamper, &mut rep)?;
    }

    let top = src.get(
        "/eth/v1/beacon/light_client/finality_update",
        "finality_update.json",
    )?;
    let _ = check_version(&top, "finality_update")?;
    check_finality(&p.cfg, data(&top), o.tamper, &mut rep)?;

    Ok(rep)
}

fn finality_item(obj: &Value, tamper: bool) -> Result<FinalityItem, String> {
    let attested = beacon_header(field(obj, "attested_header")?)?;
    let finalized = beacon_header(field(obj, "finalized_header")?)?;
    let mut branch = hex_array::<32>(obj, "finality_branch")?;
    if tamper && is_branch_present(&branch) {
        flip_last(&mut branch);
    }
    Ok(FinalityItem {
        attested: WireHeader::from(&attested),
        finalized: WireHeader::from(&finalized),
        branch,
    })
}

fn hex_vec(v: &Value, k: &str) -> Result<Vec<u8>, String> {
    let s = field(v, k)?
        .as_str()
        .ok_or_else(|| format!("`{k}`: not a string"))?;
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| format!("`{k}`: {e}"))
}

fn update_wire(obj: &Value, o: &Opts) -> Result<UpdateWire, String> {
    let attested = beacon_header(field(obj, "attested_header")?)?;
    let finalized = beacon_header(field(obj, "finalized_header")?)?;
    let mut finality_branch = hex_array::<32>(obj, "finality_branch")?;
    let agg = field(obj, "sync_aggregate")?;
    let bits = hex_vec(agg, "sync_committee_bits")?;
    let mut signature = hex_vec(agg, "sync_committee_signature")?;
    let (next_pubkeys, next_aggregate, next_branch) = match obj.get("next_sync_committee") {
        Some(sc) => (
            hex_array::<48>(sc, "pubkeys")?.concat(),
            hex_vec(sc, "aggregate_pubkey")?,
            hex_array::<32>(obj, "next_sync_committee_branch")?,
        ),
        None => (vec![], vec![], vec![]),
    };
    if o.tamper && is_branch_present(&finality_branch) {
        flip_last(&mut finality_branch);
    }
    if o.tamper_sig {
        signature[0] ^= 1;
    }
    Ok(UpdateWire {
        attested: WireHeader::from(&attested),
        next_pubkeys,
        next_aggregate,
        next_branch,
        finalized: WireHeader::from(&finalized),
        finality_branch,
        bits,
        signature,
        signature_slot: as_u64(obj, "signature_slot")?,
    })
}

fn load_sync_params(src: &Source, o: &Opts) -> Result<(Bytes32, Vec<(u64, [u8; 4])>, u64), String> {
    let spec = src.get("/eth/v1/config/spec", "config_spec.json")?;
    let d = data(&spec);
    let mut forks = vec![(0u64, hex_field::<4>(d, "GENESIS_FORK_VERSION")?)];
    for name in ["ALTAIR", "BELLATRIX", "CAPELLA", "DENEB", "ELECTRA", "FULU"] {
        let (vk, ek) = (format!("{name}_FORK_VERSION"), format!("{name}_FORK_EPOCH"));
        if d.get(&vk).is_none() || d.get(&ek).is_none() {
            continue;
        }
        let epoch = as_u64(d, &ek)?;
        if epoch != FAR_FUTURE_EPOCH {
            forks.push((epoch, hex_field::<4>(d, &vk)?));
        }
    }
    forks.sort_by_key(|f| f.0);
    let g = src.get("/eth/v1/beacon/genesis", "genesis.json")?;
    let g = data(&g);
    let mut gvr = hex_field::<32>(g, "genesis_validators_root")?;
    if o.other_chain {
        gvr[0] ^= 1;
    }
    let genesis_time = as_u64(g, "genesis_time")?;
    let sps = as_u64(d, "SECONDS_PER_SLOT")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let slot = now.saturating_sub(genesis_time) / sps;
    Ok((gvr, forks, slot))
}

pub fn collect(o: &Opts) -> Result<GuestInput, String> {
    let src = Source {
        base: &o.source,
        save_dir: o.save_dir.as_ref(),
    };
    let p = load_params(&src)?;

    let root_hex = format!("0x{}", hex::encode(o.trusted_root));
    let top = src.get(
        &format!("/eth/v1/beacon/light_client/bootstrap/{root_hex}"),
        "bootstrap.json",
    )?;
    check_version(&top, "bootstrap")?;
    let b = data(&top);
    let header = beacon_header(field(b, "header")?)?;
    let sc = field(b, "current_sync_committee")?;
    let pubkeys = hex_array::<48>(sc, "pubkeys")?;
    let aggregate = hex_field::<48>(sc, "aggregate_pubkey")?;
    let mut boot_branch = hex_array::<32>(b, "current_sync_committee_branch")?;
    if o.tamper {
        flip_last(&mut boot_branch);
    }

    let period = header.slot / (p.cfg.slots_per_epoch * p.epochs_per_period);
    let top = src.get(
        &format!(
            "/eth/v1/beacon/light_client/updates?start_period={period}&count={}",
            o.count
        ),
        "updates.json",
    )?;
    let items = top
        .as_array()
        .or_else(|| top.get("data").and_then(|d| d.as_array()))
        .ok_or("updates: expected a JSON array")?;
    let want_sync = o.sync || o.tamper_sig || o.other_chain;
    let mut finality = vec![];
    let mut updates = vec![];
    for item in items {
        check_version(item, "update")?;
        if o.latest_only {
            // Only the newest finality_update (below) is sent to the guest.
            continue;
        }
        finality.push(finality_item(data(item), o.tamper)?);
        if want_sync {
            updates.push(update_wire(data(item), o)?);
        }
    }
    let top = src.get(
        "/eth/v1/beacon/light_client/finality_update",
        "finality_update.json",
    )?;
    check_version(&top, "finality_update")?;
    finality.push(finality_item(data(&top), o.tamper)?);
    if want_sync {
        updates.push(update_wire(data(&top), o)?);
    }
    let sync = if want_sync {
        let (genesis_validators_root, forks, current_slot) = load_sync_params(&src, o)?;
        Some(SyncInput {
            genesis_validators_root,
            epochs_per_period: p.epochs_per_period,
            forks,
            current_slot,
            updates,
        })
    } else {
        None
    };

    Ok(GuestInput {
        slots_per_epoch: p.cfg.slots_per_epoch,
        electra_fork_epoch: p.cfg.electra_fork_epoch,
        gloas_fork_epoch: p.cfg.gloas_fork_epoch,
        trusted_root: o.trusted_root,
        boot_header: WireHeader::from(&header),
        pubkeys: pubkeys.concat(),
        aggregate: aggregate.to_vec(),
        boot_branch,
        finality,
        sync,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn h2(a: &Bytes32, b: &Bytes32) -> Bytes32 {
        let mut h = Sha256::new();
        h.update(a);
        h.update(b);
        h.finalize().into()
    }
    fn leaf(i: u64) -> Bytes32 {
        let mut h = Sha256::new();
        h.update(b"host-test");
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
                .map(|p| h2(&p[0], &p[1]))
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
    fn x(b: &[u8]) -> String {
        format!("0x{}", hex::encode(b))
    }
    fn xs(v: &[Bytes32]) -> String {
        v.iter()
            .map(|b| format!("\"{}\"", x(b)))
            .collect::<Vec<_>>()
            .join(",")
    }
    fn hdr_json(h: &BeaconBlockHeader) -> String {
        format!(
            r#"{{"beacon":{{"slot":"{}","proposer_index":"{}","parent_root":"{}","state_root":"{}","body_root":"{}"}}}}"#,
            h.slot,
            h.proposer_index,
            x(&h.parent_root),
            x(&h.state_root),
            x(&h.body_root)
        )
    }

    /// Writes a synthetic Electra-era dataset: committee tree depth 6 idx 22 (gindex 86),
    /// finality tree depth 7 idx 41 (gindex 169). Returns (dir, trusted_root).
    fn write_fixture(tag: &str) -> (PathBuf, Bytes32) {
        let dir = std::env::temp_dir().join(format!("le-sync-test-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        // committee + bootstrap header
        let pks: Vec<[u8; 48]> = (0..512u64)
            .map(|i| {
                let mut p = [0u8; 48];
                p[..32].copy_from_slice(&leaf(i));
                p
            })
            .collect();
        let agg = [7u8; 48];
        let croot = le_sync_core::sync_committee_root(&pks, &agg).unwrap();
        let mut leaves: Vec<Bytes32> = (0..64).map(leaf).collect();
        leaves[22] = croot;
        let l = levels(leaves);
        let bh = BeaconBlockHeader {
            slot: 20 * 32 + 3,
            proposer_index: 9,
            parent_root: leaf(100),
            state_root: l.last().unwrap()[0],
            body_root: leaf(101),
        };
        let trusted = bh.hash_tree_root();
        let pk_json = pks
            .iter()
            .map(|p| format!("\"{}\"", x(p)))
            .collect::<Vec<_>>()
            .join(",");
        fs::write(dir.join("bootstrap.json"), format!(
            r#"{{"version":"electra","data":{{"header":{},"current_sync_committee":{{"pubkeys":[{}],"aggregate_pubkey":"{}"}},"current_sync_committee_branch":[{}]}}}}"#,
            hdr_json(&bh), pk_json, x(&agg), xs(&branch(&l, 22))
        )).unwrap();

        // finality fixtures (two different attested headers)
        let mk = |salt: u64| {
            let fin = BeaconBlockHeader {
                slot: 20 * 32 + salt * 32,
                proposer_index: salt,
                parent_root: leaf(200 + salt),
                state_root: leaf(300 + salt),
                body_root: leaf(400 + salt),
            };
            let mut lv: Vec<Bytes32> = (0..128).map(|i| leaf(1000 * salt + i)).collect();
            lv[41] = fin.hash_tree_root();
            let l = levels(lv);
            let att = BeaconBlockHeader {
                slot: fin.slot + 64,
                proposer_index: 1,
                parent_root: leaf(500 + salt),
                state_root: l.last().unwrap()[0],
                body_root: leaf(600 + salt),
            };
            (att, fin, branch(&l, 41))
        };
        let (a1, f1, b1) = mk(1);
        let (a2, f2, b2) = mk(2);
        let upd = |a: &BeaconBlockHeader, f: &BeaconBlockHeader, b: &[Bytes32]| {
            format!(
                r#"{{"attested_header":{},"finalized_header":{},"finality_branch":[{}],"sync_aggregate":{{"sync_committee_bits":"0x","sync_committee_signature":"0x"}},"signature_slot":"{}"}}"#,
                hdr_json(a),
                hdr_json(f),
                xs(b),
                a.slot + 1
            )
        };
        fs::write(
            dir.join("updates.json"),
            format!(r#"[{{"version":"electra","data":{}}}]"#, upd(&a1, &f1, &b1)),
        )
        .unwrap();
        fs::write(
            dir.join("finality_update.json"),
            format!(r#"{{"version":"fulu","data":{}}}"#, upd(&a2, &f2, &b2)),
        )
        .unwrap();
        fs::write(dir.join("config_spec.json"), r#"{"data":{"SLOTS_PER_EPOCH":"32","EPOCHS_PER_SYNC_COMMITTEE_PERIOD":"256","ELECTRA_FORK_EPOCH":"10","FULU_FORK_EPOCH":"15","GLOAS_FORK_EPOCH":"18446744073709551615"}}"#).unwrap();
        (dir, trusted)
    }

    /// Sprint 1 fixtures carry no sync section, so BLS is never reached.
    struct NoBls;
    impl le_sync_core::sync::Bls for NoBls {
        fn fast_aggregate_verify(
            &self,
            _: &[[u8; 48]],
            _: &[u8; 48],
            _: &[u8],
            _: &Bytes32,
            _: &[u8; 96],
        ) -> bool {
            false
        }
    }

    fn opts(dir: &PathBuf, root: Bytes32, tamper: bool) -> Opts {
        Opts {
            source: dir.display().to_string(),
            trusted_root: root,
            count: 1,
            save_dir: None,
            tamper,
            sync: false,
            tamper_sig: false,
            other_chain: false,
            latest_only: false,
        }
    }

    #[test]
    fn offline_pipeline_passes_on_valid_data() {
        let (dir, root) = write_fixture("ok");
        let rep = run(&opts(&dir, root, false)).unwrap();
        assert!(rep.success(false), "{rep:?}");
        assert_eq!(
            (rep.finality_pass, rep.finality_fail, rep.finality_skip),
            (2, 0, 0)
        );
    }

    #[test]
    fn offline_pipeline_rejects_everything_when_tampered() {
        let (dir, root) = write_fixture("tamper");
        let rep = run(&opts(&dir, root, true)).unwrap();
        assert!(rep.success(true), "{rep:?}");
        assert_eq!((rep.finality_pass, rep.finality_fail), (0, 2));
        assert!(!rep.bootstrap_ok);
    }

    #[test]
    fn wrong_trusted_root_is_fatal() {
        let (dir, mut root) = write_fixture("root");
        root[0] ^= 1;
        let e = run(&opts(&dir, root, false)).unwrap_err();
        assert!(e.contains("TrustedRootMismatch"), "{e}");
    }

    #[test]
    fn gloas_version_is_refused() {
        let (dir, root) = write_fixture("gloas");
        let p = dir.join("finality_update.json");
        let s = fs::read_to_string(&p)
            .unwrap()
            .replace(r#""version":"fulu""#, r#""version":"gloas""#);
        fs::write(&p, s).unwrap();
        let e = run(&opts(&dir, root, false)).unwrap_err();
        assert!(e.contains("not supported"), "{e}");
    }

    #[test]
    fn collect_then_verify_matches_native_run() {
        let (dir, root) = write_fixture("collect");
        let i = le_sync_wire::verify(&collect(&opts(&dir, root, false)).unwrap(), &NoBls);
        assert!(i.success(false), "{i:?}");
        let t = le_sync_wire::verify(&collect(&opts(&dir, root, true)).unwrap(), &NoBls);
        assert!(t.success(true), "{t:?}");
    }

    #[test]
    fn latest_only_sends_just_the_finality_update() {
        let (dir, root) = write_fixture("latest");
        let all = collect(&Opts {
            sync: true,
            ..opts(&dir, root, false)
        });
        // The synthetic fixture has no genesis.json, so a sync collect cannot complete;
        // compare the finality lists instead, which are built before that point is reached.
        assert!(all.is_err());
        let full = collect(&opts(&dir, root, false)).unwrap();
        let latest = collect(&Opts {
            latest_only: true,
            ..opts(&dir, root, false)
        })
        .unwrap();
        assert_eq!(full.finality.len(), 2);
        assert_eq!(latest.finality.len(), 1);
        assert_eq!(latest.finality[0], full.finality[1]);
    }

    #[test]
    fn update_wire_parses_finality_update_and_full_update_shapes() {
        let h = BeaconBlockHeader {
            slot: 40,
            proposer_index: 1,
            parent_root: leaf(1),
            state_root: leaf(2),
            body_root: leaf(3),
        };
        let br = |n: usize| {
            format!(
                "[{}]",
                (0..n)
                    .map(|i| format!("\"{}\"", x(&leaf(i as u64))))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        let agg = format!(
            r#"{{"sync_committee_bits":"0x{}","sync_committee_signature":"0x{}"}}"#,
            "ff".repeat(64),
            "07".repeat(96)
        );
        let fin = format!(
            r#"{{"attested_header":{a},"finalized_header":{a},"finality_branch":{fb},"sync_aggregate":{agg},"signature_slot":"41"}}"#,
            a = hdr_json(&h),
            fb = br(7),
            agg = agg
        );
        let o = Opts {
            source: String::new(),
            trusted_root: [0; 32],
            count: 1,
            save_dir: None,
            tamper: false,
            sync: true,
            tamper_sig: true,
            other_chain: false,
            latest_only: false,
        };
        let u = update_wire(
            &serde_json::from_slice::<Value>(fin.as_bytes()).unwrap(),
            &o,
        )
        .unwrap();
        assert_eq!(
            (
                u.signature_slot,
                u.bits.len(),
                u.signature.len(),
                u.next_pubkeys.len()
            ),
            (41, 64, 96, 0)
        );
        assert_eq!(u.signature[0], 0x07 ^ 1); // tamper_sig flipped one bit

        let sc = format!(
            r#"{{"pubkeys":[{}],"aggregate_pubkey":"0x{}"}}"#,
            (0..2)
                .map(|_| format!("\"0x{}\"", "11".repeat(48)))
                .collect::<Vec<_>>()
                .join(","),
            "22".repeat(48)
        );
        let full = fin.replacen("\"signature_slot\"", &format!("\"next_sync_committee\":{sc},\"next_sync_committee_branch\":{nb},\"signature_slot\"", sc = sc, nb = br(6)), 1);
        let u = update_wire(
            &serde_json::from_slice::<Value>(full.as_bytes()).unwrap(),
            &Opts {
                tamper_sig: false,
                ..o
            },
        )
        .unwrap();
        assert_eq!(
            (
                u.next_pubkeys.len(),
                u.next_aggregate.len(),
                u.next_branch.len()
            ),
            (96, 48, 6)
        );
    }
}
