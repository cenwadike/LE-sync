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
//!
//! Everything with logic in it lives here (argument parsing, endpoint building, slot and period
//! arithmetic, exit-code mapping) so it is unit-testable; `main.rs` is only I/O glue.

use le_sync_core::sync::ChainBinding;
use le_sync_core::{
    is_branch_present, verify_bootstrap, verify_finality_branch, BeaconBlockHeader, Bytes32,
    ChainConfig, Error,
};
use le_sync_wire::{
    build_chain_binding, check_chain_binding, FinalityItem, GuestInput, GuestOutput, SyncInput,
    UpdateWire, WireHeader,
};
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

pub const USAGE: &str = "\
le-sync: fetch light-client data from a beacon API, verify it INSIDE the RISC Zero guest, print cycles

USAGE:
  le-sync --source <URL|DIR> --trusted-root <0x..> [--count N] [--save-dir DIR]
          [--tamper] [--sync] [--tamper-sig] [--other-chain] [--cross-config DIR]
          [--latest-only]

  --source        beacon API base URL (e.g. https://<host>) or a directory of saved JSON
                  (config_spec.json, bootstrap.json, updates.json, finality_update.json, genesis.json)
  --trusted-root  weak-subjectivity checkpoint: block root of the first block of a recently
                  finalized epoch (verify it against 2+ independent sources)
  --count         sync-committee periods to request from /light_client/updates (default 1)
  --save-dir      write each fetched response here (reproducible offline re-runs)
  --tamper        flip one bit in each branch; the guest must reject all (exit 0 if so)
  --sync          full update validation incl. BLS aggregate signature in the guest
  --tamper-sig    with --sync: flip one bit of every signature; guest must reject (exit 0 if so)
  --other-chain   with --sync: other genesis_validators_root; guest must reject AND the chain
                  binding check must report a mismatch (exit 0 if both)
  --cross-config  take the chain identity (DEPOSIT_CHAIN_ID, genesis_validators_root, fork
                  schedule) from DIR (saved config_spec.json + genesis.json of another network)
                  while updates, bootstrap and clock stay from --source; implies --sync. Guest
                  must reject AND the chain binding check must report a mismatch (exit 0 if both)
  --latest-only   with --sync: send the guest only the newest finality_update (cost isolation)

EXIT CODES:
  0  OK
  1  failed (guest error, journal decode, trusted root differs, or checks not satisfied)
  2  usage error
  3  CHAIN MISMATCH: the journal commits a chain other than the one this host is configured for
";

#[derive(Clone, Debug)]
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
    /// With `sync`: take the chain identity (`DEPOSIT_CHAIN_ID`, genesis validators root, fork
    /// schedule) from this saved directory (`config_spec.json` + `genesis.json`) instead of
    /// `--source`, while the updates, bootstrap, preset timing and clock still come from
    /// `--source`. The guest must reject (signing domain) and the consumer chain check must
    /// report a mismatch against the host's own (`--source`) chain.
    pub cross_config: Option<PathBuf>,
}

impl Opts {
    /// Runs that need the guest's sync section.
    pub fn wants_sync(&self) -> bool {
        self.sync || self.tamper_sig || self.other_chain || self.cross_config.is_some()
    }

    /// Runs built to present a different chain than the host's own: the journal's chain binding
    /// MUST differ from the expected one.
    pub fn expects_chain_mismatch(&self) -> bool {
        self.other_chain || self.cross_config.is_some()
    }

    /// Runs where the guest must validate nothing and reject something.
    pub fn expects_sync_reject(&self) -> bool {
        self.tamper_sig || self.other_chain || self.cross_config.is_some() || self.tamper
    }
}

/// Parse command-line arguments (without the program name).
/// `Err("")` means "help requested": print usage, nothing else.
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Opts, String> {
    let mut a = args.into_iter();
    let (mut source, mut root, mut count, mut save, mut tamper) = (None, None, 1u64, None, false);
    let (mut sync, mut tamper_sig, mut other_chain, mut latest_only) = (false, false, false, false);
    let mut cross_config: Option<PathBuf> = None;
    while let Some(k) = a.next() {
        let mut val = |name: &str| a.next().ok_or_else(|| format!("{name} needs a value"));
        match k.as_str() {
            "--source" => source = Some(val("--source")?),
            "--trusted-root" => root = Some(val("--trusted-root")?),
            "--count" => {
                count = val("--count")?
                    .parse()
                    .map_err(|e| format!("--count: {e}"))?
            }
            "--save-dir" => save = Some(PathBuf::from(val("--save-dir")?)),
            "--tamper" => tamper = true,
            "--sync" => sync = true,
            "--tamper-sig" => tamper_sig = true,
            "--other-chain" => other_chain = true,
            "--cross-config" => cross_config = Some(PathBuf::from(val("--cross-config")?)),
            "--latest-only" => latest_only = true,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    let root_s = root.ok_or("--trusted-root is required")?;
    let raw = hex::decode(root_s.strip_prefix("0x").unwrap_or(&root_s))
        .map_err(|e| format!("--trusted-root: {e}"))?;
    let trusted_root: [u8; 32] = raw
        .try_into()
        .map_err(|_| "--trusted-root must be 32 bytes".to_string())?;
    Ok(Opts {
        source: source.ok_or("--source is required")?,
        trusted_root,
        count,
        save_dir: save,
        tamper,
        sync,
        tamper_sig,
        other_chain,
        latest_only,
        cross_config,
    })
}

/// What to print on stderr for a `parse_args` error (empty error = plain usage).
pub fn usage_error_text(e: &str) -> String {
    if e.is_empty() {
        USAGE.to_string()
    } else {
        format!("error: {e}\n\n{USAGE}")
    }
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

// ---- pure helpers (unit-tested directly; a directory source ignores endpoints) -----------------

/// Sync-committee period of a slot: `slot / (slots_per_epoch * epochs_per_period)`.
pub fn sync_period(slot: u64, slots_per_epoch: u64, epochs_per_period: u64) -> Result<u64, String> {
    let len = slots_per_epoch.saturating_mul(epochs_per_period);
    if len == 0 {
        return Err("SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD is 0".into());
    }
    Ok(slot / len)
}

pub fn bootstrap_endpoint(root: &Bytes32) -> String {
    format!(
        "/eth/v1/beacon/light_client/bootstrap/0x{}",
        hex::encode(root)
    )
}

pub fn updates_endpoint(period: u64, count: u64) -> String {
    format!("/eth/v1/beacon/light_client/updates?start_period={period}&count={count}")
}

/// Slot at wall-clock `now_secs` for a chain with the given genesis time and slot length.
/// Saturates at 0 before genesis.
pub fn slot_at(now_secs: u64, genesis_time: u64, seconds_per_slot: u64) -> Result<u64, String> {
    if seconds_per_slot == 0 {
        return Err("SECONDS_PER_SLOT is 0".into());
    }
    Ok(now_secs.saturating_sub(genesis_time) / seconds_per_slot)
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

    let top = src.get(&bootstrap_endpoint(&o.trusted_root), "bootstrap.json")?;
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

    let period = sync_period(header.slot, p.cfg.slots_per_epoch, p.epochs_per_period)?;
    let top = src.get(&updates_endpoint(period, o.count), "updates.json")?;
    let items = top
        .as_array()
        .or_else(|| top.get("data").and_then(|d| d.as_array()))
        .ok_or("updates: expected a JSON array")?;
    for item in items {
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
        if let Some(b) = signature.first_mut() {
            *b ^= 1;
        }
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

/// Chain identity read from a `/config/spec` + `/beacon/genesis` pair.
#[derive(Clone, Debug)]
struct ChainFacts {
    /// `DEPOSIT_CHAIN_ID`: a declared label, not covered by any signature.
    chain_id: u64,
    genesis_validators_root: Bytes32,
    forks: Vec<(u64, [u8; 4])>,
    genesis_time: u64,
    seconds_per_slot: u64,
}

fn load_chain_facts(src: &Source) -> Result<ChainFacts, String> {
    let spec = src.get("/eth/v1/config/spec", "config_spec.json")?;
    let d = data(&spec);
    let chain_id = as_u64(d, "DEPOSIT_CHAIN_ID")
        .map_err(|e| format!("config_spec: {e} (needed for the chain binding)"))?;
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
    Ok(ChainFacts {
        chain_id,
        genesis_validators_root: hex_field::<32>(g, "genesis_validators_root")?,
        forks,
        genesis_time: as_u64(g, "genesis_time")?,
        seconds_per_slot: as_u64(d, "SECONDS_PER_SLOT")?,
    })
}

/// Chosen by the host (the guest has no clock). Always derived from the host's OWN chain, even
/// in a cross-config run, so a rejection cannot be a clock artefact.
fn current_slot(own: &ChainFacts) -> Result<u64, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    slot_at(now, own.genesis_time, own.seconds_per_slot)
}

/// What `collect_checked` hands back: the guest input plus the binding the host EXPECTS the
/// journal to commit, built from the host's own (`--source`) configuration only, never from
/// anything `--other-chain` / `--cross-config` altered.
pub struct Collected {
    pub input: GuestInput,
    /// `None` when the run has no sync section (nothing is bound then).
    pub expected: Option<ChainBinding>,
}

pub fn collect(o: &Opts) -> Result<GuestInput, String> {
    collect_checked(o).map(|c| c.input)
}

pub fn collect_checked(o: &Opts) -> Result<Collected, String> {
    let src = Source {
        base: &o.source,
        save_dir: o.save_dir.as_ref(),
    };
    let p = load_params(&src)?;

    let top = src.get(&bootstrap_endpoint(&o.trusted_root), "bootstrap.json")?;
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

    let period = sync_period(header.slot, p.cfg.slots_per_epoch, p.epochs_per_period)?;
    let top = src.get(&updates_endpoint(period, o.count), "updates.json")?;
    let items = top
        .as_array()
        .or_else(|| top.get("data").and_then(|d| d.as_array()))
        .ok_or("updates: expected a JSON array")?;
    let want_sync = o.wants_sync();
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
    let (sync, expected) = if want_sync {
        // The host's own chain: source of the expected binding and of the clock.
        let own = load_chain_facts(&src)?;
        let expected = build_chain_binding(
            p.cfg.slots_per_epoch,
            p.epochs_per_period,
            own.chain_id,
            &own.genesis_validators_root,
            &own.forks,
        )
        .map_err(|e| format!("chain binding: {e:?}"))?;
        let current_slot = current_slot(&own)?;
        // What the guest is told. Only the chain identity is swapped in a cross-config run;
        // preset timing and fork-epoch config stay the host's own so the Merkle layer is
        // unchanged and the signing domain is the only thing that can fail. Cross-config files
        // are never saved over `--save-dir`.
        let mut sent = match &o.cross_config {
            Some(dir) => {
                let base = dir.display().to_string();
                let x = Source {
                    base: &base,
                    save_dir: None,
                };
                load_chain_facts(&x).map_err(|e| format!("cross-config {base}: {e}"))?
            }
            None => own.clone(),
        };
        if o.other_chain {
            sent.genesis_validators_root[0] ^= 1;
        }
        (
            Some(SyncInput {
                chain_id: sent.chain_id,
                genesis_validators_root: sent.genesis_validators_root,
                epochs_per_period: p.epochs_per_period,
                forks: sent.forks,
                current_slot,
                updates,
            }),
            Some(expected),
        )
    } else {
        (None, None)
    };

    let input = GuestInput {
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
    };
    Ok(Collected { input, expected })
}

/// Outcome of judging a journal. `main` maps it to an exit code; kept here so it is testable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    /// The journal commits a chain other than the host's own, in a run that did not ask for it.
    ChainMismatch(Error),
    /// The run presented another chain (`--cross-config` / `--other-chain`), yet the journal's
    /// binding matched the host's own chain: the consumer check failed to notice.
    ChainMismatchNotDetected,
    TrustedRootDiffers,
    NotOk,
}

/// Process exit code for a verdict (documented in `USAGE`).
pub fn verdict_exit_code(v: &Verdict) -> u8 {
    match v {
        Verdict::Ok => 0,
        Verdict::ChainMismatch(_) => 3,
        Verdict::ChainMismatchNotDetected | Verdict::TrustedRootDiffers | Verdict::NotOk => 1,
    }
}

/// Judge a journal. The chain check comes first: nothing else in the journal is trusted until
/// it says which chain the proof is about.
pub fn judge(o: &Opts, out: &GuestOutput, expected: Option<&ChainBinding>) -> Verdict {
    let chain = expected.map(|e| check_chain_binding(out, e));
    match (chain, o.expects_chain_mismatch()) {
        (Some(Err(e)), false) => return Verdict::ChainMismatch(e),
        (Some(Ok(())), true) => return Verdict::ChainMismatchNotDetected,
        _ => {}
    }
    if out.trusted_root != o.trusted_root {
        return Verdict::TrustedRootDiffers;
    }
    // tamper-sig / other-chain / cross-config leave Sprint 1 checks untouched: they must pass.
    let sync_ok = !o.wants_sync() || out.sync_success(o.expects_sync_reject());
    if out.success(o.tamper) && sync_ok {
        Verdict::Ok
    } else {
        Verdict::NotOk
    }
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
            cross_config: None,
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

    // ---- chain binding / cross-config ---------------------------------------------------------

    /// Overwrites `config_spec.json` with a spec that also carries chain identity, and writes
    /// `genesis.json`. Keeps the preset values `write_fixture` uses (32 / 256 / Electra at 10).
    fn write_chain_files(
        dir: &PathBuf,
        chain_id: Option<u64>,
        gvr_byte: u8,
        genesis_fork: [u8; 4],
        genesis_time: u64,
    ) {
        fs::create_dir_all(dir).unwrap();
        let mut d = serde_json::json!({
            "SLOTS_PER_EPOCH": "32",
            "EPOCHS_PER_SYNC_COMMITTEE_PERIOD": "256",
            "ELECTRA_FORK_EPOCH": "10",
            "FULU_FORK_EPOCH": "15",
            "GLOAS_FORK_EPOCH": "18446744073709551615",
            "GENESIS_FORK_VERSION": x(&genesis_fork),
            "ELECTRA_FORK_VERSION": "0x05000001",
            "FULU_FORK_VERSION": "0x06000001",
            "SECONDS_PER_SLOT": "12"
        });
        if let Some(id) = chain_id {
            d["DEPOSIT_CHAIN_ID"] = serde_json::Value::String(id.to_string());
        }
        fs::write(
            dir.join("config_spec.json"),
            serde_json::json!({ "data": d }).to_string(),
        )
        .unwrap();
        fs::write(
            dir.join("genesis.json"),
            serde_json::json!({ "data": {
                "genesis_time": genesis_time.to_string(),
                "genesis_validators_root": x(&[gvr_byte; 32]),
                "genesis_fork_version": x(&genesis_fork)
            }})
            .to_string(),
        )
        .unwrap();
    }

    fn sync_opts(dir: &PathBuf, root: Bytes32) -> Opts {
        Opts {
            sync: true,
            ..opts(dir, root, false)
        }
    }

    /// A saved "other chain" directory (spec + genesis only), e.g. a testnet.
    fn other_chain_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("le-sync-other-{tag}-{}", std::process::id()));
        write_chain_files(
            &dir,
            Some(11155111),
            0xBB,
            [0x90, 0, 0, 0x69],
            1_000_000_000,
        );
        dir
    }

    #[test]
    fn sync_collect_requires_deposit_chain_id() {
        let (dir, root) = write_fixture("nochainid");
        write_chain_files(&dir, None, 0xAA, [0, 0, 0, 1], 0);
        let e = collect(&sync_opts(&dir, root)).unwrap_err();
        assert!(e.contains("DEPOSIT_CHAIN_ID"), "{e}");
    }

    #[test]
    fn no_sync_run_has_no_expected_binding() {
        let (dir, root) = write_fixture("nosync");
        let c = collect_checked(&opts(&dir, root, false)).unwrap();
        assert!(c.input.sync.is_none() && c.expected.is_none());
    }

    #[test]
    fn expected_binding_is_built_from_the_hosts_own_config_and_matches_the_journal() {
        let (dir, root) = write_fixture("bind");
        write_chain_files(&dir, Some(1), 0xAA, [0, 0, 0, 1], 0);
        let c = collect_checked(&sync_opts(&dir, root)).unwrap();
        let exp = c.expected.unwrap();
        assert_eq!(exp.chain_id, 1);
        assert_eq!(exp.genesis_validators_root, [0xAA; 32]);
        assert_eq!((exp.slots_per_epoch, exp.epochs_per_period), (32, 256));
        // forks: genesis, Electra (epoch 10), Fulu (epoch 15), sorted by epoch
        let s = c.input.sync.as_ref().unwrap();
        assert_eq!(
            s.forks,
            vec![(0, [0, 0, 0, 1]), (10, [5, 0, 0, 1]), (15, [6, 0, 0, 1])]
        );
        let out = le_sync_wire::verify(&c.input, &NoBls);
        assert!(out.bootstrap_ok, "{out:?}");
        assert_eq!(check_chain_binding(&out, &exp), Ok(()));
    }

    #[test]
    fn other_chain_flips_the_gvr_and_is_caught_by_the_consumer_check() {
        let (dir, root) = write_fixture("otherchain");
        write_chain_files(&dir, Some(1), 0xAA, [0, 0, 0, 1], 0);
        let c = collect_checked(&Opts {
            other_chain: true,
            ..opts(&dir, root, false)
        })
        .unwrap();
        let s = c.input.sync.as_ref().unwrap();
        assert_eq!(s.genesis_validators_root[0], 0xAA ^ 1);
        assert_eq!(s.chain_id, 1, "only the gvr is altered");
        let out = le_sync_wire::verify(&c.input, &NoBls);
        assert_eq!(
            check_chain_binding(&out, &c.expected.unwrap()),
            Err(Error::ChainMismatch)
        );
    }

    #[test]
    fn other_chain_flips_exactly_one_bit_of_the_first_gvr_byte() {
        // 0xAA ^ 1 == 0xAA | 1, so the test above cannot tell `^=` from `|=`. 0xAB can:
        // xor clears the bit (0xAA), or-ing leaves it set (0xAB), and-ing gives 0x01.
        let (dir, root) = write_fixture("otherchain-ab");
        write_chain_files(&dir, Some(1), 0xAB, [0, 0, 0, 1], 0);
        let c = collect_checked(&Opts {
            other_chain: true,
            ..opts(&dir, root, false)
        })
        .unwrap();
        let g = c.input.sync.as_ref().unwrap().genesis_validators_root;
        assert_eq!(g[0], 0xAA);
        assert_eq!(&g[1..], &[0xAB; 31][..], "only byte 0 changes");
    }

    #[test]
    fn cross_config_swaps_only_the_chain_identity_and_is_caught_by_the_consumer_check() {
        let (dir, root) = write_fixture("cross-a");
        write_chain_files(&dir, Some(1), 0xAA, [0, 0, 0, 1], 0);
        let other = other_chain_dir("cross-b");

        let base = collect_checked(&sync_opts(&dir, root)).unwrap();
        let c = collect_checked(&Opts {
            cross_config: Some(other.clone()),
            ..opts(&dir, root, false) // note: `sync` not set; cross-config implies it
        })
        .unwrap();
        let (b, s) = (
            base.input.sync.as_ref().unwrap(),
            c.input.sync.as_ref().unwrap(),
        );

        // identity comes from the cross-config directory ...
        assert_eq!(s.chain_id, 11155111);
        assert_eq!(s.genesis_validators_root, [0xBB; 32]);
        assert_ne!(s.forks, b.forks);
        // ... everything else stays the host's own
        assert_eq!(c.input.slots_per_epoch, base.input.slots_per_epoch);
        assert_eq!(c.input.electra_fork_epoch, base.input.electra_fork_epoch);
        assert_eq!(s.epochs_per_period, b.epochs_per_period);
        assert_eq!(c.input.boot_header, base.input.boot_header);
        assert_eq!(s.updates, b.updates);
        // the clock is the host's own genesis time (0), not the cross-config's (1e9): a
        // rejection must not be a clock artefact (allow one slot of drift between two calls)
        assert!(s.current_slot.abs_diff(b.current_slot) <= 1);

        // the expectation is unaffected by the swap
        assert_eq!(c.expected, base.expected);
        let out = le_sync_wire::verify(&c.input, &NoBls);
        assert!(out.bootstrap_ok, "bootstrap is unaffected: {out:?}");
        assert_eq!(
            check_chain_binding(&out, &c.expected.unwrap()),
            Err(Error::ChainMismatch)
        );
    }

    #[test]
    fn cross_config_files_are_not_saved_over_save_dir() {
        let (dir, root) = write_fixture("cross-save-a");
        write_chain_files(&dir, Some(1), 0xAA, [0, 0, 0, 1], 0);
        let other = other_chain_dir("cross-save-b");
        let saved = std::env::temp_dir().join(format!("le-sync-saved-{}", std::process::id()));
        collect_checked(&Opts {
            cross_config: Some(other),
            save_dir: Some(saved.clone()),
            ..opts(&dir, root, false)
        })
        .unwrap();
        let g: Value =
            serde_json::from_slice(&fs::read(saved.join("genesis.json")).unwrap()).unwrap();
        assert_eq!(
            g["data"]["genesis_validators_root"],
            Value::String(x(&[0xAA; 32])),
            "saved genesis.json must be the host's own, not the cross-config's"
        );
    }

    #[test]
    fn cross_config_with_a_missing_directory_is_a_clear_error() {
        let (dir, root) = write_fixture("cross-missing");
        write_chain_files(&dir, Some(1), 0xAA, [0, 0, 0, 1], 0);
        let e = collect_checked(&Opts {
            cross_config: Some(dir.join("does-not-exist")),
            ..opts(&dir, root, false)
        })
        .err()
        .unwrap();
        assert!(e.contains("cross-config"), "{e}");
    }

    // ---- verdicts -------------------------------------------------------------------------------

    fn bind(chain_id: u64, gvr_byte: u8) -> ChainBinding {
        build_chain_binding(32, 256, chain_id, &[gvr_byte; 32], &[(0, [0, 0, 0, 1])]).unwrap()
    }

    /// A journal as the guest would commit it for chain `b`.
    fn journal(root: Bytes32, b: &ChainBinding, validated: u32, rejected: u32) -> GuestOutput {
        GuestOutput {
            trusted_root: root,
            bootstrap_ok: true,
            finality_pass: 1,
            sync_validated: validated,
            sync_rejected: rejected,
            chain_id: b.chain_id,
            genesis_validators_root: b.genesis_validators_root,
            chain_binding: b.digest(),
            ..Default::default()
        }
    }

    #[test]
    fn judge_normal_run_is_ok_and_unexpected_chain_mismatch_is_distinct() {
        let root = [3u8; 32];
        let (own, other) = (bind(1, 0xAA), bind(11155111, 0xBB));
        let o = Opts {
            sync: true,
            trusted_root: root,
            ..opts(&PathBuf::new(), root, false)
        };
        assert_eq!(
            judge(&o, &journal(root, &own, 1, 0), Some(&own)),
            Verdict::Ok
        );
        // otherwise-perfect numbers, wrong chain: not a generic NotOk
        assert_eq!(
            judge(&o, &journal(root, &other, 1, 0), Some(&own)),
            Verdict::ChainMismatch(Error::ChainMismatch)
        );
        // label-only difference is caught too
        assert_eq!(
            judge(&o, &journal(root, &bind(2, 0xAA), 1, 0), Some(&own)),
            Verdict::ChainMismatch(Error::ChainMismatch)
        );
    }

    #[test]
    fn judge_cross_config_needs_both_the_mismatch_and_a_guest_rejection() {
        let root = [3u8; 32];
        let (own, other) = (bind(1, 0xAA), bind(11155111, 0xBB));
        let o = Opts {
            cross_config: Some(PathBuf::from("x")),
            ..opts(&PathBuf::new(), root, false)
        };
        // mismatch at the consumer + rejection at the guest => the run succeeded
        assert_eq!(
            judge(&o, &journal(root, &other, 0, 1), Some(&own)),
            Verdict::Ok
        );
        // the guest ACCEPTED data under the other chain's identity => failure
        assert_eq!(
            judge(&o, &journal(root, &other, 1, 0), Some(&own)),
            Verdict::NotOk
        );
        // the journal still names the host's own chain => the swap did not take effect
        assert_eq!(
            judge(&o, &journal(root, &own, 0, 1), Some(&own)),
            Verdict::ChainMismatchNotDetected
        );
        // same for the quick --other-chain demo
        let oc = Opts {
            other_chain: true,
            ..opts(&PathBuf::new(), root, false)
        };
        assert_eq!(
            judge(&oc, &journal(root, &other, 0, 1), Some(&own)),
            Verdict::Ok
        );
        assert_eq!(
            judge(&oc, &journal(root, &own, 0, 1), Some(&own)),
            Verdict::ChainMismatchNotDetected
        );
    }

    #[test]
    fn judge_checks_trusted_root_and_handles_runs_without_sync() {
        let root = [3u8; 32];
        let own = bind(1, 0xAA);
        let o = Opts {
            sync: true,
            ..opts(&PathBuf::new(), root, false)
        };
        let mut j = journal(root, &own, 1, 0);
        j.trusted_root = [4u8; 32];
        assert_eq!(judge(&o, &j, Some(&own)), Verdict::TrustedRootDiffers);

        // a Sprint 1 run: no sync section, no expected binding, no chain check
        let s1 = opts(&PathBuf::new(), root, false);
        let j = GuestOutput {
            trusted_root: root,
            bootstrap_ok: true,
            finality_pass: 1,
            ..Default::default()
        };
        assert_eq!(judge(&s1, &j, None), Verdict::Ok);
    }

    #[test]
    fn judge_tolerates_below_threshold_rejections_in_a_normal_sync_run() {
        let root = [3u8; 32];
        let own = bind(1, 0xAA);
        let o = Opts {
            sync: true,
            ..opts(&PathBuf::new(), root, false)
        };
        let mut j = journal(root, &own, 2, 1);
        j.sync_below_threshold = 1;
        assert_eq!(judge(&o, &j, Some(&own)), Verdict::Ok);
        j.sync_below_threshold = 0; // a real rejection (e.g. bad signature)
        assert_eq!(judge(&o, &j, Some(&own)), Verdict::NotOk);
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
            cross_config: None,
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

    // ==== Phase D: pure helpers and mutation-hardening ===========================================

    fn report(bootstrap_ok: bool, pass: u32, fail: u32) -> Report {
        Report {
            bootstrap_ok,
            finality_pass: pass,
            finality_fail: fail,
            finality_skip: 0,
        }
    }

    #[test]
    fn report_success_non_tamper_requires_all_three_conjuncts() {
        assert!(report(true, 1, 0).success(false));
        assert!(report(true, 5, 0).success(false));
        assert!(!report(false, 1, 0).success(false)); // bootstrap failed
        assert!(!report(true, 0, 0).success(false)); // nothing passed (kills `>` -> `>=`)
        assert!(!report(true, 1, 1).success(false)); // something failed
        assert!(!report(true, 2, 1).success(false));
    }

    #[test]
    fn report_success_tamper_requires_all_three_conjuncts() {
        assert!(report(false, 0, 1).success(true));
        assert!(report(false, 0, 4).success(true));
        assert!(!report(true, 0, 1).success(true)); // bootstrap must have been rejected
        assert!(!report(false, 1, 1).success(true)); // a tampered branch passed
        assert!(!report(false, 0, 0).success(true)); // nothing rejected (kills `>` -> `>=`)
    }

    #[test]
    fn report_success_flag_selects_opposite_rules() {
        let normal = report(true, 1, 0);
        let tampered = report(false, 0, 1);
        assert!(normal.success(false) && !normal.success(true));
        assert!(tampered.success(true) && !tampered.success(false));
    }

    #[test]
    fn source_is_http_recognises_both_schemes_only() {
        let is = |b: &str| {
            Source {
                base: b,
                save_dir: None,
            }
            .is_http()
        };
        assert!(is("http://localhost:5052"));
        assert!(is("https://beacon.example"));
        assert!(!is("/tmp/saved-run"));
        assert!(!is("relative/dir"));
        assert!(!is(""));
        assert!(!is("ftp://x"));
        assert!(!is("httpx://x"));
    }

    #[test]
    fn flip_last_flips_exactly_one_bit_of_the_last_node() {
        let mut b = vec![[0xABu8; 32], [0xABu8; 32]];
        flip_last(&mut b);
        assert_eq!(b[0], [0xAB; 32], "earlier nodes untouched");
        assert_eq!(b[1][0], 0xAA, "bit 0 of byte 0 flipped (0xAB ^ 1)");
        assert_eq!(&b[1][1..], &[0xAB; 31][..], "other bytes untouched");
        flip_last(&mut b);
        assert_eq!(b[1], [0xAB; 32], "flipping twice restores");
        let mut zeros = vec![[0u8; 32]];
        flip_last(&mut zeros);
        assert_eq!(zeros[0][0], 1);
        // empty branch: no panic, nothing to flip
        let mut empty: Vec<Bytes32> = vec![];
        flip_last(&mut empty);
        assert!(empty.is_empty());
    }

    #[test]
    fn sync_period_divides_by_the_full_period_length() {
        // mainnet-like preset: 32 * 256 = 8192 slots per period
        assert_eq!(sync_period(0, 32, 256), Ok(0));
        assert_eq!(sync_period(8191, 32, 256), Ok(0));
        assert_eq!(sync_period(8192, 32, 256), Ok(1));
        assert_eq!(sync_period(3 * 8192 + 5, 32, 256), Ok(3));
        // distinguishes `*` from `+` (32 + 256 = 288) and `/` from `%`
        assert_eq!(sync_period(576, 32, 256), Ok(0));
        assert_eq!(sync_period(10 * 8192, 32, 256), Ok(10));
        // minimal preset
        assert_eq!(sync_period(64, 8, 8), Ok(1));
        // zero config is an error, not a divide-by-zero panic
        assert!(sync_period(1, 0, 256).is_err());
        assert!(sync_period(1, 32, 0).is_err());
    }

    #[test]
    fn endpoints_are_built_exactly() {
        assert_eq!(
            bootstrap_endpoint(&[0xAB; 32]),
            format!(
                "/eth/v1/beacon/light_client/bootstrap/0x{}",
                "ab".repeat(32)
            )
        );
        assert_eq!(
            updates_endpoint(3, 2),
            "/eth/v1/beacon/light_client/updates?start_period=3&count=2"
        );
    }

    #[test]
    fn slot_at_is_elapsed_seconds_over_slot_length() {
        assert_eq!(slot_at(1120, 1000, 12), Ok(10));
        assert_eq!(slot_at(1119, 1000, 12), Ok(9));
        assert_eq!(slot_at(1000, 1000, 12), Ok(0));
        assert_eq!(slot_at(500, 1000, 12), Ok(0), "before genesis saturates");
        assert_eq!(slot_at(1_700_000_000, 0, 12), Ok(141_666_666));
        assert!(slot_at(1, 0, 0).is_err());
    }

    #[test]
    fn current_slot_uses_the_wall_clock_and_the_hosts_own_genesis() {
        let own = ChainFacts {
            chain_id: 1,
            genesis_validators_root: [0; 32],
            forks: vec![(0, [0; 4])],
            genesis_time: 0,
            seconds_per_slot: 12,
        };
        let s = current_slot(&own).unwrap();
        assert!(
            s > 100_000_000,
            "wall clock / 12 is on the order of 1e8+: {s}"
        );
        let slower = ChainFacts {
            seconds_per_slot: 24,
            ..own.clone()
        };
        let s2 = current_slot(&slower).unwrap();
        assert!(s2.abs_diff(s / 2) <= 1, "{s2} vs {s}");
        let bad = ChainFacts {
            seconds_per_slot: 0,
            ..own
        };
        assert!(current_slot(&bad).is_err());
    }

    // ---- spec-driven fixtures for load_params / load_chain_facts ---------------------------------

    fn spec_dir(tag: &str, spec: serde_json::Value) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("le-sync-spec-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("config_spec.json"),
            serde_json::json!({ "data": spec }).to_string(),
        )
        .unwrap();
        fs::write(
            dir.join("genesis.json"),
            serde_json::json!({ "data": {
                "genesis_time": "1000",
                "genesis_validators_root": x(&[0xCC; 32])
            }})
            .to_string(),
        )
        .unwrap();
        dir
    }

    fn src_of(dir: &PathBuf) -> String {
        dir.display().to_string()
    }

    fn base_spec() -> serde_json::Value {
        serde_json::json!({
            "SLOTS_PER_EPOCH": "32",
            "EPOCHS_PER_SYNC_COMMITTEE_PERIOD": "256",
            "ELECTRA_FORK_EPOCH": "10",
            "DEPOSIT_CHAIN_ID": "1",
            "GENESIS_FORK_VERSION": "0x00000000",
            "SECONDS_PER_SLOT": "12"
        })
    }

    fn params_of(spec: serde_json::Value, tag: &str) -> Result<Params, String> {
        let dir = spec_dir(tag, spec);
        let base = src_of(&dir);
        load_params(&Source {
            base: &base,
            save_dir: None,
        })
    }

    fn facts_of(spec: serde_json::Value, tag: &str) -> Result<ChainFacts, String> {
        let dir = spec_dir(tag, spec);
        let base = src_of(&dir);
        load_chain_facts(&Source {
            base: &base,
            save_dir: None,
        })
    }

    #[test]
    fn load_params_reads_the_preset_and_distinguishes_gloas_states() {
        // GLOAS absent
        let p = params_of(base_spec(), "p-absent").unwrap();
        assert_eq!(p.cfg.slots_per_epoch, 32);
        assert_eq!(p.cfg.electra_fork_epoch, 10);
        assert_eq!(p.epochs_per_period, 256);
        assert_eq!(p.cfg.gloas_fork_epoch, None);

        // GLOAS far-future means "not scheduled"
        let mut s = base_spec();
        s["GLOAS_FORK_EPOCH"] = "18446744073709551615".into();
        assert_eq!(params_of(s, "p-far").unwrap().cfg.gloas_fork_epoch, None);

        // GLOAS scheduled: must be Some(epoch), not None (kills `!=` -> `==`)
        let mut s = base_spec();
        s["GLOAS_FORK_EPOCH"] = "100".into();
        assert_eq!(
            params_of(s, "p-sched").unwrap().cfg.gloas_fork_epoch,
            Some(100)
        );

        // missing required key is a clear error
        let mut s = base_spec();
        s.as_object_mut().unwrap().remove("SLOTS_PER_EPOCH");
        assert!(params_of(s, "p-missing")
            .map_err(|err| { err.contains("SLOTS_PER_EPOCH") })
            .is_err());
    }

    #[test]
    fn load_chain_facts_builds_the_fork_schedule_from_complete_entries_only() {
        let mut s = base_spec();
        s["ALTAIR_FORK_VERSION"] = "0x01000000".into();
        s["ALTAIR_FORK_EPOCH"] = "0".into();
        s["ELECTRA_FORK_VERSION"] = "0x05000000".into();
        // listed out of order on purpose: the result must be sorted by epoch
        s["FULU_FORK_VERSION"] = "0x06000000".into();
        s["FULU_FORK_EPOCH"] = "30".into();
        let f = facts_of(s, "f-ok").unwrap();
        assert_eq!(f.chain_id, 1);
        assert_eq!(f.genesis_validators_root, [0xCC; 32]);
        assert_eq!((f.genesis_time, f.seconds_per_slot), (1000, 12));
        assert_eq!(
            f.forks,
            vec![
                (0, [0, 0, 0, 0]),
                (0, [1, 0, 0, 0]),
                (10, [5, 0, 0, 0]),
                (30, [6, 0, 0, 0])
            ]
        );
    }

    #[test]
    fn load_chain_facts_skips_half_present_and_far_future_forks() {
        // version without epoch: skipped (kills `||` -> `&&`, which would error on the epoch)
        let mut s = base_spec();
        s["DENEB_FORK_VERSION"] = "0x04000000".into();
        let f = facts_of(s, "f-vonly").unwrap();
        assert_eq!(f.forks, vec![(0, [0, 0, 0, 0]),]);
        // (ELECTRA_FORK_EPOCH is in the base spec but has no version: also skipped)

        // epoch without version: skipped
        let mut s = base_spec();
        s["CAPELLA_FORK_EPOCH"] = "5".into();
        assert_eq!(
            facts_of(s, "f-eonly").unwrap().forks,
            vec![(0, [0, 0, 0, 0])]
        );

        // far-future epoch: not scheduled, so excluded
        let mut s = base_spec();
        s["FULU_FORK_VERSION"] = "0x06000000".into();
        s["FULU_FORK_EPOCH"] = "18446744073709551615".into();
        assert_eq!(facts_of(s, "f-far").unwrap().forks, vec![(0, [0, 0, 0, 0])]);
    }

    #[test]
    fn load_chain_facts_reports_missing_chain_id() {
        let mut s = base_spec();
        s.as_object_mut().unwrap().remove("DEPOSIT_CHAIN_ID");
        let e = facts_of(s, "f-noid").unwrap_err();
        assert!(e.contains("DEPOSIT_CHAIN_ID"), "{e}");
    }

    // ---- check_finality / finality_item / update_wire tamper semantics ------------------------------

    fn fixture_obj(tag: &str) -> (Value, ChainConfig) {
        let (dir, _) = write_fixture(tag);
        let v: Value =
            serde_json::from_slice(&fs::read(dir.join("finality_update.json")).unwrap()).unwrap();
        let cfg = ChainConfig {
            slots_per_epoch: 32,
            electra_fork_epoch: 10,
            gloas_fork_epoch: None,
        };
        (data(&v).clone(), cfg)
    }

    fn with_zero_branch(obj: &Value) -> Value {
        let mut o = obj.clone();
        o["finality_branch"] = serde_json::json!(vec![x(&[0u8; 32]); 7]);
        o
    }

    #[test]
    fn check_finality_counts_each_outcome_separately() {
        let (valid, cfg) = fixture_obj("cf");
        let zero = with_zero_branch(&valid);
        let mut rep = Report::default();

        check_finality(&cfg, &valid, false, &mut rep).unwrap();
        assert_eq!(
            (rep.finality_pass, rep.finality_fail, rep.finality_skip),
            (1, 0, 0)
        );
        check_finality(&cfg, &valid, false, &mut rep).unwrap();
        assert_eq!(
            (rep.finality_pass, rep.finality_fail, rep.finality_skip),
            (2, 0, 0)
        );

        check_finality(&cfg, &zero, false, &mut rep).unwrap();
        assert_eq!(
            (rep.finality_pass, rep.finality_fail, rep.finality_skip),
            (2, 0, 1)
        );
        check_finality(&cfg, &zero, false, &mut rep).unwrap();
        assert_eq!(
            (rep.finality_pass, rep.finality_fail, rep.finality_skip),
            (2, 0, 2)
        );

        // tamper flips the branch: verification fails, counted as fail (not pass, not skip)
        check_finality(&cfg, &valid, true, &mut rep).unwrap();
        assert_eq!(
            (rep.finality_pass, rep.finality_fail, rep.finality_skip),
            (2, 1, 2)
        );
        check_finality(&cfg, &valid, true, &mut rep).unwrap();
        assert_eq!(
            (rep.finality_pass, rep.finality_fail, rep.finality_skip),
            (2, 2, 2)
        );

        // an absent branch stays a skip even when tampering (nothing to flip)
        check_finality(&cfg, &zero, true, &mut rep).unwrap();
        assert_eq!(
            (rep.finality_pass, rep.finality_fail, rep.finality_skip),
            (2, 2, 3)
        );
    }

    #[test]
    fn finality_item_tampers_only_a_present_branch() {
        let (valid, _) = fixture_obj("fi");
        let orig = hex_array::<32>(&valid, "finality_branch").unwrap();

        let untouched = finality_item(&valid, false).unwrap();
        assert_eq!(untouched.branch, orig, "no tamper: branch unchanged");

        let flipped = finality_item(&valid, true).unwrap();
        assert_eq!(flipped.branch[..6], orig[..6], "earlier nodes untouched");
        assert_eq!(flipped.branch[6][0], orig[6][0] ^ 1);
        assert_eq!(flipped.branch[6][1..], orig[6][1..]);

        // absent branch + tamper: must stay all-zero (an `||` mutant would flip it)
        let zero = with_zero_branch(&valid);
        let z = finality_item(&zero, true).unwrap();
        assert!(!is_branch_present(&z.branch));
        let z = finality_item(&zero, false).unwrap();
        assert!(!is_branch_present(&z.branch));
    }

    #[test]
    fn update_wire_tampers_only_a_present_finality_branch() {
        let (valid, _) = fixture_obj("uw");
        let orig = hex_array::<32>(&valid, "finality_branch").unwrap();
        let base = Opts {
            source: String::new(),
            trusted_root: [0; 32],
            count: 1,
            save_dir: None,
            tamper: false,
            sync: true,
            tamper_sig: false,
            other_chain: false,
            latest_only: false,
            cross_config: None,
        };

        assert_eq!(update_wire(&valid, &base).unwrap().finality_branch, orig);

        let t = update_wire(
            &valid,
            &Opts {
                tamper: true,
                ..base.clone()
            },
        )
        .unwrap();
        assert_eq!(t.finality_branch[6][0], orig[6][0] ^ 1);
        assert_eq!(t.finality_branch[..6], orig[..6]);

        let zero = with_zero_branch(&valid);
        for tamper in [false, true] {
            let u = update_wire(
                &zero,
                &Opts {
                    tamper,
                    ..base.clone()
                },
            )
            .unwrap();
            assert!(!is_branch_present(&u.finality_branch), "tamper={tamper}");
        }
    }

    #[test]
    fn tamper_sig_on_an_empty_signature_does_not_panic() {
        // the fixture's sync_aggregate carries an empty signature ("0x")
        let (valid, _) = fixture_obj("uw-empty-sig");
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
            cross_config: None,
        };
        assert!(update_wire(&valid, &o).unwrap().signature.is_empty());
    }

    // ---- argument parsing / exit codes ----------------------------------------------------------------

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
    const ROOT: &str = "abababababababababababababababababababababababababababababababab";

    #[test]
    fn parse_args_minimal_and_defaults() {
        let o = parse_args(args(&["--source", "/d", "--trusted-root", ROOT])).unwrap();
        assert_eq!(o.source, "/d");
        assert_eq!(o.trusted_root, [0xAB; 32]);
        assert_eq!(o.count, 1);
        assert!(o.save_dir.is_none() && o.cross_config.is_none());
        assert!(!(o.tamper || o.sync || o.tamper_sig || o.other_chain || o.latest_only));
        // 0x prefix accepted
        let p = format!("0x{ROOT}");
        assert_eq!(
            parse_args(args(&["--source", "/d", "--trusted-root", &p]))
                .unwrap()
                .trusted_root,
            [0xAB; 32]
        );
    }

    #[test]
    fn parse_args_reads_every_flag() {
        let o = parse_args(args(&[
            "--source",
            "https://b",
            "--trusted-root",
            ROOT,
            "--count",
            "4",
            "--save-dir",
            "/s",
            "--tamper",
            "--sync",
            "--tamper-sig",
            "--other-chain",
            "--cross-config",
            "/x",
            "--latest-only",
        ]))
        .unwrap();
        assert_eq!(o.source, "https://b");
        assert_eq!(o.count, 4);
        assert_eq!(o.save_dir, Some(PathBuf::from("/s")));
        assert_eq!(o.cross_config, Some(PathBuf::from("/x")));
        assert!(o.tamper && o.sync && o.tamper_sig && o.other_chain && o.latest_only);
    }

    #[test]
    fn parse_args_rejects_bad_input_with_specific_messages() {
        let e = |a: &[&str]| parse_args(args(a)).unwrap_err();
        assert_eq!(e(&["--help"]), "");
        assert_eq!(e(&["-h"]), "");
        assert!(e(&["--bogus"]).contains("unknown argument `--bogus`"));
        assert!(e(&["--source"]).contains("--source needs a value"));
        assert!(e(&["--source", "/d"]).contains("--trusted-root is required"));
        assert!(e(&["--trusted-root", ROOT]).contains("--source is required"));
        assert!(e(&["--source", "/d", "--trusted-root", "zz"]).contains("--trusted-root"));
        assert!(e(&["--source", "/d", "--trusted-root", "abab"]).contains("32 bytes"));
        assert!(e(&["--source", "/d", "--trusted-root", ROOT, "--count", "x"]).contains("--count"));
    }

    #[test]
    fn usage_error_text_is_plain_usage_for_help_and_prefixed_otherwise() {
        assert_eq!(usage_error_text(""), USAGE);
        let t = usage_error_text("boom");
        assert!(t.starts_with("error: boom\n\n"));
        assert!(t.ends_with(USAGE));
    }

    #[test]
    fn verdict_exit_codes_match_the_documented_contract() {
        assert_eq!(verdict_exit_code(&Verdict::Ok), 0);
        assert_eq!(
            verdict_exit_code(&Verdict::ChainMismatch(Error::ChainMismatch)),
            3
        );
        assert_eq!(verdict_exit_code(&Verdict::ChainMismatchNotDetected), 1);
        assert_eq!(verdict_exit_code(&Verdict::TrustedRootDiffers), 1);
        assert_eq!(verdict_exit_code(&Verdict::NotOk), 1);
        assert!(USAGE.contains("3  CHAIN MISMATCH"));
    }
}
