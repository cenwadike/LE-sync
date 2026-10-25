//! Host side of LE-Sync Sprints 1-5 (Sprint 4: `eth_getProof` account/storage proofs; Sprint 5:
//! receipt proofs for logs, predicates, statement IDs): fetch `bootstrap` / `updates` / `finality_update` from a
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

use le_sync_core::sync::{has_supermajority, ChainBinding};
use le_sync_core::{
    is_branch_present, verify_bootstrap, verify_finality_branch, BeaconBlockHeader, Bytes32,
    ChainConfig, Error,
};
use le_sync_wire::{
    build_chain_binding, check_chain_binding, ExecWire, FinalityItem, GuestInput, GuestOutput,
    LogInput, PredicateWire, StateInput, SyncInput, UpdateWire, WireHeader,
};
use serde_json::Value;

pub mod receipts;
use receipts::{
    check_position, find_log, flip_first_node as flip_first_receipt_node, is_state_target,
    parse_predicate, parse_tx_sel, quantity, resolve_tx, Filter, LogData, ReceiptData,
    ReceiptsTrie, TxSel,
};
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
          [--address 0x.. [--slot 0x..] --execution-rpc <URL|DIR>]
          [--expect-value 0x..] [--expect-balance 0x..] [--tamper-state] [--tamper-exec]
          [--log-address 0x.. [--log-topic0..3 0x..] [--log-tx N|0x<hash> [--log-index N]]
           --execution-rpc <URL|DIR>] [--predicate <target><op><operand>]
          [--expect-id 0x..] [--tamper-receipt]
          [--prove --receipt-out <file>]
  le-sync <the same flags as the run> --verify-receipt <file>

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
  --address       Ethereum account to prove under the finalized execution state root (20 bytes);
                  implies --sync. The guest derives the state root itself from the finalized
                  header; nothing the RPC says about roots is trusted
  --slot          storage slot to prove (up to 32 bytes, default 0x0)
  --execution-rpc JSON-RPC URL serving eth_getProof, or a directory holding state_proof.json
                  (the saved response of a previous run: offline re-runs). Needed with --address
  --expect-value  with --address: the journal's slot value must equal this (hex, left-padded)
  --expect-balance with --address: the journal's account balance must equal this (hex wei)
  --tamper-state  with --address: flip one bit of the first account-proof node; the guest must
                  reject with the trie-proof error (204) (exit 0 if so)
  --tamper-exec   with --address and/or --log-address: flip one bit of the execution header's
                  state root (receipts root for the log); the guest must reject with the branch
                  error (201) (exit 0 if so). Wins over --tamper-state and --tamper-receipt
  --log-address   prove an event log emitted by this contract (20 bytes) in the newest finalized
                  block, under that block's receipts root; implies --sync. Needs --execution-rpc
                  (eth_getBlockReceipts) or a directory holding block_receipts.json
  --log-topic0..3 require this topic at that position (0x, up to 32 bytes, left-padded); omitted
                  positions match anything. topic0 is the event signature hash
  --log-tx        the transaction: a position in the block (decimal) or its 0x hash. Without it
                  the host picks the first log in the block that matches address and topics
  --log-index     which log of that transaction (default 0). Needs --log-tx
  --predicate     with --address or --log-address: a condition the guest checks over the verified
                  value, `<target><op><operand>`. Targets: balance, storage (need --address),
                  topicN, dataN (the N-th 32-byte word of the log data; need --log-address).
                  Operators: == and !=. A predicate that does not hold makes the guest reject (206).
                  Example: --predicate 'data0==0x2710'
  --expect-id     the journal's statement ID must equal this (32 bytes): the log's with
                  --log-address, otherwise the storage slot's with --address
  --tamper-receipt with --log-address: flip one bit of the first receipt-proof node; the guest
                  must reject with the trie-proof error (204) (exit 0 if so)

  --prove         after the guest has executed and every check passed, prove the same run and
                  verify the receipt against this build's guest image ID. Needs --receipt-out.
                  Refused for tamper and other-chain runs (the guest rejects those on purpose)
  --receipt-out   with --prove: write the receipt (journal + seal) to this file
  --verify-receipt FILE
                  verify a saved receipt against this build's guest image ID, then judge its
                  journal with the other flags exactly as a live run would. No guest run, and no
                  network when --source is a saved directory. Give the flags of the original run
  RISC0_DEV_MODE  receipts made in dev mode are fake. --prove and --verify-receipt refuse to run
                  while it is set

EXIT CODES:
  0  OK
  1  failed (guest error, journal decode, trusted root differs, checks not satisfied, or a
     receipt whose journal differs from the executed one)
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
    /// Sprint 4: account + storage proof section. `StateOpts::default()` = none.
    pub state: StateOpts,
}

/// Sprint 4 options. `address` switches the state section on; everything else refines it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateOpts {
    pub address: Option<[u8; 20]>,
    /// `None` = slot 0 (the proof is still fetched; use `--expect-balance` for balance-only runs).
    pub slot: Option<Bytes32>,
    /// JSON-RPC URL (`eth_getProof`) or a directory containing `state_proof.json`.
    pub execution_rpc: Option<String>,
    pub expect_value: Option<Bytes32>,
    pub expect_balance: Option<Bytes32>,
    /// Flip a bit in the first account-proof node: the guest must answer `InvalidTrieProof`.
    pub tamper_state: bool,
    /// Flip a bit in the execution header's `state_root` (and, for a log section, its
    /// `receipts_root`): the guest must answer `InvalidBranch`. Takes precedence over
    /// `tamper_state` and `tamper_receipt` (the anchor is checked first).
    pub tamper_exec: bool,
    /// Sprint 5: predicate over the balance or the slot value. Needs `address`.
    pub predicate: Option<PredicateWire>,
    /// Sprint 5: required statement ID (the log's if a log is requested, else the slot's).
    pub expect_id: Option<Bytes32>,
    /// Sprint 5: log section options.
    pub log: LogOpts,
}

/// Sprint 5 options. `address` switches the log section on; the RPC comes from
/// `StateOpts::execution_rpc`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogOpts {
    pub address: Option<[u8; 20]>,
    /// Required topics by position; `None` matches anything.
    pub topics: [Option<Bytes32>; 4],
    /// `None` = the host picks the first matching log in the block.
    pub tx: Option<TxSel>,
    /// `None` = 0. Only with `tx`.
    pub log_index: Option<u32>,
    /// Predicate over a topic or data word of the log. Needs `address`.
    pub predicate: Option<PredicateWire>,
    /// Flip a bit in the first receipt-proof node: the guest must answer `InvalidTrieProof`.
    pub tamper_receipt: bool,
}

impl LogOpts {
    pub fn requested(&self) -> bool {
        self.address.is_some()
    }
}

impl StateOpts {
    pub fn requested(&self) -> bool {
        self.address.is_some()
    }
    /// Any execution-layer section: the host must pick an anchor from the updates.
    pub fn needs_anchor(&self) -> bool {
        self.requested() || self.log.requested()
    }
}

impl Opts {
    /// Runs that need the guest's sync section.
    pub fn wants_sync(&self) -> bool {
        self.sync
            || self.tamper_sig
            || self.other_chain
            || self.cross_config.is_some()
            || self.state.needs_anchor()
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
    let mut st = StateOpts::default();
    let mut rpc: Option<String> = None;
    let mut predicate: Option<PredicateWire> = None;
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
            "--address" => {
                st.address =
                    Some(parse_address(&val("--address")?).map_err(|e| format!("--address: {e}"))?)
            }
            "--slot" => {
                st.slot = Some(parse_word(&val("--slot")?).map_err(|e| format!("--slot: {e}"))?)
            }
            "--execution-rpc" => rpc = Some(val("--execution-rpc")?),
            "--log-address" => {
                st.log.address = Some(
                    parse_address(&val("--log-address")?)
                        .map_err(|e| format!("--log-address: {e}"))?,
                )
            }
            k @ ("--log-topic0" | "--log-topic1" | "--log-topic2" | "--log-topic3") => {
                let pos = (k.as_bytes()[k.len() - 1] - b'0') as usize;
                st.log.topics[pos] = Some(parse_word(&val(k)?).map_err(|e| format!("{k}: {e}"))?)
            }
            "--log-tx" => {
                st.log.tx =
                    Some(parse_tx_sel(&val("--log-tx")?).map_err(|e| format!("--log-tx: {e}"))?)
            }
            "--log-index" => {
                st.log.log_index = Some(
                    val("--log-index")?
                        .parse()
                        .map_err(|e| format!("--log-index: {e}"))?,
                )
            }
            "--predicate" => {
                predicate = Some(
                    parse_predicate(&val("--predicate")?)
                        .map_err(|e| format!("--predicate: {e}"))?,
                )
            }
            "--expect-id" => {
                st.expect_id = Some(
                    parse_word(&val("--expect-id")?).map_err(|e| format!("--expect-id: {e}"))?,
                )
            }
            "--tamper-receipt" => st.log.tamper_receipt = true,
            "--expect-value" => {
                st.expect_value = Some(
                    parse_word(&val("--expect-value")?)
                        .map_err(|e| format!("--expect-value: {e}"))?,
                )
            }
            "--expect-balance" => {
                st.expect_balance = Some(
                    parse_word(&val("--expect-balance")?)
                        .map_err(|e| format!("--expect-balance: {e}"))?,
                )
            }
            "--tamper-state" => st.tamper_state = true,
            "--tamper-exec" => st.tamper_exec = true,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument `{other}`")),
        }
    }
    // A predicate belongs to the section its target reads.
    if let Some(p) = predicate {
        if is_state_target(&p.target) {
            if st.address.is_none() {
                return Err("--predicate on balance or storage needs --address".into());
            }
            st.predicate = Some(p);
        } else {
            if st.log.address.is_none() {
                return Err("--predicate on a topic or data word needs --log-address".into());
            }
            st.log.predicate = Some(p);
        }
    }
    st.execution_rpc = rpc.clone();
    if st.address.is_none() {
        if st.slot.is_some()
            || st.expect_value.is_some()
            || st.expect_balance.is_some()
            || st.tamper_state
        {
            return Err(
                "--slot, --expect-value, --expect-balance and --tamper-state need --address".into(),
            );
        }
        if (rpc.is_some() || st.tamper_exec || st.expect_id.is_some()) && st.log.address.is_none() {
            return Err(
                "--execution-rpc, --tamper-exec and --expect-id need --address (or --log-address)"
                    .into(),
            );
        }
    } else if rpc.is_none() {
        return Err(
            "--address needs --execution-rpc (a JSON-RPC URL or a directory with state_proof.json)"
                .into(),
        );
    }
    if st.log.address.is_none() {
        if st.log.topics.iter().any(|t| t.is_some())
            || st.log.tx.is_some()
            || st.log.log_index.is_some()
            || st.log.tamper_receipt
        {
            return Err(
                "--log-topic0..3, --log-tx, --log-index and --tamper-receipt need --log-address"
                    .into(),
            );
        }
    } else {
        if rpc.is_none() {
            return Err("--log-address needs --execution-rpc (a JSON-RPC URL or a directory with block_receipts.json)".into());
        }
        if st.log.log_index.is_some() && st.log.tx.is_none() {
            return Err("--log-index needs --log-tx".into());
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
        state: st,
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

// ---- Sprint 4: account + storage state proof ---------------------------------------------------

// BEGIN pure helpers (no serde_json: unit-tested in isolation too)

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let t = s.strip_prefix("0x").unwrap_or(s);
    let padded = if t.len() % 2 == 1 {
        format!("0{t}")
    } else {
        t.to_string()
    };
    hex::decode(padded).map_err(|e| e.to_string())
}

/// 20-byte Ethereum address, `0x` optional.
pub fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let raw = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| e.to_string())?;
    raw.try_into()
        .map_err(|_| "must be exactly 20 bytes".to_string())
}

/// Up to 32 bytes of hex (odd length allowed), left-padded to a big-endian 32-byte word.
pub fn parse_word(s: &str) -> Result<Bytes32, String> {
    let raw = parse_hex_bytes(s)?;
    if raw.len() > 32 {
        return Err("must be at most 32 bytes".into());
    }
    let mut out = [0u8; 32];
    out[32 - raw.len()..].copy_from_slice(&raw);
    Ok(out)
}

/// Decimal string -> 32-byte little-endian uint256 (the SSZ encoding of `base_fee_per_gas`).
pub fn dec_u256_le(s: &str) -> Result<Bytes32, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("`{s}` is not a decimal integer"));
    }
    let mut out = [0u8; 32];
    for digit in s.bytes().map(|b| (b - b'0') as u32) {
        let mut carry = digit;
        for byte in out.iter_mut() {
            let v = (*byte as u32) * 10 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return Err(format!("`{s}` overflows uint256"));
        }
    }
    Ok(out)
}

/// The JSON-RPC body that asks for one account and one storage slot at `block`.
pub fn state_proof_request(address: &[u8; 20], slot: &Bytes32, block: u64) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_getProof","params":["0x{}",["0x{}"],"0x{:x}"]}}"#,
        hex::encode(address),
        hex::encode(slot),
        block
    )
}

/// Flip one bit of the first byte of the first node (the RLP list header): the node no longer
/// hashes to what its parent (or the state root) commits to.
pub fn flip_first_node(nodes: &mut [Vec<u8>]) {
    if let Some(b) = nodes.first_mut().and_then(|n| n.first_mut()) {
        *b ^= 1;
    }
}

// END pure helpers

/// A finalized header's execution payload header and the `execution_branch` that ties it to the
/// header's `body_root`, taken from an update the guest's strict gate will not reject.
#[derive(Clone, Debug)]
struct Anchor {
    slot: u64,
    exec: ExecWire,
    branch: Vec<Bytes32>,
}

fn as_u256_le(v: &Value, k: &str) -> Result<Bytes32, String> {
    let f = field(v, k)?;
    match f.as_str() {
        Some(s) => dec_u256_le(s).map_err(|e| format!("`{k}`: {e}")),
        None => match f.as_u64() {
            Some(n) => dec_u256_le(&n.to_string()).map_err(|e| format!("`{k}`: {e}")),
            None => Err(format!("`{k}`: not a decimal integer")),
        },
    }
}

/// `finalized_header.execution` of a light-client update (Deneb layout, 17 fields).
fn exec_wire(v: &Value) -> Result<ExecWire, String> {
    Ok(ExecWire {
        parent_hash: hex_field::<32>(v, "parent_hash")?,
        fee_recipient: hex_field::<20>(v, "fee_recipient")?,
        state_root: hex_field::<32>(v, "state_root")?,
        receipts_root: hex_field::<32>(v, "receipts_root")?,
        logs_bloom: hex_vec(v, "logs_bloom")?,
        prev_randao: hex_field::<32>(v, "prev_randao")?,
        block_number: as_u64(v, "block_number")?,
        gas_limit: as_u64(v, "gas_limit")?,
        gas_used: as_u64(v, "gas_used")?,
        timestamp: as_u64(v, "timestamp")?,
        extra_data: hex_vec(v, "extra_data")?,
        base_fee_per_gas: as_u256_le(v, "base_fee_per_gas")?,
        block_hash: hex_field::<32>(v, "block_hash")?,
        transactions_root: hex_field::<32>(v, "transactions_root")?,
        withdrawals_root: hex_field::<32>(v, "withdrawals_root")?,
        blob_gas_used: as_u64(v, "blob_gas_used")?,
        excess_blob_gas: as_u64(v, "excess_blob_gas")?,
    })
}

/// The anchor candidate of one update object, or `None` if it cannot move the guest's store:
/// no finality branch (no finalized header), no `execution` data, or participation below 2/3
/// (mirrors the guest's strict gate, `wire::process_update_strict`).
fn anchor_of(obj: &Value) -> Result<Option<Anchor>, String> {
    if !is_branch_present(&hex_array::<32>(obj, "finality_branch")?) {
        return Ok(None);
    }
    let fin = field(obj, "finalized_header")?;
    let (Some(exec), Some(_)) = (fin.get("execution"), fin.get("execution_branch")) else {
        return Ok(None);
    };
    let bits = match obj.get("sync_aggregate") {
        Some(a) => hex_vec(a, "sync_committee_bits")?,
        None => vec![],
    };
    if !has_supermajority(&bits) {
        return Ok(None);
    }
    Ok(Some(Anchor {
        slot: beacon_header(fin)?.slot,
        exec: exec_wire(exec)?,
        branch: hex_array::<32>(fin, "execution_branch")?,
    }))
}

/// The newest finalized header among the candidates: the one the guest's store ends on if every
/// candidate validates. If the guest ends elsewhere (a bad signature, say) the anchor simply
/// fails to verify there: the guest, not this choice, decides.
fn pick_anchor(c: Vec<Anchor>) -> Option<Anchor> {
    c.into_iter().max_by_key(|a| a.slot)
}

/// `eth_getProof` response (full JSON-RPC envelope or just the result) from the JSON-RPC
/// endpoint, or from `<dir>/state_proof.json`; saved to `--save-dir` as `state_proof.json`.
fn fetch_state_proof(
    rpc: &str,
    save_dir: Option<&PathBuf>,
    address: &[u8; 20],
    slot: &Bytes32,
    block: u64,
) -> Result<Value, String> {
    let bytes: Vec<u8> = if rpc.starts_with("http://") || rpc.starts_with("https://") {
        let resp = ureq::post(rpc)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json")
            .send_string(&state_proof_request(address, slot, block))
            .map_err(|e| format!("POST {rpc} eth_getProof: {e}"))?;
        resp.into_string()
            .map_err(|e| format!("read body of {rpc}: {e}"))?
            .into_bytes()
    } else {
        let p = PathBuf::from(rpc).join("state_proof.json");
        fs::read(&p).map_err(|e| format!("read {}: {e}", p.display()))?
    };
    if let Some(dir) = save_dir {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        fs::write(dir.join("state_proof.json"), &bytes)
            .map_err(|e| format!("save state_proof.json: {e}"))?;
    }
    let v = serde_json::from_slice::<Value>(&bytes)
        .map_err(|e| format!("state_proof.json: bad JSON: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("eth_getProof failed: {err}"));
    }
    Ok(v)
}

/// `(accountProof, storageProof[0].proof)` as raw RLP nodes. The response's own `balance`,
/// `storageHash`, `value` etc. are ignored: only the proof nodes are used, and the guest checks
/// them against roots it derived itself.
pub fn parse_state_proof(v: &Value) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), String> {
    let r = v.get("result").unwrap_or(v);
    let nodes = |a: &Value, what: &str| -> Result<Vec<Vec<u8>>, String> {
        a.as_array()
            .ok_or_else(|| format!("{what}: not an array"))?
            .iter()
            .map(|e| {
                e.as_str()
                    .ok_or_else(|| format!("{what}: element not a string"))
                    .and_then(|s| {
                        hex::decode(s.strip_prefix("0x").unwrap_or(s))
                            .map_err(|e| format!("{what}: {e}"))
                    })
            })
            .collect()
    };
    let account = nodes(field(r, "accountProof")?, "accountProof")?;
    let storage = match r
        .get("storageProof")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
    {
        Some(sp) => nodes(field(sp, "proof")?, "storageProof[0].proof")?,
        None => vec![],
    };
    Ok((account, storage))
}

/// `eth_getBlockReceipts` response from the JSON-RPC endpoint, or from
/// `<dir>/block_receipts.json`; saved to `--save-dir` as `block_receipts.json`.
fn fetch_block_receipts(
    rpc: &str,
    save_dir: Option<&PathBuf>,
    block: u64,
) -> Result<Value, String> {
    let bytes: Vec<u8> = if rpc.starts_with("http://") || rpc.starts_with("https://") {
        let resp = ureq::post(rpc)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json")
            .send_string(&receipts::block_receipts_request(block))
            .map_err(|e| format!("POST {rpc} eth_getBlockReceipts: {e}"))?;
        resp.into_string()
            .map_err(|e| format!("read body of {rpc}: {e}"))?
            .into_bytes()
    } else {
        let p = PathBuf::from(rpc).join("block_receipts.json");
        fs::read(&p).map_err(|e| format!("read {}: {e}", p.display()))?
    };
    if let Some(dir) = save_dir {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        fs::write(dir.join("block_receipts.json"), &bytes)
            .map_err(|e| format!("save block_receipts.json: {e}"))?;
    }
    let v = serde_json::from_slice::<Value>(&bytes)
        .map_err(|e| format!("block_receipts.json: bad JSON: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("eth_getBlockReceipts failed: {err}"));
    }
    Ok(v)
}

fn hex_string_bytes(v: &Value, k: &str) -> Result<Vec<u8>, String> {
    let s = field(v, k)?
        .as_str()
        .ok_or_else(|| format!("`{k}`: not a string"))?;
    parse_hex_bytes(s).map_err(|e| format!("`{k}`: {e}"))
}

fn quantity_field(v: &Value, k: &str) -> Result<u64, String> {
    let s = field(v, k)?
        .as_str()
        .ok_or_else(|| format!("`{k}`: not a string"))?;
    quantity(s).map_err(|e| format!("`{k}`: {e}"))
}

/// Every receipt of the block, in order. A receipt without a post-Byzantium `status` (a
/// pre-Byzantium `root` instead) is refused: the guest would refuse it too.
pub fn parse_block_receipts(v: &Value) -> Result<Vec<ReceiptData>, String> {
    let r = v.get("result").unwrap_or(v);
    let arr = r.as_array().ok_or(
        "block receipts: expected a JSON array (the node may not serve eth_getBlockReceipts)",
    )?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, e) in arr.iter().enumerate() {
        let at = |m: String| format!("receipt {i}: {m}");
        // the position in the array is the trie key: a node that reorders them is wrong
        let idx = quantity_field(e, "transactionIndex").map_err(at)?;
        if idx != i as u64 {
            return Err(format!("receipt {i}: transactionIndex is {idx}"));
        }
        let bloom: [u8; receipts::BLOOM_LEN] = hex_string_bytes(e, "logsBloom")
            .map_err(at)?
            .try_into()
            .map_err(|_| format!("receipt {i}: logsBloom is not 256 bytes"))?;
        let ty = quantity_field(e, "type").map_err(at)?;
        let tx_type =
            u8::try_from(ty).map_err(|_| format!("receipt {i}: type {ty} is not a byte"))?;
        let status = quantity_field(e, "status").map_err(at)?;
        if status > 1 {
            return Err(format!("receipt {i}: status {status}"));
        }
        let mut logs = vec![];
        for (j, l) in field(e, "logs")?
            .as_array()
            .ok_or_else(|| format!("receipt {i}: logs is not an array"))?
            .iter()
            .enumerate()
        {
            let at = |m: String| format!("receipt {i} log {j}: {m}");
            let topics = hex_array::<32>(l, "topics").map_err(at)?;
            logs.push(LogData {
                address: hex_field::<20>(l, "address").map_err(at)?,
                topics,
                data: hex_string_bytes(l, "data").map_err(at)?,
            });
        }
        out.push(ReceiptData {
            tx_hash: hex_field::<32>(e, "transactionHash").map_err(at)?,
            tx_type,
            success: status == 1,
            cumulative_gas: quantity_field(e, "cumulativeGasUsed").map_err(at)?,
            bloom,
            logs,
        });
    }
    Ok(out)
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
    let want_state = o.state.needs_anchor();
    let mut anchors: Vec<Anchor> = vec![];
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
        if want_state {
            anchors.extend(anchor_of(data(item))?);
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
    if want_state {
        anchors.extend(anchor_of(data(&top))?);
    }
    let (sync, expected) = if want_sync {
        // The host's own chain: source of the expected binding and of the clock.
        let own = load_chain_facts(&src)?;
        let expected = binding_from(&p, &own)?;
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

    let state = match o.state.address {
        None => None,
        Some(address) => {
            let anchor = pick_anchor(anchors.clone()).ok_or(
                "no update with a finalized execution header and >= 2/3 sync participation was \
                 fetched; retry shortly, or run without --latest-only",
            )?;
            let rpc = o
                .state
                .execution_rpc
                .as_deref()
                .ok_or("--address needs --execution-rpc")?;
            let slot = o.state.slot.unwrap_or([0u8; 32]);
            // The block comes from the (still unverified) header; the guest proves it, and a proof
            // fetched for any other block fails against the state root the guest derives.
            let proof = fetch_state_proof(
                rpc,
                o.save_dir.as_ref(),
                &address,
                &slot,
                anchor.exec.block_number,
            )?;
            let (mut account_proof, storage_proof) = parse_state_proof(&proof)?;
            let mut exec = anchor.exec;
            if o.state.tamper_state {
                flip_first_node(&mut account_proof);
            }
            if o.state.tamper_exec {
                exec.state_root[0] ^= 1;
            }
            Some(StateInput {
                exec,
                exec_branch: anchor.branch,
                address,
                slot,
                account_proof,
                storage_proof,
                predicate: o.state.predicate,
            })
        }
    };

    let log = match o.state.log.address {
        None => None,
        Some(address) => {
            let anchor = pick_anchor(anchors).ok_or(
                "no update with a finalized execution header and >= 2/3 sync participation was \
                 fetched; retry shortly, or run without --latest-only",
            )?;
            let rpc = o
                .state
                .execution_rpc
                .as_deref()
                .ok_or("--log-address needs --execution-rpc")?;
            let lo = &o.state.log;
            // The block comes from the (still unverified) header. The rebuilt receipts root must
            // equal that header's `receipts_root`; the guest then proves the header itself.
            let receipts = parse_block_receipts(&fetch_block_receipts(
                rpc,
                o.save_dir.as_ref(),
                anchor.exec.block_number,
            )?)?;
            let trie = ReceiptsTrie::new(&receipts);
            if trie.root() != anchor.exec.receipts_root {
                return Err(format!(
                    "the receipts of block {} rebuild to root 0x{} but its header says 0x{}: \
                     the RPC served another block or non-canonical data",
                    anchor.exec.block_number,
                    hex::encode(trie.root()),
                    hex::encode(anchor.exec.receipts_root)
                ));
            }
            let filter = Filter {
                address,
                topics: lo.topics,
            };
            let (tx, log_index) = match &lo.tx {
                Some(sel) => {
                    let tx = resolve_tx(&receipts, sel)?;
                    let li = lo.log_index.unwrap_or(0);
                    check_position(&receipts, tx, li, &filter)?;
                    (tx, li)
                }
                None => find_log(&receipts, &filter).ok_or_else(|| {
                    format!(
                        "no log in block {} matches the address and topics asked for",
                        anchor.exec.block_number
                    )
                })?,
            };
            let mut receipt_proof = trie
                .proof(tx)
                .ok_or_else(|| format!("the block has no transaction {tx}"))?;
            let mut exec = anchor.exec;
            if o.state.tamper_exec {
                exec.receipts_root[0] ^= 1;
            }
            if lo.tamper_receipt {
                flip_first_receipt_node(&mut receipt_proof);
            }
            Some(LogInput {
                exec,
                exec_branch: anchor.branch,
                tx_index: tx,
                log_index,
                receipt_proof,
                address,
                topics: lo.topics,
                predicate: lo.predicate,
            })
        }
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
        state,
        log,
    };
    Ok(Collected { input, expected })
}

/// The binding the host expects the journal to commit, from its own parameters and chain facts.
fn binding_from(p: &Params, own: &ChainFacts) -> Result<ChainBinding, String> {
    build_chain_binding(
        p.cfg.slots_per_epoch,
        p.epochs_per_period,
        own.chain_id,
        &own.genesis_validators_root,
        &own.forks,
    )
    .map_err(|e| format!("chain binding: {e:?}"))
}

/// The chain binding for `--verify-receipt`: built from `--source` only (a saved directory
/// works offline), never from the receipt.
pub fn expected_binding(o: &Opts) -> Result<ChainBinding, String> {
    let src = Source {
        base: &o.source,
        save_dir: None,
    };
    let p = load_params(&src)?;
    let own = load_chain_facts(&src)?;
    binding_from(&p, &own)
}

// ==== Proof output ===========================================================================

/// Proof-step options. Parsed apart from `Opts` (`split_proof_args`) so the run options stay as
/// they are.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProofOpts {
    /// Prove after a successful execute.
    pub prove: bool,
    /// Where `--prove` writes the receipt.
    pub receipt_out: Option<PathBuf>,
    /// Verify this saved receipt instead of running the guest.
    pub verify_receipt: Option<PathBuf>,
}

/// Take `--prove`, `--receipt-out` and `--verify-receipt` out of the arguments; everything else
/// is returned, in order, for `parse_args`.
pub fn split_proof_args<I: IntoIterator<Item = String>>(
    args: I,
) -> Result<(ProofOpts, Vec<String>), String> {
    let mut a = args.into_iter();
    let mut po = ProofOpts::default();
    let mut rest = vec![];
    while let Some(k) = a.next() {
        match k.as_str() {
            "--prove" => po.prove = true,
            "--receipt-out" => {
                po.receipt_out = Some(PathBuf::from(
                    a.next().ok_or("--receipt-out needs a value")?,
                ))
            }
            "--verify-receipt" => {
                po.verify_receipt = Some(PathBuf::from(
                    a.next().ok_or("--verify-receipt needs a value")?,
                ))
            }
            _ => rest.push(k),
        }
    }
    if po.prove && po.verify_receipt.is_some() {
        return Err("--prove and --verify-receipt cannot be combined".into());
    }
    if po.prove && po.receipt_out.is_none() {
        return Err("--prove needs --receipt-out <file>".into());
    }
    if !po.prove && po.receipt_out.is_some() {
        return Err("--receipt-out needs --prove".into());
    }
    Ok((po, rest))
}

/// Why a run cannot be proved or verified as a receipt: a tamper or other-chain run is built to
/// be rejected, so there is nothing to prove.
pub fn proof_run_error(o: &Opts) -> Option<&'static str> {
    let negative = o.tamper
        || o.tamper_sig
        || o.other_chain
        || o.cross_config.is_some()
        || o.state.tamper_state
        || o.state.tamper_exec
        || o.state.log.tamper_receipt;
    negative
        .then_some("a tamper or other-chain run is rejected on purpose: there is nothing to prove")
}

/// The receipt must commit exactly the journal the guest executed to.
pub fn judge_receipt_journal(executed: &[u8], receipt: &[u8]) -> Verdict {
    if executed == receipt {
        Verdict::Ok
    } else {
        Verdict::ReceiptJournalDiffers
    }
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
    /// Sprint 1-3 checks passed but the committed state section is not what was asked for
    /// (rejected, wrong address/slot, wrong expected value/balance, or a tamper run whose
    /// rejection was not the expected typed error).
    StateNotOk,
    /// Same for the Sprint 5 log section (rejected, wrong log, wrong predicate or statement ID,
    /// or a tamper run whose rejection was not the expected typed error).
    LogNotOk,
    /// The proved receipt's journal is not the journal the guest executed to.
    ReceiptJournalDiffers,
    NotOk,
}

/// Process exit code for a verdict (documented in `USAGE`).
pub fn verdict_exit_code(v: &Verdict) -> u8 {
    match v {
        Verdict::Ok => 0,
        Verdict::ChainMismatch(_) => 3,
        Verdict::ChainMismatchNotDetected
        | Verdict::TrustedRootDiffers
        | Verdict::StateNotOk
        | Verdict::LogNotOk
        | Verdict::ReceiptJournalDiffers
        | Verdict::NotOk => 1,
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
        if !state_ok_for(o, out) {
            Verdict::StateNotOk
        } else if !log_ok_for(o, out) {
            Verdict::LogNotOk
        } else {
            Verdict::Ok
        }
    } else {
        Verdict::NotOk
    }
}

/// Sprint 4 judgement, on the journal only. Without `--address` there is nothing to judge.
/// Tamper runs must be rejected by the guest with the specific typed error (the anchor is
/// checked first, so `--tamper-exec` wins over `--tamper-state`).
fn state_ok_for(o: &Opts, out: &GuestOutput) -> bool {
    let st = &o.state;
    let Some(address) = st.address else {
        return true;
    };
    let rejected_with =
        |e: Error| out.state_checked && !out.state_ok && out.state_error_code == e.code();
    if st.tamper_exec {
        return rejected_with(Error::InvalidBranch);
    }
    if st.tamper_state {
        return rejected_with(Error::InvalidTrieProof);
    }
    out.state_checked
        && out.state_ok
        && out.state_error_code == 0
        && out.state_address == address
        && out.state_slot == st.slot.unwrap_or([0u8; 32])
        && st.expect_value.map_or(true, |v| out.state_value == v)
        && st.expect_balance.map_or(true, |b| out.account_balance == b)
        && out.state_predicate == st.predicate
        // `--expect-id` names the log's ID when a log is requested, else the slot's
        && (st.log.requested() || st.expect_id.map_or(true, |id| out.state_statement_id == id))
}

/// Sprint 5 judgement, on the journal only. Without `--log-address` there is nothing to judge.
/// Tamper runs must be rejected by the guest with the specific typed error (the anchor is
/// checked first, so `--tamper-exec` wins over `--tamper-receipt`).
fn log_ok_for(o: &Opts, out: &GuestOutput) -> bool {
    let st = &o.state;
    let lg = &st.log;
    let Some(address) = lg.address else {
        return true;
    };
    let rejected_with = |e: Error| out.log_checked && !out.log_ok && out.log_error_code == e.code();
    if st.tamper_exec {
        return rejected_with(Error::InvalidBranch);
    }
    if lg.tamper_receipt {
        return rejected_with(Error::InvalidTrieProof);
    }
    out.log_checked
        && out.log_ok
        && out.log_error_code == 0
        && out.log_address == address
        && lg.topics.iter().enumerate().all(|(i, want)| match want {
            None => true,
            Some(t) => (out.log_topic_count as usize) > i && out.log_topics[i] == *t,
        })
        && match lg.tx {
            Some(TxSel::Index(n)) => out.log_tx_index == n,
            // a hash was resolved to a position by the host; the guest proves the position
            Some(TxSel::Hash(_)) | None => true,
        }
        && lg.log_index.map_or(true, |i| out.log_index == i)
        && out.log_predicate == lg.predicate
        && st.expect_id.map_or(true, |id| out.log_statement_id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use le_sync_wire::PredicateTarget;
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
            state: StateOpts::default(),
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
            state: StateOpts::default(),
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
            state: StateOpts::default(),
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
            state: StateOpts::default(),
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

    // ==== Proof output ===========================================================================

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
    const ROOT_HEX: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

    fn run_opts(extra: &[&str]) -> Opts {
        let mut a = vec!["--source", "x", "--trusted-root", ROOT_HEX];
        a.extend_from_slice(extra);
        parse_args(sv(&a)).unwrap()
    }

    #[test]
    fn proof_split_takes_its_flags_and_keeps_the_rest_in_order() {
        let (po, rest) = split_proof_args(sv(&[
            "--source",
            "x",
            "--prove",
            "--address",
            "0xaa",
            "--receipt-out",
            "r.bin",
            "--sync",
        ]))
        .unwrap();
        assert!(po.prove);
        assert_eq!(po.receipt_out, Some(PathBuf::from("r.bin")));
        assert_eq!(po.verify_receipt, None);
        assert_eq!(rest, sv(&["--source", "x", "--address", "0xaa", "--sync"]));

        let (po, rest) =
            split_proof_args(sv(&["--verify-receipt", "r.bin", "--source", "d"])).unwrap();
        assert!(!po.prove);
        assert_eq!(po.verify_receipt, Some(PathBuf::from("r.bin")));
        assert_eq!(rest, sv(&["--source", "d"]));

        let (po, rest) = split_proof_args(sv(&["--source", "x"])).unwrap();
        assert_eq!(po, ProofOpts::default());
        assert_eq!(rest, sv(&["--source", "x"]));
        let (po, rest) = split_proof_args(Vec::<String>::new()).unwrap();
        assert_eq!(po, ProofOpts::default());
        assert!(rest.is_empty());
    }

    #[test]
    fn proof_split_rules() {
        let e = |v: &[&str]| split_proof_args(sv(v)).unwrap_err();
        assert_eq!(e(&["--prove"]), "--prove needs --receipt-out <file>");
        assert_eq!(
            e(&["--receipt-out", "r.bin"]),
            "--receipt-out needs --prove"
        );
        assert_eq!(
            e(&["--prove", "--receipt-out", "a", "--verify-receipt", "b"]),
            "--prove and --verify-receipt cannot be combined"
        );
        assert_eq!(
            e(&["--prove", "--receipt-out"]),
            "--receipt-out needs a value"
        );
        assert_eq!(e(&["--verify-receipt"]), "--verify-receipt needs a value");
        // verify alone and prove with an output are fine
        assert!(split_proof_args(sv(&["--verify-receipt", "b"])).is_ok());
        assert!(split_proof_args(sv(&["--prove", "--receipt-out", "a"])).is_ok());
    }

    #[test]
    fn proof_is_refused_for_every_negative_run_and_allowed_otherwise() {
        let addr = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
        let neg: Vec<Vec<&str>> = vec![
            vec!["--tamper"],
            vec!["--sync", "--tamper-sig"],
            vec!["--sync", "--other-chain"],
            vec!["--cross-config", "d"],
            vec!["--address", addr, "--execution-rpc", "r", "--tamper-state"],
            vec!["--address", addr, "--execution-rpc", "r", "--tamper-exec"],
            vec![
                "--log-address",
                addr,
                "--execution-rpc",
                "r",
                "--tamper-receipt",
            ],
        ];
        for n in neg {
            assert!(proof_run_error(&run_opts(&n)).is_some(), "{n:?}");
        }
        assert_eq!(proof_run_error(&run_opts(&[])), None);
        assert_eq!(proof_run_error(&run_opts(&["--sync"])), None);
        assert_eq!(
            proof_run_error(&run_opts(&["--address", addr, "--execution-rpc", "r"])),
            None
        );
        assert_eq!(
            proof_run_error(&run_opts(&["--log-address", addr, "--execution-rpc", "r"])),
            None
        );
    }

    #[test]
    fn proof_receipt_journal_must_equal_the_executed_one() {
        assert_eq!(judge_receipt_journal(b"abc", b"abc"), Verdict::Ok);
        assert_eq!(judge_receipt_journal(b"", b""), Verdict::Ok);
        assert_eq!(
            judge_receipt_journal(b"abc", b"abd"),
            Verdict::ReceiptJournalDiffers
        );
        assert_eq!(
            judge_receipt_journal(b"abc", b"ab"),
            Verdict::ReceiptJournalDiffers
        );
        assert_eq!(
            judge_receipt_journal(b"ab", b"abc"),
            Verdict::ReceiptJournalDiffers
        );
        assert_eq!(verdict_exit_code(&Verdict::ReceiptJournalDiffers), 1);
    }

    #[test]
    fn proof_flags_are_in_the_usage() {
        for f in [
            "--prove",
            "--receipt-out",
            "--verify-receipt",
            "RISC0_DEV_MODE",
        ] {
            assert!(USAGE.contains(f), "{f}");
        }
    }

    // ==== Sprint 4: account + storage state proof ================================================

    fn word(n: u8) -> Bytes32 {
        let mut w = [0u8; 32];
        w[31] = n;
        w
    }

    fn exec_json() -> Value {
        serde_json::json!({
            "parent_hash": x(&[1u8; 32]),
            "fee_recipient": x(&[2u8; 20]),
            "state_root": x(&[3u8; 32]),
            "receipts_root": x(&[4u8; 32]),
            "logs_bloom": x(&[5u8; 256]),
            "prev_randao": x(&[6u8; 32]),
            "block_number": "24000123",
            "gas_limit": "36000000",
            "gas_used": "777",
            "timestamp": "1700000000",
            "extra_data": "0x6c6521",
            "base_fee_per_gas": "256",
            "block_hash": x(&[7u8; 32]),
            "transactions_root": x(&[8u8; 32]),
            "withdrawals_root": x(&[9u8; 32]),
            "blob_gas_used": "0",
            "excess_blob_gas": "0"
        })
    }

    fn fin_obj(slot: u64, with_exec: bool) -> Value {
        let h = BeaconBlockHeader {
            slot,
            proposer_index: 1,
            parent_root: leaf(1),
            state_root: leaf(2),
            body_root: leaf(3),
        };
        let mut v: Value = serde_json::from_str(&hdr_json(&h)).unwrap();
        if with_exec {
            v["execution"] = exec_json();
            v["execution_branch"] = serde_json::json!(vec![x(&leaf(9)); 4]);
        }
        v
    }

    fn upd_obj(slot: u64, bits: &str, branch_present: bool, with_exec: bool) -> Value {
        let node = if branch_present { leaf(1) } else { [0u8; 32] };
        serde_json::json!({
            "finalized_header": fin_obj(slot, with_exec),
            "finality_branch": vec![x(&node); 7],
            "sync_aggregate": { "sync_committee_bits": bits, "sync_committee_signature": "0x" }
        })
    }

    #[test]
    fn exec_wire_parses_the_beacon_api_shape() {
        let e = exec_wire(&exec_json()).unwrap();
        assert_eq!(e.block_number, 24_000_123);
        assert_eq!(
            (e.gas_limit, e.gas_used, e.timestamp),
            (36_000_000, 777, 1_700_000_000)
        );
        assert_eq!(e.fee_recipient, [2u8; 20]);
        assert_eq!(e.state_root, [3u8; 32]);
        assert_eq!(e.logs_bloom.len(), 256);
        assert_eq!(e.extra_data, b"le!".to_vec());
        assert_eq!(e.block_hash, [7u8; 32]);
        assert_eq!((e.blob_gas_used, e.excess_blob_gas), (0, 0));
        let mut fee = [0u8; 32];
        fee[1] = 1; // 256, little-endian
        assert_eq!(e.base_fee_per_gas, fee);

        // a JSON number is accepted for the base fee
        let mut j = exec_json();
        j["base_fee_per_gas"] = 7.into();
        assert_eq!(exec_wire(&j).unwrap().base_fee_per_gas[0], 7);

        // missing field and wrong-length hash are clear errors naming the field
        let mut j = exec_json();
        j.as_object_mut().unwrap().remove("blob_gas_used");
        assert!(exec_wire(&j).unwrap_err().contains("blob_gas_used"));
        let mut j = exec_json();
        j["state_root"] = "0x1234".into();
        assert!(exec_wire(&j).unwrap_err().contains("state_root"));
        let mut j = exec_json();
        j["base_fee_per_gas"] = "abc".into();
        assert!(exec_wire(&j).unwrap_err().contains("base_fee_per_gas"));
    }

    #[test]
    fn anchor_of_only_offers_updates_the_guest_can_apply() {
        let a = anchor_of(&upd_obj(704, "0xffff", true, true))
            .unwrap()
            .unwrap();
        assert_eq!(a.slot, 704);
        assert_eq!(a.exec.block_number, 24_000_123);
        assert_eq!(a.branch.len(), 4);
        // participation: 16 bits, 2/3 needs 11 set (11 * 3 >= 32), 10 does not
        assert!(anchor_of(&upd_obj(704, "0xff07", true, true))
            .unwrap()
            .is_some());
        assert!(anchor_of(&upd_obj(704, "0xff03", true, true))
            .unwrap()
            .is_none());
        assert!(anchor_of(&upd_obj(704, "0x0001", true, true))
            .unwrap()
            .is_none());
        assert!(anchor_of(&upd_obj(704, "0x", true, true))
            .unwrap()
            .is_none());
        // no finality branch, or no execution data: nothing to anchor to
        assert!(anchor_of(&upd_obj(704, "0xffff", false, true))
            .unwrap()
            .is_none());
        assert!(anchor_of(&upd_obj(704, "0xffff", true, false))
            .unwrap()
            .is_none());
    }

    #[test]
    fn pick_anchor_takes_the_newest_finalized_slot() {
        let e = exec_wire(&exec_json()).unwrap();
        let mk = |slot| Anchor {
            slot,
            exec: e.clone(),
            branch: vec![],
        };
        assert_eq!(pick_anchor(vec![mk(5), mk(9), mk(7)]).unwrap().slot, 9);
        assert_eq!(pick_anchor(vec![mk(9), mk(5)]).unwrap().slot, 9);
        assert!(pick_anchor(vec![]).is_none());
    }

    #[test]
    fn parse_state_proof_reads_nodes_and_ignores_the_responses_own_claims() {
        let full = serde_json::json!({"jsonrpc":"2.0","id":1,"result":{
            "accountProof": ["0x01", "0xabcd"],
            "balance": "0xdeadbeef", "storageHash": x(&[9u8; 32]),
            "storageProof": [{"key": "0x0", "value": "0x5", "proof": ["0xc0", "0x80"]}]
        }});
        let want = (
            vec![vec![1u8], vec![0xab, 0xcd]],
            vec![vec![0xc0u8], vec![0x80]],
        );
        assert_eq!(parse_state_proof(&full).unwrap(), want);
        // the bare result object (no JSON-RPC envelope) works too
        assert_eq!(parse_state_proof(&full["result"]).unwrap(), want);
        // an absent account / empty storage proof list
        let none = serde_json::json!({"result":{"accountProof":["0x01"],"storageProof":[]}});
        assert_eq!(parse_state_proof(&none).unwrap(), (vec![vec![1u8]], vec![]));
        // errors name what is wrong
        let e = parse_state_proof(&serde_json::json!({"result":{}})).unwrap_err();
        assert!(e.contains("accountProof"), "{e}");
        assert!(parse_state_proof(&serde_json::json!({"result":{"accountProof":["zz"]}})).is_err());
        assert!(parse_state_proof(&serde_json::json!({"result":{"accountProof":[1]}})).is_err());
        assert!(parse_state_proof(&serde_json::json!({"result":{"accountProof":"0x"}})).is_err());
    }

    #[test]
    fn fetch_state_proof_reads_saves_and_reports_rpc_errors_offline() {
        let dir = std::env::temp_dir().join(format!("le-sync-sp-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let src = dir.display().to_string();
        let ok = r#"{"result":{"accountProof":["0x01"],"storageProof":[]}}"#;
        fs::write(dir.join("state_proof.json"), ok).unwrap();
        let saved = std::env::temp_dir().join(format!("le-sync-sp-saved-{}", std::process::id()));
        let v = fetch_state_proof(&src, Some(&saved), &[0u8; 20], &[0u8; 32], 1).unwrap();
        assert!(v.get("result").is_some());
        assert_eq!(
            fs::read_to_string(saved.join("state_proof.json")).unwrap(),
            ok
        );

        fs::write(
            dir.join("state_proof.json"),
            r#"{"error":{"code":-32000,"message":"missing trie node"}}"#,
        )
        .unwrap();
        let e = fetch_state_proof(&src, None, &[0u8; 20], &[0u8; 32], 1).unwrap_err();
        assert!(
            e.contains("eth_getProof failed") && e.contains("missing trie node"),
            "{e}"
        );

        let e = fetch_state_proof(&src, None, &[0u8; 20], &[0u8; 32], 1);
        assert!(e.is_err());
        let missing = dir.join("nope").display().to_string();
        let e = fetch_state_proof(&missing, None, &[0u8; 20], &[0u8; 32], 1).unwrap_err();
        assert!(e.contains("state_proof.json"), "{e}");
    }

    /// `write_fixture` plus chain files, a supermajority `finality_update` carrying an execution
    /// header, and a saved `state_proof.json`.
    fn write_state_dir(tag: &str) -> (PathBuf, Bytes32) {
        let (dir, root) = write_fixture(tag);
        write_chain_files(&dir, Some(1), 0xAA, [0, 0, 0, 1], 0);
        let p = dir.join("finality_update.json");
        let mut v: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        v["data"]["sync_aggregate"]["sync_committee_bits"] =
            format!("0x{}", "ff".repeat(64)).into();
        v["data"]["finalized_header"]["execution"] = exec_json();
        v["data"]["finalized_header"]["execution_branch"] = serde_json::json!(vec![x(&leaf(9)); 4]);
        fs::write(&p, v.to_string()).unwrap();
        fs::write(
            dir.join("state_proof.json"),
            serde_json::json!({"result":{
                "accountProof": ["0xf90001", "0x80"],
                "storageProof": [{"key": "0x1", "proof": ["0xc0"]}]
            }})
            .to_string(),
        )
        .unwrap();
        (dir, root)
    }

    fn state_opts_for(dir: &PathBuf, st: StateOpts) -> Opts {
        Opts {
            state: StateOpts {
                address: Some([0x11; 20]),
                slot: Some(word(1)),
                execution_rpc: Some(dir.display().to_string()),
                ..st
            },
            ..opts(dir, [0u8; 32], false)
        }
    }

    #[test]
    fn collect_builds_the_state_section_from_the_newest_anchor_and_the_saved_proof() {
        let (dir, root) = write_state_dir("st-ok");
        let mut o = state_opts_for(&dir, StateOpts::default());
        o.trusted_root = root;
        let c = collect_checked(&o).unwrap();
        assert!(c.input.sync.is_some(), "--address implies --sync");
        let st = c.input.state.as_ref().unwrap();
        assert_eq!((st.address, st.slot), ([0x11; 20], word(1)));
        assert_eq!(st.exec.block_number, 24_000_123);
        assert_eq!(st.exec.state_root, [3u8; 32]);
        assert_eq!(st.exec_branch.len(), 4);
        assert_eq!(st.account_proof, vec![vec![0xf9u8, 0, 1], vec![0x80]]);
        assert_eq!(st.storage_proof, vec![vec![0xc0u8]]);

        // slot defaults to 0
        let mut d = o.clone();
        d.state.slot = None;
        assert_eq!(
            collect_checked(&d).unwrap().input.state.unwrap().slot,
            [0u8; 32]
        );

        // --tamper-state flips only the first byte of the first account node
        let mut t = o.clone();
        t.state.tamper_state = true;
        let ts = collect_checked(&t).unwrap().input.state.unwrap();
        assert_eq!(ts.account_proof, vec![vec![0xf8u8, 0, 1], vec![0x80]]);
        assert_eq!(ts.exec, st.exec);

        // --tamper-exec flips one bit of the execution state root only
        let mut t = o.clone();
        t.state.tamper_exec = true;
        let ts = collect_checked(&t).unwrap().input.state.unwrap();
        assert_eq!(ts.exec.state_root[0], 3 ^ 1);
        assert_eq!(&ts.exec.state_root[1..], &[3u8; 31][..]);
        assert_eq!(ts.account_proof, st.account_proof);

        // a run without --address has no state section
        let plain = collect_checked(&Opts {
            trusted_root: root,
            ..opts(&dir, root, false)
        })
        .unwrap();
        assert!(plain.input.state.is_none());
    }

    #[test]
    fn collect_without_a_usable_anchor_is_a_clear_error() {
        // the plain fixture's updates carry no execution data and an empty participation bitfield
        let (dir, root) = write_fixture("st-none");
        write_chain_files(&dir, Some(1), 0xAA, [0, 0, 0, 1], 0);
        let mut o = state_opts_for(&dir, StateOpts::default());
        o.trusted_root = root;
        let e = collect_checked(&o).err().unwrap();
        assert!(
            e.contains("no update with a finalized execution header"),
            "{e}"
        );
    }

    #[test]
    fn parse_args_reads_the_state_flags_and_validates_them() {
        let addr = format!("0x{}", "11".repeat(20));
        let o = parse_args(args(&[
            "--source",
            "/d",
            "--trusted-root",
            ROOT,
            "--address",
            &addr,
            "--slot",
            "0x1",
            "--execution-rpc",
            "/rpc",
            "--expect-value",
            "0x1234",
            "--expect-balance",
            "0x0f4240",
            "--tamper-state",
            "--tamper-exec",
        ]))
        .unwrap();
        let st = &o.state;
        assert_eq!(st.address, Some([0x11; 20]));
        assert_eq!(st.slot, Some(word(1)));
        assert_eq!(st.execution_rpc.as_deref(), Some("/rpc"));
        assert_eq!(&st.expect_value.unwrap()[30..], &[0x12, 0x34]);
        assert_eq!(&st.expect_balance.unwrap()[29..], &[0x0f, 0x42, 0x40]);
        assert!(st.tamper_state && st.tamper_exec && st.requested());
        assert!(o.wants_sync(), "--address implies --sync");

        let min = parse_args(args(&["--source", "/d", "--trusted-root", ROOT])).unwrap();
        assert_eq!(min.state, StateOpts::default());
        assert!(!min.state.requested() && !min.wants_sync());

        let e = |a: &[&str]| parse_args(args(a)).unwrap_err();
        let base = ["--source", "/d", "--trusted-root", ROOT];
        let with = |extra: &[&str]| -> Vec<String> {
            base.iter()
                .chain(extra.iter())
                .map(|s| s.to_string())
                .collect()
        };
        for lone in [
            vec!["--slot", "0x1"],
            vec!["--execution-rpc", "/r"],
            vec!["--expect-value", "0x1"],
            vec!["--expect-balance", "0x1"],
            vec!["--tamper-state"],
            vec!["--tamper-exec"],
        ] {
            let err = parse_args(with(&lone)).unwrap_err();
            assert!(err.contains("need --address"), "{lone:?}: {err}");
        }
        let err = parse_args(with(&["--address", &addr])).unwrap_err();
        assert!(err.contains("--execution-rpc"), "{err}");
        assert!(e(&["--address", "0x12"]).contains("--address"));
        let err = parse_args(with(&[
            "--address",
            &"11".repeat(19),
            "--execution-rpc",
            "/r",
        ]))
        .unwrap_err();
        assert!(
            err.contains("--address") && err.contains("20 bytes"),
            "{err}"
        );
        let err = parse_args(with(&[
            "--address",
            &addr,
            "--execution-rpc",
            "/r",
            "--slot",
            "zz",
        ]))
        .unwrap_err();
        assert!(err.contains("--slot"), "{err}");
    }

    fn state_journal(root: Bytes32, own: &ChainBinding, addr: [u8; 20]) -> GuestOutput {
        GuestOutput {
            state_checked: true,
            state_ok: true,
            state_address: addr,
            state_slot: [0u8; 32],
            state_value: word(5),
            account_balance: word(6),
            account_present: true,
            ..journal(root, own, 1, 0)
        }
    }

    fn judge_opts(root: Bytes32, st: StateOpts) -> Opts {
        Opts {
            sync: true,
            state: st,
            ..opts(&PathBuf::new(), root, false)
        }
    }

    #[test]
    fn judge_requires_the_committed_state_to_match_the_request() {
        let root = [3u8; 32];
        let own = bind(1, 0xAA);
        let addr = [0x11u8; 20];
        let st = StateOpts {
            address: Some(addr),
            execution_rpc: Some("x".into()),
            ..Default::default()
        };
        let o = judge_opts(root, st.clone());
        let j = state_journal(root, &own, addr);
        assert_eq!(judge(&o, &j, Some(&own)), Verdict::Ok);

        let not_ok = |mutate: &dyn Fn(&mut GuestOutput)| {
            let mut b = j.clone();
            mutate(&mut b);
            judge(&o, &b, Some(&own))
        };
        assert_eq!(
            not_ok(&|b| b.state_address = [0x12; 20]),
            Verdict::StateNotOk
        );
        assert_eq!(not_ok(&|b| b.state_ok = false), Verdict::StateNotOk);
        assert_eq!(not_ok(&|b| b.state_checked = false), Verdict::StateNotOk);
        assert_eq!(not_ok(&|b| b.state_error_code = 201), Verdict::StateNotOk);
        assert_eq!(not_ok(&|b| b.state_slot = word(1)), Verdict::StateNotOk);

        // the requested slot must be the committed one (default: zero)
        let o1 = judge_opts(
            root,
            StateOpts {
                slot: Some(word(1)),
                ..st.clone()
            },
        );
        assert_eq!(judge(&o1, &j, Some(&own)), Verdict::StateNotOk);
        let mut j1 = j.clone();
        j1.state_slot = word(1);
        assert_eq!(judge(&o1, &j1, Some(&own)), Verdict::Ok);

        // expected value / balance are compared against the journal
        for (v, want) in [(5u8, Verdict::Ok), (6, Verdict::StateNotOk)] {
            let ov = judge_opts(
                root,
                StateOpts {
                    expect_value: Some(word(v)),
                    ..st.clone()
                },
            );
            assert_eq!(judge(&ov, &j, Some(&own)), want, "value {v}");
        }
        for (b, want) in [(6u8, Verdict::Ok), (5, Verdict::StateNotOk)] {
            let ob = judge_opts(
                root,
                StateOpts {
                    expect_balance: Some(word(b)),
                    ..st.clone()
                },
            );
            assert_eq!(judge(&ob, &j, Some(&own)), want, "balance {b}");
        }

        // Sprint 1-3 failures still win: a bad sync run is NotOk, not StateNotOk
        let mut bad_sync = j.clone();
        bad_sync.sync_validated = 0;
        assert_eq!(judge(&o, &bad_sync, Some(&own)), Verdict::NotOk);

        // without --address the state part of the journal is not judged at all
        let plain = judge_opts(root, StateOpts::default());
        assert_eq!(
            judge(&plain, &journal(root, &own, 1, 0), Some(&own)),
            Verdict::Ok
        );
    }

    #[test]
    fn judge_tamper_runs_must_be_rejected_with_the_specific_typed_error() {
        let root = [3u8; 32];
        let own = bind(1, 0xAA);
        let addr = [0x11u8; 20];
        let base = StateOpts {
            address: Some(addr),
            execution_rpc: Some("x".into()),
            ..Default::default()
        };
        let rejected = |code: u16| GuestOutput {
            state_checked: true,
            state_error_code: code,
            ..journal(root, &own, 1, 0)
        };
        let ts = judge_opts(
            root,
            StateOpts {
                tamper_state: true,
                ..base.clone()
            },
        );
        assert_eq!(
            judge(&ts, &rejected(Error::InvalidTrieProof.code()), Some(&own)),
            Verdict::Ok
        );
        assert_eq!(
            judge(&ts, &rejected(Error::InvalidBranch.code()), Some(&own)),
            Verdict::StateNotOk
        );
        assert_eq!(judge(&ts, &rejected(0), Some(&own)), Verdict::StateNotOk);
        // the guest accepting tampered data is the failure we are testing for
        assert_eq!(
            judge(&ts, &state_journal(root, &own, addr), Some(&own)),
            Verdict::StateNotOk
        );
        // never evaluated is not a rejection either
        assert_eq!(
            judge(&ts, &journal(root, &own, 1, 0), Some(&own)),
            Verdict::StateNotOk
        );

        let te = judge_opts(
            root,
            StateOpts {
                tamper_exec: true,
                ..base.clone()
            },
        );
        assert_eq!(
            judge(&te, &rejected(Error::InvalidBranch.code()), Some(&own)),
            Verdict::Ok
        );
        assert_eq!(
            judge(&te, &rejected(Error::InvalidTrieProof.code()), Some(&own)),
            Verdict::StateNotOk
        );

        // both flags: the anchor is checked first, so the branch error is the expected one
        let both = judge_opts(
            root,
            StateOpts {
                tamper_state: true,
                tamper_exec: true,
                ..base
            },
        );
        assert_eq!(
            judge(&both, &rejected(Error::InvalidBranch.code()), Some(&own)),
            Verdict::Ok
        );
        assert_eq!(
            judge(&both, &rejected(Error::InvalidTrieProof.code()), Some(&own)),
            Verdict::StateNotOk
        );

        assert_eq!(verdict_exit_code(&Verdict::StateNotOk), 1);
    }
    // ---- Sprint 5: log section flags and judgement ---------------------------------------------

    fn log_args(extra: &[&str]) -> Vec<String> {
        let mut v = vec!["--source", "/d", "--trusted-root", ROOT];
        v.extend_from_slice(extra);
        args(&v)
    }
    const CONTRACT: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";

    #[test]
    fn log_flags_parse_into_the_log_options() {
        let o = parse_args(log_args(&[
            "--log-address",
            CONTRACT,
            "--log-topic0",
            "0x01",
            "--log-topic2",
            "0x02",
            "--log-tx",
            "129",
            "--log-index",
            "2",
            "--execution-rpc",
            "/rpc",
            "--expect-id",
            "0x07",
            "--tamper-receipt",
        ]))
        .unwrap();
        let lg = &o.state.log;
        assert_eq!(lg.address, Some([0xc0; 20]));
        assert_eq!(lg.topics, [Some(word(1)), None, Some(word(2)), None]);
        assert_eq!(lg.tx, Some(TxSel::Index(129)));
        assert_eq!(lg.log_index, Some(2));
        assert!(lg.tamper_receipt && lg.predicate.is_none());
        assert_eq!(o.state.execution_rpc.as_deref(), Some("/rpc"));
        assert_eq!(o.state.expect_id, Some(word(7)));
        // a log run needs the sync section but not an account
        assert!(o.state.log.requested() && !o.state.requested());
        assert!(o.state.needs_anchor() && o.wants_sync());
        // a transaction by hash, topics 1 and 3
        let h = format!("0x{}", "ab".repeat(32));
        let o = parse_args(log_args(&[
            "--log-address",
            CONTRACT,
            "--execution-rpc",
            "/r",
            "--log-tx",
            &h,
            "--log-topic1",
            "0x09",
            "--log-topic3",
            "0x0a",
        ]))
        .unwrap();
        assert_eq!(o.state.log.tx, Some(TxSel::Hash([0xab; 32])));
        assert_eq!(
            o.state.log.topics,
            [None, Some(word(9)), None, Some(word(10))]
        );
        // no log flags: nothing requested
        let o = parse_args(log_args(&[])).unwrap();
        assert_eq!(o.state.log, LogOpts::default());
        assert!(!o.state.needs_anchor());
    }

    #[test]
    fn a_predicate_goes_to_the_section_its_target_reads() {
        let addr = "11".repeat(20);
        let both = [
            "--address",
            &addr,
            "--log-address",
            CONTRACT,
            "--execution-rpc",
            "/r",
        ];
        let with = |p: &str| {
            let mut v = both.to_vec();
            v.extend(["--predicate", p]);
            parse_args(log_args(&v)).unwrap()
        };
        let o = with("balance==0x05");
        assert_eq!(
            o.state.predicate.map(|p| p.target),
            Some(PredicateTarget::Balance)
        );
        assert!(o.state.log.predicate.is_none());
        let o = with("storage!=0x00");
        assert_eq!(
            o.state.predicate.map(|p| p.target),
            Some(PredicateTarget::StorageValue)
        );
        let o = with("data0==0x2710");
        assert_eq!(
            o.state.log.predicate.map(|p| p.target),
            Some(PredicateTarget::DataWord(0))
        );
        assert!(o.state.predicate.is_none());
        let o = with("topic2!=0x01");
        assert_eq!(
            o.state.log.predicate.map(|p| p.target),
            Some(PredicateTarget::Topic(2))
        );
    }

    #[test]
    fn log_flag_errors_say_what_is_missing() {
        let err = |extra: &[&str]| parse_args(log_args(extra)).unwrap_err();
        // log-only flags without --log-address
        for lone in [
            vec!["--log-topic0", "0x1"],
            vec!["--log-tx", "1"],
            vec!["--log-index", "1"],
            vec!["--tamper-receipt"],
        ] {
            assert!(err(&lone).contains("--log-address"), "{lone:?}");
        }
        // --log-address needs an RPC, --log-index needs --log-tx
        assert!(err(&["--log-address", CONTRACT]).contains("--execution-rpc"));
        assert!(err(&[
            "--log-address",
            CONTRACT,
            "--execution-rpc",
            "/r",
            "--log-index",
            "1"
        ])
        .contains("--log-tx"));
        // the shared flags still say --address (or --log-address)
        for lone in [
            vec!["--execution-rpc", "/r"],
            vec!["--tamper-exec"],
            vec!["--expect-id", "0x1"],
        ] {
            assert!(err(&lone).contains("--address"), "{lone:?}");
        }
        // predicate on the wrong section
        let addr = "11".repeat(20);
        assert!(err(&["--predicate", "balance==0x1"]).contains("--address"));
        assert!(err(&["--predicate", "data0==0x1"]).contains("--log-address"));
        assert!(err(&[
            "--address",
            &addr,
            "--execution-rpc",
            "/r",
            "--predicate",
            "topic0==0x1"
        ])
        .contains("--log-address"));
        // malformed values
        assert!(err(&["--log-address", "0x12"]).contains("--log-address"));
        assert!(err(&[
            "--log-address",
            CONTRACT,
            "--log-topic0",
            &format!("0x{}", "11".repeat(33))
        ])
        .contains("--log-topic0"));
        assert!(err(&["--log-address", CONTRACT, "--log-tx", "abc"]).contains("--log-tx"));
        assert!(err(&["--log-address", CONTRACT, "--log-index", "-1"]).contains("--log-index"));
        assert!(err(&["--predicate", "nonsense"]).contains("--predicate"));
        assert!(err(&["--expect-id", "zz"]).contains("--expect-id"));
    }

    fn log_journal(root: Bytes32, own: &ChainBinding) -> GuestOutput {
        GuestOutput {
            log_checked: true,
            log_ok: true,
            log_address: [0xc0; 20],
            log_tx_index: 129,
            log_index: 2,
            log_topic_count: 3,
            log_topics: [word(1), word(8), word(2), [0; 32]],
            log_statement_id: word(7),
            ..journal(root, own, 1, 0)
        }
    }
    fn log_opts(root: Bytes32, lg: LogOpts, st: StateOpts) -> Opts {
        judge_opts(
            root,
            StateOpts {
                execution_rpc: Some("x".into()),
                log: lg,
                ..st
            },
        )
    }
    fn base_log() -> LogOpts {
        LogOpts {
            address: Some([0xc0; 20]),
            ..Default::default()
        }
    }

    #[test]
    fn a_log_run_is_judged_on_what_the_journal_commits() {
        let root = [0xab; 32];
        let own = bind(1, 0xAA);
        let j = log_journal(root, &own);
        let ok = |lg: LogOpts, st: StateOpts, j: &GuestOutput| {
            judge(&log_opts(root, lg, st), j, Some(&own))
        };
        assert_eq!(ok(base_log(), StateOpts::default(), &j), Verdict::Ok);
        // topic constraints are compared with the committed topics, by position
        let t = |topics| LogOpts {
            topics,
            ..base_log()
        };
        assert_eq!(
            ok(
                t([Some(word(1)), None, Some(word(2)), None]),
                StateOpts::default(),
                &j
            ),
            Verdict::Ok
        );
        assert_eq!(
            ok(
                t([Some(word(9)), None, None, None]),
                StateOpts::default(),
                &j
            ),
            Verdict::LogNotOk
        );
        // a constraint on a position the log does not have
        assert_eq!(
            ok(
                t([None, None, None, Some([0; 32])]),
                StateOpts::default(),
                &j
            ),
            Verdict::LogNotOk
        );
        // address, position, log index
        let mut bad = j.clone();
        bad.log_address[0] ^= 1;
        assert_eq!(
            ok(base_log(), StateOpts::default(), &bad),
            Verdict::LogNotOk
        );
        let pos = |tx, li| LogOpts {
            tx: Some(tx),
            log_index: li,
            ..base_log()
        };
        assert_eq!(
            ok(pos(TxSel::Index(129), Some(2)), StateOpts::default(), &j),
            Verdict::Ok
        );
        assert_eq!(
            ok(pos(TxSel::Index(130), None), StateOpts::default(), &j),
            Verdict::LogNotOk
        );
        assert_eq!(
            ok(pos(TxSel::Index(129), Some(1)), StateOpts::default(), &j),
            Verdict::LogNotOk
        );
        // a hash is resolved by the host; any position is accepted for it
        assert_eq!(
            ok(pos(TxSel::Hash([1; 32]), None), StateOpts::default(), &j),
            Verdict::Ok
        );
        // the predicate that held must be the one asked for
        let p = parse_predicate("data0==0x2710").unwrap();
        let asked = LogOpts {
            predicate: Some(p),
            ..base_log()
        };
        assert_eq!(
            ok(asked.clone(), StateOpts::default(), &j),
            Verdict::LogNotOk
        );
        let held = GuestOutput {
            log_predicate: Some(p),
            ..j.clone()
        };
        assert_eq!(ok(asked, StateOpts::default(), &held), Verdict::Ok);
        let other = parse_predicate("data0==0x2711").unwrap();
        let wrong = GuestOutput {
            log_predicate: Some(other),
            ..j.clone()
        };
        assert_eq!(
            ok(
                LogOpts {
                    predicate: Some(p),
                    ..base_log()
                },
                StateOpts::default(),
                &wrong
            ),
            Verdict::LogNotOk
        );
        // a journal predicate nobody asked for is not accepted either
        assert_eq!(
            ok(base_log(), StateOpts::default(), &held),
            Verdict::LogNotOk
        );
        // the statement ID
        let id = |n| StateOpts {
            expect_id: Some(word(n)),
            ..Default::default()
        };
        assert_eq!(ok(base_log(), id(7), &j), Verdict::Ok);
        assert_eq!(ok(base_log(), id(8), &j), Verdict::LogNotOk);
        // rejected or never evaluated
        let rejected = GuestOutput {
            log_ok: false,
            log_error_code: Error::LogMismatch.code(),
            ..j.clone()
        };
        assert_eq!(
            ok(base_log(), StateOpts::default(), &rejected),
            Verdict::LogNotOk
        );
        assert_eq!(
            ok(base_log(), StateOpts::default(), &journal(root, &own, 1, 0)),
            Verdict::LogNotOk
        );
        assert_eq!(verdict_exit_code(&Verdict::LogNotOk), 1);
    }

    #[test]
    fn log_tamper_runs_pass_only_on_their_own_code() {
        let root = [0xab; 32];
        let own = bind(1, 0xAA);
        let rejected = |code: u16| GuestOutput {
            log_checked: true,
            log_error_code: code,
            ..journal(root, &own, 1, 0)
        };
        let j = |lg: LogOpts, st: StateOpts, o: &GuestOutput| {
            judge(&log_opts(root, lg, st), o, Some(&own))
        };
        let receipt = LogOpts {
            tamper_receipt: true,
            ..base_log()
        };
        assert_eq!(
            j(
                receipt.clone(),
                StateOpts::default(),
                &rejected(Error::InvalidTrieProof.code())
            ),
            Verdict::Ok
        );
        assert_eq!(
            j(
                receipt.clone(),
                StateOpts::default(),
                &rejected(Error::InvalidBranch.code())
            ),
            Verdict::LogNotOk
        );
        assert_eq!(
            j(
                receipt.clone(),
                StateOpts::default(),
                &rejected(Error::LogMismatch.code())
            ),
            Verdict::LogNotOk
        );
        assert_eq!(
            j(receipt.clone(), StateOpts::default(), &rejected(0)),
            Verdict::LogNotOk
        );
        // the guest accepting a tampered proof is the failure we test for
        assert_eq!(
            j(
                receipt.clone(),
                StateOpts::default(),
                &log_journal(root, &own)
            ),
            Verdict::LogNotOk
        );
        // --tamper-exec wins: the anchor is checked first
        let exec = StateOpts {
            tamper_exec: true,
            ..Default::default()
        };
        assert_eq!(
            j(
                base_log(),
                exec.clone(),
                &rejected(Error::InvalidBranch.code())
            ),
            Verdict::Ok
        );
        assert_eq!(
            j(
                base_log(),
                exec.clone(),
                &rejected(Error::InvalidTrieProof.code())
            ),
            Verdict::LogNotOk
        );
        assert_eq!(
            j(receipt, exec, &rejected(Error::InvalidBranch.code())),
            Verdict::Ok
        );
    }

    #[test]
    fn state_predicate_and_id_are_judged_too() {
        let root = [0xab; 32];
        let own = bind(1, 0xAA);
        let addr = [0x11u8; 20];
        let p = parse_predicate("balance==0x06").unwrap();
        let st = StateOpts {
            address: Some(addr),
            execution_rpc: Some("x".into()),
            predicate: Some(p),
            ..Default::default()
        };
        let o = judge_opts(root, st.clone());
        let held = GuestOutput {
            state_predicate: Some(p),
            state_statement_id: word(3),
            ..state_journal(root, &own, addr)
        };
        assert_eq!(judge(&o, &held, Some(&own)), Verdict::Ok);
        // the predicate did not hold (or was not echoed)
        assert_eq!(
            judge(&o, &state_journal(root, &own, addr), Some(&own)),
            Verdict::StateNotOk
        );
        // without a predicate asked for, an echoed one is refused
        let none = judge_opts(
            root,
            StateOpts {
                predicate: None,
                ..st.clone()
            },
        );
        assert_eq!(judge(&none, &held, Some(&own)), Verdict::StateNotOk);
        // --expect-id names the slot's statement when no log is requested
        let id = |n| {
            judge_opts(
                root,
                StateOpts {
                    predicate: None,
                    expect_id: Some(word(n)),
                    ..st.clone()
                },
            )
        };
        let plain = GuestOutput {
            state_predicate: None,
            ..held.clone()
        };
        assert_eq!(judge(&id(3), &plain, Some(&own)), Verdict::Ok);
        assert_eq!(judge(&id(4), &plain, Some(&own)), Verdict::StateNotOk);
    }
}
