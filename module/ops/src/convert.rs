//! Beacon and execution JSON -> the wire types the program takes. Ported from `host/src/lib.rs`
//! (`update_wire`, `exec_wire`, `parse_state_proof`); nothing here is trusted.
use le_sync_core::{BeaconBlockHeader, Bytes32};
use le_sync_wire::{ExecWire, UpdateWire, WireHeader};
use serde_json::Value;

type Res<T> = Result<T, String>;

fn data(v: &Value) -> &Value {
    v.get("data").unwrap_or(v)
}
fn field<'a>(v: &'a Value, k: &str) -> Res<&'a Value> {
    v.get(k).ok_or_else(|| format!("missing field `{k}`"))
}
fn as_u64(v: &Value, k: &str) -> Res<u64> {
    let f = field(v, k)?;
    match f.as_str() {
        Some(s) => s.parse::<u64>().map_err(|e| format!("`{k}`: {e}")),
        None => f.as_u64().ok_or_else(|| format!("`{k}`: not a u64")),
    }
}
pub fn hex_n<const N: usize>(s: &str) -> Res<[u8; N]> {
    let raw = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| format!("hex: {e}"))?;
    <[u8; N]>::try_from(raw.as_slice())
        .map_err(|_| format!("expected {N} bytes, got {}", raw.len()))
}
fn hex_field<const N: usize>(v: &Value, k: &str) -> Res<[u8; N]> {
    let s = field(v, k)?
        .as_str()
        .ok_or_else(|| format!("`{k}`: not a string"))?;
    hex_n::<N>(s).map_err(|e| format!("`{k}`: {e}"))
}
fn hex_vec(v: &Value, k: &str) -> Res<Vec<u8>> {
    let s = field(v, k)?
        .as_str()
        .ok_or_else(|| format!("`{k}`: not a string"))?;
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| format!("`{k}`: {e}"))
}
fn hex_array<const N: usize>(v: &Value, k: &str) -> Res<Vec<[u8; N]>> {
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
fn beacon_header(v: &Value) -> Res<BeaconBlockHeader> {
    let b = v.get("beacon").unwrap_or(v);
    Ok(BeaconBlockHeader {
        slot: as_u64(b, "slot")?,
        proposer_index: as_u64(b, "proposer_index")?,
        parent_root: hex_field::<32>(b, "parent_root")?,
        state_root: hex_field::<32>(b, "state_root")?,
        body_root: hex_field::<32>(b, "body_root")?,
    })
}
fn u256_le(v: &Value, k: &str) -> Res<Bytes32> {
    let f = field(v, k)?;
    let s = match f.as_str() {
        Some(s) => s.to_string(),
        None => f
            .as_u64()
            .map(|n| n.to_string())
            .ok_or_else(|| format!("`{k}`: not a decimal"))?,
    };
    // decimal -> 32 little-endian bytes
    let mut out = [0u8; 32];
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            return Err(format!("`{k}`: not a decimal integer"));
        }
        let mut carry = (c - b'0') as u32;
        for b in out.iter_mut() {
            let t = *b as u32 * 10 + carry;
            *b = (t & 0xff) as u8;
            carry = t >> 8;
        }
        if carry != 0 {
            return Err(format!("`{k}`: does not fit 256 bits"));
        }
    }
    Ok(out)
}

/// `finalized_header.execution` (Deneb layout, 17 fields).
pub fn exec_wire(v: &Value) -> Res<ExecWire> {
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
        base_fee_per_gas: u256_le(v, "base_fee_per_gas")?,
        block_hash: hex_field::<32>(v, "block_hash")?,
        transactions_root: hex_field::<32>(v, "transactions_root")?,
        withdrawals_root: hex_field::<32>(v, "withdrawals_root")?,
        blob_gas_used: as_u64(v, "blob_gas_used")?,
        excess_blob_gas: as_u64(v, "excess_blob_gas")?,
    })
}

/// An all-zero execution header, for an update that does not move the finalized header (the
/// program reads the argument but uses it only when the finalized header moved).
pub fn empty_exec() -> ExecWire {
    ExecWire {
        parent_hash: [0; 32],
        fee_recipient: [0; 20],
        state_root: [0; 32],
        receipts_root: [0; 32],
        logs_bloom: vec![0; 256],
        prev_randao: [0; 32],
        block_number: 0,
        gas_limit: 0,
        gas_used: 0,
        timestamp: 0,
        extra_data: vec![],
        base_fee_per_gas: [0; 32],
        block_hash: [0; 32],
        transactions_root: [0; 32],
        withdrawals_root: [0; 32],
        blob_gas_used: 0,
        excess_blob_gas: 0,
    }
}

/// One update as the program takes it, with what the submitter needs to choose and order it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub wire: UpdateWire,
    pub finalized_slot: u64,
    pub carries_next: bool,
    pub exec: ExecWire,
    pub exec_branch: Vec<Bytes32>,
}

/// One update object (`attested_header`, `finalized_header`, `sync_aggregate`, ...).
pub fn candidate(obj: &Value) -> Res<Candidate> {
    let attested = beacon_header(field(obj, "attested_header")?)?;
    let fin_obj = field(obj, "finalized_header")?;
    let finalized = beacon_header(fin_obj)?;
    let finality_branch = hex_array::<32>(obj, "finality_branch")?;
    let agg = field(obj, "sync_aggregate")?;
    let (next_pubkeys, next_aggregate, next_branch) = match obj.get("next_sync_committee") {
        Some(sc) => (
            hex_array::<48>(sc, "pubkeys")?.concat(),
            hex_vec(sc, "aggregate_pubkey")?,
            hex_array::<32>(obj, "next_sync_committee_branch")?,
        ),
        None => (vec![], vec![], vec![]),
    };
    let (exec, exec_branch) = match (fin_obj.get("execution"), fin_obj.get("execution_branch")) {
        (Some(e), Some(_)) => (exec_wire(e)?, hex_array::<32>(fin_obj, "execution_branch")?),
        _ => (empty_exec(), vec![]),
    };
    Ok(Candidate {
        carries_next: !next_pubkeys.is_empty(),
        finalized_slot: finalized.slot,
        wire: UpdateWire {
            attested: WireHeader::from(&attested),
            next_pubkeys,
            next_aggregate,
            next_branch,
            finalized: WireHeader::from(&finalized),
            finality_branch,
            bits: hex_vec(agg, "sync_committee_bits")?,
            signature: hex_vec(agg, "sync_committee_signature")?,
            signature_slot: as_u64(obj, "signature_slot")?,
        },
        exec,
        exec_branch,
    })
}

/// The body of `/light_client/updates` (an array of `{version, data}`) or of
/// `/light_client/finality_update` (one `{version, data}`) as candidates.
pub fn candidates(body: &str) -> Res<Vec<Candidate>> {
    let v: Value = serde_json::from_str(body).map_err(|e| format!("bad JSON: {e}"))?;
    match &v {
        Value::Array(items) => items.iter().map(|i| candidate(data(i))).collect(),
        other => Ok(vec![candidate(data(other))?]),
    }
}

/// `bootstrap`: the committee's public keys (`current_sync_committee.pubkeys`), flat.
pub fn bootstrap_keys(body: &str) -> Res<Vec<[u8; 48]>> {
    let v: Value = serde_json::from_str(body).map_err(|e| format!("bad JSON: {e}"))?;
    hex_array::<48>(field(data(&v), "current_sync_committee")?, "pubkeys")
}

/// `bootstrap`: the checkpoint header, the committee's aggregate key and the branch, as
/// `init_instance` takes them.
pub struct BootstrapWire {
    pub header: BeaconBlockHeader,
    pub aggregate: Vec<u8>,
    pub branch: Vec<Bytes32>,
    pub keys: Vec<[u8; 48]>,
}

pub fn bootstrap(body: &str) -> Res<BootstrapWire> {
    let v: Value = serde_json::from_str(body).map_err(|e| format!("bad JSON: {e}"))?;
    let d = data(&v);
    let sc = field(d, "current_sync_committee")?;
    Ok(BootstrapWire {
        header: beacon_header(field(d, "header")?)?,
        aggregate: hex_vec(sc, "aggregate_pubkey")?,
        branch: hex_array::<32>(d, "current_sync_committee_branch")?,
        keys: hex_array::<48>(sc, "pubkeys")?,
    })
}

/// `eth_getProof` -> (account proof nodes, storage proof nodes of the first slot).
pub fn state_proof(body: &str) -> Res<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let v: Value = serde_json::from_str(body).map_err(|e| format!("bad JSON: {e}"))?;
    let r = v.get("result").unwrap_or(&v);
    let nodes = |a: &Value, what: &str| -> Res<Vec<Vec<u8>>> {
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

/// The newest finalized header's beacon header of a finality update body (for status).
pub fn finalized_slot_of(body: &str) -> Res<u64> {
    let v: Value = serde_json::from_str(body).map_err(|e| format!("bad JSON: {e}"))?;
    Ok(beacon_header(field(data(&v), "finalized_header")?)?.slot)
}
