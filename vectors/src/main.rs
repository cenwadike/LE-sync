//! `run-vectors <consensus-spec-tests dir> [minimal|mainnet]`
//! Walks tests/<preset>/{electra,fulu}/light_client/sync/pyspec_tests/*; prints PASS/SKIP/FAIL.
#![cfg_attr(not(feature = "native-blst"), allow(unused_imports))]
use le_sync_core::sync::{Bls, BlsSignature};
use le_sync_core::{BlsPubkey, Bytes32};
use le_sync_vectors::*;
use serde_yaml::Value;
use std::{fs, path::Path, process::ExitCode};

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

// Which BLS the vectors run against. Default: native `blst` (as before). With
// `--features bls-zk` or `--features bls-blst-guest` the GUEST impl from `wire/src/bls.rs`
// is used instead, to prove it against the spec vectors before comparing its cost.
#[cfg(any(feature = "bls-zk", feature = "bls-blst-guest"))]
fn verifier() -> impl Bls {
    le_sync_wire::bls::Impl
}
#[cfg(not(any(feature = "bls-zk", feature = "bls-blst-guest")))]
fn verifier() -> impl Bls {
    Blst
}

#[cfg(not(any(
    feature = "native-blst",
    feature = "bls-zk",
    feature = "bls-blst-guest"
)))]
compile_error!("enable one of: native-blst (default), bls-zk, bls-blst-guest");

#[cfg(feature = "native-blst")]
#[cfg_attr(any(feature = "bls-zk", feature = "bls-blst-guest"), allow(dead_code))]
struct Blst;
#[cfg(feature = "native-blst")]
impl Bls for Blst {
    fn fast_aggregate_verify(
        &self,
        committee: &[BlsPubkey],
        _aggregate_pubkey: &BlsPubkey,
        bits: &[u8],
        msg: &Bytes32,
        sig: &BlsSignature,
    ) -> bool {
        use blst::min_pk::{PublicKey, Signature};
        let Ok(sig) = Signature::from_bytes(sig) else {
            return false;
        };
        let mut keys = vec![];
        for (i, k) in committee.iter().enumerate() {
            if bits[i / 8] >> (i % 8) & 1 == 1 {
                match PublicKey::key_validate(k) {
                    Ok(p) => keys.push(p),
                    Err(_) => return false,
                }
            }
        }
        if keys.is_empty() {
            return false;
        }
        let refs: Vec<&PublicKey> = keys.iter().collect();
        sig.fast_aggregate_verify(true, msg, DST, &refs) == blst::BLST_ERROR::BLST_SUCCESS
    }
}

fn h32(v: &Value) -> Result<Bytes32, String> {
    let s = v.as_str().ok_or("not a string")?;
    let b = hex_dec(s.trim_start_matches("0x"))?;
    b.try_into().map_err(|_| "not 32 bytes".to_string())
}
fn hex_dec(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
fn ssz(p: &Path) -> Result<Vec<u8>, String> {
    let raw = fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
    // TENTATIVE: files are snappy *raw block* format (not framed). If this errors, try snap::read::FrameDecoder.
    snap::raw::Decoder::new()
        .decompress_vec(&raw)
        .map_err(|e| format!("snappy {}: {e}", p.display()))
}
fn checks(v: &Value) -> Result<Checks, String> {
    let one = |k: &str| -> Result<Option<HeaderCheck>, String> {
        match v.get("checks").and_then(|c| c.get(k)) {
            None => Ok(None),
            Some(h) => Ok(Some(HeaderCheck {
                slot: h.get("slot").and_then(Value::as_u64).ok_or("slot")?,
                beacon_root: h32(h.get("beacon_root").ok_or("beacon_root")?)?,
            })),
        }
    };
    Ok(Checks {
        finalized: one("finalized_header")?,
        optimistic: one("optimistic_header")?,
    })
}

fn load(dir: &Path) -> Result<(Meta, Vec<u8>, Vec<Step>), String> {
    let m: Value = serde_yaml::from_str(
        &fs::read_to_string(dir.join("meta.yaml")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let g = |k: &str| m.get(k).ok_or(format!("meta.{k} missing"));

    // meta.yaml carries only digests, not a fork version. The signing version is set by
    // `main` from `Preset::version_for(fork)`; this is a placeholder until then.
    let meta = Meta {
        genesis_validators_root: h32(g("genesis_validators_root")?)?,
        trusted_block_root: h32(g("trusted_block_root")?)?,
        bootstrap_fork_digest: g("bootstrap_fork_digest")?
            .as_str()
            .ok_or("digest")?
            .to_string(),
        store_fork_version: [0; 4],
    };

    let boot = ssz(&dir.join("bootstrap.ssz_snappy"))?;
    let steps_v: Value = serde_yaml::from_str(
        &fs::read_to_string(dir.join("steps.yaml")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let mut steps = vec![];
    for s in steps_v.as_sequence().ok_or("steps not a list")? {
        if let Some(p) = s.get("process_update") {
            let name = p.get("update").and_then(Value::as_str).ok_or("update")?;
            steps.push(Step::ProcessUpdate {
                update_fork_digest: p
                    .get("update_fork_digest")
                    .and_then(Value::as_str)
                    .ok_or("digest")?
                    .to_string(),
                update_ssz: ssz(&dir.join(format!("{name}.ssz_snappy")))?,
                current_slot: p
                    .get("current_slot")
                    .and_then(Value::as_u64)
                    .ok_or("current_slot")?,
                checks: checks(p)?,
            });
        } else if let Some(p) = s.get("force_update") {
            steps.push(Step::ForceUpdate {
                current_slot: p
                    .get("current_slot")
                    .and_then(Value::as_u64)
                    .ok_or("current_slot")?,
                checks: checks(p)?,
            });
        } else if let Some(p) = s.get("upgrade_store") {
            let checks = checks(p)?;
            steps.push(Step::UpgradeStore { checks });
        } else {
            return Err("step missing process_update/force_update/upgrade_store".into());
        }
    }
    Ok((meta, boot, steps))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: run-vectors <consensus-spec-tests dir> [minimal|mainnet]");
        return ExitCode::from(2);
    }
    let (pname, preset) = if args.get(2).map(String::as_str) == Some("mainnet") {
        ("mainnet", MAINNET)
    } else {
        ("minimal", MINIMAL)
    };
    let (mut pass, mut skip, mut fail) = (0, 0, 0);
    for fork in ["electra", "fulu"] {
        let root = Path::new(&args[1])
            .join("tests")
            .join(pname)
            .join(fork)
            .join("light_client/sync/pyspec_tests");
        let Ok(rd) = fs::read_dir(&root) else {
            println!("-- {fork}: {} not found", root.display());
            continue;
        };
        let mut dirs: Vec<_> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        for d in dirs {
            let name = format!("{fork}/{}", d.file_name().unwrap().to_string_lossy());
            let out = match load(&d) {
                Ok((mut meta, boot, steps)) => {
                    // Signing domain version for this fork (Electra vs Fulu differ).
                    meta.store_fork_version = preset.version_for(fork);
                    run_case(
                        &preset,
                        &meta,
                        fork == "electra",
                        &boot,
                        &steps,
                        &verifier(),
                    )
                }
                Err(e) => Outcome::Skip(format!("load: {e}")),
            };
            match &out {
                Outcome::Pass => {
                    pass += 1;
                    println!("PASS {name}")
                }
                Outcome::Skip(r) => {
                    skip += 1;
                    println!("SKIP {name}: {r}")
                }
                Outcome::Fail(r) => {
                    fail += 1;
                    println!("FAIL {name}: {r}")
                }
            }
        }
    }
    println!("pass {pass}  skip {skip}  fail {fail}");
    if fail > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
