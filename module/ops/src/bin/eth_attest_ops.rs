//! `eth_attest_ops --config config/<env>.toml <command> [flags]`
//!
//!   init                             init_instance from the configured trusted root; prints the instance ID
//!   update                           one pass of the submitter (fetch, defer, wait for signature slot, then begin/miller/finish)
//!   slot                             the finalized slot the store holds
//!   show                             the instance as the chain holds it
//!   attest-account  --address A      attest an account under the newest header record
//!   attest-storage  --address A --slot S
//!   attest-log   --address A --topic0 T
//!
//! Test flags: `update --tamper signature` (native preflight only), `update --replay-last`, `update --only miller`,
//! `update --kill-after begin`, `update --resume` (the same as `update`: progress is read from
//! the chain), `attest-* --tamper proof|header-root` (`state-root` is a legacy alias),
//! `attest-* --instance-id 0x..`.
use eth_attest_ops::config::{hex32, Config};
use eth_attest_ops::engine::with_submitter;
use eth_attest_ops::lez::Ids;
use eth_attest_ops::submitter::Opts;
use std::path::PathBuf;
use std::process::ExitCode;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn run(args: Vec<String>) -> Result<(), String> {
    let path =
        flag(&args, "--config").ok_or("usage: eth_attest_ops --config <file> <command> [flags]")?;
    let cfg = Config::load(std::path::Path::new(&path))?;
    let state = flag(&args, "--state-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(".eth-attest-state").join(cfg.or("env", "name", "default"))
        });
    // the command is the first argument that is not a flag or a flag's value
    let cmd = {
        let mut skip = false;
        let mut found = None;
        for a in &args {
            if skip {
                skip = false;
                continue;
            }
            if a.starts_with("--") {
                skip = matches!(
                    a.as_str(),
                    "--config"
                        | "--state-dir"
                        | "--tamper"
                        | "--only"
                        | "--kill-after"
                        | "--address"
                        | "--slot"
                        | "--instance-id"
                        | "--topic0"
                );
                continue;
            }
            found = Some(a.clone());
            break;
        }
        found.ok_or("no command given")?
    };
    let tamper = flag(&args, "--tamper");
    let instance_override = flag(&args, "--instance-id")
        .map(|s| hex32(&s))
        .transpose()?;

    with_submitter(&cfg, &state, |s| {
        let is_attestation = matches!(
            cmd.as_str(),
            "attest-account" | "attest-storage" | "attest-log"
        );
        if let Some(id) = instance_override.filter(|_| !is_attestation) {
            s.ids = Ids::new(s.ids.program, id);
        }
        match cmd.as_str() {
            "init" => {
                println!("0x{}", hex::encode(s.init()?));
            }
            "slot" => println!("{}", s.finalized_slot()?),
            "show" => println!("{:#?}", s.read_instance()?),
            "update" => {
                let report = if has(&args, "--replay-last") {
                    s.replay_last()?
                } else {
                    let o = Opts {
                        tamper_signature: tamper.as_deref() == Some("signature"),
                        only_miller: flag(&args, "--only").as_deref() == Some("miller"),
                        stop_after_begin: flag(&args, "--kill-after").as_deref() == Some("begin"),
                        force: tamper.is_some() && tamper.as_deref() != Some("signature"),
                    };
                    s.run_once(cfg.num_or("submitter", "defer_ms_max", 0)?, &o)?
                };
                println!("{report:#?}");
                if tamper.as_deref() == Some("signature")
                    && report.applied.is_empty()
                    && report.skipped.is_empty()
                {
                    return Err(match report.waiting_for_signature_slot {
                        Some(slot) => format!(
                            "no ready update to test signature rejection; waiting for signature slot {slot}"
                        ),
                        None => "no fresh update available to test signature rejection".into(),
                    });
                }
                // a refused update is an error for the caller, with the program's code
                if let Some(why) = report.skipped.first() {
                    return Err(why.clone());
                }
            }
            "attest-account" | "attest-storage" => {
                let address = flag(&args, "--address").ok_or("--address is required")?;
                let slot = if cmd == "attest-storage" {
                    Some(flag(&args, "--slot").ok_or("--slot is required")?)
                } else {
                    None
                };
                let id = s.attest_state(
                    &address,
                    slot.as_deref(),
                    tamper.as_deref() == Some("proof"),
                    matches!(tamper.as_deref(), Some("header-root" | "state-root")),
                    instance_override,
                )?;
                println!("statement 0x{}", hex::encode(id));
            }
            "attest-log" => {
                let address = flag(&args, "--address").ok_or("--address is required")?;
                let topic0 = flag(&args, "--topic0").ok_or("--topic0 is required")?;
                let id = s.attest_log(&address, &topic0, instance_override)?;
                println!("statement 0x{}", hex::encode(id));
            }
            other => return Err(format!("unknown command `{other}`")),
        }
        Ok(())
    })
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
