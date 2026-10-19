use le_sync::{run, Opts};
use std::{env, path::PathBuf, process::ExitCode};

const USAGE: &str = "\
le-sync: fetch light-client bootstrap/updates from a beacon API and verify SSZ Merkle branches

USAGE:
  le-sync --source <URL|DIR> --trusted-root <0x..> [--count N] [--save-dir DIR] [--tamper]

  --source        beacon API base URL (e.g. https://<host>) or a directory of saved JSON
                  (config_spec.json, bootstrap.json, updates.json, finality_update.json)
  --trusted-root  weak-subjectivity checkpoint: block root of the first block of a recently
                  finalized epoch (verify it against 2+ independent sources)
  --count         sync-committee periods to request from /light_client/updates (default 1)
  --save-dir      write each fetched response here (reproducible offline re-runs)
  --tamper        flip one bit in each branch; every check must then FAIL (exit 0 if so)
";

fn parse() -> Result<Opts, String> {
    let mut a = env::args().skip(1);
    let (mut source, mut root, mut count, mut save, mut tamper) = (None, None, 1u64, None, false);
    while let Some(k) = a.next() {
        let mut val = |name: &str| a.next().ok_or_else(|| format!("{name} needs a value"));
        match k.as_str() {
            "--source" => source = Some(val("--source")?),
            "--trusted-root" => root = Some(val("--trusted-root")?),
            "--count" => count = val("--count")?.parse().map_err(|e| format!("--count: {e}"))?,
            "--save-dir" => save = Some(PathBuf::from(val("--save-dir")?)),
            "--tamper" => tamper = true,
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
    })
}

fn main() -> ExitCode {
    let opts = match parse() {
        Ok(o) => o,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {e}\n");
            }
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&opts) {
        Ok(rep) if rep.success(opts.tamper) => {
            println!("OK ({rep:?})");
            ExitCode::SUCCESS
        }
        Ok(rep) => {
            eprintln!("NOT OK ({rep:?})");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
