//! Pure parts of the bench: argument parsing, the guest's cycle line, the table. No risc0, no
//! crypto, so it is unit-tested without the guest.

pub const SCENARIOS: [&str; 3] = ["full", "min", "handoff"];
pub const INPUTS: [&str; 2] = ["plain", "lez"];

pub const USAGE: &str = "\
le-sync-bench: execute-only cycles of the three staged update steps (Begin, Miller, Finish)

usage: cargo run --manifest-path bench/Cargo.toml --release -- [flags]

  --committee N   committee size: a power of two from 8 to 512 (default 512, mainnet)
  --scenario S    full     finality-only update, every member signs
                  min      finality-only update, fewest signers the 2/3 gate accepts (default)
                  handoff  update that carries the next committee, fewest signers the gate accepts
  --input F       plain  the guest reads the store and update directly, commits only the result (default)
                  lez    the guest reads and commits as a real LEZ program does: accounts, instruction
                         words, and the whole output echoed (`ProgramOutput`); see guest-stage/src/lez_io.rs
  --cap N         per-transaction cycle cap to compare against (LEZ v0.1.2 public execution: 33554432)
  --keys N        instead of the steps, measure decoding N committee keys (compressed vs hinted)
  --detail        also print each step's guest log (the bls-blst phase breakdown)
  -h, --help      this text
";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opts {
    pub committee: usize,
    pub scenario: String,
    pub input: String,
    pub keys: Option<usize>,
    pub cap: Option<u64>,
    pub detail: bool,
    pub help: bool,
}

fn number(flag: &str, v: Option<String>) -> Result<u64, String> {
    let v = v.ok_or_else(|| format!("{flag} needs a value"))?;
    v.replace('_', "")
        .parse::<u64>()
        .map_err(|_| format!("{flag}: not a number: {v}"))
}

pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Opts, String> {
    let mut o = Opts {
        committee: 512,
        scenario: "min".to_string(),
        input: "plain".to_string(),
        keys: None,
        cap: None,
        detail: false,
        help: false,
    };
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => o.help = true,
            "--detail" => o.detail = true,
            "--committee" => o.committee = number("--committee", it.next())? as usize,
            "--cap" => o.cap = Some(number("--cap", it.next())?),
            "--keys" => o.keys = Some(number("--keys", it.next())? as usize),
            "--input" => {
                o.input = it.next().ok_or("--input needs a value")?;
            }
            "--scenario" => {
                o.scenario = it.next().ok_or("--scenario needs a value")?;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if o.help {
        return Ok(o);
    }
    if !SCENARIOS.contains(&o.scenario.as_str()) {
        return Err(format!(
            "--scenario: {} is not one of {}",
            o.scenario,
            SCENARIOS.join(", ")
        ));
    }
    if !INPUTS.contains(&o.input.as_str()) {
        return Err(format!(
            "--input: {} is not one of {}",
            o.input,
            INPUTS.join(", ")
        ));
    }
    if o.keys.is_some_and(|k| !(1..=512).contains(&k)) {
        return Err("--keys: not a number from 1 to 512".to_string());
    }
    if !(8..=512).contains(&o.committee) || !o.committee.is_power_of_two() {
        return Err(format!(
            "--committee: {} is not a power of two from 8 to 512",
            o.committee
        ));
    }
    Ok(o)
}

/// Fewest signers of `n` members that satisfy the 2/3 gate (`signers * 3 >= n * 2`).
pub fn min_participants(n: usize) -> usize {
    (2 * n + 2) / 3
}

/// What the guest logs once per run: `guest-stage cycles: mode=<m> read=<n> step=<n> commit=<n>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestLine {
    pub mode: String,
    pub read: u64,
    pub step: u64,
    pub commit: u64,
}

/// The last `guest-stage cycles:` line in the guest's captured stdout.
pub fn parse_guest_line(stdout: &str) -> Option<GuestLine> {
    let line = stdout
        .lines()
        .rev()
        .find_map(|l| l.split_once("guest-stage cycles:").map(|(_, rest)| rest))?;
    let field = |key: &str| {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(key))
            .map(str::to_string)
    };
    Some(GuestLine {
        mode: field("mode=")?,
        read: field("read=")?.parse().ok()?,
        step: field("step=")?.parse().ok()?,
        commit: field("commit=")?.parse().ok()?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub step: &'static str,
    /// Payload bytes handed to the step (store, job, update), not the serialized size.
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub guest: GuestLine,
    /// The executor's own total for the run (`SessionInfo::cycles`).
    pub executor: u64,
}

impl Row {
    pub fn guest_sum(&self) -> u64 {
        self.guest.read + self.guest.step + self.guest.commit
    }
}

/// `n.nnn` with thousands separators: 12345678 -> "12,345,678".
pub fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Executor cycles against the cap. No cap given: say so rather than invent one.
pub fn headroom(cycles: u64, cap: Option<u64>) -> String {
    match cap {
        None => "cap not set".to_string(),
        Some(c) if cycles > c => format!("OVER by {}", group(cycles - c)),
        Some(c) => {
            let tenths = (cycles as u128 * 1000 / c.max(1) as u128) as u64;
            format!(
                "{}.{}% of cap, {} left",
                tenths / 10,
                tenths % 10,
                group(c - cycles)
            )
        }
    }
}

pub fn over_cap(rows: &[Row], cap: Option<u64>) -> bool {
    cap.is_some_and(|c| rows.iter().any(|r| r.executor > c))
}

pub fn table(rows: &[Row], cap: Option<u64>) -> String {
    let mut s = format!(
        "{:<7} {:>9} {:>9} {:>13} {:>13} {:>11} {:>13} {:>13}  {}\n",
        "step", "in (B)", "out (B)", "read", "step", "commit", "guest sum", "executor", "headroom"
    );
    for r in rows {
        s.push_str(&format!(
            "{:<7} {:>9} {:>9} {:>13} {:>13} {:>11} {:>13} {:>13}  {}\n",
            r.step,
            group(r.input_bytes as u64),
            group(r.output_bytes as u64),
            group(r.guest.read),
            group(r.guest.step),
            group(r.guest.commit),
            group(r.guest_sum()),
            group(r.executor),
            headroom(r.executor, cap)
        ));
    }
    s
}

/// The machine line `scripts/env.sh` (`le_cost`) reads. Executor cycles of each step.
pub fn cost_line(scenario: &str, rows: &[Row]) -> Option<String> {
    let get = |name: &str| rows.iter().find(|r| r.step == name).map(|r| r.executor);
    Some(format!(
        "cost: scenario={} begin={} miller={} finish={}",
        scenario,
        get("begin")?,
        get("miller")?,
        get("finish")?
    ))
}

/// What `keys.rs` logs: `keys cycles: n=<n> uncompress=<total> hinted=<total> add=<total>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeysLine {
    pub n: u64,
    pub uncompress: u64,
    pub hinted: u64,
    pub add: u64,
}

pub fn parse_keys_line(stdout: &str) -> Option<KeysLine> {
    let line = stdout
        .lines()
        .rev()
        .find_map(|l| l.split_once("keys cycles:").map(|(_, rest)| rest))?;
    let field = |key: &str| {
        line.split_whitespace()
            .find_map(|w| w.strip_prefix(key))
            .and_then(|v| v.parse::<u64>().ok())
    };
    Some(KeysLine {
        n: field("n=")?,
        uncompress: field("uncompress=")?,
        hinted: field("hinted=")?,
        add: field("add=")?,
    })
}

/// Totals and per-key cycles for the three key operations, and what the hint changes.
pub fn keys_table(k: &KeysLine) -> String {
    let per = |t: u64| t / k.n.max(1);
    let mut s = format!("committee keys: n={}\n", k.n);
    for (name, t) in [
        ("decode compressed", k.uncompress),
        ("decode with y-hint", k.hinted),
        ("mixed addition", k.add),
    ] {
        s.push_str(&format!(
            "  {:<20} {:>13} cycles  {:>9} per key\n",
            name,
            group(t),
            group(per(t))
        ));
    }
    if k.hinted < k.uncompress {
        let saved = k.uncompress - k.hinted;
        let tenths = (saved as u128 * 1000 / k.uncompress.max(1) as u128) as u64;
        s.push_str(&format!(
            "  the hint saves {} cycles ({}.{}% of the compressed decode)\n",
            group(saved),
            tenths / 10,
            tenths % 10
        ));
    } else {
        s.push_str("  the hint does not save cycles\n");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Result<Opts, String> {
        parse_args(a.iter().map(|s| s.to_string()))
    }

    fn g(mode: &str, read: u64, step: u64, commit: u64) -> GuestLine {
        GuestLine {
            mode: mode.to_string(),
            read,
            step,
            commit,
        }
    }

    fn row(step: &'static str, executor: u64) -> Row {
        Row {
            step,
            input_bytes: 3_413,
            output_bytes: 641,
            guest: g(step, 1_000, executor - 1_500, 500),
            executor,
        }
    }

    #[test]
    fn defaults_are_mainnet_size_and_the_minimum_participation_case() {
        let o = args(&[]).unwrap();
        assert_eq!(
            o,
            Opts {
                committee: 512,
                scenario: "min".to_string(),
                input: "plain".to_string(),
                keys: None,
                cap: None,
                detail: false,
                help: false
            }
        );
    }

    #[test]
    fn every_flag_is_read() {
        let o = args(&[
            "--committee",
            "32",
            "--scenario",
            "handoff",
            "--cap",
            "10_000_000",
            "--input",
            "lez",
            "--keys",
            "170",
            "--detail",
        ])
        .unwrap();
        assert_eq!(o.input, "lez");
        assert_eq!(o.keys, Some(170));
        assert_eq!(o.committee, 32);
        assert_eq!(o.scenario, "handoff");
        assert_eq!(o.cap, Some(10_000_000));
        assert!(o.detail);
        assert!(args(&["-h"]).unwrap().help);
        assert!(args(&["--help", "--scenario", "nope"]).unwrap().help);
    }

    #[test]
    fn bad_arguments_are_named() {
        assert_eq!(args(&["--x"]), Err("unknown argument: --x".to_string()));
        assert_eq!(args(&["--cap"]), Err("--cap needs a value".to_string()));
        assert_eq!(
            args(&["--cap", "ten"]),
            Err("--cap: not a number: ten".to_string())
        );
        assert_eq!(
            args(&["--scenario"]),
            Err("--scenario needs a value".to_string())
        );
        assert!(args(&["--scenario", "nope"])
            .unwrap_err()
            .contains("full, min, handoff"));
        assert_eq!(args(&["--input"]), Err("--input needs a value".to_string()));
        assert_eq!(
            args(&["--input", "raw"]),
            Err("--input: raw is not one of plain, lez".to_string())
        );
        assert!(args(&["--keys", "0"]).unwrap_err().contains("1 to 512"));
        assert!(args(&["--keys", "513"]).unwrap_err().contains("1 to 512"));
        assert!(args(&["--keys", "512"]).is_ok());
        for bad in ["0", "4", "7", "24", "1024", "513"] {
            assert!(
                args(&["--committee", bad])
                    .unwrap_err()
                    .contains("power of two from 8 to 512"),
                "{bad}"
            );
        }
        for good in ["8", "16", "32", "64", "128", "256", "512"] {
            assert!(args(&["--committee", good]).is_ok(), "{good}");
        }
    }

    #[test]
    fn the_gate_minimum_is_the_smallest_that_passes() {
        assert_eq!(min_participants(32), 22);
        assert_eq!(min_participants(512), 342);
        assert_eq!(min_participants(8), 6);
        for n in [8usize, 16, 32, 64, 128, 256, 512] {
            let p = min_participants(n);
            assert!(p * 3 >= n * 2, "{n}: {p} must pass");
            assert!((p - 1) * 3 < n * 2, "{n}: {} must fail", p - 1);
        }
    }

    #[test]
    fn guest_line_is_parsed_from_noisy_output() {
        let out = "bls-blst cycles: prepare=5\nguest-stage cycles: mode=miller read=10 step=20 commit=30\n";
        assert_eq!(parse_guest_line(out), Some(g("miller", 10, 20, 30)));
        // the last line wins
        let two = "guest-stage cycles: mode=begin read=1 step=2 commit=3\nguest-stage cycles: mode=finish read=4 step=5 commit=6\n";
        assert_eq!(parse_guest_line(two), Some(g("finish", 4, 5, 6)));
    }

    #[test]
    fn a_missing_or_partial_guest_line_is_none() {
        assert_eq!(parse_guest_line(""), None);
        assert_eq!(parse_guest_line("run_sync cycles: setup=1"), None);
        assert_eq!(
            parse_guest_line("guest-stage cycles: mode=begin read=1 step=2"),
            None
        );
        assert_eq!(
            parse_guest_line("guest-stage cycles: mode=begin read=x step=2 commit=3"),
            None
        );
        assert_eq!(
            parse_guest_line("guest-stage cycles: read=1 step=2 commit=3"),
            None
        );
    }

    #[test]
    fn numbers_are_grouped() {
        assert_eq!(group(0), "0");
        assert_eq!(group(999), "999");
        assert_eq!(group(1_000), "1,000");
        assert_eq!(group(12_345_678), "12,345,678");
        assert_eq!(group(100_000), "100,000");
    }

    #[test]
    fn headroom_states_what_it_compares() {
        assert_eq!(headroom(5, None), "cap not set");
        assert_eq!(
            headroom(5_000_000, Some(10_000_000)),
            "50.0% of cap, 5,000,000 left"
        );
        assert_eq!(
            headroom(10_000_000, Some(10_000_000)),
            "100.0% of cap, 0 left"
        );
        assert_eq!(headroom(10_000_001, Some(10_000_000)), "OVER by 1");
        assert_eq!(headroom(1, Some(3)), "33.3% of cap, 2 left");
    }

    #[test]
    fn over_cap_looks_at_every_step() {
        let rows = [
            row("begin", 3_000),
            row("miller", 9_000),
            row("finish", 4_000),
        ];
        assert!(!over_cap(&rows, None));
        assert!(!over_cap(&rows, Some(9_000)));
        assert!(over_cap(&rows, Some(8_999)));
    }

    #[test]
    fn table_has_one_line_per_step_and_the_numbers() {
        let rows = [
            row("begin", 3_000),
            row("miller", 9_000),
            row("finish", 4_000),
        ];
        let t = table(&rows, Some(10_000));
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("step"));
        assert!(lines[1].starts_with("begin"));
        assert!(lines[1].contains("3,413"));
        assert!(lines[1].contains("30.0% of cap, 7,000 left"));
        assert!(lines[2].starts_with("miller") && lines[2].contains("9,000"));
        assert!(lines[3].starts_with("finish"));
        assert!(table(&rows, None).contains("cap not set"));
        // the guest sum is read + step + commit
        assert_eq!(rows[0].guest_sum(), 1_000 + 1_500 + 500);
        assert!(lines[1].contains("3,000"));
    }

    #[test]
    fn cost_line_is_the_contract_with_env_sh() {
        let rows = [
            row("begin", 3_000),
            row("miller", 9_000),
            row("finish", 4_000),
        ];
        assert_eq!(
            cost_line("min", &rows),
            Some("cost: scenario=min begin=3000 miller=9000 finish=4000".to_string())
        );
        assert_eq!(cost_line("min", &rows[..2]), None);
    }

    #[test]
    fn keys_line_and_table() {
        let out = "noise\nkeys cycles: n=170 uncompress=17000000 hinted=3400000 add=850000\n";
        let k = parse_keys_line(out).unwrap();
        assert_eq!(
            k,
            KeysLine {
                n: 170,
                uncompress: 17_000_000,
                hinted: 3_400_000,
                add: 850_000
            }
        );
        let t = keys_table(&k);
        assert!(t.starts_with("committee keys: n=170\n"));
        assert!(t.contains("100,000 per key"));
        assert!(t.contains("20,000 per key"));
        assert!(t.contains("5,000 per key"));
        assert!(t.contains("saves 13,600,000 cycles (80.0%"));
        let worse = KeysLine {
            hinted: 17_000_000,
            ..k.clone()
        };
        assert!(keys_table(&worse).contains("does not save"));
        assert_eq!(parse_keys_line(""), None);
        assert_eq!(
            parse_keys_line("keys cycles: n=1 uncompress=2 hinted=3"),
            None
        );
        assert_eq!(
            parse_keys_line("keys cycles: n=x uncompress=2 hinted=3 add=4"),
            None
        );
    }
}
