//! Gas per instruction: the executor cycles of each of the six instructions, measured by running
//! them through the state machine on a chain that also runs each transaction in the RISC Zero
//! executor (`Chain::measure`). The cap is LEZ v0.1.2's public execution limit.
//!
//! Scenarios of the update (as in the M1 bench): `full` (every member signs), `min` (the fewest
//! the 2/3 gate accepts: the most absent keys), `handoff` (also carries the next committee, at
//! minimum participation: the largest update, and the one that merkleizes a committee).
use crate::harness::{Chain, Ids, CYCLE_CAP};
use crate::world::{clock_ms, min_participants, Spec, World, ADDR, LOG_TX, SLOT_A};
use execute_attestation_deployment_methods::ETH_ATTEST_ELF;

pub struct Row {
    pub name: String,
    pub scenario: &'static str,
    pub cycles: Option<u64>,
}

fn row(rows: &mut Vec<Row>, name: &str, scenario: &'static str, cycles: Option<u64>) {
    rows.push(Row {
        name: name.to_string(),
        scenario,
        cycles,
    });
}

/// Measure every instruction at committee size `n`.
pub fn table(n: usize) -> Vec<Row> {
    let w = World::new(n, 1);
    let cfg = w.config(1);
    let mut chain = Chain::new(ETH_ATTEST_ELF, clock_ms(41), true);
    let ids = Ids::new(&chain.program_id(), cfg.id());
    let mut rows = vec![];

    let init = chain.init(&ids, &cfg, &w.bootstrap());
    init.expect_ok("init_instance");
    row(&mut rows, "init_instance", "-", init.cycles);
    let fresh = chain.clone();

    let mut synced = None;
    for (scenario, present, carry_next) in [
        ("full", n, false),
        ("min", min_participants(n), false),
        ("handoff", min_participants(n), true),
    ] {
        let mut c = fresh.clone();
        let u = w.update(&Spec {
            present,
            carry_next,
            ..Spec::new(n)
        });
        let job = c.job_for(&ids, &cfg, &u);
        let begin = c.begin(&ids, &job, &u);
        begin.expect_ok("begin_update");
        row(&mut rows, "begin_update", scenario, begin.cycles);
        let miller = c.miller(&job);
        miller.expect_ok("miller_update");
        row(&mut rows, "miller_update", scenario, miller.cycles);
        let finish = c.finish(&ids, &job, &u);
        finish.expect_ok("finish_update");
        row(&mut rows, "finish_update", scenario, finish.cycles);
        if scenario == "full" {
            synced = Some((c, u));
        }
    }

    let (mut c, u) = synced.expect("the full scenario ran");
    let account = w.exec.account(ADDR);
    let storage = w.exec.storage(SLOT_A);
    let log = w.exec.log(LOG_TX, 0);
    for (name, scenario, is_log, claim) in [
        ("attest_state", "account", false, &account),
        ("attest_state", "storage", false, &storage),
        ("attest_log", "log", true, &log),
    ] {
        let id = crate::harness::statement_id_of(&cfg, &u.record, claim);
        let out = c.attest(&ids, is_log, u.finalized_root, id, claim);
        out.expect_ok(name);
        row(&mut rows, name, scenario, out.cycles);
    }
    rows
}

pub fn format(rows: &[Row], n: usize) -> String {
    let mut s = format!(
        "eth_attest, committee of {n}; executor cycles per transaction (cap {CYCLE_CAP})\n\n"
    );
    s.push_str("| instruction | scenario | cycles | of the cap |\n|---|---|---:|---:|\n");
    for r in rows {
        let (c, p) = match r.cycles {
            Some(c) => (
                group(c),
                format!("{:.1}%", c as f64 * 100.0 / CYCLE_CAP as f64),
            ),
            None => ("not measured".into(), "-".into()),
        };
        s.push_str(&format!("| {} | {} | {} | {} |\n", r.name, r.scenario, c, p));
    }
    s.push('\n');
    for r in rows {
        if let Some(c) = r.cycles {
            s.push_str(&format!(
                "cost: instruction={} scenario={} cycles={}\n",
                r.name, r.scenario, c
            ));
        }
    }
    s
}

fn group(n: u64) -> String {
    let d = n.to_string();
    let mut out = String::new();
    for (i, ch) in d.chars().enumerate() {
        if i > 0 && (d.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}
