//! The module's methods, as the Logos wrapper calls them. Every method returns JSON text:
//! `{"ok":true,...}` or `{"ok":false,"error":"..."}` (the error carries the program's
//! `le-sync error <code>` when there is one).
use crate::config::Config;
use crate::lez::{parse_program_id, WalletLez};
use crate::source::HttpSource;
use crate::submitter::{Opts, Report, Submitter};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

type Res<T> = Result<T, String>;

pub type Events = Arc<dyn Fn(&str, &str) + Send + Sync>;

pub struct Engine {
    cfg: Config,
    state_dir: PathBuf,
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
    last: Arc<Mutex<Value>>,
}

fn report_json(r: &Report) -> Value {
    json!({
        "ok": true,
        "up_to_date_at": r.up_to_date_at,
        "waiting_for_signature_slot": r.waiting_for_signature_slot,
        "applied": r.applied.iter().map(|a| json!({
            "finalized_slot": a.finalized_slot,
            "txs": a.txs.iter().map(|(n, h)| json!({"instruction": n, "tx": h})).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "skipped": r.skipped,
        "stopped_after": r.stopped,
    })
}

fn fail(e: String) -> String {
    json!({"ok": false, "error": e}).to_string()
}

/// Build the source and the chain client the way every method needs them, and run `f`.
pub fn with_submitter<T>(
    cfg: &Config,
    state_dir: &std::path::Path,
    f: impl FnOnce(&mut Submitter) -> Res<T>,
) -> Res<T> {
    let source = HttpSource {
        beacon: cfg.beacon_url()?,
        execution: cfg.execution_url()?,
    };
    let program = parse_program_id(cfg.need("lez", "program_id")?)?;
    let lez = WalletLez::from_env(program)?;
    let mut s = Submitter::new(cfg, &source, &lez, state_dir.to_path_buf())?;
    f(&mut s)
}

impl Engine {
    pub fn open(config_path: &str, state_dir: PathBuf) -> Res<Engine> {
        Ok(Engine {
            cfg: Config::load(std::path::Path::new(config_path))?,
            state_dir,
            stop: Arc::new(AtomicBool::new(true)),
            worker: Mutex::new(None),
            last: Arc::new(Mutex::new(json!({"state": "idle"}))),
        })
    }

    fn defer_max_ms(&self) -> u64 {
        self.cfg
            .num_or("submitter", "defer_ms_max", 6_000)
            .unwrap_or(6_000)
    }

    pub fn submit_update(&self) -> String {
        match with_submitter(&self.cfg, &self.state_dir, |s| {
            s.run_once(self.defer_max_ms(), &Opts::default())
        }) {
            Ok(r) => report_json(&r).to_string(),
            Err(e) => fail(e),
        }
    }

    pub fn read_instance(&self) -> String {
        match with_submitter(&self.cfg, &self.state_dir, |s| s.read_instance()) {
            Ok(i) => json!({
                "ok": true,
                "instance_id": format!("0x{}", hex::encode(i.instance_id)),
                "config_matches_chain": i.config_matches_chain,
                "finalized_slot": i.finalized_slot,
                "optimistic_slot": i.optimistic_slot,
                "next_committee_known": i.next_committee_known,
                "newest_record_slot": i.newest_record_slot,
                "clock_slot": i.clock_slot,
                "behind_by_slots": i.clock_slot.saturating_sub(i.finalized_slot),
            })
            .to_string(),
            Err(e) => fail(e),
        }
    }

    /// `slot` empty: attest the account; otherwise the storage slot.
    pub fn attest_state(&self, address: &str, slot: &str) -> String {
        let slot = (!slot.is_empty()).then_some(slot);
        match with_submitter(&self.cfg, &self.state_dir, |s| {
            s.attest_state(address, slot, false, false, None)
        }) {
            Ok(id) => {
                json!({"ok": true, "statement_id": format!("0x{}", hex::encode(id))}).to_string()
            }
            Err(e) => fail(e),
        }
    }

    /// Attest the first successful log matching the address and topic0 in the latest finalized
    /// execution block.
    pub fn attest_log(&self, address: &str, topic0: &str) -> String {
        match with_submitter(&self.cfg, &self.state_dir, |s| {
            s.attest_log(address, topic0, None)
        }) {
            Ok(id) => {
                json!({"ok": true, "statement_id": format!("0x{}", hex::encode(id))}).to_string()
            }
            Err(e) => fail(e),
        }
    }

    /// Start the background submitter: every `[submitter] poll_seconds` (12), bring the
    /// instance up to date; on failure back off up to a minute and keep going.
    pub fn start(&self, events: Events) -> String {
        let mut w = self.worker.lock().unwrap();
        if w.is_some() && !self.stop.load(Ordering::SeqCst) {
            return fail("already running".into());
        }
        self.stop.store(false, Ordering::SeqCst);
        let (cfg, dir, stop, last) = (
            self.cfg.clone(),
            self.state_dir.clone(),
            self.stop.clone(),
            self.last.clone(),
        );
        let defer = self.defer_max_ms();
        let poll = cfg
            .num_or("submitter", "poll_seconds", 12)
            .unwrap_or(12)
            .max(1);
        *w = Some(std::thread::spawn(move || {
            let mut backoff = 0u64;
            while !stop.load(Ordering::SeqCst) {
                let started = Instant::now();
                match with_submitter(&cfg, &dir, |s| s.run_once(defer, &Opts::default())) {
                    Ok(r) => {
                        backoff = 0;
                        for a in &r.applied {
                            events("update_submitted", &a.finalized_slot.to_string());
                        }
                        *last.lock().unwrap() = report_json(&r);
                    }
                    Err(e) => {
                        backoff = (backoff * 2).clamp(poll, 60);
                        events("update_failed", &e);
                        *last.lock().unwrap() =
                            json!({"ok": false, "error": e, "retry_in_seconds": backoff});
                    }
                }
                let pause = Duration::from_secs(poll.max(backoff));
                while started.elapsed() < pause && !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }));
        json!({"ok": true, "running": true}).to_string()
    }

    /// Clean shutdown: lets an update in flight finish its current transaction wait, then joins.
    pub fn stop(&self) -> String {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.worker.lock().unwrap().take() {
            let _ = h.join();
        }
        json!({"ok": true, "running": false}).to_string()
    }

    pub fn status(&self) -> String {
        json!({
            "running": !self.stop.load(Ordering::SeqCst),
            "config": self.cfg.path.display().to_string(),
            "last": *self.last.lock().unwrap(),
        })
        .to_string()
    }
}
