//! The `eth_attest_module` provider on the builder-driven cdylib path (no build.rs): the C ABI
//! scaffold, the `EthAttestModule` trait and the typed event emitters are generated from
//! `eth_attest_module.lidl`; this file is the implementation, and it holds no logic of its own:
//! every method calls `eth_attest_ops::engine::Engine`.
//!
//! Untested against the Logos builder as yet: written from `logos-rust-sdk`'s own doctest
//! (`cross-language-composition`). If the generated trait differs (argument types, event
//! emitter names), the compiler will say so here and nowhere else.
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/generated/provider_gen.rs"
));

use eth_attest_ops::engine::Engine;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Default)]
struct Impl {
    engine: Option<Arc<Engine>>,
}

fn err(msg: &str) -> String {
    serde_json::json!({"ok": false, "error": msg}).to_string()
}

impl Impl {
    fn engine(&self) -> Result<&Arc<Engine>, String> {
        self.engine
            .as_ref()
            .ok_or_else(|| err("not configured: call configure(config_path) first"))
    }
}

impl EthAttestModule for Impl {
    /// Load the environment file. The submitter's state (committee-key cache) lives in the
    /// module instance's own persistence directory.
    fn configure(&mut self, config_path: String) -> String {
        let dir = context()
            .map(|c| PathBuf::from(c.instance_persistence_path))
            .unwrap_or_else(|| PathBuf::from(".eth-attest-state"));
        match Engine::open(&config_path, dir) {
            Ok(e) => {
                self.engine = Some(Arc::new(e));
                serde_json::json!({"ok": true}).to_string()
            }
            Err(e) => err(&e),
        }
    }

    fn start(&mut self) -> String {
        match self.engine() {
            Ok(e) => e.start(Arc::new(|name, arg| match name {
                "update_submitted" => emit_update_submitted(arg.to_string()),
                _ => emit_update_failed(arg.to_string()),
            })),
            Err(m) => m,
        }
    }

    fn stop(&mut self) -> String {
        match self.engine() {
            Ok(e) => e.stop(),
            Err(m) => m,
        }
    }

    fn status(&mut self) -> String {
        match self.engine() {
            Ok(e) => e.status(),
            Err(m) => m,
        }
    }

    fn read_instance(&mut self) -> String {
        match self.engine() {
            Ok(e) => e.read_instance(),
            Err(m) => m,
        }
    }

    fn submit_update(&mut self) -> String {
        match self.engine() {
            Ok(e) => e.submit_update(),
            Err(m) => m,
        }
    }

    fn attest_state(&mut self, address: String, slot: String) -> String {
        match self.engine() {
            Ok(e) => e.attest_state(&address, &slot),
            Err(m) => m,
        }
    }

    fn attest_log(&mut self, address: String, topic0: String) -> String {
        match self.engine() {
            Ok(e) => e.attest_log(&address, &topic0),
            Err(m) => m,
        }
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<Impl>();
}
