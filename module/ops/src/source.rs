//! Where Ethereum material comes from. The program verifies everything it is given, so a source
//! is untrusted: a lying source can make an update fail, never make a wrong one succeed.
//!
//! `EthSource` is the one interface the module needs. `HttpSource` serves it from a beacon API
//! and an execution JSON-RPC endpoint (the real ones, or `scripts/replay_server.sh`, which speaks
//! the same paths). A Logos implementation, serving the same five calls through the Ethereum
//! RPC module, plugs in here without touching the rest.
pub type Res<T> = Result<T, String>;

pub trait EthSource {
    /// `GET /eth/v1/beacon/light_client/bootstrap/{root}`
    fn bootstrap(&self, block_root: &str) -> Res<String>;
    /// `GET /eth/v1/beacon/light_client/updates?start_period=&count=`
    fn updates(&self, start_period: u64, count: u64) -> Res<String>;
    /// `GET /eth/v1/beacon/light_client/finality_update`
    fn finality_update(&self) -> Res<String>;
    /// `eth_getProof(address, slots, block)`
    fn proof(&self, address: &str, slots: &[String], block: u64) -> Res<String>;
    /// `eth_getBlockReceipts(block)`
    fn block_receipts(&self, block: u64) -> Res<String>;
}

pub struct HttpSource {
    pub beacon: String,
    pub execution: String,
}

fn get(url: &str) -> Res<String> {
    ureq::get(url)
        .set("Accept", "application/json")
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?
        .into_string()
        .map_err(|e| format!("read {url}: {e}"))
}

fn rpc(url: &str, method: &str, params: &str) -> Res<String> {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let text = ureq::post(url)
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| format!("POST {url} {method}: {e}"))?
        .into_string()
        .map_err(|e| format!("read {url}: {e}"))?;
    if text.contains("\"error\"") {
        return Err(format!("{method} failed: {text}"));
    }
    Ok(text)
}

impl EthSource for HttpSource {
    fn bootstrap(&self, block_root: &str) -> Res<String> {
        get(&format!(
            "{}/eth/v1/beacon/light_client/bootstrap/{block_root}",
            self.beacon
        ))
    }
    fn updates(&self, start_period: u64, count: u64) -> Res<String> {
        get(&format!(
            "{}/eth/v1/beacon/light_client/updates?start_period={start_period}&count={count}",
            self.beacon
        ))
    }
    fn finality_update(&self) -> Res<String> {
        get(&format!(
            "{}/eth/v1/beacon/light_client/finality_update",
            self.beacon
        ))
    }
    fn proof(&self, address: &str, slots: &[String], block: u64) -> Res<String> {
        let slots = slots
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",");
        rpc(
            &self.execution,
            "eth_getProof",
            &format!("[\"{address}\",[{slots}],\"0x{block:x}\"]"),
        )
    }
    fn block_receipts(&self, block: u64) -> Res<String> {
        rpc(
            &self.execution,
            "eth_getBlockReceipts",
            &format!("[\"0x{block:x}\"]"),
        )
    }
}

/// Run `f` up to `tries` times, pausing between failures: a temporary outage leaves nothing half
/// done, because nothing is written before the material is complete.
pub fn retry<T>(tries: u32, pause_ms: u64, mut f: impl FnMut() -> Res<T>) -> Res<T> {
    let mut last = String::new();
    for i in 0..tries.max(1) {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                last = e;
                if i + 1 < tries {
                    std::thread::sleep(std::time::Duration::from_millis(pause_ms));
                }
            }
        }
    }
    Err(last)
}
