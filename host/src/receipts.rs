//! Sprint 5 host helpers with no I/O: turn an RPC block's receipts into the receipts trie, pick
//! a log, build the proof the guest checks, and parse the `--predicate` flag.
//!
//! Nothing here is trusted. The guest re-checks the proof against the `receipts_root` of the
//! execution header it proves from the finalized beacon header. The one check the host adds is
//! that the rebuilt trie has the root the (still unverified) header claims: if it does not, the
//! RPC data or this encoder is wrong, and the run stops before the guest is invoked.
//!
//! The trie builder is the one in `le-sync-testkit`: it shares no code with the verifier, and
//! its output is verified by the guest.

use le_sync_testkit::trie::{index_key, rlp_bytes, rlp_list, Trie};
use le_sync_wire::{PredicateOp, PredicateTarget, PredicateWire};

pub type Bytes32 = [u8; 32];

pub const BLOOM_LEN: usize = 256;

/// One log as the RPC reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogData {
    pub address: [u8; 20],
    pub topics: Vec<Bytes32>,
    pub data: Vec<u8>,
}

/// One receipt as the RPC reports it (`eth_getBlockReceipts`), in block order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptData {
    /// The transaction's hash (used only to find a transaction by `--log-tx 0x..`).
    pub tx_hash: Bytes32,
    /// EIP-2718 type: 0 is legacy (no type byte in the trie value).
    pub tx_type: u8,
    pub success: bool,
    pub cumulative_gas: u64,
    pub bloom: [u8; BLOOM_LEN],
    pub logs: Vec<LogData>,
}

/// Big-endian bytes of `v` with no leading zero; empty for 0 (the RLP integer form).
fn trim_be(v: u64) -> Vec<u8> {
    v.to_be_bytes()
        .iter()
        .copied()
        .skip_while(|b| *b == 0)
        .collect()
}

/// The receipts-trie value: `rlp([status, cumulative_gas, bloom, logs])`, prefixed with the
/// type byte for a typed receipt (EIP-2718). Status is `0x01` for success and the empty string
/// for failure (EIP-658).
pub fn encode_receipt(r: &ReceiptData) -> Vec<u8> {
    let logs: Vec<Vec<u8>> = r
        .logs
        .iter()
        .map(|l| {
            let topics: Vec<Vec<u8>> = l.topics.iter().map(|t| rlp_bytes(t)).collect();
            rlp_list(&[rlp_bytes(&l.address), rlp_list(&topics), rlp_bytes(&l.data)])
        })
        .collect();
    let status: &[u8] = if r.success { &[1] } else { &[] };
    let body = rlp_list(&[
        rlp_bytes(status),
        rlp_bytes(&trim_be(r.cumulative_gas)),
        rlp_bytes(&r.bloom),
        rlp_list(&logs),
    ]);
    if r.tx_type == 0 {
        body
    } else {
        let mut v = vec![r.tx_type];
        v.extend(body);
        v
    }
}

/// The receipts trie of one block.
pub struct ReceiptsTrie {
    trie: Trie,
    count: u64,
}

impl ReceiptsTrie {
    pub fn new(receipts: &[ReceiptData]) -> ReceiptsTrie {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = receipts
            .iter()
            .enumerate()
            .map(|(i, r)| (index_key(i as u64), encode_receipt(r)))
            .collect();
        ReceiptsTrie {
            trie: Trie::new_raw(&entries),
            count: receipts.len() as u64,
        }
    }
    pub fn root(&self) -> Bytes32 {
        self.trie.root
    }
    /// Proof nodes for the receipt at `index`, root first. `None` if the block has no such
    /// transaction.
    pub fn proof(&self, index: u64) -> Option<Vec<Vec<u8>>> {
        (index < self.count).then(|| self.trie.prove_raw(&index_key(index)))
    }
}

/// What to look for: the emitting contract and per-position topics (`None` is a wildcard).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Filter {
    pub address: [u8; 20],
    pub topics: [Option<Bytes32>; 4],
}

impl Filter {
    fn matches(&self, l: &LogData) -> bool {
        l.address == self.address
            && self.topics.iter().enumerate().all(|(i, want)| match want {
                None => true,
                Some(t) => l.topics.get(i) == Some(t),
            })
    }
}

/// Which transaction of the block `--log-tx` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxSel {
    Index(u64),
    Hash(Bytes32),
}

/// `--log-tx`: a decimal position in the block, or a 32-byte transaction hash (`0x` + 64 hex).
pub fn parse_tx_sel(s: &str) -> Result<TxSel, String> {
    if let Some(h) = s.strip_prefix("0x") {
        if h.len() != 64 {
            return Err(
                "a transaction hash is 0x + 64 hex digits; a position is a decimal number".into(),
            );
        }
        let raw = hex::decode(h).map_err(|e| e.to_string())?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        return Ok(TxSel::Hash(out));
    }
    s.parse::<u64>()
        .map(TxSel::Index)
        .map_err(|_| "a transaction is a decimal position or a 0x transaction hash".to_string())
}

/// Position of the selected transaction in the block.
pub fn resolve_tx(receipts: &[ReceiptData], sel: &TxSel) -> Result<u64, String> {
    match sel {
        TxSel::Index(i) => Ok(*i),
        TxSel::Hash(h) => receipts
            .iter()
            .position(|r| r.tx_hash == *h)
            .map(|i| i as u64)
            .ok_or_else(|| "no transaction with that hash in the block".to_string()),
    }
}

/// A JSON-RPC quantity: `0x` and at least one hex digit.
pub fn quantity(s: &str) -> Result<u64, String> {
    let h = s
        .strip_prefix("0x")
        .ok_or_else(|| format!("`{s}`: a quantity starts with 0x"))?;
    // an empty digit string is an error from `from_str_radix`
    u64::from_str_radix(h, 16).map_err(|e| format!("`{s}`: {e}"))
}

/// `(tx_index, log_index)` of the first successful-transaction log that matches, in block order.
pub fn find_log(receipts: &[ReceiptData], f: &Filter) -> Option<(u64, u32)> {
    for (t, r) in receipts.iter().enumerate() {
        if !r.success {
            continue;
        }
        if let Some(l) = r.logs.iter().position(|l| f.matches(l)) {
            return Some((t as u64, l as u32));
        }
    }
    None
}

/// Check that a log of that position exists and matches, so a chosen `--log-tx` / `--log-index`
/// fails here with a readable message instead of as a guest error.
pub fn check_position(
    receipts: &[ReceiptData],
    tx: u64,
    log: u32,
    f: &Filter,
) -> Result<(), String> {
    let r = receipts.get(tx as usize).ok_or_else(|| {
        format!(
            "the block has {} transactions, no index {tx}",
            receipts.len()
        )
    })?;
    let l = r
        .logs
        .get(log as usize)
        .ok_or_else(|| format!("transaction {tx} has {} logs, no index {log}", r.logs.len()))?;
    if !f.matches(l) {
        return Err(format!(
            "log {log} of transaction {tx} does not match the address and topics asked for"
        ));
    }
    Ok(())
}

/// Left-padded 32-byte word from up to 32 bytes of hex (odd length allowed), `0x` optional.
pub fn word(s: &str) -> Result<Bytes32, String> {
    let t = s.strip_prefix("0x").unwrap_or(s);
    let padded = if t.len() % 2 == 1 {
        format!("0{t}")
    } else {
        t.to_string()
    };
    let raw = hex::decode(padded).map_err(|e| e.to_string())?;
    if raw.len() > 32 {
        return Err("must be at most 32 bytes".into());
    }
    let mut out = [0u8; 32];
    out[32 - raw.len()..].copy_from_slice(&raw);
    Ok(out)
}

/// `--predicate`: `<target><op><operand>`.
///
/// * target: `balance`, `storage`, `topic<N>` or `data<N>` (the N-th 32-byte word of the log data)
/// * op: `==` or `!=`
/// * operand: hex, at most 32 bytes, left-padded
///
/// Examples: `balance==0x0de0b6b3a7640000`, `topic2!=0x00..01`, `data0==0x2710`.
pub fn parse_predicate(s: &str) -> Result<PredicateWire, String> {
    let (at, op) = match (s.find("=="), s.find("!=")) {
        (Some(e), None) => (e, PredicateOp::Eq),
        (None, Some(n)) => (n, PredicateOp::Ne),
        (None, None) => return Err("expected `==` or `!=`".into()),
        (Some(_), Some(_)) => return Err("expected exactly one of `==` and `!=`".into()),
    };
    let (target, operand) = (&s[..at], &s[at + 2..]);
    if operand.strip_prefix("0x").unwrap_or(operand).is_empty() {
        return Err("the operand is empty".into());
    }
    let index = |rest: &str| -> Result<u32, String> {
        rest.parse::<u32>()
            .map_err(|_| format!("`{target}`: the position after the name must be a number"))
    };
    let target = match target {
        "balance" => PredicateTarget::Balance,
        "storage" => PredicateTarget::StorageValue,
        t if t.starts_with("topic") => PredicateTarget::Topic(index(&t["topic".len()..])?),
        t if t.starts_with("data") => PredicateTarget::DataWord(index(&t["data".len()..])?),
        other => {
            return Err(format!(
                "unknown target `{other}` (balance, storage, topicN, dataN)"
            ))
        }
    };
    Ok(PredicateWire {
        target,
        op,
        operand: word(operand).map_err(|e| format!("operand: {e}"))?,
    })
}

/// True if the predicate reads the account or the slot (the state section); false if it reads
/// a log.
pub fn is_state_target(t: &PredicateTarget) -> bool {
    matches!(t, PredicateTarget::Balance | PredicateTarget::StorageValue)
}

/// The JSON-RPC body asking for every receipt of block `block`.
pub fn block_receipts_request(block: u64) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_getBlockReceipts","params":["0x{block:x}"]}}"#
    )
}

/// Flip one bit of the first byte of the first proof node: it no longer hashes to what the
/// receipts root commits to.
pub fn flip_first_node(nodes: &mut [Vec<u8>]) {
    if let Some(b) = nodes.first_mut().and_then(|n| n.first_mut()) {
        *b ^= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use le_sync_core::mpt::verify_index_proof;
    use le_sync_core::receipt::{log_at, select_log, LogFilter};

    fn t(n: u8) -> Bytes32 {
        [n; 32]
    }
    fn log(addr: u8, topics: &[u8], data: &[u8]) -> LogData {
        LogData {
            address: [addr; 20],
            topics: topics.iter().map(|n| t(*n)).collect(),
            data: data.to_vec(),
        }
    }
    fn receipt(tx_type: u8, success: bool, logs: Vec<LogData>) -> ReceiptData {
        ReceiptData {
            tx_hash: [0; 32],
            tx_type,
            success,
            cumulative_gas: 0x5208,
            bloom: [0u8; BLOOM_LEN],
            logs,
        }
    }
    /// 300 transactions: every third has a log from contract 0xA1 with topic0 = its index.
    fn block() -> Vec<ReceiptData> {
        (0..300u32)
            .map(|i| {
                let logs = if i % 3 == 0 {
                    vec![log(0xA1, &[(i % 251) as u8, 0x22], &[i as u8; 32])]
                } else {
                    vec![]
                };
                receipt([0, 1, 2][(i % 3) as usize], true, logs)
            })
            .collect()
    }

    #[test]
    fn encoding_round_trips_through_the_core_parser_for_every_type() {
        for ty in [0u8, 1, 2] {
            let r = receipt(
                ty,
                true,
                vec![log(0xA1, &[1, 2, 3], &[9; 40]), log(0xB2, &[], &[])],
            );
            let leaf = encode_receipt(&r);
            assert_eq!(leaf[0] == ty, ty != 0, "type byte only for typed receipts");
            let l = log_at(&leaf, 0).unwrap();
            assert_eq!(l.address, [0xA1; 20]);
            assert_eq!(l.topic_count, 3);
            assert_eq!(l.topics[..3], [t(1), t(2), t(3)]);
            assert_eq!(l.data, &[9u8; 40][..]);
            let l = log_at(&leaf, 1).unwrap();
            assert_eq!((l.address, l.topic_count, l.data.len()), ([0xB2; 20], 0, 0));
        }
    }

    #[test]
    fn status_and_gas_use_the_canonical_forms() {
        use le_sync_core::Error;
        // a failed transaction encodes status as the empty string: the parser says so
        let failed = encode_receipt(&receipt(2, false, vec![log(0xA1, &[1], &[])]));
        assert_eq!(log_at(&failed, 0), Err(Error::LogMismatch));
        // gas is minimal big-endian: zero is empty, 0x5208 is two bytes, u64::MAX is eight
        for gas in [0u64, 1, 0x7f, 0x80, 0x5208, 0x1_0000, u64::MAX] {
            let mut r = receipt(2, true, vec![log(0xA1, &[1], &[])]);
            r.cumulative_gas = gas;
            assert!(log_at(&encode_receipt(&r), 0).is_ok(), "gas {gas:#x}");
        }
        assert_eq!(trim_be(0), Vec::<u8>::new());
        assert_eq!(trim_be(0x5208), vec![0x52, 0x08]);
    }

    #[test]
    fn every_receipt_proves_under_the_rebuilt_root() {
        let rs = block();
        let tr = ReceiptsTrie::new(&rs);
        for i in [0u64, 1, 2, 3, 126, 127, 128, 129, 255, 256, 299] {
            let proof = tr.proof(i).unwrap();
            let leaf = verify_index_proof(&tr.root(), i, &proof)
                .unwrap()
                .expect("receipt present");
            assert_eq!(leaf, &encode_receipt(&rs[i as usize])[..], "tx {i}");
        }
        assert_eq!(tr.proof(300), None);
        assert_eq!(tr.proof(u64::MAX), None);
    }

    #[test]
    fn the_root_changes_with_any_receipt() {
        let rs = block();
        let a = ReceiptsTrie::new(&rs).root();
        let mut b = rs.clone();
        b[128].cumulative_gas += 1;
        assert_ne!(ReceiptsTrie::new(&b).root(), a);
        let mut b = rs.clone();
        b.pop();
        assert_ne!(ReceiptsTrie::new(&b).root(), a);
        let mut b = rs;
        b.swap(0, 3);
        assert_ne!(ReceiptsTrie::new(&b).root(), a);
    }

    #[test]
    fn find_log_picks_the_first_match_in_block_order() {
        let rs = block();
        let any_a1 = Filter {
            address: [0xA1; 20],
            topics: [None; 4],
        };
        assert_eq!(find_log(&rs, &any_a1), Some((0, 0)));
        // a topic pins one transaction: index 150 -> topic0 150
        let f = Filter {
            address: [0xA1; 20],
            topics: [Some(t(150)), Some(t(0x22)), None, None],
        };
        assert_eq!(find_log(&rs, &f), Some((150, 0)));
        // wrong address, absent topic, topic position the log does not have
        assert_eq!(
            find_log(
                &rs,
                &Filter {
                    address: [0xB2; 20],
                    topics: [None; 4]
                }
            ),
            None
        );
        assert_eq!(
            find_log(
                &rs,
                &Filter {
                    address: [0xA1; 20],
                    topics: [Some(t(0xEE)), None, None, None]
                }
            ),
            None
        );
        assert_eq!(
            find_log(
                &rs,
                &Filter {
                    address: [0xA1; 20],
                    topics: [None, None, Some(t(1)), None]
                }
            ),
            None
        );
    }

    #[test]
    fn find_log_skips_failed_transactions_and_returns_the_log_index() {
        let rs = vec![
            receipt(2, false, vec![log(0xA1, &[1], &[])]),
            receipt(2, true, vec![log(0xA1, &[9], &[]), log(0xA1, &[1], &[])]),
        ];
        let f = Filter {
            address: [0xA1; 20],
            topics: [Some(t(1)), None, None, None],
        };
        assert_eq!(find_log(&rs, &f), Some((1, 1)));
    }

    #[test]
    fn check_position_explains_each_failure() {
        let rs = block();
        let f = Filter {
            address: [0xA1; 20],
            topics: [Some(t(150)), None, None, None],
        };
        assert_eq!(check_position(&rs, 150, 0, &f), Ok(()));
        assert!(check_position(&rs, 300, 0, &f).unwrap_err().contains("300"));
        assert!(check_position(&rs, 150, 1, &f)
            .unwrap_err()
            .contains("1 logs"));
        assert!(check_position(&rs, 3, 0, &f)
            .unwrap_err()
            .contains("does not match"));
        assert!(check_position(&rs, 1, 0, &f)
            .unwrap_err()
            .contains("0 logs"));
    }

    #[test]
    fn a_found_log_verifies_in_the_core_verifier() {
        // end to end on the host side: find, prove, verify with the core filter
        let rs = block();
        let tr = ReceiptsTrie::new(&rs);
        let f = Filter {
            address: [0xA1; 20],
            topics: [Some(t(150)), None, None, None],
        };
        let (tx, li) = find_log(&rs, &f).unwrap();
        let proof = tr.proof(tx).unwrap();
        let leaf = verify_index_proof(&tr.root(), tx, &proof).unwrap().unwrap();
        let core_f = LogFilter {
            address: f.address,
            topics: f.topics,
        };
        let l = select_log(leaf, li as usize, &core_f).unwrap();
        assert_eq!(l.data, &[150u8; 32][..]);
    }

    #[test]
    fn predicate_flag_parses_every_target_and_operator() {
        let p = parse_predicate("balance==0x0de0b6b3a7640000").unwrap();
        assert_eq!(p.target, PredicateTarget::Balance);
        assert_eq!(p.op, PredicateOp::Eq);
        assert_eq!(
            p.operand[24..],
            [0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]
        );
        assert_eq!(p.operand[..24], [0u8; 24]);
        let p = parse_predicate("storage!=0x0").unwrap();
        assert_eq!(
            (p.target, p.op),
            (PredicateTarget::StorageValue, PredicateOp::Ne)
        );
        assert_eq!(p.operand, [0u8; 32]);
        let p = parse_predicate("topic2==0x01").unwrap();
        assert_eq!(
            (p.target, p.op),
            (PredicateTarget::Topic(2), PredicateOp::Eq)
        );
        assert_eq!(p.operand[31], 1);
        let p = parse_predicate("data10!=0x2710").unwrap();
        assert_eq!(p.target, PredicateTarget::DataWord(10));
        assert_eq!(p.operand[30..], [0x27, 0x10]);
        // odd-length hex is left-padded, like `--slot`
        assert_eq!(
            parse_predicate("data0==0x123").unwrap().operand[30..],
            [0x01, 0x23]
        );
        // a full 32-byte operand
        let full = format!("topic0=={}", format!("0x{}", "ab".repeat(32)));
        assert_eq!(parse_predicate(&full).unwrap().operand, [0xab; 32]);
    }

    #[test]
    fn predicate_flag_rejects_malformed_input() {
        for bad in [
            "",
            "balance",
            "balance=0x1",
            "balance===0x1",
            "balance==0x1!=0x2",
            "balance>=0x1",
            "bal==0x1",
            "topic==0x1",
            "topicx==0x1",
            "topic-1==0x1",
            "data==0x1",
            "topic99999999999==0x1",
            "balance==",
            "balance==0x",
            "balance==0xzz",
            &format!("balance==0x{}", "11".repeat(33)),
            "==0x1",
        ] {
            assert!(parse_predicate(bad).is_err(), "`{bad}` was accepted");
        }
    }

    #[test]
    fn transactions_are_selected_by_position_or_by_hash() {
        assert_eq!(parse_tx_sel("0"), Ok(TxSel::Index(0)));
        assert_eq!(parse_tx_sel("150"), Ok(TxSel::Index(150)));
        let h = format!("0x{}", "ab".repeat(32));
        assert_eq!(parse_tx_sel(&h), Ok(TxSel::Hash([0xab; 32])));
        for bad in [
            "",
            "-1",
            "0x12",
            "0x",
            "abc",
            &format!("0x{}", "zz".repeat(32)),
            &format!("0x{}", "ab".repeat(33)),
            "18446744073709551616",
        ] {
            assert!(parse_tx_sel(bad).is_err(), "`{bad}` was accepted");
        }
        let mut rs = block();
        rs[7].tx_hash = [0xab; 32];
        assert_eq!(resolve_tx(&rs, &TxSel::Hash([0xab; 32])), Ok(7));
        assert!(resolve_tx(&rs, &TxSel::Hash([0xcd; 32])).is_err());
        // a position is returned as given: `check_position` judges it
        assert_eq!(resolve_tx(&rs, &TxSel::Index(5000)), Ok(5000));
    }

    #[test]
    fn quantities() {
        assert_eq!(quantity("0x0"), Ok(0));
        assert_eq!(quantity("0x1"), Ok(1));
        assert_eq!(quantity("0x5208"), Ok(0x5208));
        assert_eq!(quantity("0xffffffffffffffff"), Ok(u64::MAX));
        for bad in ["", "0x", "5208", "0xg", "0x10000000000000000", "-0x1"] {
            assert!(quantity(bad).is_err(), "`{bad}` was accepted");
        }
    }

    #[test]
    fn predicate_errors_name_the_problem() {
        let msg = |s: &str| parse_predicate(s).unwrap_err();
        assert!(msg("balance==0x1!=0x2").contains("exactly one"));
        assert!(msg("balance").contains("`==` or `!=`"));
        assert!(msg("bal==0x1").contains("unknown target"));
        assert!(msg("topicx==0x1").contains("number"));
        assert!(msg("balance==0x").contains("empty"));
        assert!(msg(&format!("balance==0x{}", "11".repeat(33))).contains("32 bytes"));
    }

    #[test]
    fn state_and_log_targets_are_told_apart() {
        assert!(is_state_target(&PredicateTarget::Balance));
        assert!(is_state_target(&PredicateTarget::StorageValue));
        assert!(!is_state_target(&PredicateTarget::Topic(0)));
        assert!(!is_state_target(&PredicateTarget::DataWord(0)));
    }

    #[test]
    fn request_body_and_tamper_helper() {
        assert_eq!(
            block_receipts_request(26_262_717),
            r#"{"jsonrpc":"2.0","id":1,"method":"eth_getBlockReceipts","params":["0x190bcbd"]}"#
        );
        let mut nodes = vec![vec![0xf9, 1], vec![2]];
        flip_first_node(&mut nodes);
        assert_eq!(nodes, vec![vec![0xf8, 1], vec![2]]);
        let mut empty: Vec<Vec<u8>> = vec![];
        flip_first_node(&mut empty);
        let mut hollow = vec![vec![]];
        flip_first_node(&mut hollow);
        assert_eq!(hollow, vec![Vec::<u8>::new()]);
    }

    #[test]
    fn the_flipped_proof_no_longer_verifies() {
        let rs = block();
        let tr = ReceiptsTrie::new(&rs);
        let mut proof = tr.proof(150).unwrap();
        assert!(verify_index_proof(&tr.root(), 150, &proof)
            .unwrap()
            .is_some());
        flip_first_node(&mut proof);
        assert!(verify_index_proof(&tr.root(), 150, &proof).is_err());
    }
}
