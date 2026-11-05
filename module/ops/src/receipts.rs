//! Parse block receipts and build the receipt-trie proof used by `attest_log`.
//!
//! The RPC response is untrusted. The caller must compare the rebuilt root with the
//! finalized header record before using the proof.
use le_sync_core::exec::BLOOM_LEN;
use le_sync_core::keccak::{keccak256, EMPTY_TRIE_ROOT};
use le_sync_core::receipt::MAX_TOPICS;
use le_sync_core::Bytes32;
use serde_json::Value;
use std::collections::BTreeMap;

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../../testkit/src/trie.rs"]
mod reference_trie;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogData {
    pub address: [u8; 20],
    pub topics: Vec<Bytes32>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptData {
    pub tx_type: u8,
    pub success: bool,
    pub cumulative_gas: u64,
    pub bloom: [u8; BLOOM_LEN],
    pub logs: Vec<LogData>,
}

fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value, String> {
    v.get(key).ok_or_else(|| format!("missing field `{key}`"))
}

fn quantity(v: &Value, key: &str) -> Result<u64, String> {
    let s = field(v, key)?
        .as_str()
        .ok_or_else(|| format!("`{key}`: not a string"))?;
    let digits = s
        .strip_prefix("0x")
        .ok_or_else(|| format!("`{key}`: quantity must start with 0x"))?;
    u64::from_str_radix(digits, 16).map_err(|e| format!("`{key}`: {e}"))
}

fn bytes(v: &Value, key: &str) -> Result<Vec<u8>, String> {
    let s = field(v, key)?
        .as_str()
        .ok_or_else(|| format!("`{key}`: not a string"))?;
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| format!("`{key}`: {e}"))
}

fn fixed<const N: usize>(v: &Value, key: &str) -> Result<[u8; N], String> {
    let raw = bytes(v, key)?;
    raw.try_into()
        .map_err(|raw: Vec<u8>| format!("`{key}`: expected {N} bytes, got {}", raw.len()))
}

/// Parse `eth_getBlockReceipts` in canonical transaction order.
pub fn parse_block_receipts(v: &Value) -> Result<Vec<ReceiptData>, String> {
    let result = v.get("result").unwrap_or(v);
    let list = result.as_array().ok_or(
        "block receipts: expected a JSON array (the node may not serve eth_getBlockReceipts)",
    )?;
    let mut receipts = Vec::with_capacity(list.len());
    for (index, item) in list.iter().enumerate() {
        let at = |message: String| format!("receipt {index}: {message}");
        let tx_index = quantity(item, "transactionIndex").map_err(at)?;
        if tx_index != index as u64 {
            return Err(format!("receipt {index}: transactionIndex is {tx_index}"));
        }
        let tx_type = u8::try_from(quantity(item, "type").map_err(at)?)
            .map_err(|_| format!("receipt {index}: type is not a byte"))?;
        if tx_type > 4 {
            return Err(format!(
                "receipt {index}: unsupported receipt type 0x{tx_type:02x}"
            ));
        }
        let status = quantity(item, "status").map_err(at)?;
        if status > 1 {
            return Err(format!("receipt {index}: status {status}"));
        }
        let bloom = fixed::<BLOOM_LEN>(item, "logsBloom").map_err(at)?;
        let logs_value = field(item, "logs").map_err(at)?;
        let logs_array = logs_value
            .as_array()
            .ok_or_else(|| format!("receipt {index}: logs is not an array"))?;
        let mut logs = Vec::with_capacity(logs_array.len());
        for (log_index, log) in logs_array.iter().enumerate() {
            let at = |message: String| format!("receipt {index} log {log_index}: {message}");
            let address = fixed::<20>(log, "address").map_err(at)?;
            let topic_values = field(log, "topics").map_err(at)?;
            let topic_values = topic_values.as_array().ok_or_else(|| {
                format!("receipt {index} log {log_index}: topics is not an array")
            })?;
            let topics = topic_values
                .iter()
                .map(|topic| {
                    let s = topic
                        .as_str()
                        .ok_or_else(|| "topic is not a string".to_string())?;
                    let raw = hex::decode(s.strip_prefix("0x").unwrap_or(s))
                        .map_err(|e| format!("topic: {e}"))?;
                    raw.try_into().map_err(|raw: Vec<u8>| {
                        format!("topic: expected 32 bytes, got {}", raw.len())
                    })
                })
                .collect::<Result<Vec<Bytes32>, String>>()
                .map_err(at)?;
            if topics.len() > MAX_TOPICS {
                return Err(format!(
                    "receipt {index} log {log_index}: more than {MAX_TOPICS} topics"
                ));
            }
            let data = bytes(log, "data").map_err(at)?;
            logs.push(LogData {
                address,
                topics,
                data,
            });
        }
        receipts.push(ReceiptData {
            tx_type,
            success: status == 1,
            cumulative_gas: quantity(item, "cumulativeGasUsed").map_err(at)?,
            bloom,
            logs,
        });
    }
    Ok(receipts)
}

fn length_prefix(len: usize, base: u8) -> Vec<u8> {
    if len < 56 {
        vec![base + len as u8]
    } else {
        let be: Vec<u8> = len
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|b| *b == 0)
            .collect();
        let mut out = vec![base + 55 + be.len() as u8];
        out.extend(be);
        out
    }
}

fn rlp_bytes(value: &[u8]) -> Vec<u8> {
    if value.len() == 1 && value[0] < 0x80 {
        return value.to_vec();
    }
    let mut out = length_prefix(value.len(), 0x80);
    out.extend_from_slice(value);
    out
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = length_prefix(payload.len(), 0xc0);
    out.extend(payload);
    out
}

fn trim_be(value: u64) -> Vec<u8> {
    value
        .to_be_bytes()
        .iter()
        .copied()
        .skip_while(|b| *b == 0)
        .collect()
}

fn encode_receipt(receipt: &ReceiptData) -> Vec<u8> {
    let logs: Vec<Vec<u8>> = receipt
        .logs
        .iter()
        .map(|log| {
            let topics: Vec<Vec<u8>> = log.topics.iter().map(|t| rlp_bytes(t)).collect();
            rlp_list(&[
                rlp_bytes(&log.address),
                rlp_list(&topics),
                rlp_bytes(&log.data),
            ])
        })
        .collect();
    let status: &[u8] = if receipt.success { &[1] } else { &[] };
    let body = rlp_list(&[
        rlp_bytes(status),
        rlp_bytes(&trim_be(receipt.cumulative_gas)),
        rlp_bytes(&receipt.bloom),
        rlp_list(&logs),
    ]);
    if receipt.tx_type == 0 {
        body
    } else {
        let mut value = vec![receipt.tx_type];
        value.extend(body);
        value
    }
}

fn index_key(index: u64) -> Vec<u8> {
    rlp_bytes(&trim_be(index))
}

fn nibbles(key: &[u8]) -> Vec<u8> {
    key.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect()
}

fn hex_prefix(path: &[u8], leaf: bool) -> Vec<u8> {
    let flag = if leaf { 2 } else { 0 };
    let mut out = Vec::new();
    let mut i = 0;
    if path.len() % 2 == 1 {
        out.push(((flag | 1) << 4) | path[0]);
        i = 1;
    } else {
        out.push(flag << 4);
    }
    while i < path.len() {
        out.push((path[i] << 4) | path[i + 1]);
        i += 2;
    }
    out
}

fn child_ref(node: &[u8]) -> Vec<u8> {
    if node.len() < 32 {
        node.to_vec()
    } else {
        rlp_bytes(&keccak256(node))
    }
}

fn build_node(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    if entries.len() == 1 {
        return rlp_list(&[
            rlp_bytes(&hex_prefix(&entries[0].0, true)),
            rlp_bytes(&entries[0].1),
        ]);
    }
    let mut common = 0;
    while entries
        .iter()
        .all(|(key, _)| key.len() > common && key[common] == entries[0].0[common])
    {
        common += 1;
    }
    if common > 0 {
        let rest: Vec<_> = entries
            .iter()
            .map(|(key, value)| (key[common..].to_vec(), value.clone()))
            .collect();
        let child = build_node(&rest);
        return rlp_list(&[
            rlp_bytes(&hex_prefix(&entries[0].0[..common], false)),
            child_ref(&child),
        ]);
    }
    let mut slots = vec![rlp_bytes(&[]); 17];
    for nibble in 0..16u8 {
        let group: Vec<_> = entries
            .iter()
            .filter(|(key, _)| key[0] == nibble)
            .map(|(key, value)| (key[1..].to_vec(), value.clone()))
            .collect();
        if !group.is_empty() {
            slots[nibble as usize] = child_ref(&build_node(&group));
        }
    }
    rlp_list(&slots)
}

fn collect_proof(entries: &[(Vec<u8>, Vec<u8>)], key: &[u8], out: &mut Vec<Vec<u8>>, root: bool) {
    let encoded = build_node(entries);
    if root || encoded.len() >= 32 {
        out.push(encoded);
    }
    if entries.len() == 1 {
        return;
    }
    let mut common = 0;
    while entries
        .iter()
        .all(|(entry, _)| entry.len() > common && entry[common] == entries[0].0[common])
    {
        common += 1;
    }
    if common > 0 {
        if key.len() >= common && key[..common] == entries[0].0[..common] {
            let rest: Vec<_> = entries
                .iter()
                .map(|(entry, value)| (entry[common..].to_vec(), value.clone()))
                .collect();
            collect_proof(&rest, &key[common..], out, false);
        }
        return;
    }
    if key.is_empty() {
        return;
    }
    let group: Vec<_> = entries
        .iter()
        .filter(|(entry, _)| entry[0] == key[0])
        .map(|(entry, value)| (entry[1..].to_vec(), value.clone()))
        .collect();
    if !group.is_empty() {
        collect_proof(&group, &key[1..], out, false);
    }
}

/// A receipt trie whose keys are `rlp(transaction_index)`.
pub struct ReceiptsTrie {
    root: Bytes32,
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl ReceiptsTrie {
    pub fn new(receipts: &[ReceiptData]) -> Self {
        let entries: BTreeMap<_, _> = receipts
            .iter()
            .enumerate()
            .map(|(index, receipt)| (index_key(index as u64), encode_receipt(receipt)))
            .collect();
        let root = if entries.is_empty() {
            EMPTY_TRIE_ROOT
        } else {
            let nibble_entries: Vec<_> = entries
                .iter()
                .map(|(key, value)| (nibbles(key), value.clone()))
                .collect();
            keccak256(&build_node(&nibble_entries))
        };
        Self { root, entries }
    }

    pub fn root(&self) -> Bytes32 {
        self.root
    }

    pub fn proof(&self, index: u64) -> Option<Vec<Vec<u8>>> {
        let key = index_key(index);
        if !self.entries.contains_key(&key) {
            return None;
        }
        let entries: Vec<_> = self
            .entries
            .iter()
            .map(|(key, value)| (nibbles(key), value.clone()))
            .collect();
        let mut proof = Vec::new();
        collect_proof(&entries, &nibbles(&key), &mut proof, true);
        Some(proof)
    }
}

/// Return the first successful-receipt log matching its address and topic0.
pub fn find_log(
    receipts: &[ReceiptData],
    address: &[u8; 20],
    topic0: &Bytes32,
) -> Option<(u64, u32)> {
    for (tx_index, receipt) in receipts.iter().enumerate() {
        if !receipt.success {
            continue;
        }
        if let Some(log_index) = receipt
            .logs
            .iter()
            .position(|log| log.address == *address && log.topics.first() == Some(topic0))
        {
            return Some((tx_index as u64, log_index as u32));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use le_sync_core::mpt::verify_index_proof;
    use serde_json::json;

    fn receipt(index: usize, address: &str, topic: &str) -> Value {
        json!({
            "transactionIndex": format!("0x{index:x}"),
            "type": "0x2",
            "status": "0x1",
            "cumulativeGasUsed": "0x5208",
            "logsBloom": format!("0x{}", "00".repeat(BLOOM_LEN)),
            "logs": [{
                "address": address,
                "topics": [topic],
                "data": "0xabcdef"
            }]
        })
    }

    #[test]
    fn receipt_trie_root_and_proof_verify() {
        let address = format!("0x{}", "11".repeat(20));
        let topic = format!("0x{}", "22".repeat(32));
        let receipts = parse_block_receipts(&json!({"result": [
            receipt(0, &address, &topic),
            receipt(1, &address, &topic)
        ]}))
        .unwrap();
        let trie = ReceiptsTrie::new(&receipts);
        let proof = trie.proof(1).unwrap();
        let leaf = verify_index_proof(&trie.root(), 1, &proof)
            .unwrap()
            .unwrap();
        assert!(le_sync_core::receipt::log_at(leaf, 0).is_ok());
        let expected_entries: Vec<_> = receipts
            .iter()
            .enumerate()
            .map(|(index, receipt)| {
                (
                    reference_trie::index_key(index as u64),
                    encode_receipt(receipt),
                )
            })
            .collect();
        let expected = reference_trie::Trie::new_raw(&expected_entries);
        assert_eq!(trie.root(), expected.root);
        assert_eq!(proof, expected.prove_raw(&reference_trie::index_key(1)));
        assert_eq!(find_log(&receipts, &[0x11; 20], &[0x22; 32]), Some((0, 0)));
        assert_eq!(trie.proof(2), None);
    }

    #[test]
    fn supports_legacy_and_typed_receipt_encodings() {
        let address = format!("0x{}", "11".repeat(20));
        let topic = format!("0x{}", "22".repeat(32));
        for tx_type in 0..=4 {
            let mut item = receipt(0, &address, &topic);
            item["type"] = json!(format!("0x{tx_type:x}"));
            let receipts = parse_block_receipts(&json!({"result": [item]})).unwrap();
            let trie = ReceiptsTrie::new(&receipts);
            let proof = trie.proof(0).unwrap();
            let leaf = verify_index_proof(&trie.root(), 0, &proof)
                .unwrap()
                .unwrap();
            assert!(le_sync_core::receipt::log_at(leaf, 0).is_ok());
        }
    }

    #[test]
    fn rejects_reordered_and_unsupported_receipts() {
        let address = format!("0x{}", "11".repeat(20));
        let topic = format!("0x{}", "22".repeat(32));
        let reordered = json!({"result": [receipt(1, &address, &topic)]});
        assert!(parse_block_receipts(&reordered)
            .unwrap_err()
            .contains("transactionIndex is 1"));
        let mut unsupported = receipt(0, &address, &topic);
        unsupported["type"] = json!("0x5");
        assert!(parse_block_receipts(&json!({"result": [unsupported]}))
            .unwrap_err()
            .contains("unsupported receipt type"));
    }

    #[test]
    fn failed_receipts_do_not_supply_log_matches() {
        let address = format!("0x{}", "11".repeat(20));
        let topic = format!("0x{}", "22".repeat(32));
        let mut failed = receipt(0, &address, &topic);
        failed["status"] = json!("0x0");
        let receipts = parse_block_receipts(&json!({"result": [failed]})).unwrap();
        assert_eq!(find_log(&receipts, &[0x11; 20], &[0x22; 32]), None);
    }

    #[test]
    fn rejects_logs_with_more_than_four_topics() {
        let topics: Vec<_> = (0..5)
            .map(|n| format!("0x{}", format!("{n:02x}").repeat(32)))
            .collect();
        let mut item = receipt(
            0,
            &format!("0x{}", "11".repeat(20)),
            &format!("0x{}", "22".repeat(32)),
        );
        item["logs"][0]["topics"] = json!(topics);
        assert!(parse_block_receipts(&json!({"result": [item]}))
            .unwrap_err()
            .contains("more than 4 topics"));
    }
}
