//! Receipt leaf parsing and log selection (`no_std`, no alloc).
//!
//! The input is the value of a receipts-trie leaf that `mpt::verify_index_proof` has already
//! tied to a `receipts_root`. This file only reads it; it proves nothing by itself.
//!
//! Encoding (EIP-2718): the trie value is either a legacy receipt, which is the RLP list
//! itself, or `TransactionType || ReceiptPayload` for a typed receipt. The payload is
//! `rlp([status, cumulative_gas_used, logs_bloom, logs])` and each log is
//! `[address, [topic, ...], data]`.
//!
//! Strict: one accepted shape per receipt. Anything else is `Error::InvalidRlp` (203):
//! * an unknown or unsupported type byte, or a first byte that is an RLP string,
//! * trailing bytes, wrong arity, a non-canonical integer, a bloom that is not 256 bytes,
//! * an address that is not 20 bytes, a topic that is not 32 bytes, more than 4 topics.
//!
//! Semantic failures are `Error::LogMismatch` (205): a failed transaction (status 0), a log
//! index beyond the receipt's logs, or a log that does not match the requested filter.
//!
//! Supported types: legacy, `0x01` (EIP-2930) and `0x02` (EIP-1559). Types `0x03` (EIP-4844)
//! and `0x04` (EIP-7702) are refused until their receipt payload is confirmed against the
//! EIPs; a transaction of those types fails closed.
//!
//! Spec: EIP-2718 (envelope and trie placement), EIP-658 (status), Yellow Paper (receipt, log).

use crate::exec::BLOOM_LEN;
use crate::rlp::{canonical_uint, decode_exact, decode_item, split_list, Item};
use crate::{Bytes32, Error};

/// A log carries at most four topics (`LOG0`..`LOG4`).
pub const MAX_TOPICS: usize = 4;

/// Typed receipt envelopes this parser accepts. See the module note on `0x03` and `0x04`.
const SUPPORTED_TYPES: [u8; 2] = [0x01, 0x02];

/// One decoded log. `topics[..topic_count]` are valid; the rest are zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Log<'a> {
    pub address: [u8; 20],
    pub topics: [Bytes32; MAX_TOPICS],
    pub topic_count: usize,
    pub data: &'a [u8],
}

/// What a log must match: the emitting address and, per position, an optional topic.
/// `None` is a wildcard. A `Some` at position `i` requires the log to have a topic `i`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogFilter {
    pub address: [u8; 20],
    pub topics: [Option<Bytes32>; MAX_TOPICS],
}

impl Log<'_> {
    pub fn matches(&self, filter: &LogFilter) -> bool {
        if self.address != filter.address {
            return false;
        }
        for i in 0..MAX_TOPICS {
            if let Some(t) = &filter.topics[i] {
                if i >= self.topic_count || self.topics[i] != *t {
                    return false;
                }
            }
        }
        true
    }
}

/// The payload list of a receipt leaf: strips the type byte of a typed receipt, or takes a
/// legacy receipt as is. Rejects trailing bytes.
fn receipt_list(leaf: &[u8]) -> Result<&[u8], Error> {
    let first = *leaf.first().ok_or(Error::InvalidRlp)?;
    // A typed receipt starts with a supported type byte. Anything else must be a legacy
    // receipt: a whole RLP list. An unknown type byte or an RLP string fails `decode_exact`
    // or the list check below.
    let body = if SUPPORTED_TYPES.contains(&first) {
        &leaf[1..]
    } else {
        leaf
    };
    match decode_exact(body)? {
        Item::List { payload, .. } => Ok(payload),
        Item::Bytes(_) => Err(Error::InvalidRlp),
    }
}

fn parse_log(item: Item<'_>) -> Result<Log<'_>, Error> {
    let Item::List { payload, .. } = item else {
        return Err(Error::InvalidRlp);
    };
    let (fields, n) = split_list::<3>(payload)?;
    // `split_list::<3>` already rejects more than 3 items
    if n < 3 {
        return Err(Error::InvalidRlp);
    }
    let a = fields[0].as_bytes()?;
    if a.len() != 20 {
        return Err(Error::InvalidRlp);
    }
    let mut address = [0u8; 20];
    address.copy_from_slice(a);

    let Item::List {
        payload: mut rest, ..
    } = fields[1]
    else {
        return Err(Error::InvalidRlp);
    };
    let mut topics = [[0u8; 32]; MAX_TOPICS];
    let mut topic_count = 0;
    while !rest.is_empty() {
        if topic_count == MAX_TOPICS {
            return Err(Error::InvalidRlp);
        }
        let (t, r) = decode_item(rest)?;
        let t = t.as_bytes()?;
        if t.len() != 32 {
            return Err(Error::InvalidRlp);
        }
        topics[topic_count].copy_from_slice(t);
        topic_count += 1;
        rest = r;
    }
    Ok(Log {
        address,
        topics,
        topic_count,
        data: fields[2].as_bytes()?,
    })
}

/// Decode the receipt in `leaf` and return its `log_index`-th log.
///
/// Checks the receipt's shape and that the transaction succeeded. Logs before `log_index` are
/// skipped (their RLP headers must be well formed); only the selected log is decoded in full.
pub fn log_at(leaf: &[u8], log_index: usize) -> Result<Log<'_>, Error> {
    let (items, n) = split_list::<4>(receipt_list(leaf)?)?;
    // `split_list::<4>` already rejects more than 4 items
    if n < 4 {
        return Err(Error::InvalidRlp);
    }
    // EIP-658: 1 is success, 0 is the empty string. A 32-byte pre-Byzantium state root, or any
    // other value, is not a status.
    match items[0].as_bytes()? {
        [1] => {}
        [] => return Err(Error::LogMismatch),
        _ => return Err(Error::InvalidRlp),
    }
    canonical_uint(items[1].as_bytes()?, 8)?;
    if items[2].as_bytes()?.len() != BLOOM_LEN {
        return Err(Error::InvalidRlp);
    }
    let Item::List {
        payload: mut logs, ..
    } = items[3]
    else {
        return Err(Error::InvalidRlp);
    };
    for _ in 0..log_index {
        if logs.is_empty() {
            return Err(Error::LogMismatch);
        }
        logs = decode_item(logs)?.1;
    }
    if logs.is_empty() {
        return Err(Error::LogMismatch);
    }
    parse_log(decode_item(logs)?.0)
}

/// `log_at`, then require the log to match `filter`.
pub fn select_log<'a>(
    leaf: &'a [u8],
    log_index: usize,
    filter: &LogFilter,
) -> Result<Log<'a>, Error> {
    let log = log_at(leaf, log_index)?;
    if log.matches(filter) {
        Ok(log)
    } else {
        Err(Error::LogMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpt::testutil::{rlp_bytes, rlp_list};

    const ADDR: [u8; 20] = [0xA1; 20];
    fn topic(n: u8) -> Bytes32 {
        [n; 32]
    }

    /// `[address, [topics], data]`
    fn log(addr: &[u8], topics: &[Vec<u8>], data: &[u8]) -> Vec<u8> {
        let ts: Vec<Vec<u8>> = topics.iter().map(|t| rlp_bytes(t)).collect();
        rlp_list(&[rlp_bytes(addr), rlp_list(&ts), rlp_bytes(data)])
    }
    fn good_log(n: u8) -> Vec<u8> {
        log(&ADDR, &[topic(n).to_vec(), topic(n + 1).to_vec()], &[n; 40])
    }
    /// `[status, gas, bloom, logs]` from raw (already RLP-encoded) fields.
    fn payload(fields: &[Vec<u8>]) -> Vec<u8> {
        rlp_list(fields)
    }
    fn fields(status: &[u8], gas: &[u8], bloom: &[u8], logs: &[Vec<u8>]) -> Vec<Vec<u8>> {
        vec![
            rlp_bytes(status),
            rlp_bytes(gas),
            rlp_bytes(bloom),
            rlp_list(logs),
        ]
    }
    fn receipt(logs: &[Vec<u8>]) -> Vec<u8> {
        payload(&fields(&[1], &[0x52, 0x08], &[0u8; BLOOM_LEN], logs))
    }
    fn typed(t: u8, body: Vec<u8>) -> Vec<u8> {
        let mut v = vec![t];
        v.extend(body);
        v
    }
    fn parsed(leaf: &[u8], i: usize) -> Result<Log<'_>, Error> {
        log_at(leaf, i)
    }
    fn filter() -> LogFilter {
        LogFilter {
            address: ADDR,
            topics: [Some(topic(1)), None, None, None],
        }
    }

    #[test]
    fn legacy_and_typed_receipts_give_the_same_log() {
        let logs = [good_log(1)];
        let legacy = receipt(&logs);
        let t1 = typed(0x01, receipt(&logs));
        let t2 = typed(0x02, receipt(&logs));
        let want = parsed(&legacy, 0).unwrap();
        assert_eq!(want.address, ADDR);
        assert_eq!(want.topic_count, 2);
        assert_eq!(want.topics[0], topic(1));
        assert_eq!(want.topics[1], topic(2));
        assert_eq!(want.topics[2], [0u8; 32]);
        assert_eq!(want.data, &[1u8; 40][..]);
        assert_eq!(parsed(&t1, 0), Ok(want));
        assert_eq!(parsed(&t2, 0), Ok(want));
    }

    #[test]
    fn logs_are_selected_by_index() {
        let leaf = receipt(&[good_log(1), good_log(10), good_log(20)]);
        for (i, n) in [(0usize, 1u8), (1, 10), (2, 20)] {
            let l = parsed(&leaf, i).unwrap();
            assert_eq!(l.topics[0], topic(n), "index {i}");
        }
        assert_eq!(parsed(&leaf, 3), Err(Error::LogMismatch));
        assert_eq!(parsed(&leaf, 1000), Err(Error::LogMismatch));
        // a receipt with no logs
        assert_eq!(parsed(&receipt(&[]), 0), Err(Error::LogMismatch));
    }

    #[test]
    fn zero_to_four_topics_are_accepted_and_five_are_not() {
        for n in 0..=4u8 {
            let ts: Vec<Vec<u8>> = (0..n).map(|i| topic(i + 1).to_vec()).collect();
            let leaf = receipt(&[log(&ADDR, &ts, &[])]);
            let l = parsed(&leaf, 0).unwrap();
            assert_eq!(l.topic_count, n as usize);
            assert_eq!(l.data, &[] as &[u8]);
        }
        let ts: Vec<Vec<u8>> = (0..5u8).map(|i| topic(i + 1).to_vec()).collect();
        let leaf = receipt(&[log(&ADDR, &ts, &[])]);
        assert_eq!(parsed(&leaf, 0), Err(Error::InvalidRlp));
    }

    #[test]
    fn unknown_unsupported_and_misplaced_type_bytes_are_rejected() {
        let body = receipt(&[good_log(1)]);
        // 0x00 is reserved, 0x03 and 0x04 are not yet supported, the rest are unknown
        for t in [0x00u8, 0x03, 0x04, 0x05, 0x10, 0x7f] {
            assert_eq!(
                parsed(&typed(t, body.clone()), 0),
                Err(Error::InvalidRlp),
                "type {t:#x}"
            );
        }
        // a first byte that is an RLP string header, not a type and not a list
        for t in [0x80u8, 0x81, 0xb7, 0xb8, 0xbf] {
            assert_eq!(
                parsed(&typed(t, body.clone()), 0),
                Err(Error::InvalidRlp),
                "first byte {t:#x}"
            );
        }
        assert_eq!(parsed(&[], 0), Err(Error::InvalidRlp));
        // a type byte followed by a string instead of a list
        assert_eq!(
            parsed(&typed(0x02, rlp_bytes(&[1, 2, 3])), 0),
            Err(Error::InvalidRlp)
        );
    }

    #[test]
    fn wrong_arity_is_rejected() {
        let ok = fields(&[1], &[0x52, 0x08], &[0u8; BLOOM_LEN], &[good_log(1)]);
        for k in 0..4 {
            let mut short = ok.clone();
            short.remove(k);
            assert_eq!(
                parsed(&payload(&short), 0),
                Err(Error::InvalidRlp),
                "removed {k}"
            );
        }
        let mut long = ok.clone();
        long.push(rlp_bytes(&[1]));
        assert_eq!(parsed(&payload(&long), 0), Err(Error::InvalidRlp));
        assert_eq!(parsed(&payload(&[]), 0), Err(Error::InvalidRlp));
    }

    #[test]
    fn status_rules() {
        let with = |status: &[u8]| {
            payload(&fields(
                status,
                &[0x52, 0x08],
                &[0u8; BLOOM_LEN],
                &[good_log(1)],
            ))
        };
        assert!(parsed(&with(&[1]), 0).is_ok());
        // a failed transaction has no usable log
        assert_eq!(parsed(&with(&[]), 0), Err(Error::LogMismatch));
        // not a status: 0 as a byte, 2, a 32-byte pre-Byzantium state root
        assert_eq!(parsed(&with(&[0]), 0), Err(Error::InvalidRlp));
        assert_eq!(parsed(&with(&[2]), 0), Err(Error::InvalidRlp));
        assert_eq!(parsed(&with(&[0x11; 32]), 0), Err(Error::InvalidRlp));
        // a list in the status position
        let mut f = fields(&[1], &[0x52, 0x08], &[0u8; BLOOM_LEN], &[good_log(1)]);
        f[0] = rlp_list(&[]);
        assert_eq!(parsed(&payload(&f), 0), Err(Error::InvalidRlp));
    }

    #[test]
    fn gas_and_bloom_shapes() {
        let with = |gas: &[u8], bloom: &[u8]| payload(&fields(&[1], gas, bloom, &[good_log(1)]));
        let bloom = [0u8; BLOOM_LEN];
        assert!(parsed(&with(&[], &bloom), 0).is_ok());
        assert!(parsed(&with(&[1; 8], &bloom), 0).is_ok());
        // leading zero, more than 8 bytes
        assert_eq!(parsed(&with(&[0, 1], &bloom), 0), Err(Error::InvalidRlp));
        assert_eq!(parsed(&with(&[1; 9], &bloom), 0), Err(Error::InvalidRlp));
        // bloom must be exactly 256 bytes
        assert_eq!(
            parsed(&with(&[1], &[0u8; BLOOM_LEN - 1]), 0),
            Err(Error::InvalidRlp)
        );
        assert_eq!(
            parsed(&with(&[1], &[0u8; BLOOM_LEN + 1]), 0),
            Err(Error::InvalidRlp)
        );
        // lists where bytes are required
        let mut f = fields(&[1], &[1], &bloom, &[good_log(1)]);
        f[1] = rlp_list(&[]);
        assert_eq!(parsed(&payload(&f), 0), Err(Error::InvalidRlp));
        let mut f = fields(&[1], &[1], &bloom, &[good_log(1)]);
        f[2] = rlp_list(&[]);
        assert_eq!(parsed(&payload(&f), 0), Err(Error::InvalidRlp));
    }

    #[test]
    fn logs_field_must_be_a_list() {
        let mut f = fields(&[1], &[1], &[0u8; BLOOM_LEN], &[]);
        f[3] = rlp_bytes(&[1, 2, 3]);
        assert_eq!(parsed(&payload(&f), 0), Err(Error::InvalidRlp));
    }

    #[test]
    fn bad_address_topic_and_log_shapes_are_rejected() {
        let t = topic(1).to_vec();
        for len in [0usize, 19, 21, 32] {
            let leaf = receipt(&[log(&vec![0xA1; len], &[t.clone()], &[])]);
            assert_eq!(parsed(&leaf, 0), Err(Error::InvalidRlp), "address {len}");
        }
        for len in [0usize, 1, 31, 33] {
            let leaf = receipt(&[log(&ADDR, &[vec![7u8; len]], &[])]);
            assert_eq!(parsed(&leaf, 0), Err(Error::InvalidRlp), "topic {len}");
        }
        // a log with 2 or 4 items
        let two = rlp_list(&[rlp_bytes(&ADDR), rlp_list(&[])]);
        assert_eq!(parsed(&receipt(&[two]), 0), Err(Error::InvalidRlp));
        let four = rlp_list(&[
            rlp_bytes(&ADDR),
            rlp_list(&[]),
            rlp_bytes(&[]),
            rlp_bytes(&[]),
        ]);
        assert_eq!(parsed(&receipt(&[four]), 0), Err(Error::InvalidRlp));
        // topics as a string, data as a list, the log itself as a string
        let bad_topics = rlp_list(&[rlp_bytes(&ADDR), rlp_bytes(&[1, 2]), rlp_bytes(&[])]);
        assert_eq!(parsed(&receipt(&[bad_topics]), 0), Err(Error::InvalidRlp));
        let bad_data = rlp_list(&[rlp_bytes(&ADDR), rlp_list(&[]), rlp_list(&[])]);
        assert_eq!(parsed(&receipt(&[bad_data]), 0), Err(Error::InvalidRlp));
        assert_eq!(
            parsed(&receipt(&[rlp_bytes(&[1, 2, 3])]), 0),
            Err(Error::InvalidRlp)
        );
        // a topic that is a list
        let list_topic = rlp_list(&[rlp_bytes(&ADDR), rlp_list(&[rlp_list(&[])]), rlp_bytes(&[])]);
        assert_eq!(parsed(&receipt(&[list_topic]), 0), Err(Error::InvalidRlp));
    }

    #[test]
    fn trailing_and_truncated_bytes_are_rejected() {
        let legacy = receipt(&[good_log(1)]);
        let t2 = typed(0x02, legacy.clone());
        for leaf in [&legacy, &t2] {
            let mut more = leaf.clone();
            more.push(0x00);
            assert_eq!(parsed(&more, 0), Err(Error::InvalidRlp));
            let cut = &leaf[..leaf.len() - 1];
            assert_eq!(parsed(cut, 0), Err(Error::InvalidRlp));
        }
    }

    #[test]
    fn a_malformed_log_before_the_selected_one_is_caught_by_its_header() {
        // the first item is a string header claiming 255 bytes that are not there
        let logs = rlp_list(&[vec![0xb8, 0xff], good_log(5)]);
        let f = vec![
            rlp_bytes(&[1]),
            rlp_bytes(&[1]),
            rlp_bytes(&[0u8; BLOOM_LEN]),
            logs,
        ];
        assert_eq!(parsed(&payload(&f), 1), Err(Error::InvalidRlp));
        assert_eq!(parsed(&payload(&f), 0), Err(Error::InvalidRlp));
    }

    #[test]
    fn filter_matching() {
        let leaf = receipt(&[good_log(1)]);
        let l = parsed(&leaf, 0).unwrap();
        // address only, address and one topic, both topics
        assert!(l.matches(&LogFilter {
            address: ADDR,
            topics: [None; 4]
        }));
        assert!(l.matches(&filter()));
        assert!(l.matches(&LogFilter {
            address: ADDR,
            topics: [Some(topic(1)), Some(topic(2)), None, None],
        }));
        // wildcard in front of a constraint
        assert!(l.matches(&LogFilter {
            address: ADDR,
            topics: [None, Some(topic(2)), None, None],
        }));
        // wrong address
        let mut f = filter();
        f.address[0] ^= 1;
        assert!(!l.matches(&f));
        // wrong topic at each position that exists
        assert!(!l.matches(&LogFilter {
            address: ADDR,
            topics: [Some(topic(9)), None, None, None],
        }));
        assert!(!l.matches(&LogFilter {
            address: ADDR,
            topics: [None, Some(topic(9)), None, None],
        }));
        // a constraint on a topic the log does not have
        assert!(!l.matches(&LogFilter {
            address: ADDR,
            topics: [None, None, Some(topic(0)), None],
        }));
        assert!(!l.matches(&LogFilter {
            address: ADDR,
            topics: [None, None, None, Some(topic(0))],
        }));
        // a zero topic constraint is not a wildcard: the log's absent topic is not 0x00..00
        let zero = receipt(&[log(&ADDR, &[], &[])]);
        let lz = parsed(&zero, 0).unwrap();
        assert!(!lz.matches(&LogFilter {
            address: ADDR,
            topics: [Some([0u8; 32]), None, None, None],
        }));
    }

    #[test]
    fn select_log_returns_a_match_and_logmismatch_otherwise() {
        let leaf = receipt(&[good_log(1), good_log(10)]);
        let l = select_log(&leaf, 0, &filter()).unwrap();
        assert_eq!(l.topics[0], topic(1));
        // right receipt, wrong log for the filter
        assert_eq!(select_log(&leaf, 1, &filter()), Err(Error::LogMismatch));
        // index out of range
        assert_eq!(select_log(&leaf, 2, &filter()), Err(Error::LogMismatch));
        // a malformed receipt is a shape error, not a mismatch
        assert_eq!(select_log(&[0xc0], 0, &filter()), Err(Error::InvalidRlp));
    }
}
