//! Minimal, zero-copy, STRICT RLP reader (`no_std`, no alloc).
//!
//! Strict means: every value has exactly one accepted encoding. Non-canonical forms are
//! rejected with `Error::InvalidRlp`:
//! * a single byte below 0x80 wrapped in a 0x81 string header,
//! * long-form lengths below 56, or with leading zero bytes,
//! * lengths that overflow `usize` or run past the input,
//! * trailing bytes after a top-level item (`decode_exact`).
//!
//! Spec: Ethereum Yellow Paper Appendix B (RLP); ethereum.org "Recursive Length Prefix".

use crate::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item<'a> {
    /// A byte string (payload only).
    Bytes(&'a [u8]),
    /// A list. `raw` is the full encoding including its header (needed to re-parse an
    /// embedded trie node); `payload` is the concatenated encoding of its items.
    List { raw: &'a [u8], payload: &'a [u8] },
}

impl<'a> Item<'a> {
    pub fn as_bytes(&self) -> Result<&'a [u8], Error> {
        match self {
            Item::Bytes(b) => Ok(b),
            Item::List { .. } => Err(Error::InvalidRlp),
        }
    }
}

/// Big-endian length of `n` bytes (1..=8): no leading zero, fits `usize`.
fn long_len(input: &[u8], n: usize) -> Result<usize, Error> {
    if n == 0 || n > 8 || input.len() < n || input[0] == 0 {
        return Err(Error::InvalidRlp);
    }
    let mut v: u64 = 0;
    for b in &input[..n] {
        v = (v << 8) + *b as u64;
    }
    usize::try_from(v).map_err(|_| Error::InvalidRlp)
}

/// Decode one item from the front of `input`; returns it and the unread remainder.
pub fn decode_item(input: &[u8]) -> Result<(Item<'_>, &[u8]), Error> {
    let first = *input.first().ok_or(Error::InvalidRlp)?;
    let (is_list, header, len) = match first {
        0x00..=0x7f => return Ok((Item::Bytes(&input[..1]), &input[1..])),
        0x80..=0xb7 => (false, 1usize, (first - 0x80) as usize),
        0xb8..=0xbf => {
            let n = (first - 0xb7) as usize;
            let len = long_len(&input[1..], n)?;
            if len < 56 {
                return Err(Error::InvalidRlp);
            }
            (false, 1 + n, len)
        }
        0xc0..=0xf7 => (true, 1usize, (first - 0xc0) as usize),
        0xf8..=0xff => {
            let n = (first - 0xf7) as usize;
            let len = long_len(&input[1..], n)?;
            if len < 56 {
                return Err(Error::InvalidRlp);
            }
            (true, 1 + n, len)
        }
    };
    let end = header.checked_add(len).ok_or(Error::InvalidRlp)?;
    if input.len() < end {
        return Err(Error::InvalidRlp);
    }
    let payload = &input[header..end];
    // A one-byte string below 0x80 must be encoded as itself.
    if !is_list && len == 1 && payload[0] < 0x80 {
        return Err(Error::InvalidRlp);
    }
    let item = if is_list {
        Item::List {
            raw: &input[..end],
            payload,
        }
    } else {
        Item::Bytes(payload)
    };
    Ok((item, &input[end..]))
}

/// Decode a whole buffer as exactly one item (no trailing bytes).
pub fn decode_exact(input: &[u8]) -> Result<Item<'_>, Error> {
    let (item, rest) = decode_item(input)?;
    if rest.is_empty() {
        Ok(item)
    } else {
        Err(Error::InvalidRlp)
    }
}

/// Split a list payload into at most `N` items. Returns the items and how many were read;
/// more than `N` items is an error.
pub fn split_list<'a, const N: usize>(
    mut payload: &'a [u8],
) -> Result<([Item<'a>; N], usize), Error> {
    let mut out = [Item::Bytes(&[]); N];
    let mut n = 0;
    while !payload.is_empty() {
        if n == N {
            return Err(Error::InvalidRlp);
        }
        let (item, rest) = decode_item(payload)?;
        out[n] = item;
        n += 1;
        payload = rest;
    }
    Ok((out, n))
}

/// A canonical RLP integer payload: no leading zero byte, at most `max` bytes. Empty = 0.
pub fn canonical_uint(bytes: &[u8], max: usize) -> Result<&[u8], Error> {
    if bytes.len() > max || bytes.first() == Some(&0) {
        return Err(Error::InvalidRlp);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(i: Item<'_>) -> &[u8] {
        match i {
            Item::Bytes(b) => b,
            _ => panic!("not bytes"),
        }
    }

    #[test]
    fn short_forms() {
        assert_eq!(bytes(decode_exact(&[0x00]).unwrap()), &[0x00]);
        assert_eq!(bytes(decode_exact(&[0x7f]).unwrap()), &[0x7f]);
        assert_eq!(bytes(decode_exact(&[0x80]).unwrap()), &[] as &[u8]);
        assert_eq!(bytes(decode_exact(&[0x81, 0x80]).unwrap()), &[0x80]);
        assert_eq!(
            bytes(decode_exact(&[0x83, b'd', b'o', b'g']).unwrap()),
            b"dog"
        );
        let l = decode_exact(&[0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']).unwrap();
        let Item::List { payload, raw } = l else {
            panic!()
        };
        assert_eq!(raw.len(), 9);
        let (items, n) = split_list::<4>(payload).unwrap();
        assert_eq!(n, 2);
        assert_eq!(bytes(items[0]), b"cat");
        assert_eq!(bytes(items[1]), b"dog");
        // empty list
        let Item::List { payload, .. } = decode_exact(&[0xc0]).unwrap() else {
            panic!()
        };
        assert!(payload.is_empty());
    }

    #[test]
    fn long_forms() {
        // 56-byte string: header 0xb8 0x38
        let mut s = vec![0xb8, 56];
        s.extend(vec![7u8; 56]);
        assert_eq!(bytes(decode_exact(&s).unwrap()).len(), 56);
        // 55-byte string uses the short form 0xb7
        let mut s = vec![0xb7];
        s.extend(vec![7u8; 55]);
        assert_eq!(bytes(decode_exact(&s).unwrap()).len(), 55);
        // 256-byte string: 0xb9 0x01 0x00
        let mut s = vec![0xb9, 0x01, 0x00];
        s.extend(vec![1u8; 256]);
        assert_eq!(bytes(decode_exact(&s).unwrap()).len(), 256);
        // long list
        let mut l = vec![0xf8, 56];
        l.extend(vec![0x01u8; 56]);
        let Item::List { payload, .. } = decode_exact(&l).unwrap() else {
            panic!()
        };
        assert_eq!(payload.len(), 56);
    }

    #[test]
    fn rejects_non_canonical_and_malformed() {
        // single byte < 0x80 in a string header
        assert_eq!(decode_exact(&[0x81, 0x7f]), Err(Error::InvalidRlp));
        assert_eq!(decode_exact(&[0x81, 0x00]), Err(Error::InvalidRlp));
        // long form for a length < 56
        let mut s = vec![0xb8, 55];
        s.extend(vec![7u8; 55]);
        assert_eq!(decode_exact(&s), Err(Error::InvalidRlp));
        let mut l = vec![0xf8, 5];
        l.extend(vec![1u8; 5]);
        assert_eq!(decode_exact(&l), Err(Error::InvalidRlp));
        // leading zero in the length
        let mut s = vec![0xb9, 0x00, 0x38];
        s.extend(vec![7u8; 56]);
        assert_eq!(decode_exact(&s), Err(Error::InvalidRlp));
        // truncated payload / truncated length / empty input
        assert_eq!(decode_exact(&[0x83, b'd', b'o']), Err(Error::InvalidRlp));
        assert_eq!(decode_exact(&[0xb9, 0x01]), Err(Error::InvalidRlp));
        assert_eq!(decode_exact(&[]), Err(Error::InvalidRlp));
        // trailing bytes
        assert_eq!(decode_exact(&[0x80, 0x80]), Err(Error::InvalidRlp));
        // length that overflows: 8 length bytes of 0xff
        let mut s = vec![0xbf];
        s.extend([0xffu8; 8]);
        assert_eq!(decode_exact(&s), Err(Error::InvalidRlp));
        // list whose child runs past the list payload: the outer header is fine, the child is
        // validated when the list is split
        let Item::List { payload, .. } = decode_exact(&[0xc2, 0x83, 0x01]).unwrap() else {
            panic!()
        };
        assert_eq!(split_list::<2>(payload).map(|_| ()), Err(Error::InvalidRlp));
    }

    #[test]
    fn split_list_limits_and_errors() {
        let Item::List { payload, .. } = decode_exact(&[0xc3, 0x01, 0x02, 0x03]).unwrap() else {
            panic!()
        };
        assert_eq!(split_list::<2>(payload).map(|_| ()), Err(Error::InvalidRlp));
        let (_, n) = split_list::<3>(payload).unwrap();
        assert_eq!(n, 3);
        // malformed inner item
        assert_eq!(
            split_list::<4>(&[0x81, 0x01]).map(|_| ()),
            Err(Error::InvalidRlp)
        );
    }

    #[test]
    fn canonical_uint_rules() {
        assert_eq!(canonical_uint(&[], 8), Ok(&[][..]));
        assert_eq!(canonical_uint(&[1, 0], 8), Ok(&[1u8, 0][..]));
        assert_eq!(canonical_uint(&[0], 8), Err(Error::InvalidRlp));
        assert_eq!(canonical_uint(&[0, 1], 8), Err(Error::InvalidRlp));
        assert_eq!(canonical_uint(&[1; 9], 8), Err(Error::InvalidRlp));
        assert_eq!(canonical_uint(&[1; 8], 8), Ok(&[1u8; 8][..]));
    }

    #[test]
    fn long_len_contract() {
        // 1..=8 length bytes; the input may be exactly `n` bytes long, or longer
        assert_eq!(long_len(&[0x38], 1), Ok(56));
        assert_eq!(long_len(&[0x01, 0x00], 2), Ok(256));
        assert_eq!(long_len(&[0x01, 0x02, 0x03], 3), Ok(0x01_02_03));
        assert_eq!(long_len(&[0x01, 0x02, 0x03, 0xff], 3), Ok(0x01_02_03));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(long_len(&[1, 0, 0, 0, 0, 0, 0, 0], 8), Ok(1usize << 56));
        // n outside 1..=8
        assert_eq!(long_len(&[1; 9], 0), Err(Error::InvalidRlp));
        assert_eq!(long_len(&[1; 9], 9), Err(Error::InvalidRlp));
        // fewer than `n` bytes available, or a leading zero byte
        assert_eq!(long_len(&[1], 2), Err(Error::InvalidRlp));
        assert_eq!(long_len(&[0, 1], 2), Err(Error::InvalidRlp));
    }
}
