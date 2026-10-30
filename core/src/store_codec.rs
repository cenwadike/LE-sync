//! Canonical, versioned encoding of `LightClientStore` (`no_std`, no alloc).
//!
//! Why it exists: the staged update (`update_job`) keeps the store between transactions, and a
//! job is bound to the exact store it was begun against by a digest of these bytes. The
//! encoding is therefore fixed-layout and canonical: one store has exactly one encoding, and
//! `decode_store` accepts nothing else.
//!
//! Layout, version 1 (all integers little-endian):
//!
//! ```text
//! version                       u8   = 1
//! finalized_header              112  slot:u64 proposer_index:u64 parent:32 state:32 body:32
//! optimistic_header             112
//! previous_max_active           u64
//! current_max_active            u64
//! current_sync_committee        len:u16, len * pubkey:48, aggregate_pubkey:48
//! next_sync_committee           len:u16, len * pubkey:48, aggregate_pubkey:48
//! ```
//!
//! Both committees have the same `len`, a power of two in `1..=MAX_SYNC_COMMITTEE_SIZE` (the
//! store invariant: `initialize_light_client_store` builds `next` with `current`'s length and
//! `validate_light_client_update` rejects any other size). Sizes: 3,413 bytes for 32 keys,
//! 49,493 for 512.
//!
//! Recorded decision: `best_valid_update` is NOT stored. It only feeds
//! `LightClientStore::force_update`, a liveness fallback after a full period without
//! finality; a store restored from these bytes starts with `None`. Keys past `len` are not
//! encoded and decode as zero.

use crate::sync::{LightClientStore, SyncCommittee};
use crate::{BeaconBlockHeader, Bytes32, Error, MAX_SYNC_COMMITTEE_SIZE};

/// The only version this crate reads or writes.
pub const STORE_CODEC_VERSION: u8 = 1;

/// Encoded `BeaconBlockHeader`: `8 + 8 + 32 + 32 + 32`.
pub const HEADER_LEN: usize = 112;

/// Encoded length of a store whose committees have `committee_len` keys.
pub const fn encoded_len(committee_len: usize) -> usize {
    1 + 2 * HEADER_LEN + 8 + 8 + 2 * (2 + 48 * committee_len + 48)
}

/// Encoded length at `MAX_SYNC_COMMITTEE_SIZE`: the buffer size that always suffices.
pub const MAX_ENCODED_LEN: usize = encoded_len(MAX_SYNC_COMMITTEE_SIZE);

fn valid_committee_len(n: usize) -> bool {
    n != 0 && n.is_power_of_two() && n <= MAX_SYNC_COMMITTEE_SIZE
}

fn put_header(sink: &mut impl FnMut(&[u8]), h: &BeaconBlockHeader) {
    sink(&h.slot.to_le_bytes());
    sink(&h.proposer_index.to_le_bytes());
    sink(&h.parent_root);
    sink(&h.state_root);
    sink(&h.body_root);
}

fn put_committee(sink: &mut impl FnMut(&[u8]), c: &SyncCommittee) {
    sink(&(c.len as u16).to_le_bytes());
    for k in c.keys() {
        sink(k);
    }
    sink(&c.aggregate_pubkey);
}

/// Feed the canonical encoding of `store` to `sink`, in order, in as many pieces as is
/// convenient. The single source of truth for the layout: `encode_store` copies the pieces
/// and `update_job::store_digest` hashes them. Fails with `StoreEncoding` (before calling
/// `sink`) if the committee lengths are not valid and equal.
pub fn write_store(store: &LightClientStore, mut sink: impl FnMut(&[u8])) -> Result<(), Error> {
    let n = store.current_sync_committee.len;
    if !valid_committee_len(n) || store.next_sync_committee.len != n {
        return Err(Error::StoreEncoding);
    }
    sink(&[STORE_CODEC_VERSION]);
    put_header(&mut sink, &store.finalized_header);
    put_header(&mut sink, &store.optimistic_header);
    sink(&store.previous_max_active_participants.to_le_bytes());
    sink(&store.current_max_active_participants.to_le_bytes());
    put_committee(&mut sink, &store.current_sync_committee);
    put_committee(&mut sink, &store.next_sync_committee);
    Ok(())
}

/// Encode `store` into `out` and return the number of bytes written (`encoded_len(n)`).
/// `StoreEncoding` if the store is not encodable or `out` is too small; `MAX_ENCODED_LEN`
/// bytes always suffice.
pub fn encode_store(store: &LightClientStore, out: &mut [u8]) -> Result<usize, Error> {
    let mut pos = 0usize;
    let mut overflow = false;
    write_store(store, |piece| {
        if pos + piece.len() <= out.len() {
            out[pos..pos + piece.len()].copy_from_slice(piece);
        } else {
            overflow = true;
        }
        pos += piece.len();
    })?;
    if overflow {
        return Err(Error::StoreEncoding);
    }
    Ok(pos)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::StoreEncoding)?;
        if end > self.bytes.len() {
            return Err(Error::StoreEncoding);
        }
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let mut b = [0u8; 8];
        b.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(b))
    }

    fn b32(&mut self) -> Result<Bytes32, Error> {
        let mut b = [0u8; 32];
        b.copy_from_slice(self.take(32)?);
        Ok(b)
    }

    fn header(&mut self) -> Result<BeaconBlockHeader, Error> {
        Ok(BeaconBlockHeader {
            slot: self.u64()?,
            proposer_index: self.u64()?,
            parent_root: self.b32()?,
            state_root: self.b32()?,
            body_root: self.b32()?,
        })
    }

    /// A committee of exactly `expect` keys if given, else of whatever valid length it states.
    fn committee(&mut self, expect: Option<usize>) -> Result<SyncCommittee, Error> {
        let mut l = [0u8; 2];
        l.copy_from_slice(self.take(2)?);
        let n = u16::from_le_bytes(l) as usize;
        if !valid_committee_len(n) || expect.is_some_and(|e| e != n) {
            return Err(Error::StoreEncoding);
        }
        let mut c = SyncCommittee::empty(n);
        for i in 0..n {
            c.pubkeys[i].copy_from_slice(self.take(48)?);
        }
        c.aggregate_pubkey.copy_from_slice(self.take(48)?);
        Ok(c)
    }
}

/// Decode a store. Accepts only the canonical v1 encoding: right version, valid equal
/// committee lengths, no truncation, no trailing bytes. Everything else is `StoreEncoding`.
/// The result has `best_valid_update == None`.
pub fn decode_store(bytes: &[u8]) -> Result<LightClientStore, Error> {
    if bytes.len() > MAX_ENCODED_LEN {
        return Err(Error::StoreEncoding);
    }
    let mut r = Reader { bytes, pos: 0 };
    if r.take(1)?[0] != STORE_CODEC_VERSION {
        return Err(Error::StoreEncoding);
    }
    let finalized_header = r.header()?;
    let optimistic_header = r.header()?;
    let previous_max_active_participants = r.u64()?;
    let current_max_active_participants = r.u64()?;
    let current_sync_committee = r.committee(None)?;
    let next_sync_committee = r.committee(Some(current_sync_committee.len))?;
    if r.pos != bytes.len() {
        return Err(Error::StoreEncoding);
    }
    Ok(LightClientStore {
        finalized_header,
        current_sync_committee,
        next_sync_committee,
        optimistic_header,
        previous_max_active_participants,
        current_max_active_participants,
        best_valid_update: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::tests::{fixture, leaf_n, N};
    use crate::sync::OwnedLightClientUpdate;

    fn enc(store: &LightClientStore) -> Vec<u8> {
        let mut out = vec![0u8; MAX_ENCODED_LEN];
        let n = encode_store(store, &mut out).unwrap();
        out.truncate(n);
        out
    }

    /// A store whose every field is distinct, so a swapped or dropped field shows.
    fn busy_store() -> LightClientStore {
        let mut s = fixture().store;
        s.finalized_header.slot = 0x0102_0304_0506_0708;
        s.finalized_header.proposer_index = 0x1112_1314_1516_1718;
        s.optimistic_header.slot = 0x2122_2324_2526_2728;
        s.optimistic_header.proposer_index = 0x3132_3334_3536_3738;
        s.previous_max_active_participants = 0x4142_4344_4546_4748;
        s.current_max_active_participants = 0x5152_5354_5556_5758;
        s.next_sync_committee = crate::sync::tests::committee(5);
        s
    }

    #[test]
    fn sizes_are_pinned() {
        assert_eq!(HEADER_LEN, 112);
        assert_eq!(encoded_len(32), 3_413);
        assert_eq!(encoded_len(512), 49_493);
        assert_eq!(MAX_ENCODED_LEN, 49_493);
        assert_eq!(enc(&busy_store()).len(), 3_413);
    }

    #[test]
    fn layout_is_byte_exact() {
        let s = busy_store();
        let b = enc(&s);
        assert_eq!(b[0], 1);
        assert_eq!(&b[1..9], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&b[9..17], &0x1112_1314_1516_1718u64.to_le_bytes());
        assert_eq!(&b[17..49], &s.finalized_header.parent_root);
        assert_eq!(&b[49..81], &s.finalized_header.state_root);
        assert_eq!(&b[81..113], &s.finalized_header.body_root);
        assert_eq!(&b[113..121], &0x2122_2324_2526_2728u64.to_le_bytes());
        assert_eq!(&b[121..129], &0x3132_3334_3536_3738u64.to_le_bytes());
        assert_eq!(&b[129..161], &s.optimistic_header.parent_root);
        assert_eq!(&b[161..193], &s.optimistic_header.state_root);
        assert_eq!(&b[193..225], &s.optimistic_header.body_root);
        assert_eq!(&b[225..233], &0x4142_4344_4546_4748u64.to_le_bytes());
        assert_eq!(&b[233..241], &0x5152_5354_5556_5758u64.to_le_bytes());
        assert_eq!(&b[241..243], &[32, 0]);
        assert_eq!(&b[243..291], &s.current_sync_committee.pubkeys[0]);
        let cur_agg = 243 + 32 * 48;
        assert_eq!(
            &b[cur_agg - 48..cur_agg],
            &s.current_sync_committee.pubkeys[31]
        );
        assert_eq!(
            &b[cur_agg..cur_agg + 48],
            &s.current_sync_committee.aggregate_pubkey
        );
        let next = cur_agg + 48;
        assert_eq!(&b[next..next + 2], &[32, 0]);
        assert_eq!(&b[next + 2..next + 50], &s.next_sync_committee.pubkeys[0]);
        let next_agg = next + 2 + 32 * 48;
        assert_eq!(
            &b[next_agg..next_agg + 48],
            &s.next_sync_committee.aggregate_pubkey
        );
        assert_eq!(next_agg + 48, b.len());
    }

    #[test]
    fn round_trips_and_drops_only_best_valid_update() {
        let f = fixture();
        let mut s = busy_store();
        let u = crate::sync::tests::upd(&f, 41);
        s.best_valid_update = Some(OwnedLightClientUpdate::from_borrowed(&u).unwrap());
        let d = decode_store(&enc(&s)).unwrap();
        assert_eq!(d.finalized_header, s.finalized_header);
        assert_eq!(d.optimistic_header, s.optimistic_header);
        assert_eq!(
            d.previous_max_active_participants,
            s.previous_max_active_participants
        );
        assert_eq!(
            d.current_max_active_participants,
            s.current_max_active_participants
        );
        assert_eq!(d.current_sync_committee, s.current_sync_committee);
        assert_eq!(d.next_sync_committee, s.next_sync_committee);
        assert!(d.best_valid_update.is_none());
        // canonical: re-encoding gives the same bytes
        assert_eq!(enc(&d), enc(&s));
    }

    #[test]
    fn full_size_committees_round_trip() {
        let mut s = busy_store();
        for (i, k) in s.current_sync_committee.pubkeys.iter_mut().enumerate() {
            k[..32].copy_from_slice(&leaf_n(i as u64));
        }
        s.current_sync_committee.len = 512;
        s.next_sync_committee = SyncCommittee::empty(512);
        s.next_sync_committee.pubkeys[511] = [9u8; 48];
        let b = enc(&s);
        assert_eq!(b.len(), 49_493);
        let d = decode_store(&b).unwrap();
        assert_eq!(d.current_sync_committee, s.current_sync_committee);
        assert_eq!(d.next_sync_committee, s.next_sync_committee);
    }

    #[test]
    fn empty_next_committee_round_trips_as_empty() {
        let s = fixture().store;
        assert!(!s.is_next_sync_committee_known());
        let d = decode_store(&enc(&s)).unwrap();
        assert!(!d.is_next_sync_committee_known());
        assert_eq!(d.next_sync_committee.len, N);
    }

    #[test]
    fn keys_past_len_are_not_encoded() {
        let mut s = busy_store();
        s.current_sync_committee.pubkeys[40] = [0xEE; 48]; // beyond len = 32
        assert_eq!(enc(&s), enc(&busy_store()));
    }

    #[test]
    fn encode_needs_exactly_the_encoded_length() {
        let s = busy_store();
        let mut exact = vec![0u8; 3_413];
        assert_eq!(encode_store(&s, &mut exact), Ok(3_413));
        let mut short = vec![0u8; 3_412];
        assert_eq!(encode_store(&s, &mut short), Err(Error::StoreEncoding));
        assert_eq!(encode_store(&s, &mut []), Err(Error::StoreEncoding));
        let mut roomy = vec![0u8; 5_000];
        assert_eq!(encode_store(&s, &mut roomy), Ok(3_413));
    }

    #[test]
    fn invalid_committee_lengths_cannot_be_encoded() {
        for bad in [0usize, 3, 24, 1024] {
            let mut s = busy_store();
            s.current_sync_committee.len = bad;
            s.next_sync_committee.len = bad;
            assert_eq!(
                encode_store(&s, &mut [0u8; MAX_ENCODED_LEN]),
                Err(Error::StoreEncoding),
                "len {bad}"
            );
        }
        let mut s = busy_store();
        s.next_sync_committee.len = 16;
        assert_eq!(
            encode_store(&s, &mut [0u8; MAX_ENCODED_LEN]),
            Err(Error::StoreEncoding)
        );
        // write_store fails before it emits anything
        let mut called = false;
        assert!(write_store(&s, |_| called = true).is_err());
        assert!(!called);
    }

    #[test]
    fn decode_rejects_every_truncation_and_any_trailing_byte() {
        let b = enc(&busy_store());
        for cut in 0..b.len() {
            assert_eq!(
                decode_store(&b[..cut]).err(),
                Some(Error::StoreEncoding),
                "cut {cut}"
            );
        }
        let mut longer = b.clone();
        longer.push(0);
        assert_eq!(decode_store(&longer).err(), Some(Error::StoreEncoding));
        assert!(decode_store(&b).is_ok());
        assert_eq!(
            decode_store(&vec![0u8; MAX_ENCODED_LEN + 1]).err(),
            Some(Error::StoreEncoding)
        );
    }

    #[test]
    fn decode_rejects_other_versions() {
        let b = enc(&busy_store());
        for v in [0u8, 2, 0xFF] {
            let mut c = b.clone();
            c[0] = v;
            assert_eq!(
                decode_store(&c).err(),
                Some(Error::StoreEncoding),
                "version {v}"
            );
        }
    }

    #[test]
    fn decode_rejects_bad_or_unequal_committee_lengths() {
        let b = enc(&busy_store());
        let cur_len_at = 241;
        let next_len_at = 241 + 2 + 32 * 48 + 48;
        for bad in [0u16, 24, 31, 33, 1024, 0xFFFF] {
            let mut c = b.clone();
            c[cur_len_at..cur_len_at + 2].copy_from_slice(&bad.to_le_bytes());
            assert_eq!(
                decode_store(&c).err(),
                Some(Error::StoreEncoding),
                "cur {bad}"
            );
            let mut c = b.clone();
            c[next_len_at..next_len_at + 2].copy_from_slice(&bad.to_le_bytes());
            assert_eq!(
                decode_store(&c).err(),
                Some(Error::StoreEncoding),
                "next {bad}"
            );
        }
        // 16 is a valid length on its own, but not equal to the other committee's
        let mut c = b.clone();
        c[next_len_at..next_len_at + 2].copy_from_slice(&16u16.to_le_bytes());
        assert_eq!(decode_store(&c).err(), Some(Error::StoreEncoding));
    }
}
