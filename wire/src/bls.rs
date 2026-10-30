//! `Bls` implementations for the guest. Enable exactly one of `bls-zk` / `bls-blst`.
//!
//! Extra features (both off by default):
//! * `cycle-trace`: the guest logs a per-phase cycle breakdown of every aggregate verify
//!   (needs `risc0-zkvm`, so guest builds only).
//! * `unchecked-pubkeys`: no effect any more. Neither backend subgroup-checks committee keys
//!   (see SECURITY JUDGEMENT below); kept so existing manifests still resolve.
//!
//! `bls-blst` also implements `le_sync_core::update_job::StagedBls`: the same check in three
//! stages (prepare, Miller loop, final exponentiation) for the three-transaction update.
//!
//! SECURITY JUDGEMENT (bls-zk): the committee pubkeys and `aggregate_pubkey` are authenticated
//! by a Merkle branch to the trusted state root, and were proof-of-possession-checked at
//! deposit, so they are already known to be valid group elements. We therefore only decompress
//! (on-curve) and skip the per-key subgroup check. The signature's subgroup check and the
//! identity check on the final aggregate are kept.
//! The aggregate trick additionally relies on the consensus rule
//! `aggregate_pubkey == eth_aggregate_pubkeys(pubkeys)` (get_next_sync_committee).
#![allow(unused_imports, unused_variables)]
use le_sync_core::sync::{Bls, BlsSignature};
use le_sync_core::{BlsPubkey, Bytes32};

/// Ethereum BLS ciphersuite (min-pk, proof-of-possession).
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub struct Impl;

#[allow(unused_macros)]
macro_rules! trace {
    ($($a:tt)*) => {{
        #[cfg(feature = "cycle-trace")]
        risc0_zkvm::guest::env::log(&format!($($a)*));
    }};
}

#[allow(dead_code)]
#[inline(always)]
fn cc() -> u64 {
    #[cfg(feature = "cycle-trace")]
    {
        risc0_zkvm::guest::env::cycle_count()
    }
    #[cfg(not(feature = "cycle-trace"))]
    {
        0
    }
}

/// Option B (risc0-patched `blst`, staged) lives in its own file, `bls/blst_impl.rs`.
#[cfg(feature = "bls-blst")]
mod blst_impl;

/// On-curve decompression only. Subgroup membership comes from the authenticated committee.
#[cfg(feature = "bls-zk")]
fn decompress(pk: &BlsPubkey) -> Option<bls12_381::G1Projective> {
    let p: Option<bls12_381::G1Affine> = bls12_381::G1Affine::from_compressed_unchecked(pk).into();
    p.map(Into::into)
}

/// Option A: spec FastAggregateVerify on the accelerated `bls12_381` crate.
///   aggPK = aggregate_pubkey - sum(absent)   (or sum(present) when most signers are absent)
///   accept iff e(aggPK, H(msg)) * e(-G1, sig) == 1   (one multi-Miller loop, one final exp)
#[cfg(feature = "bls-zk")]
impl Bls for Impl {
    fn fast_aggregate_verify(
        &self,
        committee: &[BlsPubkey],
        aggregate_pubkey: &BlsPubkey,
        bits: &[u8],
        msg: &Bytes32,
        sig: &BlsSignature,
    ) -> bool {
        use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
        use bls12_381::{
            multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
        };

        let total = committee.len();
        if total == 0 || bits.len() * 8 != total {
            return false;
        }

        let t0 = cc();
        // from_compressed checks on-curve + subgroup. Kept: the signature is untrusted input.
        let sig: Option<G2Affine> = G2Affine::from_compressed(sig).into();
        let Some(sig) = sig else { return false };
        let t_sig = cc();

        let set = |i: usize| (bits[i / 8] >> (i % 8)) & 1 == 1;
        let present = (0..total).filter(|&i| set(i)).count();
        if present == 0 {
            return false;
        }
        let absent = total - present;

        let agg: G1Projective = if absent < present {
            let Some(mut a) = decompress(aggregate_pubkey) else {
                return false;
            };
            for i in (0..total).filter(|&i| !set(i)) {
                let Some(p) = decompress(&committee[i]) else {
                    return false;
                };
                a = a - p;
            }
            a
        } else {
            let mut a = G1Projective::identity();
            for i in (0..total).filter(|&i| set(i)) {
                let Some(p) = decompress(&committee[i]) else {
                    return false;
                };
                a = a + p;
            }
            a
        };
        let agg = G1Affine::from(agg);
        if bool::from(agg.is_identity()) {
            return false;
        }
        let t_agg = cc();

        let h = G2Affine::from(<G2Projective as HashToCurve<
            ExpandMsgXmd<sha2_09::Sha256>,
        >>::hash_to_curve(msg, DST));
        let t_h = cc();

        let neg_g1 = -G1Affine::generator();
        let h_prep = G2Prepared::from(h);
        let sig_prep = G2Prepared::from(sig);
        let ok = multi_miller_loop(&[(&agg, &h_prep), (&neg_g1, &sig_prep)]).final_exponentiation()
            == Gt::identity();
        let t_p = cc();

        trace!(
            "bls-zk cycles: total={} sig={} present={} absent={} agg={} hash_to_curve={} pairing={}",
            t_p - t0, t_sig - t0, present, absent, t_agg - t_sig, t_h - t_agg, t_p - t_h
        );
        ok
    }
}

// ---- Direct unit tests for the bls-zk Impl (cargo-mutants: hit every branch) ---------------
//
// Two separate `cfg` attributes on purpose: cargo-mutants recognises a bare `#[cfg(test)]`
// module as test code and does not mutate it; it does not recognise `cfg(all(test, ...))`.
//
// Which inputs each path trusts (this is what the `<` / `<=` mutants are killed by):
//   subtract-absents (absent < present): decompresses `aggregate_pubkey` + every ABSENT key;
//                                        present keys are never decompressed.
//   sum-presents (otherwise, incl. an exact tie): decompresses every PRESENT key;
//                                        `aggregate_pubkey` and absent keys are never touched.
#[cfg(test)]
#[cfg(feature = "bls-zk")]
mod tests {
    use super::*;
    use le_sync_testkit as tk;

    const N: usize = 8;
    const BAD: BlsPubkey = [0xFFu8; 48]; // not a valid compressed G1 point

    fn verify(
        c: &tk::Committee,
        pks: &[BlsPubkey],
        agg: &BlsPubkey,
        bits: &[u8],
        msg: &Bytes32,
        sig: &BlsSignature,
    ) -> bool {
        let _ = c;
        Impl.fast_aggregate_verify(pks, agg, bits, msg, sig)
    }

    /// Honest committee + a valid signature by exactly `bits`.
    fn signed(seed: u32, bits: &[u8], msg: &Bytes32) -> (tk::Committee, BlsSignature) {
        let c = tk::committee(seed, N);
        let sig = c.sign(bits, msg);
        (c, sig)
    }

    fn with_key(c: &tk::Committee, i: usize, k: BlsPubkey) -> Vec<BlsPubkey> {
        let mut p = c.pubkeys.clone();
        p[i] = k;
        p
    }

    #[test]
    fn dst_matches_the_independent_testkit_constant() {
        assert_eq!(DST, tk::DST);
    }

    #[test]
    fn full_participation_accepts() {
        let msg = [0x11u8; 32];
        let bits = tk::bits_set(N, N);
        let (c, sig) = signed(1, &bits, &msg);
        assert!(verify(&c, &c.pubkeys, &c.aggregate, &bits, &msg, &sig));
    }

    #[test]
    fn scattered_bits_accept_on_both_paths() {
        let msg = [0x22u8; 32];
        // 3 present / 5 absent -> sum-presents; non-contiguous so bit-index arithmetic matters
        let sparse = tk::bits_from(N, &[1, 4, 6]);
        let (c, sig) = signed(2, &sparse, &msg);
        assert!(verify(&c, &c.pubkeys, &c.aggregate, &sparse, &msg, &sig));
        // 7 present / 1 absent -> subtract-absents
        let dense = tk::bits_from(N, &[0, 1, 2, 4, 5, 6, 7]);
        let (c, sig) = signed(3, &dense, &msg);
        assert!(verify(&c, &c.pubkeys, &c.aggregate, &dense, &msg, &sig));
        // the same signature does not verify for a different selection
        assert!(!verify(&c, &c.pubkeys, &c.aggregate, &sparse, &msg, &sig));
    }

    #[test]
    fn bits_spanning_two_bytes_select_the_right_members() {
        // 16-member committee, bits straddle the byte boundary (indices 7, 8, 15)
        let msg = [0x23u8; 32];
        let c = tk::committee(4, 16);
        let bits = tk::bits_from(16, &[7, 8, 15]);
        let sig = c.sign(&bits, &msg);
        assert!(verify(&c, &c.pubkeys, &c.aggregate, &bits, &msg, &sig));
        let off_by_one = tk::bits_from(16, &[6, 8, 15]);
        assert!(!verify(
            &c,
            &c.pubkeys,
            &c.aggregate,
            &off_by_one,
            &msg,
            &sig
        ));
    }

    #[test]
    fn sum_path_ignores_aggregate_and_absent_keys_but_not_present_keys() {
        let msg = [0x24u8; 32];
        let bits = tk::bits_from(N, &[1, 4, 6]); // 3 present, 5 absent
        let (c, sig) = signed(5, &bits, &msg);
        // aggregate never decompressed on this path
        assert!(verify(&c, &c.pubkeys, &BAD, &bits, &msg, &sig));
        // an ABSENT key is never decompressed
        assert!(verify(
            &c,
            &with_key(&c, 0, BAD),
            &c.aggregate,
            &bits,
            &msg,
            &sig
        ));
        // a PRESENT key must decompress
        assert!(!verify(
            &c,
            &with_key(&c, 4, BAD),
            &c.aggregate,
            &bits,
            &msg,
            &sig
        ));
    }

    #[test]
    fn exact_tie_takes_the_sum_path() {
        // 4 present / 4 absent: `absent < present` is false, so sum-presents. A `<=` mutant
        // would take subtract-absents and reject the garbage aggregate below.
        let msg = [0x25u8; 32];
        let bits = tk::bits_from(N, &[0, 2, 4, 6]);
        let (c, sig) = signed(6, &bits, &msg);
        assert!(verify(&c, &c.pubkeys, &c.aggregate, &bits, &msg, &sig));
        assert!(verify(&c, &c.pubkeys, &BAD, &bits, &msg, &sig));
        assert!(verify(
            &c,
            &with_key(&c, 1, BAD),
            &c.aggregate,
            &bits,
            &msg,
            &sig
        ));
    }

    #[test]
    fn subtract_path_trusts_aggregate_and_absent_keys_not_present_keys() {
        let msg = [0x26u8; 32];
        let bits = tk::bits_from(N, &[0, 1, 2, 4, 5, 6, 7]); // 7 present, 1 absent (index 3)
        let (c, sig) = signed(7, &bits, &msg);
        // the aggregate must decompress
        assert!(!verify(&c, &c.pubkeys, &BAD, &bits, &msg, &sig));
        // the ABSENT key must decompress
        assert!(!verify(
            &c,
            &with_key(&c, 3, BAD),
            &c.aggregate,
            &bits,
            &msg,
            &sig
        ));
        // a PRESENT key is never decompressed here: the aggregate stands in for them. This pins
        // the documented reliance on `aggregate_pubkey == sum(pubkeys)` being committed.
        assert!(verify(
            &c,
            &with_key(&c, 0, BAD),
            &c.aggregate,
            &bits,
            &msg,
            &sig
        ));
    }

    #[test]
    fn aggregate_inconsistent_with_keys_is_rejected_on_the_subtract_path() {
        let msg = [0x27u8; 32];
        let bits = tk::bits_set(N, N);
        let (c, sig) = signed(8, &bits, &msg);
        let wrong_agg = tk::committee(80, N).aggregate;
        assert!(!verify(&c, &c.pubkeys, &wrong_agg, &bits, &msg, &sig));
    }

    #[test]
    fn zero_participants_rejected_before_pairing() {
        let (c, _) = signed(9, &tk::bits_set(N, N), &[0u8; 32]);
        let bits = tk::bits_set(N, 0);
        assert!(!verify(
            &c,
            &c.pubkeys,
            &c.aggregate,
            &bits,
            &[0x44; 32],
            &[0u8; 96]
        ));
    }

    #[test]
    fn empty_committee_or_bits_length_mismatch_rejected() {
        let msg = [0x55u8; 32];

        // Empty committee: rejected regardless of signature.
        assert!(!Impl.fast_aggregate_verify(&[], &[0u8; 48], &[], &msg, &[0u8; 96]));

        // Valid signature by the full committee, so ONLY the length guard can reject below.
        let bits = tk::bits_set(N, N); // 1 byte for N = 8
        let (c, sig) = signed(10, &bits, &msg);
        assert!(verify(&c, &c.pubkeys, &c.aggregate, &bits, &msg, &sig)); // sanity: accepts

        // Too many bytes: first 8 bits are all set, so without the guard this would verify.
        assert!(!verify(
            &c,
            &c.pubkeys,
            &c.aggregate,
            &[0xFF, 0xFF],
            &msg,
            &sig
        ));
        assert!(!verify(
            &c,
            &c.pubkeys,
            &c.aggregate,
            &[0xFF, 0x00],
            &msg,
            &sig
        ));

        // Too few bytes (16-member committee, 1-byte bitfield). Valid signature by members 0..8.
        let c16 = tk::committee(14, 16);
        let bits16 = tk::bits_from(16, &[0, 1, 2, 3, 4, 5, 6, 7]);
        let sig16 = c16.sign(&bits16, &msg);
        assert!(verify(
            &c16,
            &c16.pubkeys,
            &c16.aggregate,
            &bits16,
            &msg,
            &sig16
        )); // sanity
        assert!(!verify(
            &c16,
            &c16.pubkeys,
            &c16.aggregate,
            &bits16[..1],
            &msg,
            &sig16
        ));
    }

    #[test]
    fn infinity_and_garbage_signatures_rejected() {
        let msg = [0x66u8; 32];
        let bits = tk::bits_set(N, N);
        let c = tk::committee(11, N);
        // all-zero bytes: compression flag unset, not a valid encoding
        assert!(!verify(
            &c,
            &c.pubkeys,
            &c.aggregate,
            &bits,
            &msg,
            &[0u8; 96]
        ));
        // the real encoding of the point at infinity is a valid G2 element but proves nothing
        let mut infinity = [0u8; 96];
        infinity[0] = 0xC0;
        assert!(!verify(
            &c,
            &c.pubkeys,
            &c.aggregate,
            &bits,
            &msg,
            &infinity
        ));
        assert!(!verify(
            &c,
            &c.pubkeys,
            &c.aggregate,
            &bits,
            &msg,
            &[0xFFu8; 96]
        ));
    }

    #[test]
    fn wrong_message_and_wrong_keys_rejected() {
        let msg = [0xAAu8; 32];
        let bits = tk::bits_set(N, N);
        let (c, sig) = signed(12, &bits, &msg);
        assert!(!verify(
            &c,
            &c.pubkeys,
            &c.aggregate,
            &bits,
            &[0xBB; 32],
            &sig
        ));
        // A wholly different committee (keys AND its matching aggregate) must not verify.
        // Passing `c.aggregate` here would not work: on the subtract path the aggregate stands
        // in for all present keys, so `other.pubkeys` would never be consulted.
        let other = tk::committee(99, N);
        assert!(!verify(
            &c,
            &other.pubkeys,
            &other.aggregate,
            &bits,
            &msg,
            &sig
        ));
    }

    #[test]
    fn single_flipped_signature_bit_is_rejected() {
        let msg = [0xCCu8; 32];
        let bits = tk::bits_set(N, N);
        let (c, mut sig) = signed(13, &bits, &msg);
        assert!(verify(&c, &c.pubkeys, &c.aggregate, &bits, &msg, &sig));
        sig[95] ^= 1;
        assert!(!verify(&c, &c.pubkeys, &c.aggregate, &bits, &msg, &sig));
    }
}
