//! `Bls` implementations for the guest. Enable exactly one of `bls-zk` / `bls-blst`.
//!
//! Extra features (both off by default):
//! * `cycle-trace`: the guest logs a per-phase cycle breakdown of every aggregate verify
//!   (needs `risc0-zkvm`, so guest builds only).
//! * `unchecked-pubkeys`: only affects `bls-blst`. The `bls-zk` path never subgroup-checks
//!   committee keys (see SECURITY JUDGEMENT below).
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

/// Option B: risc0-patched `blst`. Ignores `aggregate_pubkey` (blst aggregates internally).
/// Currently panics in the guest (`RUST_MIN_STACK` / sys_getenv); kept only so the feature builds.
#[cfg(feature = "bls-blst")]
impl Bls for Impl {
    fn fast_aggregate_verify(
        &self,
        committee: &[BlsPubkey],
        _aggregate_pubkey: &BlsPubkey,
        bits: &[u8],
        msg: &Bytes32,
        sig: &BlsSignature,
    ) -> bool {
        use blst::min_pk::{PublicKey, Signature};
        let t0 = cc();
        let Ok(sig) = Signature::from_bytes(sig) else {
            return false;
        };
        let mut keys = Vec::new();
        for (i, k) in committee.iter().enumerate() {
            if bits[i / 8] >> (i % 8) & 1 == 1 {
                #[cfg(not(feature = "unchecked-pubkeys"))]
                let r = PublicKey::key_validate(k);
                #[cfg(feature = "unchecked-pubkeys")]
                let r = PublicKey::uncompress(k);
                match r {
                    Ok(p) => keys.push(p),
                    Err(_) => return false,
                }
            }
        }
        if keys.is_empty() {
            return false;
        }
        let t_keys = cc();
        let refs: Vec<&PublicKey> = keys.iter().collect();
        let ok = sig.fast_aggregate_verify(true, msg, DST, &refs) == blst::BLST_ERROR::BLST_SUCCESS;
        let t_v = cc();
        trace!(
            "bls-blst cycles: total={} keys={} key_decode={} fast_aggregate_verify={}",
            t_v - t0,
            keys.len(),
            t_keys - t0,
            t_v - t_keys
        );
        ok
    }
}
