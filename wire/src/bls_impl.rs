//! Option B: risc0-patched `blst`. Ignores `aggregate_pubkey` (blst aggregates internally).
//! Currently panics in the guest (`RUST_MIN_STACK` / sys_getenv); kept only so the feature
//! builds. Excluded from mutation testing in `.cargo/mutants.toml`.
use super::*;

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
