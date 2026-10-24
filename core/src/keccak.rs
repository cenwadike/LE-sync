//! Keccak-256 (the original Keccak padding used by Ethereum, NOT NIST SHA3-256).
//!
//! This is the only place the crate touches a keccak implementation, so swapping to a
//! risc0-accelerated crate (or a patched `tiny-keccak`) is a change to this file alone.
//! Whether risc0 3.0.5 offers an accelerated keccak that applies to this crate is NOT
//! confirmed here; check it before the Sprint 6 cycle measurement.

use crate::Bytes32;
use tiny_keccak::{Hasher, Keccak};

pub fn keccak256(data: &[u8]) -> Bytes32 {
    let mut h = Keccak::v256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// `keccak256(rlp(""))`: the root of an empty trie (also the `storageRoot` of an account
/// with no storage).
pub const EMPTY_TRIE_ROOT: Bytes32 = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// `keccak256("")`: the `codeHash` of an account with no code.
pub const EMPTY_CODE_HASH: Bytes32 = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // keccak256("") and keccak256(rlp("")) = keccak256(0x80): well-known Ethereum constants.
        assert_eq!(keccak256(b""), EMPTY_CODE_HASH);
        assert_eq!(keccak256(&[0x80]), EMPTY_TRIE_ROOT);
    }

    #[test]
    fn is_keccak_not_sha3() {
        // NIST SHA3-256("") starts a7ffc6f8...; Ethereum's keccak256("") starts c5d24601...
        assert_eq!(keccak256(b"")[0], 0xc5);
    }
}
