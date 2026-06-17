//! Field-element conversion and Poseidon2 hashing helpers.
//!
//! These mirror the Go reference's use of `goldilocks` field elements and
//! `poseidon2_goldilocks_plonky2`. All hashing ultimately goes through the
//! [`poseidon-hash`] crate, whose `hash_to_quintic_extension` is byte-identical
//! to Go's `p2.HashToQuinticExtension`.

use poseidon_hash::{hash_no_pad, hash_to_quintic_extension, Fp5Element, Goldilocks, HashOut};

use crate::constants::HASH_LENGTH;
use crate::error::{Error, Result};

/// Converts a protocol value into a Goldilocks field element using the exact
/// semantics of Go's `g.GoldilocksField(x)` conversion.
///
/// Go reinterprets the integer as a `uint64` (sign-extending signed types) and
/// keeps the possibly non-canonical value; the Poseidon2 permutation reduces it
/// modulo the field prime. Feeding the canonical representative
/// (`from_noncanonical_u64`) into the same permutation yields identical output.
pub trait IntoField {
    /// The `uint64` bit pattern Go would produce for `GoldilocksField(self)`.
    fn gf_bits(self) -> u64;
}

macro_rules! into_field_unsigned {
    ($($t:ty),*) => {$(
        impl IntoField for $t {
            #[inline]
            fn gf_bits(self) -> u64 { self as u64 }
        }
    )*};
}
macro_rules! into_field_signed {
    ($($t:ty),*) => {$(
        impl IntoField for $t {
            #[inline]
            fn gf_bits(self) -> u64 { self as i64 as u64 }
        }
    )*};
}
into_field_unsigned!(u8, u16, u32, u64);
into_field_signed!(i8, i16, i32, i64);

/// Builds a Goldilocks element from any protocol integer.
#[inline]
pub fn gf<T: IntoField>(value: T) -> Goldilocks {
    Goldilocks::from_noncanonical_u64(value.gf_bits())
}

/// `p2.HashToQuinticExtension` — sponge over the input, squeezing 5 elements.
#[inline]
pub fn hash_to_fp5(elems: &[Goldilocks]) -> Fp5Element {
    hash_to_quintic_extension(elems)
}

/// `p2.HashNoPad` — 4-element Poseidon2 digest.
#[inline]
pub fn hash_digest(elems: &[Goldilocks]) -> HashOut {
    hash_no_pad(elems)
}

/// `p2.HashTwoToOne` — compresses two 4-element digests into one.
#[inline]
pub fn hash_two_to_one(a: &HashOut, b: &HashOut) -> HashOut {
    let input = [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]];
    hash_no_pad(&input)
}

/// `p2.HashNToOne` — left-folds a list of digests with [`hash_two_to_one`].
pub fn hash_n_to_one(inputs: &[HashOut]) -> HashOut {
    debug_assert!(!inputs.is_empty());
    let mut res = inputs[0];
    if inputs.len() == 1 {
        return res;
    }
    res = hash_two_to_one(&inputs[0], &inputs[1]);
    for next in &inputs[2..] {
        res = hash_two_to_one(&res, next);
    }
    res
}

/// Converts arbitrary bytes into Goldilocks elements exactly like Go's
/// `g.ArrayFromCanonicalLittleEndianBytes`: 8-byte little-endian chunks with the
/// final chunk zero-padded. Each chunk must be a canonical field element.
///
/// Used to hash the auth-token message string.
pub fn bytes_to_field_elems(bytes: &[u8]) -> Result<Vec<Goldilocks>> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(8));
    for chunk in bytes.chunks(8) {
        let mut b = [0u8; 8];
        b[..chunk.len()].copy_from_slice(chunk);
        let v = u64::from_le_bytes(b);
        if v >= Goldilocks::MODULUS {
            return Err(Error::Crypto(
                "non-canonical chunk while hashing message".to_string(),
            ));
        }
        out.push(Goldilocks::from_noncanonical_u64(v));
    }
    Ok(out)
}

/// Serializes an `Fp5Element` to 40 little-endian bytes (canonical limbs).
#[inline]
pub fn fp5_to_le_bytes(e: &Fp5Element) -> [u8; HASH_LENGTH] {
    let mut out = [0u8; HASH_LENGTH];
    out.copy_from_slice(&e.to_bytes_le());
    out
}

/// Parses an `Fp5Element` from 40 canonical little-endian bytes.
///
/// Every 8-byte limb must be `< MODULUS`, matching Go's
/// `gFp5.FromCanonicalLittleEndianBytes`.
pub fn fp5_from_canonical_le_bytes(bytes: &[u8]) -> Result<Fp5Element> {
    if bytes.len() != HASH_LENGTH {
        return Err(Error::PubKeyInvalid);
    }
    for chunk in bytes.chunks(8) {
        let mut b = [0u8; 8];
        b.copy_from_slice(chunk);
        if u64::from_le_bytes(b) >= Goldilocks::MODULUS {
            return Err(Error::PubKeyInvalid);
        }
    }
    Fp5Element::from_bytes_le(bytes).map_err(|_| Error::PubKeyInvalid)
}
