use crate::*;
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{NonZero, RandomMod, Uint, Zero};
use std::{cmp, mem};
use subtle::{Choice, ConstantTimeLess};

pub fn mod_in<const LIMBS: usize>(a: &Uint<LIMBS>, n: &Uint<LIMBS>) -> Choice {
    !a.is_zero() & a.ct_lt(n)
}

pub fn gcd<const LIMBS: usize>(lhs: &Uint<LIMBS>, rhs: &Uint<LIMBS>) -> Uint<LIMBS> {
    // borrowed from num-bigint/src/biguint.rs

    // Stein's algorithm
    if lhs.is_zero().into() {
        return *rhs;
    }
    if rhs.is_zero().into() {
        return *lhs;
    }
    let mut m = *lhs;
    let mut n = *rhs;

    // find common factors of 2
    let shift = cmp::min(n.trailing_zeros(), m.trailing_zeros());

    // divide m and n by 2 until odd
    // m inside loop
    n >>= n.trailing_zeros();

    while !bool::from(m.is_zero()) {
        m >>= m.trailing_zeros();
        if n > m {
            mem::swap(&mut n, &mut m)
        }
        m = m.wrapping_sub(&n);
    }

    n << shift
}

pub fn lcm<const LIMBS: usize>(lhs: &Uint<LIMBS>, rhs: &Uint<LIMBS>) -> Uint<LIMBS> {
    (lhs / NonZero::from_uint(gcd(lhs, rhs))).wrapping_mul(rhs)
}

pub fn random_range_with_rng<const LIMBS: usize>(
    lower: &Uint<LIMBS>,
    upper: &Uint<LIMBS>,
    rng: &mut impl CryptoRngCore,
) -> Uint<LIMBS> {
    if lower >= upper {
        panic!("lower bound is greater than or equal to upper bound");
    }
    let range = upper.wrapping_sub(lower);
    if range.is_zero().into() {
        return Uint::<LIMBS>::ZERO;
    }
    let rr = Uint::<LIMBS>::random_mod(rng, &NonZero::from_uint(range));
    lower.wrapping_add(&rr)
}

/// Convert a byte sequence to a `Uint` with a fixed number of limbs
///
/// The byte sequence is expected to be in big-endian format.
/// If the byte sequence is larger than the number of limbs, an error is returned.
/// If the byte sequence is smaller than the number of limbs, it is zero-padded.
pub fn var_bytes_to_uint<B: AsRef<[u8]>, const LIMBS: usize>(b: B) -> PaillierResult<Uint<LIMBS>> {
    let b = b.as_ref();
    if b.len() > Uint::<LIMBS>::BYTES {
        return Err(PaillierError::InvalidEncryptionInputs);
    }
    let mut bytes = vec![0u8; Uint::<LIMBS>::BYTES];
    bytes[Uint::<LIMBS>::BYTES - b.len()..].copy_from_slice(b);

    Ok(Uint::<LIMBS>::from_be_slice(&bytes))
}
