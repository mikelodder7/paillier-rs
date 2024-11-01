use super::*;
use crate::{error::*, utils::*};
use crypto_bigint::{
    modular::runtime_mod::*, ArrayEncoding, Concat, Encoding, NonZero, Uint, Zero,
};
use crypto_primes::RandomPrimeWithRng;
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A Paillier decryption key
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct DecryptionKey<const BASE: usize, const DUAL: usize, const QUAD: usize>
where
    Uint<BASE>: ArrayEncoding + Zeroize,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> + Zeroize,
    Uint<QUAD>: ArrayEncoding + Zeroize,
{
    #[zeroize(skip)]
    pub(crate) pk: EncryptionKey<BASE, DUAL, QUAD>,
    /// lcm(P - 1, Q - 1)
    pub(crate) lambda: Uint<DUAL>,
    /// Euler's totient: (P - 1)(Q - 1)
    pub(crate) totient: Uint<DUAL>,
    /// L((N + 1)^lambda mod N^2)-1 mod N
    pub(crate) u: Uint<QUAD>,
    /// The prime `p`
    pub(crate) p: Uint<BASE>,
    /// The prime `q`
    pub(crate) q: Uint<BASE>,
}

impl<const BASE: usize, const DUAL: usize, const QUAD: usize> Serialize
    for DecryptionKey<BASE, DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding + Zeroize,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> + Zeroize,
    Uint<QUAD>: ArrayEncoding + Zeroize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        CompressedDecryptionKey::<BASE>::from(self).serialize(serializer)
    }
}

impl<'de, const BASE: usize, const DUAL: usize, const QUAD: usize> Deserialize<'de>
    for DecryptionKey<BASE, DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding + Zeroize,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> + Zeroize,
    Uint<QUAD>: ArrayEncoding + Zeroize,
{
    fn deserialize<D>(deserializer: D) -> Result<DecryptionKey<BASE, DUAL, QUAD>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = CompressedDecryptionKey::<BASE>::deserialize(deserializer)?;
        Ok(DecryptionKey::from(&key))
    }
}

#[cfg(feature = "wasm")]
wasm_slice_impl!(DecryptionKey, Zeroize);

impl<const BASE: usize, const DUAL: usize, const QUAD: usize> DecryptionKey<BASE, DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding + Zeroize,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> + Zeroize,
    Uint<QUAD>: ArrayEncoding + Zeroize,
{
    /// Create a new random key
    pub fn random() -> PaillierResult<Self> {
        let mut p = Uint::<BASE>::generate_prime_with_rng(&mut OsRng, None);
        let mut q = Uint::<BASE>::generate_prime_with_rng(&mut OsRng, None);
        let res = Self::with_primes_unchecked(&p, &q);
        // Make sure the primes are zero'd
        p.zeroize();
        q.zeroize();
        res
    }

    /// Create a new key from two primes.
    /// `p` and `q` are checked if prime
    pub fn with_primes(p: &Uint<BASE>, q: &Uint<BASE>) -> PaillierResult<Self> {
        if !valid_primes(p, q) {
            return Err(PaillierError::InvalidPrimes);
        }
        Self::with_primes_unchecked(p, q)
    }

    /// Create a new key from two safe primes,
    /// `p` and `q` are not checked to see if they are safe primes
    pub fn with_primes_unchecked(p: &Uint<BASE>, q: &Uint<BASE>) -> PaillierResult<Self> {
        let p_wide = p.resize::<{ DUAL }>();
        let q_wide = q.resize::<{ DUAL }>();
        let pm1 = p_wide.wrapping_sub(&Uint::<DUAL>::ONE);
        let qm1 = q_wide.wrapping_sub(&Uint::<DUAL>::ONE);

        let modulus = p_wide.wrapping_mul(&q_wide);
        let nz_modulus = NonZero::from_uint(modulus);

        let pk = EncryptionKey::from_modulus(nz_modulus);
        let lambda = lcm(&pm1, &qm1);
        debug_assert!(!bool::from(lambda.is_zero()));
        let totient = pm1.wrapping_mul(&qm1);

        // (N+1)^lambda mod N^2
        let params = DynResidueParams::<QUAD>::new(&pk.modulus_squared);
        let mut t_value =
            DynResidue::new(&(pk.modulus_wide.wrapping_add(&Uint::<QUAD>::ONE)), params);
        t_value = t_value.pow(&lambda);

        // L((N+1)^lambda mod N^2)^-1 mod N
        let uu = pk.l(&t_value.retrieve())?;
        let (u, _ct) = uu.inv_odd_mod(&pk.modulus_wide);
        debug_assert!(bool::from(_ct));
        Ok(DecryptionKey {
            pk,
            lambda,
            totient,
            u,
            p: *p,
            q: *q,
        })
    }

    /// Reverse ciphertext to plaintext
    pub fn decrypt(&self, ciphertext: &Uint<QUAD>) -> PaillierResult<Vec<u8>> {
        if !bool::from(mod_in(ciphertext, &self.pk.modulus_squared)) {
            return Err(PaillierError::InvalidCiphertext);
        }

        // a = c^\lambda mod n^2
        let params = DynResidueParams::new(self.pk.modulus_squared.as_ref());
        let ciphertext = DynResidue::new(ciphertext, params);

        let a_value = ciphertext.pow(&self.lambda);
        // ell = L(a, N)
        let l_value = self.pk.l(&a_value.retrieve())?;
        // m = lu = L(a)*u = L(c^\lamba*)u mod n
        let modulus = DynResidueParams::new(self.pk.modulus_wide());
        let l_value = DynResidue::new(&l_value, modulus);
        let u_value = DynResidue::new(&self.u, modulus);

        let m = l_value * u_value;
        let m = m.retrieve();
        let bytes = m.to_be_bytes();
        let bytes_ref = bytes.as_ref();
        bytes_ref
            .iter()
            .position(|&x| x != 0)
            .map_or(Ok(Vec::new()), |i| Ok(bytes_ref[i..].to_vec()))
    }

    /// Get this key's byte representation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let compressed = CompressedDecryptionKey::<BASE>::from(self);
        postcard::to_stdvec(&compressed).expect("Failed to serialize")
    }

    /// Convert a byte representation to a decryption key
    pub fn from_bytes<B: AsRef<[u8]>>(data: B) -> PaillierResult<Self> {
        let compressed: CompressedDecryptionKey<BASE> = postcard::from_bytes(data.as_ref())?;
        Ok(Self::from(&compressed))
    }

    /// The Paillier modulus
    pub fn encryption_key(&self) -> &EncryptionKey<BASE, DUAL, QUAD> {
        &self.pk
    }

    /// The Paillier `lambda`
    pub fn lambda(&self) -> &Uint<DUAL> {
        &self.lambda
    }

    /// The Paillier `totient`
    pub fn totient(&self) -> &Uint<DUAL> {
        &self.totient
    }

    /// The Paillier `u` value
    pub fn u(&self) -> &Uint<QUAD> {
        &self.u
    }
}

/// The minimal representation of a Paillier decryption key
/// with no precomputation
#[derive(Debug, Clone, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct CompressedDecryptionKey<const BASE: usize>
where
    Uint<BASE>: ArrayEncoding + Zeroize,
{
    /// The prime `p`
    pub(crate) p: Uint<BASE>,
    /// The prime `q`
    pub(crate) q: Uint<BASE>,
}

impl<'de, const BASE: usize> Deserialize<'de> for CompressedDecryptionKey<BASE>
where
    Uint<BASE>: ArrayEncoding + Zeroize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
        struct InnerCompressedDecryptionKey<const BASE: usize>
        where
            Uint<BASE>: ArrayEncoding + Zeroize,
        {
            /// The prime `p`
            p: Uint<BASE>,
            /// The prime `q`
            q: Uint<BASE>,
        }

        let key = InnerCompressedDecryptionKey::deserialize(deserializer)?;
        if !valid_primes(&key.p, &key.q) {
            return Err(serde::de::Error::custom("Invalid primes"));
        }

        Ok(CompressedDecryptionKey { p: key.p, q: key.q })
    }
}

impl<const BASE: usize, const DUAL: usize, const QUAD: usize> From<&DecryptionKey<BASE, DUAL, QUAD>>
    for CompressedDecryptionKey<BASE>
where
    Uint<BASE>: ArrayEncoding + Zeroize,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> + Zeroize,
    Uint<QUAD>: ArrayEncoding + Zeroize,
{
    fn from(key: &DecryptionKey<BASE, DUAL, QUAD>) -> Self {
        Self { p: key.p, q: key.q }
    }
}

impl<const BASE: usize, const DUAL: usize, const QUAD: usize> From<&CompressedDecryptionKey<BASE>>
    for DecryptionKey<BASE, DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding + Zeroize,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> + Zeroize,
    Uint<QUAD>: ArrayEncoding + Zeroize,
{
    fn from(key: &CompressedDecryptionKey<BASE>) -> Self {
        DecryptionKey::with_primes_unchecked(&key.p, &key.q).expect("Invalid primes")
    }
}

fn valid_primes<const LIMBS: usize>(p: &Uint<LIMBS>, q: &Uint<LIMBS>) -> bool {
    // Paillier doesn't work if p == q
    p.bits() == q.bits()
        || p != q
        || p.bits() == Uint::<LIMBS>::BITS
        || p.is_prime_with_rng(&mut OsRng)
        || q.is_prime_with_rng(&mut OsRng)
}
