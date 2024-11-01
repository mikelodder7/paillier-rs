use super::*;
use crate::{error::*, utils::*};
use crypto_bigint::{
    modular::runtime_mod::*, ArrayEncoding, Concat, Encoding, NonZero, RandomMod, Uint,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::marker::PhantomData;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A compressed Paillier encryption key that only stores the modulus
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CompressedEncryptionKey<const DUAL: usize, const QUAD: usize>(
    pub(crate) NonZero<Uint<DUAL>>,
)
where
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding;

impl<const BASE: usize, const DUAL: usize, const QUAD: usize> From<EncryptionKey<BASE, DUAL, QUAD>>
    for CompressedEncryptionKey<DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    fn from(key: EncryptionKey<BASE, DUAL, QUAD>) -> Self {
        Self::from(&key)
    }
}

impl<const BASE: usize, const DUAL: usize, const QUAD: usize> From<&EncryptionKey<BASE, DUAL, QUAD>>
    for CompressedEncryptionKey<DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    fn from(key: &EncryptionKey<BASE, DUAL, QUAD>) -> Self {
        Self(key.modulus)
    }
}

impl<const BASE: usize, const DUAL: usize, const QUAD: usize>
    From<CompressedEncryptionKey<DUAL, QUAD>> for EncryptionKey<BASE, DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    fn from(key: CompressedEncryptionKey<DUAL, QUAD>) -> Self {
        Self::from(&key)
    }
}

impl<const BASE: usize, const DUAL: usize, const QUAD: usize>
    From<&CompressedEncryptionKey<DUAL, QUAD>> for EncryptionKey<BASE, DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    fn from(key: &CompressedEncryptionKey<DUAL, QUAD>) -> Self {
        Self::from_modulus(key.0)
    }
}

impl<const BASE: usize, const DUAL: usize, const QUAD: usize> From<&CompressedDecryptionKey<BASE>>
    for CompressedEncryptionKey<DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding + Zeroize,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> + Zeroize,
    Uint<QUAD>: ArrayEncoding + Zeroize,
{
    fn from(sk: &CompressedDecryptionKey<BASE>) -> CompressedEncryptionKey<DUAL, QUAD> {
        let p_wide = sk.p.resize::<{ DUAL }>();
        let q_wide = sk.q.resize::<{ DUAL }>();
        CompressedEncryptionKey(NonZero::from_uint(p_wide.wrapping_mul(&q_wide)))
    }
}

impl<const DUAL: usize, const QUAD: usize> CompressedEncryptionKey<DUAL, QUAD>
where
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    /// Get this key's byte representation
    pub fn to_bytes(self) -> Vec<u8> {
        self.0.as_ref().to_be_bytes().as_ref().to_vec()
    }

    /// Convert a byte representation to an encryption key
    pub fn from_slice<B: AsRef<[u8]>>(data: B) -> PaillierResult<Self> {
        let data = data.as_ref();
        if data.len() != Uint::<DUAL>::BYTES {
            return Err(PaillierError::InvalidEncryptionKey);
        }
        let modulus = Uint::<DUAL>::from_be_slice(data);
        Ok(Self(NonZero::from_uint(modulus)))
    }
}

/// A Paillier encryption key that also stores any precomputations
#[derive(Copy, Clone, Debug)]
pub struct EncryptionKey<const BASE: usize, const DUAL: usize, const QUAD: usize>
where
    Uint<BASE>: ArrayEncoding,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    pub(crate) modulus: NonZero<Uint<DUAL>>, // N = p * q, where p,q are primes
    pub(crate) modulus_wide: NonZero<Uint<QUAD>>, // N but fits in a wide message
    pub(crate) modulus_squared: NonZero<Uint<QUAD>>, // N^2
    pub(crate) _marker: PhantomData<Uint<BASE>>,
}

#[cfg(feature = "wasm")]
wasm_slice_impl!(EncryptionKey);

impl<const BASE: usize, const DUAL: usize, const QUAD: usize> Serialize
    for EncryptionKey<BASE, DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        CompressedEncryptionKey::from(self).serialize(serializer)
    }
}

impl<'de, const BASE: usize, const DUAL: usize, const QUAD: usize> Deserialize<'de>
    for EncryptionKey<BASE, DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let n = CompressedEncryptionKey::deserialize(deserializer)?;
        Ok(Self::from(n))
    }
}

impl<const BASE: usize, const DUAL: usize, const QUAD: usize> From<&DecryptionKey<BASE, DUAL, QUAD>>
    for EncryptionKey<BASE, DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding + Zeroize,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> + Zeroize,
    Uint<QUAD>: ArrayEncoding + Zeroize,
{
    fn from(sk: &DecryptionKey<BASE, DUAL, QUAD>) -> EncryptionKey<BASE, DUAL, QUAD> {
        sk.pk
    }
}

impl<const BASE: usize, const DUAL: usize, const QUAD: usize> EncryptionKey<BASE, DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    /// l computes a residuosity class of N^2: (x - 1) / n
    /// where it is the quotient x - 1 divided by N not modular multiplication of x - 1 times
    /// the modular multiplication inverse of N. The function comes from Paillier's 99 paper.
    pub(crate) fn l(&self, x: &Uint<QUAD>) -> PaillierResult<Uint<QUAD>> {
        // Ensure x != 1 mod N
        if (x % self.modulus_wide).ct_ne(&Uint::<QUAD>::ONE).into() {
            return Err(PaillierError::InvalidEncryptionKey);
        }

        // Ensure x \in [1..N^2]
        if !bool::from(mod_in(x, self.modulus_squared.as_ref())) {
            return Err(PaillierError::InvalidEncryptionKey);
        }

        //(x - 1) / N
        Ok(x.wrapping_sub(&Uint::<QUAD>::ONE) / self.modulus_wide)
    }

    /// Encrypt a given message with the encryption key and optionally use a random value
    /// `msg` must be less than N
    pub fn encrypt<M>(&self, msg: M) -> PaillierResult<(Uint<QUAD>, Uint<DUAL>)>
    where
        M: AsRef<[u8]>,
    {
        let msg = var_bytes_to_uint(msg)?;
        let nonce = Uint::<DUAL>::random_mod(&mut rand::rngs::OsRng, &self.modulus);

        let ciphertext = self.encrypt_with_nonce(&msg, &nonce)?;

        Ok((ciphertext, nonce))
    }

    /// Encrypt a value with the encryption key and given nonce
    pub fn encrypt_with_nonce(
        &self,
        msg: &Uint<DUAL>,
        randomizer: &Uint<DUAL>,
    ) -> PaillierResult<Uint<QUAD>> {
        if !bool::from(mod_in(msg, &self.modulus)) {
            return Err(PaillierError::InvalidEncryptionInputs);
        }

        if !bool::from(mod_in(randomizer, &self.modulus)) {
            return Err(PaillierError::InvalidEncryptionInputs);
        }

        let params = DynResidueParams::new(self.modulus_squared.as_ref());
        let input = self.modulus.as_ref().wrapping_add(&Uint::<DUAL>::ONE);

        let input = input.resize::<{ QUAD }>();
        let randomizer = randomizer.resize::<{ QUAD }>();

        // a = (N+1)^m mod N^2
        let mut lhs = DynResidue::new(&input, params);
        lhs = lhs.pow(msg);
        // b = r^N mod N^2
        let mut rhs = DynResidue::new(&randomizer, params);
        rhs = rhs.pow(&self.modulus);

        let ciphertext = lhs * rhs;
        Ok(ciphertext.retrieve())
    }

    /// Combines two Paillier ciphertexts
    /// commonly denoted in text as c1 \bigoplus c2
    pub fn add(&self, c1: &Uint<QUAD>, c2: &Uint<QUAD>) -> PaillierResult<Uint<QUAD>> {
        // constant time check
        let c1_check = mod_in(c1, &self.modulus_squared);
        let c2_check = mod_in(c2, &self.modulus_squared);
        if bool::from(!c1_check | !c2_check) {
            return Err(PaillierError::InvalidCipherTextAddInputs);
        }
        let params = DynResidueParams::new(self.modulus_squared.as_ref());
        let c1 = DynResidue::new(c1, params);
        let c2 = DynResidue::new(c2, params);

        Ok((c1 * c2).retrieve())
    }

    /// Equivalent to adding two Paillier exponents
    pub fn mul(&self, c: &Uint<QUAD>, a: &Uint<DUAL>) -> PaillierResult<Uint<QUAD>> {
        // constant time check
        let c1_check = mod_in(c, &self.modulus_squared);
        let c2_check = mod_in(a, &self.modulus);
        if bool::from(!c1_check | !c2_check) {
            return Err(PaillierError::InvalidCipherTextMulInputs);
        }
        let params = DynResidueParams::new(self.modulus_squared.as_ref());
        let c = DynResidue::new(c, params);

        Ok(c.pow(a).retrieve())
    }

    /// Get this key's byte representation
    pub fn to_bytes(self) -> Vec<u8> {
        self.modulus.as_ref().to_be_bytes().as_ref().to_vec()
    }

    /// Convert a byte representation to an encryption key
    pub fn from_bytes<B: AsRef<[u8]>>(data: B) -> PaillierResult<Self> {
        let compressed = CompressedEncryptionKey::from_slice(data)?;
        Ok(Self::from_modulus(compressed.0))
    }

    /// Constructs encryption key from the Paillier modulus
    pub fn from_modulus(modulus: NonZero<Uint<DUAL>>) -> Self {
        Self {
            modulus,
            modulus_wide: NonZero::from_uint(modulus.as_ref().resize::<{ QUAD }>()),
            modulus_squared: NonZero::from_uint(modulus.as_ref().square()),
            _marker: PhantomData,
        }
    }

    /// The Paillier modulus
    pub fn modulus(&self) -> &NonZero<Uint<DUAL>> {
        &self.modulus
    }

    /// The Paillier modulus but in a wider number
    pub fn modulus_wide(&self) -> &NonZero<Uint<QUAD>> {
        &self.modulus_wide
    }

    /// The Paillier modulus squared
    pub fn modulus_squared(&self) -> &NonZero<Uint<QUAD>> {
        &self.modulus_squared
    }
}
