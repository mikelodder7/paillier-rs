use crate::{mod_in, Ciphertext, DecryptionKey, Nonce, PaillierError, PaillierResult};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use unknown_order::BigNumber;
use zeroize::Zeroize;

/// A Paillier encryption key
#[derive(Clone, Debug, Default, Zeroize)]
pub struct EncryptionKey {
    pub(crate) n: BigNumber,  // N = p * q, where p,q are primes
    pub(crate) nn: BigNumber, // N^2
}

#[cfg(feature = "wasm")]
wasm_slice_impl!(EncryptionKey);

impl Serialize for EncryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.n.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let n = BigNumber::deserialize(deserializer)?;
        Ok(Self::from_n(n))
    }
}

impl From<&DecryptionKey> for EncryptionKey {
    fn from(sk: &DecryptionKey) -> EncryptionKey {
        sk.pk.clone()
    }
}

impl EncryptionKey {
    /// l computes a residuosity class of N^2: (x - 1) / n
    /// where it is the quotient x - 1 divided by N not modular multiplication of x - 1 times
    /// the modular multiplication inverse of N. The function comes from Paillier's 99 paper.
    pub(crate) fn l(&self, x: &BigNumber) -> PaillierResult<BigNumber> {
        let one = BigNumber::one();
        // Ensure x = 1 mod N
        if !(x % &self.n).is_one() {
            return Err(PaillierError::InvalidEncryptionKey);
        }

        // Ensure x \in [1..N^2]
        if !mod_in(x, &self.nn) {
            return Err(PaillierError::InvalidEncryptionKey);
        }

        //(x - 1) / N
        Ok((x - &one) / &self.n)
    }

    /// Encrypt a given message with the encryption key and optionally use a random value
    /// x must be less than N
    #[allow(clippy::many_single_char_names)]
    pub fn encrypt<M>(&self, x: M, r: Option<Nonce>) -> PaillierResult<(Ciphertext, Nonce)>
    where
        M: AsRef<[u8]>,
    {
        let xx = BigNumber::from_slice(x);
        let r = r.unwrap_or_else(|| Nonce::random(&self.n));

        let c = self.encrypt_num_with_nonce(&xx, &r)?;

        Ok((c, r))
    }

    /// Encrypt a number with the encryption key and given nonce
    #[allow(clippy::many_single_char_names)]
    pub fn encrypt_num_with_nonce(&self, x: &BigNumber, r: &Nonce) -> PaillierResult<Ciphertext> {
        if !mod_in(x, &self.n) {
            return Err(PaillierError::InvalidEncryptionInputs);
        }

        if !mod_in(r, &self.n) {
            return Err(PaillierError::InvalidEncryptionInputs);
        }

        // a = (N+1)^m mod N^2
        let a = (&self.n + BigNumber::one()).modpow(x, &self.nn);
        // b = r^N mod N^2
        let b = &r.modpow(&self.n, &self.nn);

        let c = a.modmul(b, &self.nn);
        Ok(c)
    }

    /// Combines two Paillier ciphertexts
    /// commonly denoted in text as c1 \bigoplus c2
    pub fn add(&self, c1: &Ciphertext, c2: &Ciphertext) -> PaillierResult<Ciphertext> {
        // constant time check
        let c1_check = mod_in(c1, &self.nn);
        let c2_check = mod_in(c2, &self.nn);
        if !c1_check | !c2_check {
            return Err(PaillierError::InvalidCipherTextAddInputs);
        }

        Ok(c1.modmul(c2, &self.nn))
    }

    /// Equivalent to adding two Paillier exponents
    pub fn mul(&self, c: &Ciphertext, a: &BigNumber) -> PaillierResult<Ciphertext> {
        // constant time check
        let c1_check = mod_in(c, &self.nn);
        let c2_check = mod_in(a, &self.n);
        if !c1_check | !c2_check {
            return Err(PaillierError::InvalidCipherTextMulInputs);
        }

        Ok(c.modpow(a, &self.nn))
    }

    /// Get this key's byte representation
    pub fn to_bytes(&self) -> Vec<u8> {
        self.n.to_bytes()
    }

    /// Convert a  byte representation to a encryption key
    pub fn from_bytes<B: AsRef<[u8]>>(data: B) -> PaillierResult<Self> {
        let data = data.as_ref();
        let n = BigNumber::from_slice(data);
        Ok(Self::from_n(n))
    }

    /// Constructs encryption key from the Paillier modulus
    pub fn from_n(n: BigNumber) -> Self {
        Self { nn: &n * &n, n }
    }

    /// The Paillier modulus
    pub fn n(&self) -> &BigNumber {
        &self.n
    }

    /// The Paillier modulus squared
    pub fn nn(&self) -> &BigNumber {
        &self.nn
    }
}
