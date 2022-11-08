use crate::{mod_in, Ciphertext, DecryptionKey, Nonce};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use unknown_order::BigNumber;
use zeroize::Zeroize;

/// A Paillier encryption key
#[derive(Clone, Debug, PartialEq, Zeroize)]
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
        Ok(Self {
            n: n.clone(),
            nn: &n * &n,
        })
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
    pub(crate) fn l(&self, x: &BigNumber) -> Option<BigNumber> {
        let one = BigNumber::one();
        // Ensure x = 1 mod N
        if x % &self.n != one {
            return None;
        }

        // Ensure x \in [1..N^2]
        if !mod_in(&x, &self.nn) {
            return None;
        }

        //(x - 1) / N
        Some((x - &one) / &self.n)
    }

    pub(crate) fn l_unchecked(&self, x: &BigNumber) -> BigNumber {
        //(x - 1) / N
        (x - &BigNumber::one()) / &self.n
    }

    /// Encrypt a given message with the encryption key and optionally use a random value
    /// x must be less than N
    #[allow(clippy::many_single_char_names)]
    pub fn encrypt<M>(&self, x: M, r: Option<Nonce>) -> Option<(Ciphertext, Nonce)>
    where
        M: AsRef<[u8]>,
    {
        let xx = BigNumber::from_slice(x);
        if !mod_in(&xx, &self.n) {
            return None;
        }

        let r = match r {
            Some(r) => {
                if !mod_in(&r, &self.n) {
                    return None;
                }
                r
            }
            None => Nonce::random(&self.n),
        };

        Some((self.encrypt_unchecked(&xx, &r), r))
    }

    /// Encrypt a given message with the encryption key and a provided random value
    /// m can be greater than N
    pub fn encrypt_unchecked(&self, m: &BigNumber, r: &Nonce) -> Ciphertext {
        debug_assert!(mod_in(r, &self.n));

        // g^m mod N^2 = (N + 1)^m mod N^2 = m N + 1 mod N^2
        // See Prop 11.26, Pg. 385 of Intro to Modern Cryptography
        let g_m = m
            .modmul(&self.n, &self.nn)
            .modadd(&BigNumber::one(), &self.nn);

        // r^N mod N^2
        let r_n = &r.modpow(&self.n, &self.nn);

        // c = g^m r^n mod N^2
        g_m.modmul(r_n, &self.nn)
    }

    /// Combines two Paillier ciphertexts
    /// commonly denoted in text as c1 \bigoplus c2
    pub fn add(&self, c1: &Ciphertext, c2: &Ciphertext) -> Option<Ciphertext> {
        // constant time check
        let c1_check = mod_in(&c1, &self.nn);
        let c2_check = mod_in(&c2, &self.nn);
        if !c1_check | !c2_check {
            return None;
        }

        Some(c1.modmul(c2, &self.nn))
    }

    /// Combines two Paillier ciphertexts (without checks)
    /// commonly denoted in text as c1 \bigoplus c2
    pub fn add_unchecked(&self, c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
        c1.modmul(c2, &self.nn)
    }

    /// Equivalent to adding two Paillier exponents
    pub fn mul(&self, c: &Ciphertext, a: &BigNumber) -> Option<Ciphertext> {
        // constant time check
        let c1_check = mod_in(&c, &self.nn);
        let c2_check = mod_in(&a, &self.n);
        if !c1_check | !c2_check {
            return None;
        }

        Some(c.modpow(a, &self.nn))
    }

    /// Equivalent to adding two Paillier exponents without checks
    pub fn mul_unchecked(&self, c: &Ciphertext, a: &BigNumber) -> Ciphertext {
        c.modpow(a, &self.nn)
    }

    /// Get this key's byte representation
    pub fn to_bytes(&self) -> Vec<u8> {
        self.n.to_bytes()
    }

    /// Convert a  byte representation to a encryption key
    pub fn from_bytes<B: AsRef<[u8]>>(data: B) -> Result<Self, String> {
        let data = data.as_ref();
        let n = BigNumber::from_slice(data);
        Ok(Self {
            n: n.clone(),
            nn: &n * &n,
        })
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
