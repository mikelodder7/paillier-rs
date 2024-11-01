use super::super::*;
use crate::{error::*, utils::*};

use crypto_bigint::{
    modular::runtime_mod::*, ArrayEncoding, Concat, Encoding, NonZero, RandomMod, Uint,
};
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::mem;

/// A range proof for a Paillier ciphertext as defined in
/// Lindell <https://eprint.iacr.org/2017/552.pdf> Appendix A.
///
/// Verifier is given the ciphertext C = ENC(ek, x).
///
/// Prover demonstrates that x<q/3 in [0, q).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RangeProof<const BASE: usize, const DUAL: usize, const QUAD: usize>
where
    Uint<BASE>: ArrayEncoding,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    pub(crate) ek: EncryptionKey<BASE, DUAL, QUAD>,
    pub(crate) range: Uint<DUAL>,
    pub(crate) ciphertext: Uint<QUAD>,
    pub(crate) inner: InnerRangeProof<DUAL, QUAD>,
    pub(crate) range_proof_ciphertext: RangeProofCiphertext<QUAD>,
    pub(crate) error_factor: RangeProofErrorFactor,
}

#[cfg(feature = "wasm")]
wasm_slice_impl!(RangeProof);

impl<const BASE: usize, const DUAL: usize, const QUAD: usize> RangeProof<BASE, DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    /// Get the encryption key that was used to generate this proof
    pub fn encryption_key(&self) -> &EncryptionKey<BASE, DUAL, QUAD> {
        &self.ek
    }

    /// Get the ciphertext that was used to generate this proof
    pub fn ciphertext(&self) -> &Uint<QUAD> {
        &self.ciphertext
    }

    /// Get the range that was used to generate this proof
    pub fn range(&self) -> &Uint<DUAL> {
        &self.range
    }

    /// Generate a range proof for a given ciphertext.
    pub fn prove(
        ek: &EncryptionKey<BASE, DUAL, QUAD>,
        range: &Uint<DUAL>,
        ciphertext: &Uint<QUAD>,
        secret_x: &Uint<DUAL>,
        secret_r: &Uint<DUAL>,
        error_factor: RangeProofErrorFactor,
        mut rng: impl RngCore + CryptoRng,
    ) -> Self {
        let (range_proof_ciphertext, randomness) =
            RangeProofCiphertext::generate(ek, range, error_factor, &mut rng);
        let e = Self::compute_challenge(ek, &range_proof_ciphertext);
        let inner =
            InnerRangeProof::generate(ek, secret_x, secret_r, &e, range, &randomness, error_factor);
        Self {
            ek: *ek,
            range: *range,
            ciphertext: *ciphertext,
            inner,
            range_proof_ciphertext,
            error_factor,
        }
    }

    /// Verify the range proof with the given parameters.
    pub fn verify_with_params(
        &self,
        ek: &EncryptionKey<BASE, DUAL, QUAD>,
        ciphertext: &Uint<QUAD>,
        range: &Uint<DUAL>,
    ) -> PaillierResult<()> {
        if self.ek.modulus != ek.modulus {
            return Err(PaillierError::InvalidEncryptionKey);
        }
        if &self.ciphertext != ciphertext {
            return Err(PaillierError::InvalidCiphertext);
        }
        if &self.range != range {
            return Err(PaillierError::InvalidRangeProof);
        }
        self.verify()
    }

    /// Verify the range proof.
    pub fn verify(&self) -> PaillierResult<()> {
        let e = Self::compute_challenge(&self.ek, &self.range_proof_ciphertext);
        self.inner.verify(
            &self.ek,
            &e,
            &self.range_proof_ciphertext,
            &self.range,
            &self.ciphertext,
            self.error_factor,
        )
    }

    /// Get this proof's byte representation
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&self).expect("Failed to serialize")
    }

    /// Create a proof from a byte representation
    pub fn from_bytes<B: AsRef<[u8]>>(data: B) -> PaillierResult<Self> {
        postcard::from_bytes(data.as_ref()).map_err(Into::into)
    }

    fn compute_challenge(
        ek: &EncryptionKey<BASE, DUAL, QUAD>,
        range_proof_ciphertext: &RangeProofCiphertext<QUAD>,
    ) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(ek.modulus.as_ref().to_be_bytes());
        range_proof_ciphertext
            .c1
            .iter()
            .for_each(|c| hasher.update(c.to_be_bytes()));
        range_proof_ciphertext
            .c2
            .iter()
            .for_each(|c| hasher.update(c.to_be_bytes()));
        // Hash output must be > error_factor
        hasher.finalize().to_vec()
    }
}

/// The inner range proof for a Paillier ciphertext as defined in
/// Lindell <https://eprint.iacr.org/2017/552.pdf> Appendix A.
///
/// Verifier is given the ciphertext C = ENC(ek, x).
///
/// Prover demonstrates that x<q/3 in [0, q).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct InnerRangeProof<const DUAL: usize, const QUAD: usize>(
    pub(crate) Vec<RangeProofResponseType<DUAL, QUAD>>,
)
where
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding;

impl<const DUAL: usize, const QUAD: usize> InnerRangeProof<DUAL, QUAD>
where
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    /// Generate a range proof for a given ciphertext.
    pub fn generate<const BASE: usize>(
        ek: &EncryptionKey<BASE, DUAL, QUAD>,
        secret_x: &Uint<DUAL>,
        secret_r: &Uint<DUAL>,
        e: &[u8],
        range: &Uint<DUAL>,
        data: &RangeProofRandomness<DUAL, QUAD>,
        error_factor: RangeProofErrorFactor,
    ) -> Self
    where
        Uint<BASE>: ArrayEncoding,
    {
        let error_factor = error_factor.into();
        // q/3
        let lower = range / NonZero::from_uint(Uint::<DUAL>::from(3u8));
        // 2q/3
        let upper = lower << 1;

        let bits = bit_vec::BitVec::from_bytes(e);
        let mut inner = Vec::with_capacity(error_factor);

        let params = DynResidueParams::new(ek.modulus());
        let secret_r = DynResidue::new(secret_r, params);

        for (i, ei) in bits.iter().take(error_factor).enumerate() {
            if ei {
                let x_w1 = secret_x.wrapping_add(&data.w1[i]);
                // Mask
                if lower < x_w1 && x_w1 < upper {
                    let r1 = DynResidue::new(&data.r1[i], params);
                    inner.push(RangeProofResponseType::Mask(Box::new(
                        RangeProofMaskResponse {
                            j: 1,
                            masked_x: x_w1,
                            masked_r: (secret_r * r1).retrieve(),
                        },
                    )));
                } else {
                    let r2 = DynResidue::new(&data.r2[i], params);
                    inner.push(RangeProofResponseType::Mask(Box::new(
                        RangeProofMaskResponse {
                            j: 2,
                            masked_x: secret_x.wrapping_add(&data.w2[i]),
                            masked_r: (secret_r * r2).retrieve(),
                        },
                    )));
                }
            } else {
                // Open
                inner.push(RangeProofResponseType::Open(Box::new(
                    RangeProofOpenResponse {
                        w1: data.w1[i],
                        w2: data.w2[i],
                        r1: data.r1[i],
                        r2: data.r2[i],
                    },
                )));
            }
        }
        Self(inner)
    }

    /// Verify the range proof.
    pub fn verify<const BASE: usize>(
        &self,
        ek: &EncryptionKey<BASE, DUAL, QUAD>,
        e: &[u8],
        range_ciphertext: &RangeProofCiphertext<QUAD>,
        range: &Uint<DUAL>,
        ciphertext_x: &Uint<QUAD>,
        error_factor: RangeProofErrorFactor,
    ) -> PaillierResult<()>
    where
        Uint<BASE>: ArrayEncoding,
    {
        // q/3
        let lower = range / NonZero::from_uint(Uint::<DUAL>::from(3u8));
        // 2q/3
        let upper = lower << 1;

        let bits = bit_vec::BitVec::from_bytes(e);
        let error_factor = error_factor.into();

        let params = DynResidueParams::new(ek.modulus_squared());
        let ciphertext_x = DynResidue::new(ciphertext_x, params);

        let mut res = true;
        for (i, ei) in bits.iter().take(error_factor).enumerate() {
            match (ei, &self.0[i]) {
                (false, RangeProofResponseType::Open(o)) => {
                    let expected_c1 = ek
                        .encrypt_with_nonce(&o.w1, &o.r1)
                        .expect("Encryption to work");
                    let expected_c2 = ek
                        .encrypt_with_nonce(&o.w2, &o.r2)
                        .expect("Encryption to work");

                    res &= expected_c1 == range_ciphertext.c1[i];
                    res &= expected_c2 == range_ciphertext.c2[i];

                    res &= o.w2 < lower && lower <= o.w1 && o.w1 <= upper
                        || o.w1 < lower && lower <= o.w2 && o.w2 <= upper;
                }
                (true, RangeProofResponseType::Mask(m)) => {
                    let ciphertext = if m.j == 1 {
                        let c1 = DynResidue::new(&range_ciphertext.c1[i], params);
                        (c1 * ciphertext_x).retrieve()
                    } else {
                        let c2 = DynResidue::new(&range_ciphertext.c2[i], params);
                        (c2 * ciphertext_x).retrieve()
                    };

                    let ciphertext_z = ek
                        .encrypt_with_nonce(&m.masked_x, &m.masked_r)
                        .expect("Encryption to work");
                    res &= ciphertext == ciphertext_z;

                    res &= lower <= m.masked_x && m.masked_x <= upper;
                }
                _ => res = false,
            }
            if !res {
                break;
            }
        }

        if res {
            Ok(())
        } else {
            Err(PaillierError::InvalidRangeProof)
        }
    }
}

/// The error factor for the range proof.
#[derive(
    Copy, Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Deserialize, Serialize,
)]
pub enum RangeProofErrorFactor {
    /// 40 bits of error
    Bits40,
    /// 80 bits of error
    #[default]
    Bits80,
    /// 128 bits of error
    Bits128,
}

macro_rules! impl_range_proof_from {
    ($($type:ident),+$(,)*) => {
        $(
            impl TryFrom<$type> for RangeProofErrorFactor {
                type Error = PaillierError;

                fn try_from(value: $type) -> Result<Self, Self::Error> {
                    match value {
                        40 => Ok(Self::Bits40),
                        80 => Ok(Self::Bits80),
                        128 => Ok(Self::Bits128),
                        _ => Err(PaillierError::InvalidRangeProofErrorFactor),
                    }
                }
            }

            impl From<RangeProofErrorFactor> for $type {
                fn from(value: RangeProofErrorFactor) -> Self {
                    match value {
                        RangeProofErrorFactor::Bits40 => 40,
                        RangeProofErrorFactor::Bits80 => 80,
                        RangeProofErrorFactor::Bits128 => 128,
                    }
                }
            }
        )+
    };
}

impl_range_proof_from!(u8, u16, i16, u32, i32, u64, i64, u128, i128, usize, isize);

/// The ciphertexts for a range proof as defined in
/// Lindell <https://eprint.iacr.org/2017/552.pdf> Appendix A.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct RangeProofCiphertext<const QUAD: usize>
where
    Uint<QUAD>: ArrayEncoding,
{
    pub(crate) c1: Vec<Uint<QUAD>>,
    pub(crate) c2: Vec<Uint<QUAD>>,
}

impl<const QUAD: usize> RangeProofCiphertext<QUAD>
where
    Uint<QUAD>: ArrayEncoding,
{
    /// Create a new range proof ciphertext.
    pub fn generate<const BASE: usize, const DUAL: usize>(
        ek: &EncryptionKey<BASE, DUAL, QUAD>,
        range: &Uint<DUAL>,
        error_factor: RangeProofErrorFactor,
        mut rng: impl RngCore + CryptoRng,
    ) -> (Self, RangeProofRandomness<DUAL, QUAD>)
    where
        Uint<BASE>: ArrayEncoding,
        Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    {
        // q/3
        let lower = range / NonZero::from_uint(Uint::<DUAL>::from(3u8));
        // 2q/3
        let upper = lower << 1;

        let error_factor = error_factor.into();
        let mut w1 = (0..error_factor)
            .map(|_| random_range_with_rng(&lower, &upper, &mut rng))
            .collect::<Vec<_>>();

        let mut w2 = w1
            .iter()
            .map(|w| w.wrapping_sub(&lower))
            .collect::<Vec<_>>();

        // probability 1/2 switch w1 and w2
        for i in 0..error_factor {
            if rng.gen::<bool>() {
                mem::swap(&mut w1[i], &mut w2[i]);
            }
        }

        let nz_lower = NonZero::from_uint(lower);
        let r1 = (0..error_factor)
            .map(|_| Uint::<DUAL>::random_mod(&mut rng, &nz_lower))
            .collect::<Vec<_>>();
        let r2 = (0..error_factor)
            .map(|_| Uint::<DUAL>::random_mod(&mut rng, &nz_lower))
            .collect::<Vec<_>>();

        let c1 = w1
            .iter()
            .zip(r1.iter())
            .map(|(w, r)| ek.encrypt_with_nonce(w, r).expect("Encrypt to work"))
            .collect::<Vec<_>>();
        let c2 = w2
            .iter()
            .zip(r2.iter())
            .map(|(w, r)| ek.encrypt_with_nonce(w, r).expect("Encrypt to work"))
            .collect::<Vec<_>>();

        (Self { c1, c2 }, RangeProofRandomness { w1, w2, r1, r2 })
    }
}

/// The randomness used in the range proof.
#[derive(Clone, Debug, Default)]
pub(crate) struct RangeProofRandomness<const DUAL: usize, const QUAD: usize>
where
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    pub(crate) w1: Vec<Uint<DUAL>>,
    pub(crate) w2: Vec<Uint<DUAL>>,
    pub(crate) r1: Vec<Uint<DUAL>>,
    pub(crate) r2: Vec<Uint<DUAL>>,
}

/// The response to a range proof.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) enum RangeProofResponseType<const DUAL: usize, const QUAD: usize>
where
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    /// Opening
    Open(Box<RangeProofOpenResponse<DUAL, QUAD>>),
    /// Masking
    Mask(Box<RangeProofMaskResponse<DUAL, QUAD>>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RangeProofOpenResponse<const DUAL: usize, const QUAD: usize>
where
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    pub(crate) w1: Uint<DUAL>,
    pub(crate) w2: Uint<DUAL>,
    pub(crate) r1: Uint<DUAL>,
    pub(crate) r2: Uint<DUAL>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RangeProofMaskResponse<const DUAL: usize, const QUAD: usize>
where
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>>,
    Uint<QUAD>: ArrayEncoding,
{
    pub(crate) j: u8,
    pub(crate) masked_x: Uint<DUAL>,
    pub(crate) masked_r: Uint<DUAL>,
}
