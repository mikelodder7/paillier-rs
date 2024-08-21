use crate::{Ciphertext, EncryptionKey, PaillierError, PaillierResult};
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::mem;
use unknown_order::BigNumber;

/// A range proof for a Paillier ciphertext as defined in
/// Lindell <https://eprint.iacr.org/2017/552.pdf> Appendix A.
///
/// Verifier is given the ciphertext C = ENC(ek, x).
///
/// Prover demonstrates that x<q/3 in [0, q).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RangeProof {
    pub(crate) ek: EncryptionKey,
    pub(crate) range: BigNumber,
    pub(crate) ciphertext: Ciphertext,
    pub(crate) inner: InnerRangeProof,
    pub(crate) range_proof_ciphertext: RangeProofCiphertext,
    pub(crate) error_factor: RangeProofErrorFactor,
}

impl RangeProof {
    /// Get the encryption key that was used to generate this proof
    pub fn encryption_key(&self) -> &EncryptionKey {
        &self.ek
    }

    /// Get the ciphertext that was used to generate this proof
    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    /// Get the range that was used to generate this proof
    pub fn range(&self) -> &BigNumber {
        &self.range
    }

    /// Generate a range proof for a given ciphertext.
    pub fn prove(
        ek: &EncryptionKey,
        range: &BigNumber,
        ciphertext: &Ciphertext,
        secret_x: &BigNumber,
        secret_r: &BigNumber,
        error_factor: RangeProofErrorFactor,
        mut rng: impl RngCore + CryptoRng,
    ) -> Self {
        let (range_proof_ciphertext, randomness) =
            RangeProofCiphertext::generate(ek, range, error_factor, &mut rng);
        let e = Self::compute_challenge(ek, &range_proof_ciphertext);
        let inner =
            InnerRangeProof::generate(ek, secret_x, secret_r, &e, range, &randomness, error_factor);
        Self {
            ek: ek.clone(),
            range: range.clone(),
            ciphertext: ciphertext.clone(),
            inner,
            range_proof_ciphertext,
            error_factor,
        }
    }

    /// Verify the range proof with the given parameters.
    pub fn verify_with_params(
        &self,
        ek: &EncryptionKey,
        ciphertext: &Ciphertext,
        range: &BigNumber,
    ) -> PaillierResult<()> {
        if self.ek.n != ek.n {
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

    fn compute_challenge(
        ek: &EncryptionKey,
        range_proof_ciphertext: &RangeProofCiphertext,
    ) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(ek.n.to_bytes());
        range_proof_ciphertext
            .c1
            .iter()
            .for_each(|c| hasher.update(c.to_bytes()));
        range_proof_ciphertext
            .c2
            .iter()
            .for_each(|c| hasher.update(c.to_bytes()));
        // Hash output must be > error_factor
        let e_num = BigNumber::from_digest(hasher);
        e_num.to_bytes()
    }
}

/// The inner range proof for a Paillier ciphertext as defined in
/// Lindell <https://eprint.iacr.org/2017/552.pdf> Appendix A.
///
/// Verifier is given the ciphertext C = ENC(ek, x).
///
/// Prover demonstrates that x<q/3 in [0, q).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct InnerRangeProof(pub(crate) Vec<RangeProofResponseType>);

impl InnerRangeProof {
    /// Generate a range proof for a given ciphertext.
    pub fn generate(
        ek: &EncryptionKey,
        secret_x: &BigNumber,
        secret_r: &BigNumber,
        e: &[u8],
        range: &BigNumber,
        data: &RangeProofRandomness,
        error_factor: RangeProofErrorFactor,
    ) -> Self {
        let error_factor = error_factor.into();
        // q/3
        let lower = range / BigNumber::from(3u8);
        // 2q/3
        let upper = &lower * BigNumber::from(2u8);

        let bits = bit_vec::BitVec::from_bytes(e);
        let mut inner = Vec::with_capacity(error_factor);
        for (i, ei) in bits.iter().take(error_factor).enumerate() {
            if ei {
                let x_w1 = secret_x + &data.w1[i];
                // Mask
                if lower < x_w1 && x_w1 < upper {
                    inner.push(RangeProofResponseType::Mask(Box::new(
                        RangeProofMaskResponse {
                            j: 1,
                            masked_x: x_w1,
                            masked_r: secret_r.modmul(&data.r1[i], &ek.n),
                        },
                    )));
                } else {
                    inner.push(RangeProofResponseType::Mask(Box::new(
                        RangeProofMaskResponse {
                            j: 2,
                            masked_x: secret_x + &data.w2[i],
                            masked_r: secret_r.modmul(&data.r2[i], &ek.n),
                        },
                    )));
                }
            } else {
                // Open
                inner.push(RangeProofResponseType::Open(Box::new(
                    RangeProofOpenResponse {
                        w1: data.w1[i].clone(),
                        w2: data.w2[i].clone(),
                        r1: data.r1[i].clone(),
                        r2: data.r2[i].clone(),
                    },
                )));
            }
        }
        Self(inner)
    }

    /// Verify the range proof.
    pub fn verify(
        &self,
        ek: &EncryptionKey,
        e: &[u8],
        range_ciphertext: &RangeProofCiphertext,
        range: &BigNumber,
        ciphertext_x: &Ciphertext,
        error_factor: RangeProofErrorFactor,
    ) -> PaillierResult<()> {
        // q/3
        let lower = range / BigNumber::from(3u8);
        // 2q/3
        let upper = &lower * BigNumber::from(2u8);

        let bits = bit_vec::BitVec::from_bytes(e);
        let error_factor = error_factor.into();

        let mut res = true;
        for (i, ei) in bits.iter().take(error_factor).enumerate() {
            match (ei, &self.0[i]) {
                (false, RangeProofResponseType::Open(o)) => {
                    let expected_c1 = ek
                        .encrypt_num_with_nonce(&o.w1, &o.r1)
                        .expect("Encryption to work");
                    let expected_c2 = ek
                        .encrypt_num_with_nonce(&o.w2, &o.r2)
                        .expect("Encryption to work");

                    res &= expected_c1 == range_ciphertext.c1[i];
                    res &= expected_c2 == range_ciphertext.c2[i];

                    res &= o.w2 < lower && lower <= o.w1 && o.w1 <= upper
                        || o.w1 < lower && lower <= o.w2 && o.w2 <= upper;
                }
                (true, RangeProofResponseType::Mask(m)) => {
                    let ciphertext = if m.j == 1 {
                        range_ciphertext.c1[i].modmul(ciphertext_x, &ek.nn)
                    } else {
                        range_ciphertext.c2[i].modmul(ciphertext_x, &ek.nn)
                    };

                    let ciphertext_z = ek
                        .encrypt_num_with_nonce(&m.masked_x, &m.masked_r)
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
    #[default]
    Bits40,
    /// 80 bits of error
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
pub(crate) struct RangeProofCiphertext {
    pub(crate) c1: Vec<BigNumber>,
    pub(crate) c2: Vec<BigNumber>,
}

impl RangeProofCiphertext {
    /// Create a new range proof ciphertext.
    pub fn generate(
        ek: &EncryptionKey,
        range: &BigNumber,
        error_factor: RangeProofErrorFactor,
        mut rng: impl RngCore + CryptoRng,
    ) -> (Self, RangeProofRandomness) {
        // q/3
        let lower = range / BigNumber::from(3u8);
        // 2q/3
        let upper = &lower * BigNumber::from(2u8);

        let error_factor = error_factor.into();
        let mut w1 = (0..error_factor)
            .map(|_| BigNumber::random_range_with_rng(&lower, &upper, &mut rng))
            .collect::<Vec<_>>();

        let mut w2 = w1.iter().map(|w| w - &lower).collect::<Vec<_>>();

        // probability 1/2 switch w1 and w2
        for i in 0..error_factor {
            if rng.gen::<bool>() {
                mem::swap(&mut w1[i], &mut w2[i]);
            }
        }

        let r1 = (0..error_factor)
            .map(|_| BigNumber::from_rng(&lower, &mut rng))
            .collect::<Vec<_>>();
        let r2 = (0..error_factor)
            .map(|_| BigNumber::from_rng(&lower, &mut rng))
            .collect::<Vec<_>>();

        let c1 = w1
            .iter()
            .zip(r1.iter())
            .map(|(w, r)| ek.encrypt_num_with_nonce(w, r).expect("Encrypt to work"))
            .collect::<Vec<_>>();
        let c2 = w2
            .iter()
            .zip(r2.iter())
            .map(|(w, r)| ek.encrypt_num_with_nonce(w, r).expect("Encrypt to work"))
            .collect::<Vec<_>>();

        (Self { c1, c2 }, RangeProofRandomness { w1, w2, r1, r2 })
    }
}

/// The randomness used in the range proof.
#[derive(Clone, Debug, Default)]
pub(crate) struct RangeProofRandomness {
    pub(crate) w1: Vec<BigNumber>,
    pub(crate) w2: Vec<BigNumber>,
    pub(crate) r1: Vec<BigNumber>,
    pub(crate) r2: Vec<BigNumber>,
}

/// The response to a range proof.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) enum RangeProofResponseType {
    /// Opening
    Open(Box<RangeProofOpenResponse>),
    /// Masking
    Mask(Box<RangeProofMaskResponse>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RangeProofOpenResponse {
    pub(crate) w1: BigNumber,
    pub(crate) w2: BigNumber,
    pub(crate) r1: BigNumber,
    pub(crate) r2: BigNumber,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RangeProofMaskResponse {
    pub(crate) j: u8,
    pub(crate) masked_x: BigNumber,
    pub(crate) masked_r: BigNumber,
}
