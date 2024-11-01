use super::super::*;
use crate::{error::*, utils::*};
use crypto_bigint::{modular::runtime_mod::*, ArrayEncoding, Concat, Uint};
use digest::{
    generic_array::{typenum::Unsigned, GenericArray},
    Digest,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Proof that a Paillier modulus is square free.
///
/// The proof checks that there are "small" factors,
/// that can be inverted in with a Paillier modulus
/// and the number of parallel instances needed for soundness
/// relates to how high to check. For a security parameter `k`,
/// where we check for prime factors up to `t`, need `l` parallel
/// instances where `l` is the smallest integer such that t^l > 2^k.
/// For 128-bit security, t = 1000 and l = 13, and Paillier modulus
/// is ≥ 2048 bits.
///
/// This proof is used in <https://eprint.iacr.org/2020/540> and
/// <https://eprint.iacr.org/2017/552> as part of their DKG.
/// A paillier key generator can prove the parameters where created honestly.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SquareFreeProof<const BASE: usize, const DUAL: usize, const QUAD: usize>(
    Vec<Uint<DUAL>>,
)
where
    Uint<BASE>: ArrayEncoding + Zeroize,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> + Zeroize,
    Uint<QUAD>: ArrayEncoding + Zeroize;

#[cfg(feature = "wasm")]
wasm_slice_impl!(SquareFreeProof);

const L: usize = 13;

impl<const BASE: usize, const DUAL: usize, const QUAD: usize> SquareFreeProof<BASE, DUAL, QUAD>
where
    Uint<BASE>: ArrayEncoding + Zeroize,
    Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> + Zeroize,
    Uint<QUAD>: ArrayEncoding + Zeroize,
{
    /// Generate a new SF proof.
    /// GG20 paper uses lots of values for the entropy like
    /// the ECDSA Public key, the curve generator and prime,
    /// and the participant id as follows
    /// generateChallenges(g, q, y, N, pi, l)
    pub fn generate<D: Digest>(sk: &DecryptionKey<BASE, DUAL, QUAD>, nonce: &[u8]) -> Self {
        // M = N^-1 mod totient
        let (n_inv, _ct) = sk.pk.modulus.as_ref().inv_mod(&sk.totient);
        debug_assert!(bool::from(_ct));

        let mut proof = Self::generate_challenges::<D>(&sk.pk, nonce);
        debug_assert_eq!(proof.len(), L);

        let params = DynResidueParams::new(sk.pk.modulus.as_ref());

        for x in proof.as_mut_slice() {
            let xx = DynResidue::new(x, params);
            *x = xx.pow(&n_inv).retrieve();
        }
        SquareFreeProof(proof)
    }

    /// Verify a Paillier modulus is square-free.
    pub fn verify<D: Digest>(&self, pk: &EncryptionKey<BASE, DUAL, QUAD>, nonce: &[u8]) -> bool {
        let proof = Self::generate_challenges::<D>(pk, nonce);
        debug_assert_eq!(proof.len(), L);
        debug_assert_eq!(proof.len(), self.0.len());
        let params = DynResidueParams::new(pk.modulus.as_ref());

        proof.iter().zip(self.0.iter()).all(|(a, b)| {
            let bb = DynResidue::new(b, params);
            *a == bb.pow(&pk.modulus).retrieve()
        })
    }

    /// Get this proof's byte representation
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&self.0).unwrap()
    }

    /// Convert a byte representation to a proof
    pub fn from_bytes<B: AsRef<[u8]>>(data: B) -> PaillierResult<Self> {
        let data = data.as_ref();
        let out = postcard::from_bytes::<Vec<Uint<DUAL>>>(data).map(Self)?;
        Ok(out)
    }

    /// Computes `l` deterministic numbers as challenges
    /// for `ProofSquareFree` which proves that the Paillier modulus is square free
    #[allow(clippy::many_single_char_names)]
    fn generate_challenges<D: Digest>(
        pk: &EncryptionKey<BASE, DUAL, QUAD>,
        nonce: &[u8],
    ) -> Vec<Uint<DUAL>> {
        let b = Uint::<DUAL>::BYTES;
        // Check that a modulus is not too small
        assert!(b >= 256);

        let h = D::OutputSize::to_usize();

        // Compute s = ⌈b/h⌉ aka the number of hash outputs required to obtain
        // `b` i.e. the number of times required to call hash to get the same bytes in `b`.
        // Compute ceil as s = (b + h - 1) / b
        let s: usize = (b + h - 1) / h;

        let mut j = 0;
        let mut m = 0usize;

        let mut x = Vec::with_capacity(L);
        while j < L {
            let mut e = Vec::with_capacity(s * h);
            let jj = (j as u32).to_be_bytes();
            let mm = (m as u32).to_be_bytes();
            for k in 0..s {
                let kk = (k as u32).to_be_bytes();
                e.extend_from_slice(Self::hash_pieces::<D>(&[nonce, &jj, &kk, &mm]).as_slice());
            }

            // truncate `e` to `b` bytes
            let xj = Uint::<DUAL>::from_be_slice(&e[..b]);

            if mod_in(&xj, pk.modulus.as_ref()).into() {
                x.push(xj);

                j += 1;

                m = 0
            } else {
                m += 1
            }
        }

        x
    }

    fn hash_pieces<D: Digest>(data: &[&[u8]]) -> GenericArray<u8, D::OutputSize> {
        // hash each piece individually to avoid potential padding attacks
        // then hash all the outputs together
        let mut hasher = D::new();
        data.iter().map(|datum| D::digest(datum)).for_each(|d| {
            hasher.update(d.as_slice());
        });
        hasher.finalize()
    }
}
