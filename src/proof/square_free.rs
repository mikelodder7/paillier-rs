use crate::{error::*, mod_in, DecryptionKey, EncryptionKey};
use digest::{
    generic_array::{typenum::Unsigned, GenericArray},
    Digest,
};
use serde::{Deserialize, Serialize};
use unknown_order::BigNumber;

/// Proof that a Paillier modulus is square free.
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
pub struct SquareFreeProof(Vec<BigNumber>);

const L: usize = 13;

#[cfg(feature = "wasm")]
wasm_slice_impl!(SquareFreeProof);

impl SquareFreeProof {
    /// Generate a new SF proof.
    /// GG20 paper uses lots of values for the entropy like
    /// the ECDSA Public key, the curve generator and prime,
    /// and the participant id as follows
    /// generateChallenges(g, q, y, N, pi, l)
    pub fn generate<D: Digest>(sk: &DecryptionKey, nonce: &[u8]) -> Option<Self> {
        // M = N^-1 mod totient
        sk.pk.n.invert(&sk.totient).map(|m| {
            let mut proof = generate_challenges::<D>(&sk.pk, nonce);
            debug_assert_eq!(proof.len(), L);
            for x in proof.as_mut_slice() {
                *x = x.modpow(&m, &sk.pk.n);
            }
            SquareFreeProof(proof)
        })
    }

    /// Verify a Paillier modulus is square-free.
    pub fn verify<D: Digest>(&self, pk: &EncryptionKey, nonce: &[u8]) -> bool {
        let proof = generate_challenges::<D>(pk, nonce);
        debug_assert_eq!(proof.len(), L);
        debug_assert_eq!(proof.len(), self.0.len());

        proof
            .iter()
            .zip(self.0.iter())
            .all(|(a, b)| a == &b.modpow(&pk.n, &pk.n))
    }

    /// Get this proof's byte representation
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&self.0).unwrap()
    }

    /// Convert a byte representation to a proof
    pub fn from_bytes<B: AsRef<[u8]>>(data: B) -> PaillierResult<Self> {
        let data = data.as_ref();
        let out = postcard::from_bytes::<Vec<BigNumber>>(data).map(Self)?;
        Ok(out)
    }
}

/// Computes `l` deterministic numbers as challenges
/// for `ProofSquareFree` which proves that the Paillier modulus is square free
#[allow(clippy::many_single_char_names)]
fn generate_challenges<D: Digest>(pk: &EncryptionKey, nonce: &[u8]) -> Vec<BigNumber> {
    let b = pk.n.to_bytes().len();
    // Check that a modulus is not too small
    assert!(b >= 256);

    let h = D::OutputSize::to_usize();

    // Compute s = ⌈b/h⌉ aka the number of hash outputs required to obtain
    // `b` i.e. the number of times require to call hash to get the same bytes in `b`.
    // Compute ceil as s = (b + h - 1) / b
    let s: usize = (b + h - 1) / h;

    let mut j = 0;
    let mut m = 0usize;

    let mut x = Vec::with_capacity(L);
    while j < L {
        let mut e = Vec::with_capacity(s * h);
        for k in 0..s {
            e.extend_from_slice(
                hash_pieces::<D>(&[nonce, &j.to_be_bytes(), &k.to_be_bytes(), &m.to_be_bytes()])
                    .as_slice(),
            );
        }

        // truncate `e` to `b` bytes
        let xj = BigNumber::from_slice(&e[..b]);

        if mod_in(&xj, &pk.n) {
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
