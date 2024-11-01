#[cfg(feature = "wasm")]
macro_rules! wasm_slice_impl {
    ($name:ident $(, $z:ident)?) => {
        impl<const BASE: usize, const DUAL: usize, const QUAD: usize>
            wasm_bindgen::describe::WasmDescribe for $name<BASE, DUAL, QUAD>
        where
            Uint<BASE>: ArrayEncoding $(+ $z)?,
            Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> $(+ $z)?,
            Uint<QUAD>: ArrayEncoding $(+ $z)?,
        {
            fn describe() {
                wasm_bindgen::describe::inform(wasm_bindgen::describe::SLICE)
            }
        }

        impl<const BASE: usize, const DUAL: usize, const QUAD: usize>
            wasm_bindgen::convert::IntoWasmAbi for $name<BASE, DUAL, QUAD>
        where
            Uint<BASE>: ArrayEncoding $(+ $z)?,
            Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> $(+ $z)?,
            Uint<QUAD>: ArrayEncoding $(+ $z)?,
        {
            type Abi = wasm_bindgen::convert::WasmSlice;

            fn into_abi(self) -> Self::Abi {
                let a = self.to_bytes();
                Self::Abi {
                    ptr: a.as_ptr().into_abi(),
                    len: a.len() as u32,
                }
            }
        }

        impl<const BASE: usize, const DUAL: usize, const QUAD: usize>
            wasm_bindgen::convert::FromWasmAbi for $name<BASE, DUAL, QUAD>
        where
            Uint<BASE>: ArrayEncoding $(+ $z)?,
            Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> $(+ $z)?,
            Uint<QUAD>: ArrayEncoding $(+ $z)?,
        {
            type Abi = wasm_bindgen::convert::WasmSlice;

            #[inline]
            unsafe fn from_abi(js: Self::Abi) -> Self {
                let ptr = <*mut u8>::from_abi(js.ptr);
                let len = js.len as usize;
                let r = std::slice::from_raw_parts(ptr, len);
                $name::from_bytes(&r).unwrap()
            }
        }

        impl<const BASE: usize, const DUAL: usize, const QUAD: usize>
            wasm_bindgen::convert::OptionIntoWasmAbi for $name<BASE, DUAL, QUAD>
        where
            Uint<BASE>: ArrayEncoding $(+ $z)?,
            Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> $(+ $z)?,
            Uint<QUAD>: ArrayEncoding $(+ $z)?,
        {
            fn none() -> wasm_bindgen::convert::WasmSlice {
                wasm_bindgen::convert::WasmSlice { ptr: 0, len: 0 }
            }
        }

        impl<const BASE: usize, const DUAL: usize, const QUAD: usize>
            wasm_bindgen::convert::OptionFromWasmAbi for $name<BASE, DUAL, QUAD>
        where
            Uint<BASE>: ArrayEncoding $(+ $z)?,
            Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> $(+ $z)?,
            Uint<QUAD>: ArrayEncoding $(+ $z)?,
        {
            fn is_none(slice: &wasm_bindgen::convert::WasmSlice) -> bool {
                slice.ptr == 0
            }
        }

        impl<const BASE: usize, const DUAL: usize, const QUAD: usize> TryFrom<wasm_bindgen::JsValue>
            for $name<BASE, DUAL, QUAD>
        where
            Uint<BASE>: ArrayEncoding $(+ $z)?,
            Uint<DUAL>: ArrayEncoding + Concat<Output = Uint<QUAD>> $(+ $z)?,
            Uint<QUAD>: ArrayEncoding $(+ $z)?,
        {
            type Error = &'static str;

            fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
                serde_wasm_bindgen::from_value(value).map_err(|_| "unable to deserialize value")
            }
        }
    };
}

macro_rules! define_types {
    ($base:ident, $double:ident, $quad:ident) => {
        use crypto_bigint::*;

        /// A base number of limbs
        pub const BASE_SIZE: usize = $base::LIMBS;
        /// A base number of bytes
        pub const BASE_BYTES: usize = $base::BYTES;
        /// A double number = 2X base number
        pub const DUAL_SIZE: usize = $double::LIMBS;
        /// A double number of bytes
        pub const DUAL_BYTES: usize = $double::BYTES;
        /// A quad number
        pub const QUAD_SIZE: usize = $quad::LIMBS;
        /// A quad number of bytes
        pub const QUAD_BYTES: usize = $quad::BYTES;

        /// A base number sized type
        pub type Base = $base;
        /// A double number sized type = 2X base number
        pub type Dual = $double;
        /// A quad number sized type = 4X base number
        pub type Quad = $quad;

        use crate::core::{
            CompressedDecryptionKey as InnerCompressedDecryptionKey,
            DecryptionKey as InnerDecryptionKey,
        };
        use crate::core::{
            CompressedEncryptionKey as InnerCompressedEncryptionKey,
            EncryptionKey as InnerEncryptionKey,
        };
        use crate::core::{RangeProof as InnerRangeProof, SquareFreeProof as InnerSquareFreeProof};

        pub use crate::core::proof::RangeProofErrorFactor;

        /// A Paillier decryption key
        pub type DecryptionKey = InnerDecryptionKey<BASE_SIZE, DUAL_SIZE, QUAD_SIZE>;
        /// The minimal representation of a Paillier decryption key
        /// with no precomputation
        pub type CompressedDecryptionKey = InnerCompressedDecryptionKey<BASE_SIZE>;
        /// A Paillier encryption key that also stores any precomputations
        pub type EncryptionKey = InnerEncryptionKey<BASE_SIZE, DUAL_SIZE, QUAD_SIZE>;
        /// A compressed Paillier encryption key that only stores the modulus
        pub type CompressedEncryptionKey = InnerCompressedEncryptionKey<DUAL_SIZE, QUAD_SIZE>;
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
        pub type SquareFreeProof = InnerSquareFreeProof<BASE_SIZE, DUAL_SIZE, QUAD_SIZE>;

        /// A range proof for a Paillier ciphertext as defined in
        /// Lindell <https://eprint.iacr.org/2017/552.pdf> Appendix A.
        ///
        /// Verifier is given the ciphertext C = ENC(ek, x).
        ///
        /// Prover demonstrates that x<q/3 in [0, q).
        pub type RangeProof = InnerRangeProof<BASE_SIZE, DUAL_SIZE, QUAD_SIZE>;
    };
}
