/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Paillier-rs contains Paillier's cryptosystem (1999)
//! Public-Key Cryptosystems based on composite degree residuosity class.
//! See <http://citeseerx.ist.psu.edu/download?doi=10.1.1.4035&rep=rep1&type=pdf>
#![deny(
    warnings,
    missing_docs,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[macro_use]
mod macros;
mod core;
mod error;
mod utils;

#[cfg(feature = "2048")]
/// Paillier 2048-bit key size
pub mod paillier2048 {
    use super::*;

    define_types!(U1024, U2048, U4096);
}
#[cfg(feature = "3072")]
/// Paillier 3072-bit key size
pub mod paillier3072 {
    use super::*;

    define_types!(U1536, U3072, U6144);
}

#[cfg(feature = "4096")]
/// Paillier 4096-bit key size
pub mod paillier4096 {
    use super::*;

    define_types!(U2048, U4096, U8192);
}

pub use crypto_bigint;
pub use crypto_primes;
pub use error::*;
pub use utils::var_bytes_to_uint;
