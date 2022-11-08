/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Paillier-rs contains Paillier's cryptosystem (1999)
//! Public-Key Cryptosystems based on composite degree residuosity class.
//! See <http://citeseerx.ist.psu.edu/download?doi=10.1.1.4035&rep=rep1&type=pdf>
#![no_std]
#![deny(
    warnings,
    missing_docs,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

#[cfg(feature = "wasm")]
#[macro_use]
mod macros;
mod decryptionkey;
mod encryptionkey;
mod proof_psf;

pub use unknown_order;

use unknown_order::BigNumber;

pub(crate) fn mod_in(a: &BigNumber, n: &BigNumber) -> bool {
    let lhs = &BigNumber::one() <= a;
    let rhs = a < n;
    lhs & rhs
}

/// A Paillier Ciphertext
pub type Ciphertext = BigNumber;
/// A Paillier nonce used during encryption
pub type Nonce = BigNumber;

pub use decryptionkey::*;
pub use encryptionkey::*;
pub use proof_psf::*;
