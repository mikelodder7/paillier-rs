use thiserror::Error;

/// Errors produced by the Paillier scheme
#[derive(Debug, Error)]
pub enum PaillierError {
    /// Postcard deserialization error
    #[error("Invalid serialized bytes: {0}")]
    PostcardError(#[from] postcard::Error),
    /// Invalid proof size
    #[error("Invalid proof size: {0}")]
    InvalidProofSize(usize),
    /// Invalid encryption key
    #[error("Invalid encryption key")]
    InvalidEncryptionKey,
    /// Invalid encryption inputs
    #[error("Invalid encryption inputs")]
    InvalidEncryptionInputs,
    #[error("Invalid decryption key")]
    /// Invalid decryption key
    InvalidDecryptionKey,
    /// Invalid ciphertext add inputs
    #[error("Invalid ciphertext add inputs")]
    InvalidCipherTextAddInputs,
    /// Invalid ciphertext multiply inputs
    #[error("Invalid ciphertext multiply inputs")]
    InvalidCipherTextMulInputs,
    /// Invalid ciphertext
    #[error("Invalid ciphertext, unable to decrypt")]
    InvalidCiphertext,
    /// Invalid range proof error factor number
    #[error("Invalid range proof error factor number")]
    InvalidRangeProofErrorFactor,
    /// Invalid verifier commitment
    #[error("Invalid verifier commitment")]
    InvalidVerifierCommitment,
    /// Invalid range proof
    #[error("Invalid range proof")]
    InvalidRangeProof,
    /// Invalid primes provided for key generation
    #[error("Invalid primes")]
    InvalidPrimes,
}

/// Paillier results
pub type PaillierResult<T> = Result<T, PaillierError>;
