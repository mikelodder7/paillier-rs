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
    /// Invalid ciphertext add inputs
    #[error("Invalid ciphertext add inputs")]
    InvalidCipherTextAddInputs,
    /// Invalid ciphertext multiply inputs
    #[error("Invalid ciphertext multiply inputs")]
    InvalidCipherTextMulInputs,
    /// Invalid ciphertext
    #[error("Invalid ciphertext, unable to decrypt")]
    InvalidCiphertext,
}

/// Paillier results
pub type PaillierResult<T> = Result<T, PaillierError>;
