use thiserror::Error;

#[derive(Error, Debug)]
pub enum LazarusError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Storage backend error: {0}")]
    Storage(String),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Unknown error")]
    Unknown,
}

// Keep the old name for backward compatibility
pub type Error = LazarusError;

pub type Result<T> = std::result::Result<T, LazarusError>;
