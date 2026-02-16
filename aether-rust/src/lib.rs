//! Aether Rust - Security and Performance Layer
//! 
//! Features:
//! - AES-256-GCM encryption
//! - RSA-4096 key generation
//! - Secure password hashing (Argon2)
//! - Zero-copy where possible
//! - Memory safety guarantees

pub mod crypto;
pub mod secure_storage;
pub mod network;

#[cfg(feature = "python")]
pub mod python_ffi;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AetherError {
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    #[error("Decryption error: {0}")]
    Decryption(String),
    
    #[error("Storage error: {0}")]
    Storage(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, AetherError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic() {
        assert_eq!(2 + 2, 4);
    }
}
