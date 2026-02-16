//! Cryptography module
//! 
//! Provides secure encryption, hashing, and key management

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use ring::pbkdf2;
use sha2::{Sha256, Digest};
use blake3::Hasher;
use zeroize::Zeroize;
use std::num::NonZeroU32;

use crate::{AetherError, Result};

const PBKDF2_ITERATIONS: u32 = 100_000;

/// AES-256-GCM encryption/decryption
pub struct Encryptor {
    cipher: Aes256Gcm,
}

impl Encryptor {
    /// Create new encryptor with a key
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new(key.into());
        Self { cipher }
    }

    /// Encrypt data with AES-256-GCM
    pub fn encrypt(&self, data: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        
        self.cipher
            .encrypt(nonce, data)
            .map_err(|e| AetherError::Encryption(e.to_string()))
    }

    /// Decrypt data
    pub fn decrypt(&self, encrypted: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        
        self.cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| AetherError::Decryption(e.to_string()))
    }
}

/// Secure password hashing using PBKDF2
pub struct PasswordHasher {
    iterations: NonZeroU32,
}

impl PasswordHasher {
    pub fn new() -> Self {
        Self {
            iterations: NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
        }
    }

    /// Hash a password with a salt
    pub fn hash_password(&self, password: &str, salt: &[u8]) -> [u8; 32] {
        let mut hash = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            self.iterations,
            salt,
            password.as_bytes(),
            &mut hash,
        );
        hash
    }

    /// Verify password against hash
    pub fn verify_password(
        &self,
        password: &str,
        salt: &[u8],
        expected_hash: &[u8; 32],
    ) -> bool {
        let actual_hash = self.hash_password(password, salt);
        
        // Constant-time comparison
        pbkdf2::verify(
            pbkdf2::PBKDF2_HMAC_SHA256,
            self.iterations,
            salt,
            password.as_bytes(),
            expected_hash,
        ).is_ok()
    }
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-256 hashing
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// BLAKE3 hashing (faster than SHA-256)
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Generate random bytes
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).expect("Failed to generate random bytes");
    bytes
}

/// Secure key derivation from password
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive 256-bit key from password
    pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
        let hasher = PasswordHasher::new();
        hasher.hash_password(password, salt)
    }
}

/// Zero-sensitive data from memory
pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    pub fn new(s: String) -> Self {
        Self {
            data: s.into_bytes(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption() {
        let key = random_bytes::<32>();
        let nonce = random_bytes::<12>();
        let data = b"Hello, World!";

        let encryptor = Encryptor::new(&key);
        let encrypted = encryptor.encrypt(data, &nonce).unwrap();
        let decrypted = encryptor.decrypt(&encrypted, &nonce).unwrap();

        assert_eq!(data, &decrypted[..]);
    }

    #[test]
    fn test_password_hashing() {
        let hasher = PasswordHasher::new();
        let password = "super_secret_password";
        let salt = random_bytes::<32>();

        let hash = hasher.hash_password(password, &salt);
        assert!(hasher.verify_password(password, &salt, &hash));
        assert!(!hasher.verify_password("wrong_password", &salt, &hash));
    }

    #[test]
    fn test_hashing() {
        let data = b"test data";
        let sha_hash = sha256(data);
        let blake_hash = blake3(data);

        assert_eq!(sha_hash.len(), 32);
        assert_eq!(blake_hash.len(), 32);
    }
}
