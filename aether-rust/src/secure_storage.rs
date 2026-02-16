//! Secure storage module
//! 
//! Encrypted key-value store for sensitive data

use sled::{Db, IVec};
use crate::{crypto::{Encryptor, random_bytes}, AetherError, Result};

/// Encrypted key-value storage
pub struct SecureVault {
    db: Db,
    encryptor: Encryptor,
}

impl SecureVault {
    /// Create or open a secure vault
    pub fn new(path: &str, master_key: &[u8; 32]) -> Result<Self> {
        let db = sled::open(path)
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        
        let encryptor = Encryptor::new(master_key);

        Ok(Self { db, encryptor })
    }

    /// Store encrypted value
    pub fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        let nonce = random_bytes::<12>();
        let encrypted = self.encryptor.encrypt(value, &nonce)?;

        // Store nonce + encrypted data
        let mut stored = Vec::with_capacity(12 + encrypted.len());
        stored.extend_from_slice(&nonce);
        stored.extend_from_slice(&encrypted);

        self.db
            .insert(key.as_bytes(), stored)
            .map_err(|e| AetherError::Storage(e.to_string()))?;

        Ok(())
    }

    /// Retrieve and decrypt value
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let stored = match self.db.get(key.as_bytes())
            .map_err(|e| AetherError::Storage(e.to_string()))? {
            Some(data) => data,
            None => return Ok(None),
        };

        if stored.len() < 12 {
            return Err(AetherError::Decryption("Invalid stored data".into()));
        }

        // Extract nonce and encrypted data
        let nonce: [u8; 12] = stored[..12].try_into().unwrap();
        let encrypted = &stored[12..];

        let decrypted = self.encryptor.decrypt(encrypted, &nonce)?;
        Ok(Some(decrypted))
    }

    /// Delete entry
    pub fn delete(&self, key: &str) -> Result<()> {
        self.db
            .remove(key.as_bytes())
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(())
    }

    /// List all keys
    pub fn keys(&self) -> Result<Vec<String>> {
        let keys: Result<Vec<String>> = self.db
            .iter()
            .keys()
            .map(|k| {
                let key_bytes = k.map_err(|e| AetherError::Storage(e.to_string()))?;
                String::from_utf8(key_bytes.to_vec())
                    .map_err(|e| AetherError::Storage(e.to_string()))
            })
            .collect();

        keys
    }

    /// Clear all data
    pub fn clear(&self) -> Result<()> {
        self.db
            .clear()
            .map_err(|e| AetherError::Storage(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_bytes;
    use tempfile::tempdir;

    #[test]
    fn test_secure_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_vault");
        let master_key = random_bytes::<32>();

        let vault = SecureVault::new(path.to_str().unwrap(), &master_key).unwrap();

        // Store
        vault.set("api_key", b"secret_api_key_12345").unwrap();
        vault.set("password", b"my_secure_password").unwrap();

        // Retrieve
        let api_key = vault.get("api_key").unwrap().unwrap();
        assert_eq!(api_key, b"secret_api_key_12345");

        // List keys
        let keys = vault.keys().unwrap();
        assert_eq!(keys.len(), 2);

        // Delete
        vault.delete("password").unwrap();
        assert!(vault.get("password").unwrap().is_none());
    }
}
