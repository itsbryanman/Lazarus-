use aes_gcm::aead::generic_array::GenericArray;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{PasswordHash, SaltString};
use argon2::password_hash::rand_core::OsRng;
use serde::{Deserialize, Serialize};
use crate::error::{Result, LazarusError};

/// Configuration stored in the repository
#[derive(Serialize, Deserialize, Clone)]
pub struct RepositoryConfig {
    /// Salt for Argon2id key derivation
    pub salt: String,
    /// Repository encryption key, encrypted with the master key
    pub encrypted_repo_key: Vec<u8>,
    /// Metadata encryption key, encrypted with the master key
    pub encrypted_metadata_key: Vec<u8>,
    /// Nonce used for encrypting the repository key
    pub repo_key_nonce: Vec<u8>,
    /// Nonce used for encrypting the metadata key
    pub metadata_key_nonce: Vec<u8>,
}

/// Key manager for handling encryption keys
pub struct KeyManager {
    /// Repository encryption key (32 bytes for AES-256)
    repo_key: [u8; 32],
    /// Metadata encryption key (32 bytes for AES-256)
    metadata_key: [u8; 32],
}

impl KeyManager {
    /// Initialize a new repository with a master password
    pub fn init_repository(master_password: &str) -> Result<(Self, RepositoryConfig)> {
        // Generate a random salt
        let salt = SaltString::generate(&mut OsRng);

        // Derive master key from password using Argon2id
        let master_key = Self::derive_master_key(master_password, salt.as_str())?;

        // Generate random repository and metadata keys
        let mut repo_key = [0u8; 32];
        let mut metadata_key = [0u8; 32];

        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut repo_key);
        rng.fill_bytes(&mut metadata_key);

        // Encrypt the keys with the master key
        use aes_gcm::{Aes256Gcm, KeyInit};
        use aes_gcm::aead::Aead;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&master_key));

        // Generate unique nonces for encrypting each key
        let mut repo_key_nonce = [0u8; 12];
        let mut metadata_key_nonce = [0u8; 12];
        rng.fill_bytes(&mut repo_key_nonce);
        rng.fill_bytes(&mut metadata_key_nonce);

        let encrypted_repo_key = cipher
            .encrypt(GenericArray::from_slice(&repo_key_nonce), &repo_key[..])
            .map_err(|_| LazarusError::EncryptionError("Failed to encrypt repository key".into()))?;

        let encrypted_metadata_key = cipher
            .encrypt(GenericArray::from_slice(&metadata_key_nonce), &metadata_key[..])
            .map_err(|_| LazarusError::EncryptionError("Failed to encrypt metadata key".into()))?;

        let config = RepositoryConfig {
            salt: salt.as_str().to_string(),
            encrypted_repo_key,
            encrypted_metadata_key,
            repo_key_nonce: repo_key_nonce.to_vec(),
            metadata_key_nonce: metadata_key_nonce.to_vec(),
        };

        let manager = KeyManager {
            repo_key,
            metadata_key,
        };

        Ok((manager, config))
    }

    /// Unlock an existing repository with a master password
    pub fn unlock_repository(master_password: &str, config: &RepositoryConfig) -> Result<Self> {
        // Derive master key from password
        let master_key = Self::derive_master_key(master_password, &config.salt)?;

        // Decrypt the keys
        use aes_gcm::{Aes256Gcm, KeyInit};
        use aes_gcm::aead::Aead;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&master_key));

        let repo_key_bytes = cipher
            .decrypt(
                GenericArray::from_slice(&config.repo_key_nonce),
                config.encrypted_repo_key.as_ref()
            )
            .map_err(|_| LazarusError::EncryptionError("Failed to decrypt repository key - wrong password?".into()))?;

        let metadata_key_bytes = cipher
            .decrypt(
                GenericArray::from_slice(&config.metadata_key_nonce),
                config.encrypted_metadata_key.as_ref()
            )
            .map_err(|_| LazarusError::EncryptionError("Failed to decrypt metadata key".into()))?;

        if repo_key_bytes.len() != 32 || metadata_key_bytes.len() != 32 {
            return Err(LazarusError::EncryptionError("Invalid key length".into()));
        }

        let mut repo_key = [0u8; 32];
        let mut metadata_key = [0u8; 32];
        repo_key.copy_from_slice(&repo_key_bytes);
        metadata_key.copy_from_slice(&metadata_key_bytes);

        Ok(KeyManager {
            repo_key,
            metadata_key,
        })
    }

    /// Derive a master key from a password and salt using Argon2id
    fn derive_master_key(password: &str, salt: &str) -> Result<[u8; 32]> {
        let argon2 = Argon2::default();

        // Parse the salt
        let salt_string = SaltString::from_b64(salt)
            .map_err(|_| LazarusError::EncryptionError("Invalid salt".into()))?;

        // Hash the password
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| LazarusError::EncryptionError(format!("Failed to hash password: {}", e)))?;

        // Extract the hash bytes
        let hash_output = password_hash.hash
            .ok_or_else(|| LazarusError::EncryptionError("No hash output".into()))?;
        let hash_bytes = hash_output.as_bytes();

        if hash_bytes.len() < 32 {
            return Err(LazarusError::EncryptionError("Hash too short".into()));
        }

        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&hash_bytes[..32]);

        Ok(master_key)
    }

    /// Get the repository encryption key
    pub fn get_repo_key(&self) -> &[u8; 32] {
        &self.repo_key
    }

    /// Get the metadata encryption key
    pub fn get_metadata_key(&self) -> &[u8; 32] {
        &self.metadata_key
    }

    /// Encrypt data with the repository key and a unique random nonce
    pub fn encrypt_data(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        use aes_gcm::{Aes256Gcm, KeyInit};
        use aes_gcm::aead::Aead;
        use rand::RngCore;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.repo_key));

        // Generate a unique random nonce for this encryption
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let encrypted = cipher
            .encrypt(GenericArray::from_slice(&nonce), data)
            .map_err(|_| LazarusError::EncryptionError("Failed to encrypt data".into()))?;

        Ok((encrypted, nonce.to_vec()))
    }

    /// Decrypt data with the repository key
    pub fn decrypt_data(&self, encrypted_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit};
        use aes_gcm::aead::Aead;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.repo_key));

        let decrypted = cipher
            .decrypt(GenericArray::from_slice(nonce), encrypted_data)
            .map_err(|_| LazarusError::EncryptionError("Failed to decrypt data".into()))?;

        Ok(decrypted)
    }

    /// Encrypt metadata with the metadata key
    pub fn encrypt_metadata(&self, metadata: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        use aes_gcm::{Aes256Gcm, KeyInit};
        use aes_gcm::aead::Aead;
        use rand::RngCore;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.metadata_key));

        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        let encrypted = cipher
            .encrypt(GenericArray::from_slice(&nonce), metadata.as_bytes())
            .map_err(|_| LazarusError::EncryptionError("Failed to encrypt metadata".into()))?;

        Ok((encrypted, nonce.to_vec()))
    }

    /// Decrypt metadata with the metadata key
    pub fn decrypt_metadata(&self, encrypted_metadata: &[u8], nonce: &[u8]) -> Result<String> {
        use aes_gcm::{Aes256Gcm, KeyInit};
        use aes_gcm::aead::Aead;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.metadata_key));

        let decrypted = cipher
            .decrypt(GenericArray::from_slice(nonce), encrypted_metadata)
            .map_err(|_| LazarusError::EncryptionError("Failed to decrypt metadata".into()))?;

        String::from_utf8(decrypted)
            .map_err(|_| LazarusError::EncryptionError("Invalid UTF-8 in metadata".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_and_unlock() {
        // Create a new repository
        let password = "test_password_12345";
        let (manager1, config) = KeyManager::init_repository(password).unwrap();

        // Unlock the repository with the same password
        let manager2 = KeyManager::unlock_repository(password, &config).unwrap();

        // Keys should be equal
        assert_eq!(manager1.get_repo_key(), manager2.get_repo_key());
        assert_eq!(manager1.get_metadata_key(), manager2.get_metadata_key());
    }

    #[test]
    fn test_unlock_wrong_password() {
        // Create a new repository
        let password = "correct_password";
        let (_manager, config) = KeyManager::init_repository(password).unwrap();

        // Try to unlock with wrong password
        let wrong_password = "wrong_password";
        let result = KeyManager::unlock_repository(wrong_password, &config);

        // Should fail
        assert!(result.is_err());
        match result {
            Err(LazarusError::EncryptionError(msg)) => {
                assert!(msg.contains("wrong password") || msg.contains("decrypt"));
            }
            _ => panic!("Expected EncryptionError"),
        }
    }

    #[test]
    fn test_data_encryption_roundtrip() {
        // Create a key manager
        let password = "test_password";
        let (manager, _config) = KeyManager::init_repository(password).unwrap();

        // Test data
        let original_data = b"This is some test data that should be encrypted and decrypted correctly!";

        // Encrypt
        let (encrypted, nonce) = manager.encrypt_data(original_data).unwrap();

        // Verify encrypted data is different from original
        assert_ne!(&encrypted[..], &original_data[..]);

        // Decrypt
        let decrypted = manager.decrypt_data(&encrypted, &nonce).unwrap();

        // Verify decrypted matches original
        assert_eq!(&decrypted[..], &original_data[..]);
    }

    #[test]
    fn test_metadata_encryption_roundtrip() {
        // Create a key manager
        let password = "test_password";
        let (manager, _config) = KeyManager::init_repository(password).unwrap();

        // Test metadata
        let original_metadata = "test_file.txt";

        // Encrypt
        let (encrypted, nonce) = manager.encrypt_metadata(original_metadata).unwrap();

        // Decrypt
        let decrypted = manager.decrypt_metadata(&encrypted, &nonce).unwrap();

        // Verify decrypted matches original
        assert_eq!(decrypted, original_metadata);
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertexts() {
        // Create a key manager
        let password = "test_password";
        let (manager, _config) = KeyManager::init_repository(password).unwrap();

        // Same plaintext
        let data = b"same data";

        // Encrypt twice
        let (encrypted1, nonce1) = manager.encrypt_data(data).unwrap();
        let (encrypted2, nonce2) = manager.encrypt_data(data).unwrap();

        // Nonces should be different
        assert_ne!(nonce1, nonce2);

        // Ciphertexts should be different (due to different nonces)
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to same plaintext
        let decrypted1 = manager.decrypt_data(&encrypted1, &nonce1).unwrap();
        let decrypted2 = manager.decrypt_data(&encrypted2, &nonce2).unwrap();
        assert_eq!(decrypted1, decrypted2);
        assert_eq!(&decrypted1[..], data);
    }

    #[test]
    fn test_decrypt_with_wrong_nonce_fails() {
        // Create a key manager
        let password = "test_password";
        let (manager, _config) = KeyManager::init_repository(password).unwrap();

        // Encrypt data
        let data = b"test data";
        let (encrypted, _correct_nonce) = manager.encrypt_data(data).unwrap();

        // Try to decrypt with wrong nonce
        let wrong_nonce = vec![0u8; 12];
        let result = manager.decrypt_data(&encrypted, &wrong_nonce);

        // Should fail
        assert!(result.is_err());
    }
}
