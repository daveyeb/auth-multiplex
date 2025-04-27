use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine};
use rand::RngCore;

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

#[derive(Debug)]
pub enum CryptoError {
    InvalidKeyLength(usize),
    EncryptionError,
    DecryptionError,
    InvalidFormat,
    Utf8Error,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKeyLength(len) => {
                write!(f, "Invalid key length: {} (expected {})", len, KEY_SIZE)
            }
            CryptoError::EncryptionError => write!(f, "Encryption failed"),
            CryptoError::DecryptionError => write!(f, "Decryption failed"),
            CryptoError::InvalidFormat => write!(f, "Invalid format"),
            CryptoError::Utf8Error => write!(f, "UTF-8 conversion error"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub struct Encryptor {
    cipher: Aes256Gcm,
}

impl Encryptor {
    pub fn new(key: &[u8]) -> Self {
        Self::try_new(key).unwrap_or_else(|e| panic!("{}", e))
    }

    /// Safe constructor that returns Result
    pub fn try_new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        let key = Key::<Aes256Gcm>::from_slice(key);
        Ok(Self {
            cipher: Aes256Gcm::new(key),
        })
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String, CryptoError> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::rng().fill_bytes(&mut nonce_bytes);

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| CryptoError::EncryptionError)?;

        Ok(format!(
            "{}:{}",
            general_purpose::STANDARD.encode(nonce_bytes),
            general_purpose::STANDARD.encode(ciphertext)
        ))
    }

    pub fn decrypt(&self, encoded: &str) -> Result<String, CryptoError> {
        let parts: Vec<&str> = encoded.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(CryptoError::InvalidFormat);
        }

        let nonce_bytes = general_purpose::STANDARD
            .decode(parts[0])
            .map_err(|_| CryptoError::InvalidFormat)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = general_purpose::STANDARD
            .decode(parts[1])
            .map_err(|_| CryptoError::InvalidFormat)?;

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionError)?;

        String::from_utf8(plaintext).map_err(|_| CryptoError::Utf8Error)
    }
}
