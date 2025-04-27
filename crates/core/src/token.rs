use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::encryption::{CryptoError, Encryptor};

/// Holds access and refresh tokens, along with expiration information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl TokenSet {
    pub fn new(
        access_token: &str,
        refresh_token: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
        encryptor: &Encryptor,
    ) -> Self {
        Self {
            access_token: encryptor
                .encrypt(access_token)
                .expect("Access Token Encryption failed"),
            refresh_token: refresh_token.map(|t| {
                encryptor
                    .encrypt(t)
                    .expect("Refresh Token Encyption failed")
            }),
            expires_at,
        }
    }

    pub fn access_token(&self, encryptor: &Encryptor) -> Result<String, CryptoError> {
        encryptor.decrypt(&self.access_token)
    }

    pub fn refresh_token(&self, encryptor: &Encryptor) -> Option<String> {
        self.refresh_token.as_ref().map(|t| {
            encryptor
                .decrypt(t)
                .expect("Refresh Token Encryption failed")
        })
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expiration) = &self.expires_at {
            Utc::now() > *expiration
        } else {
            false
        }
    }
}
