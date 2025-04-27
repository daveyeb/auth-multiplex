use chrono::{Duration, Utc};
use core_lib::{encryption::Encryptor, token::TokenSet, AuthError};
use hex_literal::hex;
use redis::{Client, Commands};

use uuid::Uuid;

#[async_trait::async_trait]
pub trait TokenStore {
    async fn create_session(&self, user_id: &str, token_set: &TokenSet) -> Result<String, AuthError>;
    async fn get_session(&self, session_id: &str) -> Result<Option<TokenSet>, AuthError>;
    async fn delete_session(&self, session_id: &str) -> Result<(), AuthError>;
    async fn update_refresh_token(
        &self,
        session_id: &str,
        new_refresh_token: &str,
    ) -> Result<bool, AuthError>;
}

pub struct RedisTokenStore {
    pub client: Client,
    pub encryptor: Encryptor,
}

impl RedisTokenStore {
    pub fn new(redis_address: String) -> Self {
        let client = redis::Client::open(redis_address)
            .map_err(|e| AuthError::ProviderError(format!("Redis connection failed: {e}")))
            .unwrap();

        // Proper 32-byte test key
        const REDIS_TOKEN_KEY: [u8; 32] = hex!(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        );

        let encyptor = Encryptor::new(&REDIS_TOKEN_KEY);

        RedisTokenStore {
            client,
            encryptor: encyptor,
        }
    }
}

#[async_trait::async_trait]
impl TokenStore for RedisTokenStore {
    async fn create_session(
        &self,
        _user_id: &str,
        token_set: &TokenSet,
    ) -> Result<String, AuthError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| AuthError::ProviderError(format!("Redis connection failed: {e}")))?;

        let session_id = Uuid::new_v4().to_string();

        let token_set = TokenSet {
            access_token: self
                .encryptor
                .encrypt(&token_set.access_token)
                .map_err(|e| AuthError::ProviderError(format!("Encryption failed: {e}")))?,
            refresh_token: match &token_set.refresh_token {
                Some(refresh_token) => Some(
                    self.encryptor
                        .encrypt(refresh_token)
                        .map_err(|e| AuthError::ProviderError(format!("Encryption failed: {e}")))?,
                ),
                None => None,
            },
            expires_at: token_set.expires_at,
        };

        let serialized = serde_json::to_string(&token_set)
            .map_err(|e| AuthError::ProviderError(format!("Serialization failed: {e}")))?;

        redis::cmd("SET")
            .arg(&session_id)
            .arg(serialized)
            .query(&mut conn)
            .map_err(|e| AuthError::ProviderError(format!("Redis SET failed: {e}")))?;

        Ok(session_id)
    }

    async fn get_session(&self, session_id: &str) -> Result<Option<TokenSet>, AuthError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| AuthError::ProviderError(format!("Redis connection failed: {e}")))?;

        let stored_data: Option<String> = redis::cmd("GET")
            .arg(session_id)
            .query(&mut conn)
            .map_err(|e| AuthError::ProviderError(format!("Redis GET failed: {e}")))?;

        if let Some(data) = stored_data {
            let stored_token: TokenSet = serde_json::from_str(&data)
                .map_err(|e| AuthError::ProviderError(format!("Deserialization failed: {e}")))?;

            let access_token = self
                .encryptor
                .decrypt(&stored_token.access_token)
                .map_err(|e| AuthError::ProviderError(format!("Decryption failed: {e}")))?;

            let refresh_token =
                match stored_token.refresh_token {
                    Some(token) => Some(self.encryptor.decrypt(&token).map_err(|e| {
                        AuthError::ProviderError(format!("Decryption failed: {e}"))
                    })?),
                    None => None,
                };

            Ok(Some(TokenSet {
                access_token,
                refresh_token,
                expires_at: stored_token.expires_at,
            }))
        } else {
            Ok(None)
        }
    }

    async fn delete_session(&self, session_id: &str) -> Result<(), AuthError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| AuthError::ProviderError(format!("Redis connection failed {e}")))?;

        redis::cmd("DEL")
            .arg(session_id)
            .query::<()>(&mut conn)
            .map_err(|e| AuthError::ProviderError(format!("DEL command failed: {e}")))?;

        Ok(())
    }

    async fn update_refresh_token(
        &self,
        session_id: &str,
        new_refresh_token: &str,
    ) -> Result<bool, AuthError> {
        let mut conn = self
            .client
            .get_connection()
            .map_err(|e| AuthError::ProviderError(format!("Redis connection failed {e}")))?;

        let json: Option<String> = conn
            .get(session_id)
            .map_err(|e| AuthError::ProviderError(format!("Redis get command failed {e}")))?;

        match json {
            Some(json_str) => {
                let mut session: TokenSet = serde_json::from_str(&json_str).unwrap();
                session.refresh_token = Some(new_refresh_token.to_string());
                session.expires_at = Some(Utc::now() + Duration::hours(24));

                // Update session in Redis
                let updated_json = serde_json::to_string(&session).unwrap();
                redis::cmd("SETEX")
                    .arg(session_id)
                    .arg(24 * 60 * 60)
                    .arg(updated_json)
                    .query::<()>(&mut conn)
                    .map_err(|e| {
                        AuthError::ProviderError(format!("Redis SETEX command failed: {e}"))
                    })?;

                Ok(true)
            }
            None => Ok(false),
        }
    }

    //pub async fn start_refresh_loop<P: OAuthProvider + Send + Sync + 'static>(provider: P) {
    //    tokio::spawn(async move {
    //        let mut interval = interval(Duration::from_secs(599)); // every 10 mins
    //        loop {
    //            interval.tick().await;
    //            if let Err(err) = provider.refresh_tokens_for_all_users().await {
    //                eprintln!("⚠️ Failed to refresh tokens: {:?}", err);
    //            }
    //        }
    //    });
    //}
}
