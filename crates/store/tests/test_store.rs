#[cfg(test)]
mod tests {
    use chrono::Utc;
    use core_lib::{encryption::Encryptor, token::TokenSet};
    use hex_literal::hex;
    use store::{RedisTokenStore, TokenStore};

    fn test_encryptor() -> Encryptor {
        let key = hex!(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        );
        Encryptor::new(&key)
    }

    fn test_token_set() -> TokenSet {
        TokenSet {
            access_token: "access_123".to_string(),
            refresh_token: Some("refresh_456".to_string()),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        }
    }

    fn create_store() -> RedisTokenStore {
        let client = redis::Client::open("redis://127.0.0.1/").expect("Failed to connect to Redis");
        RedisTokenStore {
            client,
            encryptor: test_encryptor(),
        }
    }

    #[tokio::test]
    async fn test_store_and_load_token_roundtrip() {
        let user_id = "user_123";
        let store = create_store();
        let token_set = test_token_set();

        let session_id = store
            .create_session(user_id, &token_set)
            .await
            .expect("Failed to store token");

        let loaded = store
            .get_session(&session_id)
            .await
            .expect("Failed to load token");

        assert!(loaded.is_some());
        let loaded_token = loaded.unwrap();

        assert_eq!(loaded_token.access_token, token_set.access_token);
        assert_eq!(loaded_token.refresh_token, token_set.refresh_token);
        assert_eq!(loaded_token.expires_at, token_set.expires_at);
    }

    #[tokio::test]
    async fn test_load_nonexistent_token() {
        let store = create_store();
        let result = store
            .get_session("nonexistent_user")
            .await
            .expect("Failed to call load");
        assert!(result.is_none());
    }
}
