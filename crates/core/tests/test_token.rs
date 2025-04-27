#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use core_lib::token::TokenSet;

    #[test]
    fn test_token_expiration() {
        let token = TokenSet {
            access_token: String::from("access_token"),
            refresh_token: Some(String::from("refresh_token")),
            expires_at: Some(Utc::now() + Duration::seconds(5)),
        };

        // Wait for a short time to simulate token expiration
        std::thread::sleep(std::time::Duration::from_secs(6));

        assert!(token.is_expired());
    }

    #[test]
    fn test_token_not_expired() {
        let token = TokenSet {
            access_token: String::from("access_token"),
            refresh_token: Some(String::from("refresh_token")),
            expires_at: Some(Utc::now() + Duration::seconds(10)),
        };

        assert!(!token.is_expired());
    }
}
