use token::TokenSet;

pub mod token;
pub mod encryption;
/// Represents an error that can occur during OAuth operations.
#[derive(Debug)]
pub enum AuthError {
    InvalidCredentials,
    TokenExpired,
    TokenExchangeFailed,
    ProviderError(String),
    RateLimited(String)
}



/// Represents basic user information fetched from the OAuth provider.
#[derive(Debug)]
pub struct UserInfo {
    pub user_id: String,
    pub username: String,
    pub email: Option<String>,
}

/// Defines the behavior that any OAuth provider must implement.

#[async_trait::async_trait]
pub trait OAuthProvider {
    /// Returns the URL to initiate the OAuth authorization flow.
    fn auth_url(&self) -> String;

    /// Exchanges an authorization code for an access token.
    async fn exchange_code(&self, code: &str) -> Result<TokenSet, AuthError>;

    /// Refreshes an expired access token.
    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenSet, AuthError>;

    /// Fetches user information using the access token.
    async fn get_user_info(&self, access_token: &str) -> Result<UserInfo, AuthError>;

    async fn refresh_tokens_for_all_users(&self) -> Result<(), AuthError>;
}

/// A trait to implement rate-limiting logic.
pub trait RateLimiter {
    /// Checks if a rate limit has been exceeded.
    fn check(&self, key: &str) -> bool;

    /// Records an action (e.g., API request) to enforce rate limiting.
    fn record(&self, key: &str);
}


