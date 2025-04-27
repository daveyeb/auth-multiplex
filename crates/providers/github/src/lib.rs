use std::time::Duration;
use store::RedisTokenStore;

use core_lib::{token::TokenSet, AuthError, OAuthProvider, UserInfo};
use ratelimiter::{LimiterConfig, TokenRateLimiter};
use reqwest::Client;
use serde::{Deserialize, Serialize};

const GITHUB_API_URL: &str = "https://api.github.com/user";
const GITHUB_AUTH_URL: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

#[derive(Deserialize, Serialize, Debug)]
struct GitHubTokenResponse {
    access_token: String,
    scope: Option<String>,
    token_type: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct GitHubUser {
    login: String,
    id: u64,
    email: Option<String>,
}

pub struct GitHubProvider {
    client_id: String,
    client_secret: String,
    rate_limiter: TokenRateLimiter,
    token_store: Option<RedisTokenStore>
}

impl GitHubProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        let config = LimiterConfig {
            global_limit: 100,
            global_period: Duration::from_secs(60),
            default_user_limit: 10,
            user_quota_reset_interval: Duration::from_secs(3600),
            user_inactivity_timeout: Duration::from_secs(86400),
        };

        GitHubProvider {
            client_id,
            client_secret,
            rate_limiter: TokenRateLimiter::new(config),
            token_store: None
        }
    }

    fn get_client() -> Client {
        Client::new()
    }
}

#[async_trait::async_trait]
impl OAuthProvider for GitHubProvider {
    fn auth_url(&self) -> String {
        format!(
            "{}?client_id={}&scope=user",
            GITHUB_AUTH_URL, self.client_id
        )
    }

    async fn exchange_code(&self, code: &str) -> Result<TokenSet, AuthError> {
        let client = Self::get_client();

        let res = client
            .post(GITHUB_TOKEN_URL)
            .form(&[
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
                ("code", &code.to_string()),
            ])
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|err| {
                eprintln!("Error encounterd {:?}", err);
                AuthError::TokenExchangeFailed
            })?;

        let token_response: GitHubTokenResponse = res.json().await.map_err(|err| {
            eprintln!("Error encounterd {:?}", err);
            AuthError::TokenExchangeFailed
        })?;

        Ok(TokenSet {
            access_token: token_response.access_token,
            refresh_token: None, // GitHub doesn't return a refresh token
            expires_at: None,    // GitHub tokens don't have expiration info in this flow
        })
    }

    async fn refresh_token(&self, _refresh_token: &str) -> Result<TokenSet, AuthError> {
        Err(AuthError::TokenExpired)
    }

    async fn get_user_info(&self, access_token: &str) -> Result<UserInfo, AuthError> {
        let client = Self::get_client();

        self.rate_limiter
            .check(access_token)
            .await
            .map_err(|e| AuthError::RateLimited(e.to_string()))?;

        let res = client
            .get(GITHUB_API_URL)
            .header("Authorization", format!("token {}", access_token))
            .send()
            .await
            .map_err(|_| AuthError::ProviderError("GitHub API request failed".to_string()))?;

        let user_info: GitHubUser = res
            .json()
            .await
            .map_err(|_| AuthError::ProviderError("Error parsing user info".to_string()))?;

        Ok(UserInfo {
            user_id: user_info.id.to_string(),
            username: user_info.login,
            email: user_info.email,
        })
    }

    // Github do not provide refresh token --- So skip implementation 
    async fn refresh_tokens_for_all_users(&self) -> Result<(), AuthError> {
        //let users = self.token_store.get_all_users().await;
        //
        //for user_id in users {
        //    if let Some(token_set) = self.token_store.get_token_set(&user_id).await {
        //        if token_set.is_expired() {
        //            if let Some(refresh_token) = token_set.refresh_token(&self.encryptor) {
        //                match self.refresh_token(&refresh_token).await {
        //                    Ok(new_token_set) => {
        //                        self.token_store
        //                            .save_token_set(&user_id, new_token_set)
        //                            .await?;
        //                    }
        //                    Err(e) => {
        //                        eprintln!("Failed to refresh token for user {}: {:?}", user_id, e);
        //                    }
        //                }
        //            }
        //        }
        //    }
        //}
        //
        //Ok(())
        todo!()
    }
}
