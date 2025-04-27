use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing::get,
    Json, Router,
};

use core_lib::OAuthProvider;
use github::GitHubProvider;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,          // Subject (typically user_id)
    exp: usize,           // Expiration time (unix timestamp)
    iat: usize,           // Issued at time
    access_token: String, // OAuth access token
}

#[derive(serde::Deserialize)]
struct AuthExchangeQuery {
    code: String,
}

#[derive(Serialize)]
struct AuthExchangeResponse {
    access_token: String,
    jwt_token: String, 
}

#[derive(Serialize)]
struct AuthUrlResponse {
    url: String,
}

struct AppState {
    github_provider: GitHubProvider,
    jwt_secret: String, // Secret key for JWT signing
}

async fn auth_url(
    Path(provider): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<AuthUrlResponse>, StatusCode> {
    eprintln!("being called here, provider = {}", provider);
    let url = match provider.to_lowercase().as_str() {
        "github" => Some(state.github_provider.auth_url()),
        _ => None,
    }
    .unwrap();

    Ok(Json(AuthUrlResponse { url }))
}

// Verify JWT from Authorization header
async fn verify_jwt(state: &Arc<AppState>, headers: &HeaderMap) -> Result<Claims, StatusCode> {
    // Extract Bearer token from Authorization header
    let auth_header = headers
        .get("Authorization")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Check for "Bearer " prefix
    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = &auth_header[7..]; // Remove "Bearer " prefix

    // Decode and validate the JWT
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(token_data.claims)
}

async fn auth_session(
    Path(provider): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match provider.to_lowercase().as_str() {
        "github" => {
            // Verify JWT from Authorization header
            let claims = match verify_jwt(&state, &headers).await {
                Ok(claims) => claims,
                Err(status) => return (status, "Invalid or missing JWT").into_response(),
            };
            // Return the access token from the JWT claims
            Json(AuthExchangeResponse {
                access_token: claims.access_token,
                jwt_token: "".to_string(), // We don't need to issue a new token here
            })
            .into_response()
        }
        _ => (StatusCode::UNAUTHORIZED, "Provider parameter required").into_response(),
    }
}

async fn auth_exchange(
    Path(provider): Path<String>,
    State(state): State<Arc<AppState>>,
    Query(payload): Query<AuthExchangeQuery>,
) -> impl IntoResponse {
    let code = payload.code;

    let (token_url, uri) = async {
        match provider.to_lowercase().as_str() {
            "github" => {
                let uri = std::env::var("GITHUB_REDIRECT").expect("No Github Redirect URI");
                Some((
                    state.github_provider.exchange_code(&code).await.unwrap(),
                    uri,
                ))
            }
            _ => None,
        }
    }
    .await
    .unwrap();

    // Create JWT token
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(2))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: "some_userid".to_string(), // Replace with actual user ID
        iat: chrono::Utc::now().timestamp() as usize,
        exp: expiration,
        access_token: token_url.access_token.clone(),
    };

    let jwt = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .unwrap();

    // Add the JWT as a query parameter to the redirect URI
    let redirect_uri = format!("{}?token={}", uri, jwt);

    // Redirect with JWT in URL
    Redirect::to(&redirect_uri).into_response()
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let gh_client_id = std::env::var("GITHUB_CLIENT_ID").expect("Github Client id not set");
    let gh_secret_key = std::env::var("GITHUB_SECRET_KEY").expect("Github Secret key not set");

    // JWT secret should be a strong, random value stored securely
    let jwt_secret = std::env::var("JWT_SECRET").expect("JWT secret key not set");

    let state = Arc::new(AppState {
        github_provider: GitHubProvider::new(gh_client_id, gh_secret_key),
        jwt_secret,
    });

    let app = Router::new()
        .route("/auth/exchange/{provider}", get(auth_exchange))
        .route("/auth/session/{provider}", get(auth_session))
        .route("/auth/{provider}", get(auth_url))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
