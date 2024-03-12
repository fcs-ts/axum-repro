use anyhow::Result;
use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode;
use axum::middleware::from_fn_with_state;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Builds a sha256 hash.
pub fn hash(token: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token);
    hasher.finalize().to_vec()
}

/// Tries to extract the hashed Bearer token from `Request` headers.
pub fn get_hashed_auth_token(req: &Request) -> Result<Vec<u8>> {
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or(anyhow::anyhow!("Missing auth"))?;

    let authorization = token
        .to_str()
        .map_err(|_| anyhow::anyhow!("Cannot read chars from authorization"))?;
    let split = authorization.trim().split_once(' ');
    match split {
        Some(("Bearer", contents)) => Ok(hash(contents)),
        _ if authorization == "Bearer" => Err(anyhow::anyhow!("Expected non-empty bearer")),
        _ => Err(anyhow::anyhow!(
            "Authorization header not using a bearer token"
        )),
    }
}

#[derive(Clone)]
pub struct ApiKeysStorage {
    pub api_keys: Arc<RwLock<HashSet<Vec<u8>>>>,
}

impl ApiKeysStorage {
    /// Creates a new `ApiKeysStorage`.
    pub async fn new() -> Result<Self> {
        let api_keys = Arc::new(RwLock::new(HashSet::new()));
        Ok(Self { api_keys })
    }

    pub async fn is_authorized(&self, req: &Request) -> bool {
        match get_hashed_auth_token(req) {
            Ok(h) => {
                let api_keys = self.api_keys.read().await;
                api_keys.contains(&h)
            }
            Err(_err) => false,
        }
    }
}

/// Checks authorization by looking into `ApiKeyisStorage`.
pub async fn by_api_key(
    State(api_keys): State<ApiKeysStorage>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !api_keys.is_authorized(&req).await {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(req).await)
}
async fn health() -> impl IntoResponse {
    StatusCode::OK
}

async fn route() -> impl IntoResponse {
    StatusCode::OK
}

pub fn build_router(api_keys: ApiKeysStorage) -> Router {
    let authorization_layer = from_fn_with_state(api_keys.clone(), by_api_key);
    let authorized_routes = Router::new()
        .route("/route", post(route))
        .route_layer(authorization_layer)
        .with_state(api_keys);

    let health = Router::new().route("/", get(health));

    Router::new().merge(health).merge(authorized_routes)
}

#[tokio::main]
async fn main() -> Result<()> {
    let api_keys = ApiKeysStorage::new().await?;
    let app = build_router(api_keys);

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or("127.0.0.1".to_string());
    let bind_port: u16 = std::env::var("BIND_PORT")
        .map(|e| e.parse().ok())
        .ok()
        .flatten()
        .unwrap_or(8501);

    let listener = tokio::net::TcpListener::bind(format!("{}:{}", bind_addr, bind_port)).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
