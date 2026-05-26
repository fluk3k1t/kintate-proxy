use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::{extract::Request, response::Response};
use tokio::sync::Mutex;

use crate::api::AppState;

pub async fn auth_middleware(
    State(state): State<Arc<Mutex<AppState>>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get("Authorization");
    if let Some(auth_header_value) = auth_header {
        if let Ok(auth_str) = auth_header_value.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let token_manager = state.lock().await.token_manager.clone();
                match token_manager.verify(token) {
                    Ok(true) => return Ok(next.run(req).await),
                    _ => return Err(StatusCode::UNAUTHORIZED),
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}
