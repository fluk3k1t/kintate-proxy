use std::net::SocketAddr;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

use crate::policy::{Policy, RuleData};

#[derive(Clone)]
pub struct AppState {
    pub policy: Policy,
}

pub async fn serve_api(policy: Policy, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = AppState { policy };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/rules", get(get_rules).post(add_rule))
        .route("/api/rules/{id}", delete(delete_rule))
        .route("/api/logs", get(get_logs))
        .route("/api/tags", get(get_tags).post(add_tag))
        .route("/api/tags/{sld}", delete(delete_tag))
        .layer(cors)
        .with_state(state);

    let listener = TcpListener::bind(addr).await?;
    tracing::info!("API server listening on {}", addr);
    
    axum::serve(listener, app).await?;
    Ok(())
}

async fn get_rules(State(state): State<AppState>) -> impl IntoResponse {
    let rules = state.policy.get_all_rules();
    Json(rules)
}

async fn add_rule(State(state): State<AppState>, Json(payload): Json<RuleData>) -> impl IntoResponse {
    match state.policy.insert_rule(payload) {
        Ok(_) => StatusCode::CREATED,
        Err(e) => {
            tracing::error!("Failed to add rule: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn delete_rule(State(state): State<AppState>, Path(id): Path<i64>) -> impl IntoResponse {
    match state.policy.delete_rule(id) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::error!("Failed to delete rule: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn get_logs(State(state): State<AppState>) -> impl IntoResponse {
    // Return last 100 logs
    match state.policy.get_combined_logs(100) {
        Ok(logs) => Json(logs).into_response(),
        Err(e) => {
            tracing::error!("Failed to get logs: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn get_tags(State(state): State<AppState>) -> impl IntoResponse {
    match state.policy.get_all_domain_tags() {
        Ok(tags) => Json(tags).into_response(),
        Err(e) => {
            tracing::error!("Failed to get tags: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(serde::Deserialize)]
struct AddTagPayload {
    sld: String,
    tag: String,
}

async fn add_tag(State(state): State<AppState>, Json(payload): Json<AddTagPayload>) -> impl IntoResponse {
    match state.policy.add_domain_tag(&payload.sld, &payload.tag) {
        Ok(_) => StatusCode::CREATED,
        Err(e) => {
            tracing::error!("Failed to add tag: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn delete_tag(State(state): State<AppState>, Path(sld): Path<String>) -> impl IntoResponse {
    match state.policy.delete_domain_tag(&sld) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::error!("Failed to delete tag: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
