use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{delete, get, post},
};
use rusqlite::Connection;
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::Mutex};
use tower_http::cors::{Any, CorsLayer};

use crate::limit::LimitManager;
use crate::log::AccessLogger;
use crate::token::TokenManager;
use crate::{
    auth_middleware,
    policy::{Policy, RuleData},
};

#[derive(Clone)]
pub struct AppState {
    pub policy: Policy,
    pub token_manager: TokenManager,
    pub limit_manager: LimitManager,
    pub access_logger: AccessLogger,
}

pub async fn serve_api(
    policy: Policy,
    limit_manager: LimitManager,
    access_logger: AccessLogger,
    token_manager: TokenManager,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(Mutex::new(AppState {
        policy,
        token_manager,
        limit_manager,
        access_logger,
    }));

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
        .route("/api/limits", get(get_limits))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(cors)
        .with_state(state);

    let listener = TcpListener::bind(addr).await?;
    tracing::info!("API server listening on {}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn get_limits(State(state): State<Arc<Mutex<AppState>>>) -> impl IntoResponse {}

async fn get_rules(State(state): State<Arc<Mutex<AppState>>>) -> impl IntoResponse {
    println!("get_rules");

    let rules = state.lock().await.policy.get_all_rules();
    Json(rules)
}

async fn add_rule(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(payload): Json<RuleData>,
) -> impl IntoResponse {
    match state.lock().await.policy.insert_rule(payload) {
        Ok(_) => StatusCode::CREATED,
        Err(e) => {
            tracing::error!("Failed to add rule: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn delete_rule(
    State(state): State<Arc<Mutex<AppState>>>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match state.lock().await.policy.delete_rule(id) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::error!("Failed to delete rule: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn get_logs(State(state): State<Arc<Mutex<AppState>>>) -> impl IntoResponse {
    let state = state.lock().await;
    match state.access_logger.get_combined_logs(100) {
        Ok(logs) => Json(logs).into_response(),
        Err(e) => {
            tracing::error!("Failed to get logs: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn get_tags(State(state): State<Arc<Mutex<AppState>>>) -> impl IntoResponse {
    match state.lock().await.policy.get_all_domain_tags() {
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

async fn add_tag(
    State(state): State<Arc<Mutex<AppState>>>,
    Json(payload): Json<AddTagPayload>,
) -> impl IntoResponse {
    match state
        .lock()
        .await
        .policy
        .add_domain_tag(&payload.sld, &payload.tag)
    {
        Ok(_) => StatusCode::CREATED,
        Err(e) => {
            tracing::error!("Failed to add tag: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn delete_tag(
    State(state): State<Arc<Mutex<AppState>>>,
    Path(sld): Path<String>,
) -> impl IntoResponse {
    match state.lock().await.policy.delete_domain_tag(&sld) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::error!("Failed to delete tag: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
