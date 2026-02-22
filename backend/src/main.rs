mod auth;
mod config;
mod errors;
mod handlers;
mod path_guard;
mod session;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{any, get, get_service, post};
use handlers::{
    AppState, direct_file_handler, file_handler, list_handler, login_handler, logout_handler,
    me_handler,
};
use serde_json::json;
use session::{LoginRateLimiter, SessionStore};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("backend=info,tower_http=info")),
        )
        .init();

    let config = match config::AppConfig::load() {
        Ok(value) => Arc::new(value),
        Err(err) => {
            error!("{err}");
            std::process::exit(1);
        }
    };

    let csp_header_value = HeaderValue::from_str(&config.content_security_policy)
        .unwrap_or_else(|_| HeaderValue::from_static("default-src 'self'"));
    let content_security_policy = HeaderName::from_static("content-security-policy");
    let x_content_type_options = HeaderName::from_static("x-content-type-options");
    let x_frame_options = HeaderName::from_static("x-frame-options");
    let referrer_policy = HeaderName::from_static("referrer-policy");
    let state = AppState {
        config: config.clone(),
        sessions: SessionStore::new(),
        login_limiter: LoginRateLimiter::new(config.login_max_failures, config.login_block_seconds),
    };

    let app = Router::new()
        .route("/api/list", get(list_handler))
        .route("/api/file", get(file_handler))
        .route("/d/{*path}", get(direct_file_handler))
        .route("/api/auth/login", post(login_handler))
        .route("/api/auth/logout", post(logout_handler))
        .route("/api/me", get(me_handler))
        .route("/api", any(api_not_found_handler))
        .route("/api/{*path}", any(api_not_found_handler))
        .layer(SetResponseHeaderLayer::if_not_present(
            x_content_type_options,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            x_frame_options,
            HeaderValue::from_static("SAMEORIGIN"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            referrer_policy,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            content_security_policy,
            csp_header_value,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let frontend_dist = PathBuf::from("frontend-dist");
    let app = if frontend_dist.is_dir() {
        let index_file = frontend_dist.join("index.html");
        let static_service = ServeDir::new(frontend_dist).fallback(ServeFile::new(index_file));
        app.fallback_service(get_service(static_service))
    } else {
        warn!("frontend static files not found, serving API routes only");
        app
    };

    let bind_addr: SocketAddr = match config.bind_addr.parse() {
        Ok(value) => value,
        Err(err) => {
            error!("invalid bind_addr {}: {err}", config.bind_addr);
            std::process::exit(1);
        }
    };

    info!(
        "starting server on {} with root {}",
        bind_addr,
        config.root_dir.display()
    );

    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(value) => value,
        Err(err) => {
            error!("failed to bind {}: {err}", bind_addr);
            std::process::exit(1);
        }
    };

    if let Err(err) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        error!("server error: {err}");
    }
}

async fn api_not_found_handler() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "code": "NOT_FOUND",
            "message": "API route not found."
        })),
    )
}
