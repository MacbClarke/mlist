use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use tracing::info;

use crate::errors::{ApiError, ApiResult};
use crate::session::{REFRESH_COOKIE_NAME, now_unix, unix_to_rfc3339};

use super::helpers::{
    bearer_token, build_refresh_cookie, build_totp_binding, client_ip_for_request,
    current_session, generate_totp_secret, validate_login_name, verify_totp,
};
use super::types::{
    AppState, BootstrapFinishRequest, BootstrapStartRequest, BootstrapStartResponse,
    GenericOkResponse, LoginRequest, LoginResponse, MeResponse, RefreshResponse,
};

pub async fn login_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    ConnectInfo(connect_info): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> ApiResult<(CookieJar, Json<LoginResponse>)> {
    let now = now_unix();
    let client_ip = client_ip_for_request(&headers, connect_info.ip()).to_string();
    let username = payload.username.trim();
    let limiter_key = format!("{client_ip}:{}", username.to_lowercase());

    if let Some(until) = state.login_limiter.blocked_until(&limiter_key, now).await {
        let remaining = until.saturating_sub(now);
        return Err(ApiError::rate_limited(format!(
            "Too many login failures. Retry in {remaining} seconds."
        )));
    }

    let user = state
        .db
        .user_by_username(username)
        .await?
        .filter(|value| value.enabled);

    let valid = match user.as_ref() {
        Some(user) => verify_totp(&user.username, &user.totp_secret, &payload.code)?,
        None => false,
    };

    if !valid {
        if let Some(until) = state.login_limiter.record_failure(&limiter_key, now).await {
            let remaining = until.saturating_sub(now);
            return Err(ApiError::rate_limited(format!(
                "Too many login failures. Retry in {remaining} seconds."
            )));
        }
        return Err(ApiError::unauthorized("Invalid username or code."));
    }

    let user = user.ok_or_else(|| ApiError::unauthorized("Invalid username or code."))?;
    state.login_limiter.record_success(&limiter_key).await;

    let refresh_token = uuid::Uuid::new_v4().simple().to_string();
    let refresh_expires_at = state
        .db
        .create_refresh_session(user.id, &refresh_token, state.config.refresh_ttl_seconds)
        .await?;
    let access_token = uuid::Uuid::new_v4().simple().to_string();
    let access_expires_at = state
        .db
        .create_access_token(user.id, &access_token, state.config.access_ttl_seconds)
        .await?;
    state.db.record_login(user.id).await?;

    info!(ip = client_ip, user = user.username, "login succeeded");

    let cookie = build_refresh_cookie(&refresh_token, state.config.refresh_ttl_seconds);
    let updated_jar = jar.add(cookie);

    Ok((
        updated_jar,
        Json(LoginResponse {
            ok: true,
            access_token,
            access_expires_at: unix_to_rfc3339(access_expires_at as u64),
            refresh_expires_at: unix_to_rfc3339(refresh_expires_at as u64),
            user: user.view(),
        }),
    ))
}

pub async fn bootstrap_start_handler(
    State(state): State<AppState>,
    Json(payload): Json<BootstrapStartRequest>,
) -> ApiResult<Json<BootstrapStartResponse>> {
    if !state.db.needs_bootstrap().await? {
        return Err(ApiError::forbidden("Bootstrap has already been completed."));
    }

    let username = payload.username.trim();
    validate_login_name(username)?;
    let secret = generate_totp_secret();
    let binding = build_totp_binding(username, &secret)?;
    Ok(Json(BootstrapStartResponse {
        username: username.to_string(),
        secret,
        otpauth_url: binding.otpauth_url,
        qr_data_url: binding.qr_data_url,
    }))
}

pub async fn bootstrap_finish_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<BootstrapFinishRequest>,
) -> ApiResult<(CookieJar, Json<LoginResponse>)> {
    if !state.db.needs_bootstrap().await? {
        return Err(ApiError::forbidden("Bootstrap has already been completed."));
    }

    let username = payload.username.trim();
    validate_login_name(username)?;
    if !verify_totp(username, &payload.secret, &payload.code)? {
        return Err(ApiError::unauthorized("Invalid verification code."));
    }

    let user = state.db.bootstrap_admin(username, &payload.secret).await?;
    let refresh_token = uuid::Uuid::new_v4().simple().to_string();
    let refresh_expires_at = state
        .db
        .create_refresh_session(user.id, &refresh_token, state.config.refresh_ttl_seconds)
        .await?;
    let access_token = uuid::Uuid::new_v4().simple().to_string();
    let access_expires_at = state
        .db
        .create_access_token(user.id, &access_token, state.config.access_ttl_seconds)
        .await?;
    state.db.record_login(user.id).await?;
    info!(user = user.username, "bootstrap admin created");

    let cookie = build_refresh_cookie(&refresh_token, state.config.refresh_ttl_seconds);
    let updated_jar = jar.add(cookie);

    Ok((
        updated_jar,
        Json(LoginResponse {
            ok: true,
            access_token,
            access_expires_at: unix_to_rfc3339(access_expires_at as u64),
            refresh_expires_at: unix_to_rfc3339(refresh_expires_at as u64),
            user: user.view(),
        }),
    ))
}

pub async fn refresh_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<(CookieJar, Json<RefreshResponse>)> {
    let Some(cookie) = jar.get(REFRESH_COOKIE_NAME) else {
        return Err(ApiError::auth_required());
    };

    let next_refresh_token = uuid::Uuid::new_v4().simple().to_string();
    let Some((session, refresh_expires_at)) = state
        .db
        .rotate_refresh_session(
            cookie.value(),
            &next_refresh_token,
            state.config.refresh_ttl_seconds,
        )
        .await?
    else {
        return Err(ApiError::auth_required());
    };

    let access_token = uuid::Uuid::new_v4().simple().to_string();
    let access_expires_at = state
        .db
        .create_access_token(
            session.user.id,
            &access_token,
            state.config.access_ttl_seconds,
        )
        .await?;
    let updated_jar = jar.add(build_refresh_cookie(
        &next_refresh_token,
        state.config.refresh_ttl_seconds,
    ));

    Ok((
        updated_jar,
        Json(RefreshResponse {
            ok: true,
            access_token,
            access_expires_at: unix_to_rfc3339(access_expires_at as u64),
            refresh_expires_at: unix_to_rfc3339(refresh_expires_at as u64),
            user: session.user.view(),
        }),
    ))
}

pub async fn logout_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> ApiResult<(CookieJar, Json<GenericOkResponse>)> {
    if let Some(cookie) = jar.get(REFRESH_COOKIE_NAME) {
        state.db.remove_refresh_session(cookie.value()).await?;
    }
    if let Some(token) = bearer_token(&headers) {
        state.db.remove_access_token(token).await?;
    }

    let removal = Cookie::build((REFRESH_COOKIE_NAME, ""))
        .path("/api/auth")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(0))
        .build();

    Ok((jar.remove(removal), Json(GenericOkResponse { ok: true })))
}

pub async fn me_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<MeResponse>> {
    let needs_bootstrap = state.db.needs_bootstrap().await?;
    let Some(session) = current_session(&state, &headers).await? else {
        return Ok(Json(MeResponse {
            authenticated: false,
            user: None,
            access_expires_at: None,
            needs_bootstrap,
        }));
    };

    Ok(Json(MeResponse {
        authenticated: true,
        user: Some(session.user.view()),
        access_expires_at: Some(unix_to_rfc3339(session.expires_at as u64)),
        needs_bootstrap,
    }))
}
