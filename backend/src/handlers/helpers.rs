use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use axum::http::{HeaderMap, header};
use axum_extra::extract::cookie::{Cookie, SameSite};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::db::{AuthSession, UserView};
use crate::errors::{ApiError, ApiResult};
use crate::path_guard::is_private_marker_name;
use crate::session::REFRESH_COOKIE_NAME;

use super::types::AppState;

pub(super) fn client_ip_for_request(headers: &HeaderMap, peer_ip: IpAddr) -> IpAddr {
    parse_x_forwarded_for(headers)
        .or_else(|| parse_x_real_ip(headers))
        .unwrap_or(peer_ip)
}

pub(super) fn parse_x_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let raw = headers.get("x-forwarded-for")?.to_str().ok()?;
    raw.split(',')
        .map(str::trim)
        .find_map(parse_forwarded_ip_token)
}

pub(super) fn parse_x_real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let raw = headers.get("x-real-ip")?.to_str().ok()?;
    parse_forwarded_ip_token(raw.trim())
}

fn parse_forwarded_ip_token(raw: &str) -> Option<IpAddr> {
    if raw.is_empty() {
        return None;
    }

    raw.parse::<IpAddr>()
        .ok()
        .or_else(|| raw.parse::<SocketAddr>().ok().map(|value| value.ip()))
}

pub(super) fn build_refresh_cookie(refresh_token: &str, ttl_seconds: u64) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE_NAME, refresh_token.to_string()))
        .path("/api/auth")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(ttl_seconds as i64))
        .build()
}

pub(super) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

pub(super) async fn current_session(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<Option<AuthSession>> {
    let Some(token) = bearer_token(headers) else {
        return Ok(None);
    };
    state.db.access_session_by_token(token).await
}

pub(super) async fn file_session_for_request(
    state: &AppState,
    relative_path: &str,
    signed_token: Option<&str>,
) -> ApiResult<AuthSession> {
    let Some(token) = signed_token
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(ApiError::auth_required());
    };

    state
        .db
        .signed_file_session(token, relative_path)
        .await?
        .ok_or_else(ApiError::auth_required)
}

pub(super) async fn require_session(state: &AppState, headers: &HeaderMap) -> ApiResult<AuthSession> {
    current_session(state, headers)
        .await?
        .ok_or_else(ApiError::auth_required)
}

pub(super) async fn require_admin(state: &AppState, headers: &HeaderMap) -> ApiResult<AuthSession> {
    let session = require_session(state, headers).await?;
    if !session.user.role.is_admin() {
        return Err(ApiError::forbidden("Administrator privileges required."));
    }
    Ok(session)
}

pub(super) fn validate_login_name(username: &str) -> ApiResult<()> {
    if username.trim().len() < 2 || username.trim().len() > 64 {
        return Err(ApiError::bad_request(
            "Username must be between 2 and 64 characters.",
        ));
    }
    if username.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad_request(
            "Username contains disallowed control characters.",
        ));
    }
    Ok(())
}

pub(super) fn generate_totp_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

pub(super) struct TotpBinding {
    pub(super) otpauth_url: String,
    pub(super) qr_data_url: String,
}

fn build_totp(username: &str, secret: &str) -> ApiResult<TOTP> {
    let secret_bytes = Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|_| ApiError::bad_request("Invalid TOTP secret."))?;
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("mlist".to_string()),
        username.to_string(),
    )
    .map_err(|_| ApiError::bad_request("Invalid TOTP configuration."))
}

pub(super) fn build_totp_binding(username: &str, secret: &str) -> ApiResult<TotpBinding> {
    let totp = build_totp(username, secret)?;
    let otpauth_url = totp.get_url();
    let qr_data_url = format!(
        "data:image/png;base64,{}",
        totp.get_qr_base64()
            .map_err(|_| ApiError::internal("Failed to generate QR code."))?
    );
    Ok(TotpBinding {
        otpauth_url,
        qr_data_url,
    })
}

pub(super) fn binding_response(user: UserView, secret: &str) -> ApiResult<super::types::TotpBindingResponse> {
    let binding = build_totp_binding(&user.username, secret)?;
    Ok(super::types::TotpBindingResponse {
        user,
        secret: secret.to_string(),
        otpauth_url: binding.otpauth_url,
        qr_data_url: binding.qr_data_url,
    })
}

pub(super) fn verify_totp(username: &str, secret: &str, code: &str) -> ApiResult<bool> {
    let trimmed = code.trim();
    if trimmed.len() != 6 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Ok(false);
    }
    build_totp(username, secret)?
        .check_current(trimmed)
        .map_err(|_| ApiError::internal("Failed to verify TOTP code."))
}

pub(super) fn file_name_is_marker(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(is_private_marker_name)
}
