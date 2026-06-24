use axum::Json;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::HeaderMap;

use crate::db::UserRole;
use crate::db::UserView;
use crate::errors::ApiResult;

use super::helpers::{binding_response, generate_totp_secret, require_admin, validate_login_name};
use super::types::{
    AppState, AuditEventsResponse, AuditQuery, AuditResourcesResponse, CreateUserRequest,
    GenericOkResponse, TotpBindingResponse, UsersResponse,
};

pub async fn admin_users_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<UsersResponse>> {
    require_admin(&state, &headers).await?;
    Ok(Json(UsersResponse {
        users: state.db.list_users().await?,
    }))
}

pub async fn admin_audit_events_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<AuditEventsResponse>> {
    require_admin(&state, &headers).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let offset = query.offset.unwrap_or(0).max(0);
    let mut events = state
        .db
        .list_access_events_page(query.user_id, limit + 1, offset)
        .await?;
    let has_more = events.len() > limit as usize;
    if has_more {
        events.truncate(limit as usize);
    }
    Ok(Json(AuditEventsResponse { events, has_more }))
}

pub async fn admin_audit_resources_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<AuditResourcesResponse>> {
    require_admin(&state, &headers).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let offset = query.offset.unwrap_or(0).max(0);
    let mut resources = state
        .db
        .list_resource_usage_page(query.user_id, limit + 1, offset)
        .await?;
    let has_more = resources.len() > limit as usize;
    if has_more {
        resources.truncate(limit as usize);
    }
    Ok(Json(AuditResourcesResponse {
        resources,
        has_more,
    }))
}

pub async fn admin_create_user_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateUserRequest>,
) -> ApiResult<Json<TotpBindingResponse>> {
    require_admin(&state, &headers).await?;
    let username = payload.username.trim();
    validate_login_name(username)?;
    let secret = generate_totp_secret();
    let user = state
        .db
        .create_user(username, UserRole::from(payload.role), &secret)
        .await?;
    Ok(Json(binding_response(user.view(), &secret)?))
}

pub async fn admin_disable_user_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(user_id): AxumPath<i64>,
) -> ApiResult<Json<UserView>> {
    require_admin(&state, &headers).await?;
    Ok(Json(state.db.set_user_enabled(user_id, false).await?))
}

pub async fn admin_enable_user_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(user_id): AxumPath<i64>,
) -> ApiResult<Json<UserView>> {
    require_admin(&state, &headers).await?;
    Ok(Json(state.db.set_user_enabled(user_id, true).await?))
}

pub async fn admin_delete_user_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(user_id): AxumPath<i64>,
) -> ApiResult<Json<GenericOkResponse>> {
    require_admin(&state, &headers).await?;
    state.db.delete_user(user_id).await?;
    Ok(Json(GenericOkResponse { ok: true }))
}

pub async fn admin_reset_totp_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(user_id): AxumPath<i64>,
) -> ApiResult<Json<TotpBindingResponse>> {
    require_admin(&state, &headers).await?;
    let secret = generate_totp_secret();
    let user = state.db.reset_totp(user_id, &secret).await?;
    Ok(Json(binding_response(user.view(), &secret)?))
}
