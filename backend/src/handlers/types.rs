use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::db::{
    ResourceAccessEventView, ResourceUsageView, UserFavoriteView, UserFileStateView, UserRoleInput,
    UserView,
};
use crate::db::AuthDb;
use crate::session::LoginRateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: AuthDb,
    pub login_limiter: LoginRateLimiter,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathQuery {
    pub path: Option<String>,
    pub sort: Option<String>,
    pub order: Option<String>,
    pub offset: Option<i64>,
    pub limit: Option<i64>,
    pub favorites_only: Option<bool>,
    pub search: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DirectFileQuery {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditQuery {
    pub user_id: Option<i64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
    pub path: String,
    pub entries: Vec<ListEntry>,
    pub requires_auth: bool,
    pub authorized: bool,
    pub total: usize,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListEntry {
    pub name: String,
    pub path: String,
    pub kind: EntryKind,
    pub size: Option<u64>,
    pub mtime: Option<u64>,
    pub mime: Option<String>,
    pub requires_auth: bool,
    pub authorized: bool,
    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    Dir,
    File,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub ok: bool,
    pub access_token: String,
    pub access_expires_at: String,
    pub refresh_expires_at: String,
    pub user: UserView,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeResponse {
    pub authenticated: bool,
    pub user: Option<UserView>,
    pub access_expires_at: Option<String>,
    pub needs_bootstrap: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub ok: bool,
    pub access_token: String,
    pub access_expires_at: String,
    pub refresh_expires_at: String,
    pub user: UserView,
}

#[derive(Debug, Deserialize)]
pub struct BootstrapStartRequest {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct BootstrapFinishRequest {
    pub username: String,
    pub secret: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub role: UserRoleInput,
}

#[derive(Debug, Deserialize)]
pub struct FileStateRequest {
    pub path: String,
    pub highlighted: bool,
}

#[derive(Debug, Deserialize)]
pub struct SignedFileLinkRequest {
    pub path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedFileLinkResponse {
    pub url: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpBindingResponse {
    pub user: UserView,
    pub secret: String,
    pub otpauth_url: String,
    pub qr_data_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapStartResponse {
    pub username: String,
    pub secret: String,
    pub otpauth_url: String,
    pub qr_data_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsersResponse {
    pub users: Vec<UserView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventsResponse {
    pub events: Vec<ResourceAccessEventView>,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditResourcesResponse {
    pub resources: Vec<ResourceUsageView>,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileStatesResponse {
    pub files: Vec<UserFileStateView>,
}

#[derive(Debug, Deserialize)]
pub struct FavoriteRequest {
    pub path: String,
    pub favorite: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FavoritesResponse {
    pub paths: Vec<UserFavoriteView>,
}

#[derive(Debug, Serialize)]
pub struct GenericOkResponse {
    pub ok: bool,
}
