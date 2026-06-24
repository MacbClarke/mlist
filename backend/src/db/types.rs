use serde::{Deserialize, Serialize};

use crate::errors::ApiError;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }

    pub fn is_admin(&self) -> bool {
        matches!(self, Self::Admin)
    }
}

impl TryFrom<&str> for UserRole {
    type Error = ApiError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "admin" => Ok(Self::Admin),
            "user" => Ok(Self::User),
            _ => Err(ApiError::internal("Invalid user role stored in database.")),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRoleInput {
    Admin,
    User,
}

impl From<UserRoleInput> for UserRole {
    fn from(value: UserRoleInput) -> Self {
        match value {
            UserRoleInput::Admin => Self::Admin,
            UserRoleInput::User => Self::User,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserView {
    pub id: i64,
    pub username: String,
    pub role: UserRole,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    pub total_bytes_served: i64,
}

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: i64,
    pub username: String,
    pub role: UserRole,
    pub totp_secret: String,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    pub total_bytes_served: i64,
}

impl UserRecord {
    pub fn view(&self) -> UserView {
        UserView {
            id: self.id,
            username: self.username.clone(),
            role: self.role.clone(),
            enabled: self.enabled,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_login_at: self.last_login_at,
            last_seen_at: self.last_seen_at,
            total_bytes_served: self.total_bytes_served,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ResourceKind {
    Directory,
    File,
}

impl ResourceKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "file",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceTransferState {
    Active,
    Completed,
    Aborted,
    Failed,
    Stale,
}

impl ResourceTransferState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Aborted => "aborted",
            Self::Failed => "failed",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecordResourceAccess {
    pub user_id: i64,
    pub kind: ResourceKind,
    pub path: String,
    pub route: &'static str,
    pub status: u16,
    pub bytes_served: i64,
    pub file_size: Option<i64>,
    pub range_start: Option<i64>,
    pub range_end: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceAccessEventView {
    pub id: i64,
    pub user_id: i64,
    pub username: String,
    pub resource_kind: String,
    pub path: String,
    pub route: String,
    pub status: i64,
    pub bytes_served: i64,
    pub file_size: Option<i64>,
    pub range_start: Option<i64>,
    pub range_end: Option<i64>,
    pub transfer_state: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub ended_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceUsageView {
    pub user_id: i64,
    pub username: String,
    pub path: String,
    pub file_size: Option<i64>,
    pub access_count: i64,
    pub total_bytes_served: i64,
    pub last_access_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserFileStateView {
    pub path: String,
    pub highlighted: bool,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserFavoriteView {
    pub path: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub user: UserRecord,
    pub expires_at: i64,
}
