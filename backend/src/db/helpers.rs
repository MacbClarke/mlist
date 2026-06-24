use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::errors::{ApiError, ApiResult};

use super::types::{ResourceAccessEventView, ResourceUsageView, UserRecord, UserRole};

pub(super) async fn upsert_resource_usage_delta(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: i64,
    path: &str,
    file_size: Option<i64>,
    access_count_delta: i64,
    bytes_delta: i64,
    last_access_at: i64,
) -> sqlx::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO user_resource_usage (
            user_id, path, file_size, access_count, total_bytes_served,
            last_access_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(user_id, path) DO UPDATE SET
            file_size = excluded.file_size,
            access_count = user_resource_usage.access_count + excluded.access_count,
            total_bytes_served = user_resource_usage.total_bytes_served + excluded.total_bytes_served,
            last_access_at = excluded.last_access_at
        "#,
    )
    .bind(user_id)
    .bind(path)
    .bind(file_size)
    .bind(access_count_delta.max(0))
    .bind(bytes_delta.max(0))
    .bind(last_access_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn fetch_user_by_id_from(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user_id: i64,
) -> ApiResult<UserRecord> {
    let row = sqlx::query(
        r#"
        SELECT
            u.id, u.username, u.role, u.totp_secret, u.enabled,
            u.created_at, u.updated_at, u.last_login_at, u.last_seen_at,
            COALESCE(SUM(uru.total_bytes_served), 0) AS total_bytes_served
        FROM users u
        LEFT JOIN user_resource_usage uru ON uru.user_id = u.id
        WHERE u.id = ?1
        GROUP BY u.id
        "#,
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;
    row.as_ref()
        .map(user_from_row)
        .transpose()?
        .ok_or_else(|| ApiError::not_found("User not found."))
}

pub(super) async fn fetch_user_by_username_from(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    username: &str,
) -> ApiResult<UserRecord> {
    let row = sqlx::query(
        r#"
        SELECT
            u.id, u.username, u.role, u.totp_secret, u.enabled,
            u.created_at, u.updated_at, u.last_login_at, u.last_seen_at,
            COALESCE(SUM(uru.total_bytes_served), 0) AS total_bytes_served
        FROM users u
        LEFT JOIN user_resource_usage uru ON uru.user_id = u.id
        WHERE u.username = ?1 COLLATE NOCASE
        GROUP BY u.id
        "#,
    )
    .bind(username)
    .fetch_one(&mut **tx)
    .await
    .map_err(db_error)?;
    user_from_row(&row)
}

pub(super) fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> ApiResult<UserRecord> {
    let role_raw: String = row.get("role");
    Ok(UserRecord {
        id: row.get("id"),
        username: row.get("username"),
        role: UserRole::try_from(role_raw.as_str())?,
        totp_secret: row.get("totp_secret"),
        enabled: row.get::<i64, _>("enabled") != 0,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        last_login_at: row.get("last_login_at"),
        last_seen_at: row.get("last_seen_at"),
        total_bytes_served: row.get("total_bytes_served"),
    })
}

pub(super) fn event_from_row(row: sqlx::sqlite::SqliteRow) -> ResourceAccessEventView {
    ResourceAccessEventView {
        id: row.get("id"),
        user_id: row.get("user_id"),
        username: row.get("username"),
        resource_kind: row.get("resource_kind"),
        path: row.get("path"),
        route: row.get("route"),
        status: row.get("status"),
        bytes_served: row.get("bytes_served"),
        file_size: row.get("file_size"),
        range_start: row.get("range_start"),
        range_end: row.get("range_end"),
        transfer_state: row.get("transfer_state"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        ended_at: row.get("ended_at"),
    }
}

pub(super) fn usage_from_row(row: sqlx::sqlite::SqliteRow) -> ResourceUsageView {
    ResourceUsageView {
        user_id: row.get("user_id"),
        username: row.get("username"),
        path: row.get("path"),
        file_size: row.get("file_size"),
        access_count: row.get("access_count"),
        total_bytes_served: row.get("total_bytes_served"),
        last_access_at: row.get("last_access_at"),
    }
}

pub(super) fn validate_username(username: &str) -> ApiResult<()> {
    let trimmed = username.trim();
    if trimmed.len() < 2 || trimmed.len() > 64 {
        return Err(ApiError::bad_request(
            "Username must be between 2 and 64 characters.",
        ));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad_request(
            "Username contains disallowed control characters.",
        ));
    }
    Ok(())
}

pub(super) fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    to_hex(&hasher.finalize())
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub(super) fn db_error(err: sqlx::Error) -> ApiError {
    ApiError::internal(format!("Database operation failed: {err}"))
}

pub(super) fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db_err) if db_err.is_unique_violation())
}
