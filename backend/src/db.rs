use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::errors::{ApiError, ApiResult};
use crate::session::now_unix;

#[derive(Debug, Clone)]
pub struct AuthDb {
    pool: SqlitePool,
}

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
    fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "file",
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
    pub created_at: i64,
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

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub user: UserRecord,
    pub expires_at: i64,
}

impl AuthDb {
    pub async fn connect(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|err| {
                format!(
                    "Failed to create database directory {}: {err}",
                    parent.display()
                )
            })?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(|err| format!("Failed to open database {}: {err}", path.display()))?;

        let db = Self { pool };
        db.migrate()
            .await
            .map_err(|err| format!("Failed to initialize database: {err}"))?;
        Ok(db)
    }

    async fn migrate(&self) -> sqlx::Result<()> {
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
                totp_secret TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_login_at INTEGER,
                last_seen_at INTEGER
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        self.ensure_column("users", "last_seen_at", "INTEGER")
            .await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                last_active_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions(user_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS signed_file_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                last_used_at INTEGER
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS signed_file_tokens_user_id_idx ON signed_file_tokens(user_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS signed_file_tokens_expires_at_idx ON signed_file_tokens(expires_at)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS resource_access_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                resource_kind TEXT NOT NULL CHECK (resource_kind IN ('directory', 'file')),
                path TEXT NOT NULL,
                route TEXT NOT NULL,
                status INTEGER NOT NULL,
                bytes_served INTEGER NOT NULL DEFAULT 0,
                file_size INTEGER,
                range_start INTEGER,
                range_end INTEGER,
                created_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_resource_usage (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                file_size INTEGER,
                access_count INTEGER NOT NULL DEFAULT 0,
                total_bytes_served INTEGER NOT NULL DEFAULT 0,
                last_access_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, path)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS resource_access_events_created_idx ON resource_access_events(created_at DESC)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS resource_access_events_user_created_idx ON resource_access_events(user_id, created_at DESC)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS user_resource_usage_last_access_idx ON user_resource_usage(last_access_at DESC)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_file_states (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                highlighted INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, path)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn ensure_column(
        &self,
        table: &'static str,
        column: &'static str,
        definition: &'static str,
    ) -> sqlx::Result<()> {
        let pragma = format!("PRAGMA table_info({table})");
        let rows = sqlx::query(&pragma).fetch_all(&self.pool).await?;
        let exists = rows
            .iter()
            .any(|row| row.get::<String, _>("name") == column);
        if !exists {
            let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
            sqlx::query(&sql).execute(&self.pool).await?;
        }
        Ok(())
    }

    pub async fn needs_bootstrap(&self) -> ApiResult<bool> {
        let count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM users")
            .fetch_one(&self.pool)
            .await
            .map_err(db_error)?
            .get("count");
        Ok(count == 0)
    }

    pub async fn bootstrap_admin(&self, username: &str, secret: &str) -> ApiResult<UserRecord> {
        validate_username(username)?;
        let now = now_unix() as i64;
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM users")
            .fetch_one(&mut *tx)
            .await
            .map_err(db_error)?
            .get("count");
        if count != 0 {
            return Err(ApiError::forbidden("Bootstrap has already been completed."));
        }

        sqlx::query(
            r#"
            INSERT INTO users (username, role, totp_secret, enabled, created_at, updated_at)
            VALUES (?1, 'admin', ?2, 1, ?3, ?3)
            "#,
        )
        .bind(username.trim())
        .bind(secret)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

        let user = fetch_user_by_username_from(&mut tx, username.trim()).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(user)
    }

    pub async fn create_user(
        &self,
        username: &str,
        role: UserRole,
        secret: &str,
    ) -> ApiResult<UserRecord> {
        validate_username(username)?;
        let now = now_unix() as i64;
        sqlx::query(
            r#"
            INSERT INTO users (username, role, totp_secret, enabled, created_at, updated_at)
            VALUES (?1, ?2, ?3, 1, ?4, ?4)
            "#,
        )
        .bind(username.trim())
        .bind(role.as_str())
        .bind(secret)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|err| {
            if is_unique_violation(&err) {
                ApiError::bad_request("Username already exists.")
            } else {
                db_error(err)
            }
        })?;

        self.user_by_username(username.trim())
            .await?
            .ok_or_else(|| ApiError::internal("Created user was not found."))
    }

    pub async fn list_users(&self) -> ApiResult<Vec<UserView>> {
        let rows = sqlx::query(
            r#"
            SELECT
                u.id, u.username, u.role, u.totp_secret, u.enabled,
                u.created_at, u.updated_at, u.last_login_at, u.last_seen_at,
                COALESCE(SUM(uru.total_bytes_served), 0) AS total_bytes_served
            FROM users u
            LEFT JOIN user_resource_usage uru ON uru.user_id = u.id
            GROUP BY u.id
            ORDER BY username COLLATE NOCASE
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;

        rows.into_iter()
            .map(|row| user_from_row(&row).map(|user| user.view()))
            .collect()
    }

    pub async fn user_by_username(&self, username: &str) -> ApiResult<Option<UserRecord>> {
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
        .bind(username.trim())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?;

        row.as_ref().map(user_from_row).transpose()
    }

    pub async fn create_session(
        &self,
        user_id: i64,
        token: &str,
        ttl_seconds: u64,
    ) -> ApiResult<i64> {
        let now = now_unix() as i64;
        let expires_at = now.saturating_add(ttl_seconds as i64);
        sqlx::query(
            r#"
            INSERT INTO sessions (token_hash, user_id, expires_at, created_at, last_active_at)
            VALUES (?1, ?2, ?3, ?4, ?4)
            "#,
        )
        .bind(hash_token(token))
        .bind(user_id)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(expires_at)
    }

    pub async fn session_by_token(&self, token: &str) -> ApiResult<Option<AuthSession>> {
        let now = now_unix() as i64;
        sqlx::query("DELETE FROM sessions WHERE expires_at <= ?1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;

        let token_hash = hash_token(token);
        let Some(row) = sqlx::query(
            r#"
            SELECT
                s.expires_at,
                u.id, u.username, u.role, u.totp_secret, u.enabled,
                u.created_at, u.updated_at, u.last_login_at, u.last_seen_at,
                COALESCE(SUM(uru.total_bytes_served), 0) AS total_bytes_served
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            LEFT JOIN user_resource_usage uru ON uru.user_id = u.id
            WHERE s.token_hash = ?1 AND s.expires_at > ?2
            GROUP BY s.token_hash
            "#,
        )
        .bind(&token_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?
        else {
            return Ok(None);
        };

        let user = user_from_row(&row)?;
        if !user.enabled {
            self.remove_session_by_hash(&token_hash).await?;
            return Ok(None);
        }

        sqlx::query("UPDATE sessions SET last_active_at = ?1 WHERE token_hash = ?2")
            .bind(now)
            .bind(&token_hash)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;

        Ok(Some(AuthSession {
            user,
            expires_at: row.get("expires_at"),
        }))
    }

    pub async fn create_signed_file_token(
        &self,
        user_id: i64,
        path: &str,
        token: &str,
        ttl_seconds: u64,
    ) -> ApiResult<i64> {
        let now = now_unix() as i64;
        let expires_at = now.saturating_add(ttl_seconds as i64);
        sqlx::query(
            r#"
            INSERT INTO signed_file_tokens (token_hash, user_id, path, expires_at, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
        )
        .bind(hash_token(token))
        .bind(user_id)
        .bind(path)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(expires_at)
    }

    pub async fn signed_file_session(
        &self,
        token: &str,
        path: &str,
    ) -> ApiResult<Option<AuthSession>> {
        let now = now_unix() as i64;
        sqlx::query("DELETE FROM signed_file_tokens WHERE expires_at <= ?1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;

        let token_hash = hash_token(token);
        let Some(row) = sqlx::query(
            r#"
            SELECT
                t.expires_at,
                u.id, u.username, u.role, u.totp_secret, u.enabled,
                u.created_at, u.updated_at, u.last_login_at, u.last_seen_at,
                COALESCE(SUM(uru.total_bytes_served), 0) AS total_bytes_served
            FROM signed_file_tokens t
            JOIN users u ON u.id = t.user_id
            LEFT JOIN user_resource_usage uru ON uru.user_id = u.id
            WHERE t.token_hash = ?1 AND t.path = ?2 AND t.expires_at > ?3
            GROUP BY t.token_hash
            "#,
        )
        .bind(&token_hash)
        .bind(path)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?
        else {
            return Ok(None);
        };

        let user = user_from_row(&row)?;
        if !user.enabled {
            sqlx::query("DELETE FROM signed_file_tokens WHERE user_id = ?1")
                .bind(user.id)
                .execute(&self.pool)
                .await
                .map_err(db_error)?;
            return Ok(None);
        }

        sqlx::query("UPDATE signed_file_tokens SET last_used_at = ?1 WHERE token_hash = ?2")
            .bind(now)
            .bind(&token_hash)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;

        Ok(Some(AuthSession {
            user,
            expires_at: row.get("expires_at"),
        }))
    }

    pub async fn remove_session(&self, token: &str) -> ApiResult<()> {
        self.remove_session_by_hash(&hash_token(token)).await
    }

    async fn remove_session_by_hash(&self, token_hash: &str) -> ApiResult<()> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?1")
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    pub async fn record_login(&self, user_id: i64) -> ApiResult<()> {
        let now = now_unix() as i64;
        sqlx::query("UPDATE users SET last_login_at = ?1, updated_at = ?1 WHERE id = ?2")
            .bind(now)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    pub async fn record_resource_access(&self, access: RecordResourceAccess) -> ApiResult<()> {
        let now = now_unix() as i64;
        let cutoff = now.saturating_sub(90 * 24 * 60 * 60);
        let mut tx = self.pool.begin().await.map_err(db_error)?;

        sqlx::query(
            r#"
            INSERT INTO resource_access_events (
                user_id, resource_kind, path, route, status, bytes_served,
                file_size, range_start, range_end, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
        )
        .bind(access.user_id)
        .bind(access.kind.as_str())
        .bind(&access.path)
        .bind(access.route)
        .bind(i64::from(access.status))
        .bind(access.bytes_served)
        .bind(access.file_size)
        .bind(access.range_start)
        .bind(access.range_end)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

        sqlx::query("UPDATE users SET last_seen_at = ?1, updated_at = ?1 WHERE id = ?2")
            .bind(now)
            .bind(access.user_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        if matches!(access.kind, ResourceKind::File) {
            sqlx::query(
                r#"
                INSERT INTO user_resource_usage (
                    user_id, path, file_size, access_count, total_bytes_served,
                    last_access_at
                )
                VALUES (?1, ?2, ?3, 1, ?4, ?5)
                ON CONFLICT(user_id, path) DO UPDATE SET
                    file_size = excluded.file_size,
                    access_count = user_resource_usage.access_count + 1,
                    total_bytes_served = user_resource_usage.total_bytes_served + excluded.total_bytes_served,
                    last_access_at = excluded.last_access_at
                "#,
            )
            .bind(access.user_id)
            .bind(&access.path)
            .bind(access.file_size)
            .bind(access.bytes_served)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        }

        sqlx::query("DELETE FROM resource_access_events WHERE created_at < ?1")
            .bind(cutoff)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    pub async fn list_access_events_page(
        &self,
        user_id: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> ApiResult<Vec<ResourceAccessEventView>> {
        let limit = limit.clamp(1, 501);
        let offset = offset.max(0);
        let rows = if let Some(user_id) = user_id {
            sqlx::query(
                r#"
                SELECT
                    e.id, e.user_id, u.username, e.resource_kind, e.path, e.route,
                    e.status, e.bytes_served, e.file_size, e.range_start, e.range_end, e.created_at
                FROM resource_access_events e
                JOIN users u ON u.id = e.user_id
                WHERE e.user_id = ?1
                ORDER BY e.created_at DESC, e.id DESC
                LIMIT ?2
                OFFSET ?3
                "#,
            )
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?
        } else {
            sqlx::query(
                r#"
                SELECT
                    e.id, e.user_id, u.username, e.resource_kind, e.path, e.route,
                    e.status, e.bytes_served, e.file_size, e.range_start, e.range_end, e.created_at
                FROM resource_access_events e
                JOIN users u ON u.id = e.user_id
                ORDER BY e.created_at DESC, e.id DESC
                LIMIT ?1
                OFFSET ?2
                "#,
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?
        };

        Ok(rows.into_iter().map(event_from_row).collect())
    }

    pub async fn list_resource_usage_page(
        &self,
        user_id: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> ApiResult<Vec<ResourceUsageView>> {
        let limit = limit.clamp(1, 501);
        let offset = offset.max(0);
        let rows = if let Some(user_id) = user_id {
            sqlx::query(
                r#"
                SELECT
                    uru.user_id, u.username, uru.path, uru.file_size, uru.access_count,
                    uru.total_bytes_served, uru.last_access_at
                FROM user_resource_usage uru
                JOIN users u ON u.id = uru.user_id
                WHERE uru.user_id = ?1
                ORDER BY uru.last_access_at DESC
                LIMIT ?2
                OFFSET ?3
                "#,
            )
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?
        } else {
            sqlx::query(
                r#"
                SELECT
                    uru.user_id, u.username, uru.path, uru.file_size, uru.access_count,
                    uru.total_bytes_served, uru.last_access_at
                FROM user_resource_usage uru
                JOIN users u ON u.id = uru.user_id
                ORDER BY uru.last_access_at DESC
                LIMIT ?1
                OFFSET ?2
                "#,
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(db_error)?
        };

        Ok(rows.into_iter().map(usage_from_row).collect())
    }

    pub async fn list_highlighted_files(&self, user_id: i64) -> ApiResult<Vec<UserFileStateView>> {
        let rows = sqlx::query(
            r#"
            SELECT path, highlighted, updated_at
            FROM user_file_states
            WHERE user_id = ?1 AND highlighted = 1
            ORDER BY updated_at DESC, path COLLATE NOCASE
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;

        Ok(rows
            .into_iter()
            .map(|row| UserFileStateView {
                path: row.get("path"),
                highlighted: row.get::<i64, _>("highlighted") != 0,
                updated_at: row.get("updated_at"),
            })
            .collect())
    }

    pub async fn set_file_highlighted(
        &self,
        user_id: i64,
        path: &str,
        highlighted: bool,
    ) -> ApiResult<UserFileStateView> {
        let now = now_unix() as i64;
        sqlx::query(
            r#"
            INSERT INTO user_file_states (user_id, path, highlighted, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?4)
            ON CONFLICT(user_id, path) DO UPDATE SET
                highlighted = excluded.highlighted,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(user_id)
        .bind(path)
        .bind(if highlighted { 1_i64 } else { 0_i64 })
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;

        Ok(UserFileStateView {
            path: path.to_string(),
            highlighted,
            updated_at: now,
        })
    }

    pub async fn set_user_enabled(&self, user_id: i64, enabled: bool) -> ApiResult<UserView> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let user = fetch_user_by_id_from(&mut tx, user_id).await?;
        if user.role.is_admin() && user.enabled && !enabled {
            let other_admins: i64 = sqlx::query(
                "SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND enabled = 1 AND id != ?1",
            )
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_error)?
            .get("count");
            if other_admins == 0 {
                return Err(ApiError::forbidden(
                    "Cannot disable the last enabled administrator.",
                ));
            }
        }

        let now = now_unix() as i64;
        sqlx::query("UPDATE users SET enabled = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(if enabled { 1_i64 } else { 0_i64 })
            .bind(now)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        if !enabled {
            sqlx::query("DELETE FROM sessions WHERE user_id = ?1")
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
            sqlx::query("DELETE FROM signed_file_tokens WHERE user_id = ?1")
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
        }

        let updated = fetch_user_by_id_from(&mut tx, user_id).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(updated.view())
    }

    pub async fn delete_user(&self, user_id: i64) -> ApiResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let user = fetch_user_by_id_from(&mut tx, user_id).await?;
        if user.role.is_admin() && user.enabled {
            let other_admins: i64 = sqlx::query(
                "SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND enabled = 1 AND id != ?1",
            )
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_error)?
            .get("count");
            if other_admins == 0 {
                return Err(ApiError::forbidden(
                    "Cannot delete the last enabled administrator.",
                ));
            }
        }

        for table in [
            "sessions",
            "signed_file_tokens",
            "resource_access_events",
            "user_resource_usage",
            "user_file_states",
        ] {
            let sql = format!("DELETE FROM {table} WHERE user_id = ?1");
            sqlx::query(&sql)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
        }
        sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    pub async fn reset_totp(&self, user_id: i64, secret: &str) -> ApiResult<UserRecord> {
        let now = now_unix() as i64;
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        fetch_user_by_id_from(&mut tx, user_id).await?;
        sqlx::query("UPDATE users SET totp_secret = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(secret)
            .bind(now)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        sqlx::query("DELETE FROM sessions WHERE user_id = ?1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        sqlx::query("DELETE FROM signed_file_tokens WHERE user_id = ?1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        let user = fetch_user_by_id_from(&mut tx, user_id).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(user)
    }
}

async fn fetch_user_by_id_from(
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

async fn fetch_user_by_username_from(
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

fn user_from_row(row: &sqlx::sqlite::SqliteRow) -> ApiResult<UserRecord> {
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

fn event_from_row(row: sqlx::sqlite::SqliteRow) -> ResourceAccessEventView {
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
        created_at: row.get("created_at"),
    }
}

fn usage_from_row(row: sqlx::sqlite::SqliteRow) -> ResourceUsageView {
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

fn validate_username(username: &str) -> ApiResult<()> {
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

fn hash_token(token: &str) -> String {
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

fn db_error(err: sqlx::Error) -> ApiError {
    ApiError::internal(format!("Database operation failed: {err}"))
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db_err) if db_err.is_unique_violation())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{AuthDb, RecordResourceAccess, ResourceKind, UserRole};

    fn test_db_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "mlist-{name}-{}.sqlite3",
            uuid::Uuid::new_v4().simple()
        ))
    }

    #[tokio::test]
    async fn resource_access_updates_seen_and_totals() {
        let path = test_db_path("audit");
        let db = AuthDb::connect(&path).await.unwrap();
        let user = db
            .create_user("alice", UserRole::User, "SECRET")
            .await
            .unwrap();

        let initial = db.list_users().await.unwrap();
        assert_eq!(initial[0].total_bytes_served, 0);
        assert!(initial[0].last_seen_at.is_none());

        db.record_resource_access(RecordResourceAccess {
            user_id: user.id,
            kind: ResourceKind::Directory,
            path: "movies".to_string(),
            route: "/api/list",
            status: 200,
            bytes_served: 0,
            file_size: None,
            range_start: None,
            range_end: None,
        })
        .await
        .unwrap();

        db.record_resource_access(RecordResourceAccess {
            user_id: user.id,
            kind: ResourceKind::File,
            path: "movies/demo.mp4".to_string(),
            route: "/d",
            status: 206,
            bytes_served: 100,
            file_size: Some(1_000),
            range_start: Some(0),
            range_end: Some(99),
        })
        .await
        .unwrap();

        db.record_resource_access(RecordResourceAccess {
            user_id: user.id,
            kind: ResourceKind::File,
            path: "movies/demo.mp4".to_string(),
            route: "/d",
            status: 206,
            bytes_served: 100,
            file_size: Some(1_000),
            range_start: Some(200),
            range_end: Some(299),
        })
        .await
        .unwrap();

        db.record_resource_access(RecordResourceAccess {
            user_id: user.id,
            kind: ResourceKind::File,
            path: "movies/demo.mp4".to_string(),
            route: "/d",
            status: 304,
            bytes_served: 0,
            file_size: Some(1_000),
            range_start: None,
            range_end: None,
        })
        .await
        .unwrap();

        let users = db.list_users().await.unwrap();
        assert!(users[0].last_seen_at.is_some());
        assert_eq!(users[0].total_bytes_served, 200);

        let events = db.list_access_events_page(None, 10, 0).await.unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].path, "movies/demo.mp4");

        let usage = db
            .list_resource_usage_page(Some(user.id), 10, 0)
            .await
            .unwrap();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].access_count, 3);
        assert_eq!(usage[0].total_bytes_served, 200);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn file_highlight_state_is_per_user() {
        let path = test_db_path("file-state");
        let db = AuthDb::connect(&path).await.unwrap();
        let alice = db
            .create_user("alice", UserRole::User, "SECRET")
            .await
            .unwrap();
        let bob = db
            .create_user("bob", UserRole::User, "SECRET")
            .await
            .unwrap();

        db.set_file_highlighted(alice.id, "a.mp4", true)
            .await
            .unwrap();
        db.set_file_highlighted(bob.id, "b.mp4", true)
            .await
            .unwrap();

        let alice_files = db.list_highlighted_files(alice.id).await.unwrap();
        assert_eq!(alice_files.len(), 1);
        assert_eq!(alice_files[0].path, "a.mp4");

        db.set_file_highlighted(alice.id, "a.mp4", false)
            .await
            .unwrap();
        assert!(
            db.list_highlighted_files(alice.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(db.list_highlighted_files(bob.id).await.unwrap().len(), 1);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn signed_file_tokens_are_path_bound_and_revoked_with_user() {
        let path = test_db_path("signed-file-token");
        let db = AuthDb::connect(&path).await.unwrap();
        let user = db
            .create_user("alice", UserRole::User, "SECRET")
            .await
            .unwrap();

        db.create_signed_file_token(user.id, "movies/a.mp4", "raw-token", 60)
            .await
            .unwrap();

        let session = db
            .signed_file_session("raw-token", "movies/a.mp4")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(session.user.id, user.id);
        assert!(
            db.signed_file_session("raw-token", "movies/b.mp4")
                .await
                .unwrap()
                .is_none()
        );

        db.set_user_enabled(user.id, false).await.unwrap();
        assert!(
            db.signed_file_session("raw-token", "movies/a.mp4")
                .await
                .unwrap()
                .is_none()
        );

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn delete_user_removes_user_but_keeps_last_admin() {
        let path = test_db_path("delete-user");
        let db = AuthDb::connect(&path).await.unwrap();
        let admin = db
            .create_user("admin", UserRole::Admin, "SECRET")
            .await
            .unwrap();
        let user = db
            .create_user("alice", UserRole::User, "SECRET")
            .await
            .unwrap();

        db.delete_user(user.id).await.unwrap();
        assert!(db.user_by_username("alice").await.unwrap().is_none());
        assert!(db.delete_user(admin.id).await.is_err());

        let _ = std::fs::remove_file(path);
    }
}
