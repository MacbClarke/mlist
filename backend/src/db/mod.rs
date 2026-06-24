use std::path::Path;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::session::now_unix;

mod admin;
mod file_states;
mod helpers;
mod resource_access;
#[cfg(test)]
mod tests;
mod types;
mod users;

pub use types::*;

#[derive(Debug, Clone)]
pub struct AuthDb {
    pub(super) pool: SqlitePool,
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
        db.mark_active_resource_accesses_stale()
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
            CREATE TABLE IF NOT EXISTS access_tokens (
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
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS access_tokens_user_id_idx ON access_tokens(user_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS access_tokens_expires_at_idx ON access_tokens(expires_at)",
        )
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
                transfer_state TEXT NOT NULL DEFAULT 'completed' CHECK (transfer_state IN ('active', 'completed', 'aborted', 'failed', 'stale')),
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                ended_at INTEGER
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        self.ensure_column(
            "resource_access_events",
            "transfer_state",
            "TEXT NOT NULL DEFAULT 'completed' CHECK (transfer_state IN ('active', 'completed', 'aborted', 'failed', 'stale'))",
        )
        .await?;
        self.ensure_column(
            "resource_access_events",
            "updated_at",
            "INTEGER NOT NULL DEFAULT 0",
        )
        .await?;
        self.ensure_column("resource_access_events", "ended_at", "INTEGER")
            .await?;
        sqlx::query(
            "UPDATE resource_access_events SET updated_at = created_at WHERE updated_at = 0",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "UPDATE resource_access_events SET ended_at = created_at WHERE ended_at IS NULL AND transfer_state = 'completed'",
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
            "CREATE INDEX IF NOT EXISTS resource_access_events_updated_idx ON resource_access_events(updated_at DESC, id DESC)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS resource_access_events_user_created_idx ON resource_access_events(user_id, created_at DESC)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS resource_access_events_user_updated_idx ON resource_access_events(user_id, updated_at DESC, id DESC)",
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
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_favorites (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                created_at INTEGER NOT NULL,
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

    async fn mark_active_resource_accesses_stale(&self) -> sqlx::Result<()> {
        let now = now_unix() as i64;
        sqlx::query(
            r#"
            UPDATE resource_access_events
            SET transfer_state = ?1, updated_at = ?2, ended_at = ?2
            WHERE transfer_state = ?3
            "#,
        )
        .bind(ResourceTransferState::Stale.as_str())
        .bind(now)
        .bind(ResourceTransferState::Active.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
