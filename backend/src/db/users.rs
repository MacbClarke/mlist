use sqlx::Row;

use crate::errors::{ApiError, ApiResult};
use crate::session::now_unix;

use super::helpers::{
    db_error, fetch_user_by_username_from, hash_token, is_unique_violation, user_from_row,
    validate_username,
};
use super::types::{AuthSession, UserRecord, UserView, UserRole};
use super::AuthDb;

impl AuthDb {
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

    pub async fn create_refresh_session(
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

    pub async fn create_access_token(
        &self,
        user_id: i64,
        token: &str,
        ttl_seconds: u64,
    ) -> ApiResult<i64> {
        let now = now_unix() as i64;
        let expires_at = now.saturating_add(ttl_seconds as i64);
        sqlx::query(
            r#"
            INSERT INTO access_tokens (token_hash, user_id, expires_at, created_at, last_active_at)
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

    pub async fn rotate_refresh_session(
        &self,
        current_token: &str,
        next_token: &str,
        ttl_seconds: u64,
    ) -> ApiResult<Option<(AuthSession, i64)>> {
        let now = now_unix() as i64;
        let current_hash = hash_token(current_token);
        let Some(row) = sqlx::query(
            r#"
            SELECT
                s.user_id,
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
        .bind(&current_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_error)?
        else {
            return Ok(None);
        };

        let user = user_from_row(&row)?;
        if !user.enabled {
            self.remove_sessions_for_user(user.id).await?;
            return Ok(None);
        }

        let next_expires_at = now.saturating_add(ttl_seconds as i64);
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let deleted = sqlx::query("DELETE FROM sessions WHERE token_hash = ?1")
            .bind(&current_hash)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?
            .rows_affected();
        if deleted == 0 {
            tx.commit().await.map_err(db_error)?;
            return Ok(None);
        }
        sqlx::query(
            r#"
            INSERT INTO sessions (token_hash, user_id, expires_at, created_at, last_active_at)
            VALUES (?1, ?2, ?3, ?4, ?4)
            "#,
        )
        .bind(hash_token(next_token))
        .bind(user.id)
        .bind(next_expires_at)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;

        Ok(Some((
            AuthSession {
                user,
                expires_at: row.get("expires_at"),
            },
            next_expires_at,
        )))
    }

    pub async fn access_session_by_token(&self, token: &str) -> ApiResult<Option<AuthSession>> {
        let now = now_unix() as i64;
        sqlx::query("DELETE FROM access_tokens WHERE expires_at <= ?1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;

        let token_hash = hash_token(token);
        let Some(row) = sqlx::query(
            r#"
            SELECT
                a.expires_at,
                u.id, u.username, u.role, u.totp_secret, u.enabled,
                u.created_at, u.updated_at, u.last_login_at, u.last_seen_at,
                COALESCE(SUM(uru.total_bytes_served), 0) AS total_bytes_served
            FROM access_tokens a
            JOIN users u ON u.id = a.user_id
            LEFT JOIN user_resource_usage uru ON uru.user_id = u.id
            WHERE a.token_hash = ?1 AND a.expires_at > ?2
            GROUP BY a.token_hash
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
            self.remove_access_token_by_hash(&token_hash).await?;
            return Ok(None);
        }

        sqlx::query("UPDATE access_tokens SET last_active_at = ?1 WHERE token_hash = ?2")
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

    pub async fn remove_refresh_session(&self, token: &str) -> ApiResult<()> {
        self.remove_refresh_session_by_hash(&hash_token(token))
            .await
    }

    pub async fn remove_access_token(&self, token: &str) -> ApiResult<()> {
        self.remove_access_token_by_hash(&hash_token(token)).await
    }

    async fn remove_refresh_session_by_hash(&self, token_hash: &str) -> ApiResult<()> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?1")
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn remove_access_token_by_hash(&self, token_hash: &str) -> ApiResult<()> {
        sqlx::query("DELETE FROM access_tokens WHERE token_hash = ?1")
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn remove_sessions_for_user(&self, user_id: i64) -> ApiResult<()> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        sqlx::query("DELETE FROM sessions WHERE user_id = ?1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        sqlx::query("DELETE FROM access_tokens WHERE user_id = ?1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
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
}
