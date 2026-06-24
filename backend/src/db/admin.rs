use sqlx::Row;

use crate::errors::{ApiError, ApiResult};
use crate::session::now_unix;

use super::helpers::{db_error, fetch_user_by_id_from};
use super::types::{UserRecord, UserView};
use super::AuthDb;

impl AuthDb {
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
            sqlx::query("DELETE FROM access_tokens WHERE user_id = ?1")
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
            "access_tokens",
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
        sqlx::query("DELETE FROM access_tokens WHERE user_id = ?1")
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
