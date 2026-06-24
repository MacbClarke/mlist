use std::collections::HashSet;

use sqlx::Row;

use crate::errors::ApiResult;
use crate::session::now_unix;

use super::helpers::db_error;
use super::types::{UserFavoriteView, UserFileStateView};
use super::AuthDb;

impl AuthDb {
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

    pub async fn list_favorite_paths(&self, user_id: i64) -> ApiResult<HashSet<String>> {
        let rows = sqlx::query(
            r#"
            SELECT path
            FROM user_favorites
            WHERE user_id = ?1
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;

        Ok(rows.into_iter().map(|row| row.get::<String, _>("path")).collect())
    }

    pub async fn list_favorites(&self, user_id: i64) -> ApiResult<Vec<UserFavoriteView>> {
        let rows = sqlx::query(
            r#"
            SELECT path, created_at
            FROM user_favorites
            WHERE user_id = ?1
            ORDER BY created_at DESC, path COLLATE NOCASE
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;

        Ok(rows
            .into_iter()
            .map(|row| UserFavoriteView {
                path: row.get("path"),
                created_at: row.get("created_at"),
            })
            .collect())
    }

    pub async fn set_file_favorite(
        &self,
        user_id: i64,
        path: &str,
        favorite: bool,
    ) -> ApiResult<bool> {
        let now = now_unix() as i64;
        if favorite {
            let result = sqlx::query(
                r#"
                INSERT INTO user_favorites (user_id, path, created_at)
                VALUES (?1, ?2, ?3)
                ON CONFLICT(user_id, path) DO NOTHING
                "#,
            )
            .bind(user_id)
            .bind(path)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
            Ok(result.rows_affected() > 0)
        } else {
            let result = sqlx::query(
                r#"
                DELETE FROM user_favorites
                WHERE user_id = ?1 AND path = ?2
                "#,
            )
            .bind(user_id)
            .bind(path)
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
            Ok(result.rows_affected() > 0)
        }
    }

    pub async fn delete_favorite(&self, user_id: i64, path: &str) -> ApiResult<()> {
        sqlx::query(
            r#"
            DELETE FROM user_favorites
            WHERE user_id = ?1 AND path = ?2
            "#,
        )
        .bind(user_id)
        .bind(path)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }
}
