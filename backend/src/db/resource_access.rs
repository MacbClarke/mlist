use sqlx::Row;

use crate::errors::{ApiError, ApiResult};
use crate::session::now_unix;

use super::helpers::{db_error, event_from_row, upsert_resource_usage_delta, usage_from_row};
use super::types::{
    RecordResourceAccess, ResourceAccessEventView, ResourceKind, ResourceTransferState,
    ResourceUsageView,
};
use super::AuthDb;

impl AuthDb {
    pub async fn record_resource_access(&self, access: RecordResourceAccess) -> ApiResult<()> {
        let now = now_unix() as i64;
        let cutoff = now.saturating_sub(90 * 24 * 60 * 60);
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let bytes_served = access.bytes_served.max(0);

        sqlx::query(
            r#"
            INSERT INTO resource_access_events (
                user_id, resource_kind, path, route, status, bytes_served,
                file_size, range_start, range_end, transfer_state, created_at,
                updated_at, ended_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11, ?11)
            "#,
        )
        .bind(access.user_id)
        .bind(access.kind.as_str())
        .bind(&access.path)
        .bind(access.route)
        .bind(i64::from(access.status))
        .bind(bytes_served)
        .bind(access.file_size)
        .bind(access.range_start)
        .bind(access.range_end)
        .bind(ResourceTransferState::Completed.as_str())
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
            upsert_resource_usage_delta(
                &mut tx,
                access.user_id,
                &access.path,
                access.file_size,
                1,
                bytes_served,
                now,
            )
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

    pub async fn start_resource_stream_access(
        &self,
        access: RecordResourceAccess,
    ) -> ApiResult<i64> {
        if !matches!(access.kind, ResourceKind::File) {
            return Err(ApiError::internal(
                "Streaming resource access must reference a file.",
            ));
        }

        let now = now_unix() as i64;
        let cutoff = now.saturating_sub(90 * 24 * 60 * 60);
        let mut tx = self.pool.begin().await.map_err(db_error)?;

        let result = sqlx::query(
            r#"
            INSERT INTO resource_access_events (
                user_id, resource_kind, path, route, status, bytes_served,
                file_size, range_start, range_end, transfer_state, created_at,
                updated_at, ended_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?9, ?10, ?10, NULL)
            "#,
        )
        .bind(access.user_id)
        .bind(access.kind.as_str())
        .bind(&access.path)
        .bind(access.route)
        .bind(i64::from(access.status))
        .bind(access.file_size)
        .bind(access.range_start)
        .bind(access.range_end)
        .bind(ResourceTransferState::Active.as_str())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let event_id = result.last_insert_rowid();

        sqlx::query("UPDATE users SET last_seen_at = ?1, updated_at = ?1 WHERE id = ?2")
            .bind(now)
            .bind(access.user_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        upsert_resource_usage_delta(
            &mut tx,
            access.user_id,
            &access.path,
            access.file_size,
            1,
            0,
            now,
        )
        .await
        .map_err(db_error)?;

        sqlx::query("DELETE FROM resource_access_events WHERE created_at < ?1")
            .bind(cutoff)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        tx.commit().await.map_err(db_error)?;
        Ok(event_id)
    }

    pub async fn update_resource_stream_progress(
        &self,
        event_id: i64,
        bytes_served: i64,
    ) -> ApiResult<()> {
        let now = now_unix() as i64;
        let requested_total = bytes_served.max(0);
        let mut tx = self.pool.begin().await.map_err(db_error)?;

        let Some(row) = sqlx::query(
            r#"
            SELECT user_id, resource_kind, path, file_size, bytes_served, transfer_state
            FROM resource_access_events
            WHERE id = ?1
            "#,
        )
        .bind(event_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?
        else {
            return Err(ApiError::internal("Resource access event was not found."));
        };

        let transfer_state: String = row.get("transfer_state");
        if transfer_state != ResourceTransferState::Active.as_str() {
            tx.commit().await.map_err(db_error)?;
            return Ok(());
        }

        let current_total = row.get::<i64, _>("bytes_served").max(0);
        let new_total = requested_total.max(current_total);
        let delta = new_total.saturating_sub(current_total);
        if delta == 0 {
            tx.commit().await.map_err(db_error)?;
            return Ok(());
        }

        sqlx::query(
            r#"
            UPDATE resource_access_events
            SET bytes_served = ?1, updated_at = ?2
            WHERE id = ?3
            "#,
        )
        .bind(new_total)
        .bind(now)
        .bind(event_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

        let resource_kind: String = row.get("resource_kind");
        if resource_kind == ResourceKind::File.as_str() {
            let user_id = row.get("user_id");
            let path: String = row.get("path");
            let file_size = row.get("file_size");
            upsert_resource_usage_delta(&mut tx, user_id, &path, file_size, 0, delta, now)
                .await
                .map_err(db_error)?;
        }

        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    pub async fn finish_resource_stream_access(
        &self,
        event_id: i64,
        transfer_state: ResourceTransferState,
        bytes_served: i64,
    ) -> ApiResult<()> {
        if transfer_state == ResourceTransferState::Active {
            return Err(ApiError::internal(
                "Finished stream cannot use the active transfer state.",
            ));
        }

        let now = now_unix() as i64;
        let requested_total = bytes_served.max(0);
        let mut tx = self.pool.begin().await.map_err(db_error)?;

        let Some(row) = sqlx::query(
            r#"
            SELECT user_id, resource_kind, path, file_size, bytes_served, transfer_state
            FROM resource_access_events
            WHERE id = ?1
            "#,
        )
        .bind(event_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?
        else {
            return Err(ApiError::internal("Resource access event was not found."));
        };

        let current_state: String = row.get("transfer_state");
        if current_state != ResourceTransferState::Active.as_str() {
            tx.commit().await.map_err(db_error)?;
            return Ok(());
        }

        let current_total = row.get::<i64, _>("bytes_served").max(0);
        let new_total = requested_total.max(current_total);
        let delta = new_total.saturating_sub(current_total);

        sqlx::query(
            r#"
            UPDATE resource_access_events
            SET bytes_served = ?1, transfer_state = ?2, updated_at = ?3, ended_at = ?3
            WHERE id = ?4
            "#,
        )
        .bind(new_total)
        .bind(transfer_state.as_str())
        .bind(now)
        .bind(event_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

        let resource_kind: String = row.get("resource_kind");
        if resource_kind == ResourceKind::File.as_str() {
            let user_id = row.get("user_id");
            let path: String = row.get("path");
            let file_size = row.get("file_size");
            upsert_resource_usage_delta(&mut tx, user_id, &path, file_size, 0, delta, now)
                .await
                .map_err(db_error)?;
        }

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
                    e.status, e.bytes_served, e.file_size, e.range_start, e.range_end,
                    e.transfer_state, e.created_at, e.updated_at, e.ended_at
                FROM resource_access_events e
                JOIN users u ON u.id = e.user_id
                WHERE e.user_id = ?1
                ORDER BY e.updated_at DESC, e.id DESC
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
                    e.status, e.bytes_served, e.file_size, e.range_start, e.range_end,
                    e.transfer_state, e.created_at, e.updated_at, e.ended_at
                FROM resource_access_events e
                JOIN users u ON u.id = e.user_id
                ORDER BY e.updated_at DESC, e.id DESC
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
}
