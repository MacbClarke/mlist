use std::path::PathBuf;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

use super::{AuthDb, RecordResourceAccess, ResourceKind, ResourceTransferState, UserRole};

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
    assert_eq!(events[0].transfer_state, "completed");
    assert_eq!(events[0].updated_at, events[0].created_at);
    assert_eq!(events[0].ended_at, Some(events[0].created_at));

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
async fn resource_access_migrates_legacy_events_to_completed() {
    let path = test_db_path("audit-migration");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE users (
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
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO users (
            id, username, role, totp_secret, enabled, created_at, updated_at
        )
        VALUES (1, 'legacy', 'user', 'SECRET', 1, 100, 100)
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TABLE resource_access_events (
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
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO resource_access_events (
            user_id, resource_kind, path, route, status, bytes_served,
            file_size, range_start, range_end, created_at
        )
        VALUES (1, 'file', 'old.bin', '/d', 200, 12, 12, NULL, NULL, 1234)
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let db = AuthDb::connect(&path).await.unwrap();
    let events = db.list_access_events_page(None, 10, 0).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].transfer_state, "completed");
    assert_eq!(events[0].updated_at, events[0].created_at);
    assert_eq!(events[0].ended_at, Some(events[0].created_at));

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn stream_access_progress_and_finish_accumulate_deltas() {
    let path = test_db_path("stream-audit");
    let db = AuthDb::connect(&path).await.unwrap();
    let user = db
        .create_user("alice", UserRole::User, "SECRET")
        .await
        .unwrap();

    let event_id = db
        .start_resource_stream_access(RecordResourceAccess {
            user_id: user.id,
            kind: ResourceKind::File,
            path: "movies/demo.mp4".to_string(),
            route: "/d",
            status: 200,
            bytes_served: 0,
            file_size: Some(1_000),
            range_start: None,
            range_end: None,
        })
        .await
        .unwrap();

    db.update_resource_stream_progress(event_id, 40)
        .await
        .unwrap();
    db.update_resource_stream_progress(event_id, 70)
        .await
        .unwrap();
    db.finish_resource_stream_access(event_id, ResourceTransferState::Completed, 100)
        .await
        .unwrap();

    let events = db
        .list_access_events_page(Some(user.id), 10, 0)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].bytes_served, 100);
    assert_eq!(events[0].transfer_state, "completed");
    assert!(events[0].ended_at.is_some());

    let usage = db
        .list_resource_usage_page(Some(user.id), 10, 0)
        .await
        .unwrap();
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].access_count, 1);
    assert_eq!(usage[0].total_bytes_served, 100);

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn startup_marks_leftover_active_events_stale() {
    let path = test_db_path("stream-stale");
    let db = AuthDb::connect(&path).await.unwrap();
    let user = db
        .create_user("alice", UserRole::User, "SECRET")
        .await
        .unwrap();
    db.start_resource_stream_access(RecordResourceAccess {
        user_id: user.id,
        kind: ResourceKind::File,
        path: "movies/demo.mp4".to_string(),
        route: "/d",
        status: 200,
        bytes_served: 0,
        file_size: Some(1_000),
        range_start: None,
        range_end: None,
    })
    .await
    .unwrap();
    drop(db);

    let db = AuthDb::connect(&path).await.unwrap();
    let events = db
        .list_access_events_page(Some(user.id), 10, 0)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].transfer_state, "stale");
    assert!(events[0].ended_at.is_some());

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
async fn remove_access_token_revokes_bearer_session() {
    let path = test_db_path("remove-access-token");
    let db = AuthDb::connect(&path).await.unwrap();
    let user = db
        .create_user("alice", UserRole::User, "SECRET")
        .await
        .unwrap();

    db.create_access_token(user.id, "access-one", 60)
        .await
        .unwrap();
    assert!(
        db.access_session_by_token("access-one")
            .await
            .unwrap()
            .is_some()
    );

    db.remove_access_token("access-one").await.unwrap();
    assert!(
        db.access_session_by_token("access-one")
            .await
            .unwrap()
            .is_none()
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn refresh_rotation_invalidates_previous_refresh_and_access_tokens() {
    let path = test_db_path("refresh-rotation");
    let db = AuthDb::connect(&path).await.unwrap();
    let user = db
        .create_user("alice", UserRole::User, "SECRET")
        .await
        .unwrap();

    db.create_refresh_session(user.id, "refresh-one", 60)
        .await
        .unwrap();
    db.create_access_token(user.id, "access-one", 60)
        .await
        .unwrap();

    let (session, _) = db
        .rotate_refresh_session("refresh-one", "refresh-two", 60)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.user.id, user.id);
    assert!(
        db.rotate_refresh_session("refresh-one", "refresh-three", 60)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.rotate_refresh_session("refresh-two", "refresh-three", 60)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        db.access_session_by_token("access-one")
            .await
            .unwrap()
            .is_some()
    );

    db.set_user_enabled(user.id, false).await.unwrap();
    assert!(
        db.access_session_by_token("access-one")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.rotate_refresh_session("refresh-three", "refresh-four", 60)
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
