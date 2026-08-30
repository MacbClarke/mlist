use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, UNIX_EPOCH};

use axum::http::HeaderMap;
use futures_util::StreamExt;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use async_zip::tokio::write::ZipFileWriter;
use async_zip::{Compression, ZipEntryBuilder};

use crate::db::{AuthDb, RecordResourceAccess, ResourceKind, UserRole};

use super::files::{CountingFileStream, FileAccessRecorder, visible_in_favorites_view};
use super::helpers::parse_x_forwarded_for;
use super::http_util::{
    content_disposition_inline, format_http_date, if_none_match_matches, if_range_matches,
    make_etag, parse_range_header, signed_direct_file_url,
};

fn test_path(name: &str, extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "mlist-{name}-{}.{}",
        uuid::Uuid::new_v4().simple(),
        extension
    ))
}

struct FailingReader;

impl AsyncRead for FailingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("read failed")))
    }
}

fn favorite_set(paths: &[&str]) -> HashSet<String> {
    paths.iter().map(|path| path.to_string()).collect()
}

#[test]
fn favorites_view_keeps_ancestors_of_favorite_file() {
    let favorites = favorite_set(&["a/b.txt"]);

    assert!(visible_in_favorites_view("a", true, &favorites));
    assert!(visible_in_favorites_view("a/b.txt", false, &favorites));
    assert!(!visible_in_favorites_view("a/c.txt", false, &favorites));
}

#[test]
fn favorites_view_shows_descendants_of_favorite_directory() {
    let favorites = favorite_set(&["a"]);

    assert!(visible_in_favorites_view("a", true, &favorites));
    assert!(visible_in_favorites_view("a/file.txt", false, &favorites));
    assert!(visible_in_favorites_view("a/subdir", true, &favorites));
    assert!(visible_in_favorites_view(
        "a/subdir/deep.txt",
        false,
        &favorites
    ));
}

#[tokio::test]
async fn test_streaming_zip() {
    use tokio_util::compat::FuturesAsyncWriteCompatExt;

    let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut zip_writer = ZipFileWriter::with_tokio(&mut writer);
        let builder = ZipEntryBuilder::new("hello.txt".into(), Compression::Deflate);
        let entry_writer = zip_writer.write_entry_stream(builder).await.unwrap();
        let mut compat_writer = entry_writer.compat_write();
        tokio::io::copy(&mut &b"hello world"[..], &mut compat_writer).await.unwrap();
        let entry_writer = compat_writer.into_inner();
        entry_writer.close().await.unwrap();
        zip_writer.close().await.unwrap();
    });

    let mut output = Vec::new();
    reader.read_to_end(&mut output).await.unwrap();
    assert!(!output.is_empty());
}

#[tokio::test]
async fn test_batch_download_flow() {
    use axum::extract::{Query, State};
    use axum::http::StatusCode;
    use axum::Json;
    use super::files::{batch_download_handler, create_batch_link_handler};
    use super::types::{AppState, DirectBatchQuery, SignedBatchLinkRequest};
    use crate::config::AppConfig;
    use crate::session::LoginRateLimiter;
    use std::sync::Arc;

    let root_dir = test_path("batch_root", "d");
    tokio::fs::create_dir_all(root_dir.join("sub")).await.unwrap();
    tokio::fs::write(root_dir.join("a.txt"), b"hello a").await.unwrap();
    tokio::fs::write(root_dir.join("sub/b.txt"), b"hello b").await.unwrap();

    let db_path = test_path("batch_db", "sqlite3");
    let db = AuthDb::connect(&db_path).await.unwrap();
    let user = db.create_user("bob", UserRole::Admin, "SECRET").await.unwrap();

    let config = Arc::new(AppConfig {
        root_dir: root_dir.clone(),
        database_path: db_path.clone(),
        ..AppConfig::default()
    });

    let state = AppState {
        config,
        db: db.clone(),
        login_limiter: LoginRateLimiter::new(5, 60),
    };

    db.create_access_token(user.id, "TEST_TOKEN", 3600).await.unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        "Bearer TEST_TOKEN".parse().unwrap(),
    );

    let req = SignedBatchLinkRequest {
        paths: vec!["a.txt".to_string(), "sub".to_string()],
        base_path: None,
        name: Some("my_archive.zip".to_string()),
    };
    let Json(resp) = create_batch_link_handler(State(state.clone()), headers, Json(req))
        .await
        .unwrap();

    assert!(resp.url.starts_with("/api/batch-download?token="));
    let token = resp.url.strip_prefix("/api/batch-download?token=").unwrap();

    let query = DirectBatchQuery {
        token: token.to_string(),
    };
    let response = batch_download_handler(State(state), Query(query))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/zip"
    );

    let body_bytes = axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024)
        .await
        .unwrap();
    assert!(!body_bytes.is_empty());

    let _ = tokio::fs::remove_dir_all(&root_dir).await;
    let _ = tokio::fs::remove_file(&db_path).await;
}

#[test]
fn favorites_view_matches_only_path_boundaries() {
    let favorites = favorite_set(&["a"]);

    assert!(!visible_in_favorites_view("aa", true, &favorites));
    assert!(!visible_in_favorites_view("aa/file.txt", false, &favorites));
}

#[test]
fn range_parses_open_ended() {
    let range = parse_range_header("bytes=10-", 100).unwrap();
    assert_eq!(range.start, 10);
    assert_eq!(range.end, 99);
    assert_eq!(range.len(), 90);
}

#[test]
fn range_parses_suffix() {
    let range = parse_range_header("bytes=-20", 100).unwrap();
    assert_eq!(range.start, 80);
    assert_eq!(range.end, 99);
}

#[test]
fn range_rejects_out_of_bounds_start() {
    assert!(parse_range_header("bytes=100-120", 100).is_err());
}

#[test]
fn range_rejects_multi_ranges() {
    assert!(parse_range_header("bytes=0-10,20-30", 100).is_err());
}

#[test]
fn content_disposition_contains_ascii_filename() {
    let disposition = content_disposition_inline(Path::new("/tmp/video.mkv"));
    assert!(disposition.contains("filename=\"video.mkv\""));
    assert!(disposition.contains("filename*=UTF-8''video.mkv"));
}

#[test]
fn content_disposition_encodes_utf8_filename() {
    let disposition = content_disposition_inline(Path::new("/tmp/你好 字幕.ass"));
    assert!(disposition.contains("filename=\"__ __.ass\""));
    assert!(
        disposition.contains("filename*=UTF-8''%E4%BD%A0%E5%A5%BD%20%E5%AD%97%E5%B9%95.ass")
    );
}

#[test]
fn signed_direct_file_url_encodes_path_segments() {
    assert_eq!(
        signed_direct_file_url("电影/clip one.mp4", "abc123"),
        "/d/%E7%94%B5%E5%BD%B1/clip%20one.mp4?token=abc123"
    );
}

#[tokio::test]
async fn counting_stream_records_only_consumed_bytes_on_drop() {
    let db_path = test_path("counting-stream", "sqlite3");
    let file_path = test_path("counting-stream-file", "bin");
    let db = AuthDb::connect(&db_path).await.unwrap();
    let user = db
        .create_user("alice", UserRole::User, "SECRET")
        .await
        .unwrap();
    let data = vec![7_u8; 128 * 1024];
    tokio::fs::write(&file_path, &data).await.unwrap();

    let file = tokio::fs::File::open(&file_path).await.unwrap();
    let event_id = db
        .start_resource_stream_access(RecordResourceAccess {
            user_id: user.id,
            kind: ResourceKind::File,
            path: "movie.bin".to_string(),
            route: "/d",
            status: 206,
            bytes_served: 0,
            file_size: Some(data.len() as i64),
            range_start: Some(0),
            range_end: Some(data.len() as i64 - 1),
        })
        .await
        .unwrap();
    let recorder = FileAccessRecorder::new(db.clone(), event_id);
    let mut stream = CountingFileStream::new(file.take(data.len() as u64), recorder);
    let first_chunk_len = stream.next().await.unwrap().unwrap().len();
    assert!(first_chunk_len < data.len());
    drop(stream);

    tokio::time::sleep(Duration::from_millis(50)).await;
    let usage = db
        .list_resource_usage_page(Some(user.id), 10, 0)
        .await
        .unwrap();
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].total_bytes_served, first_chunk_len as i64);

    let events = db
        .list_access_events_page(Some(user.id), 10, 0)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].bytes_served, first_chunk_len as i64);
    assert_eq!(events[0].transfer_state, "aborted");

    let _ = std::fs::remove_file(db_path);
    let _ = std::fs::remove_file(file_path);
}

#[tokio::test]
async fn counting_stream_marks_completed_after_full_consumption() {
    let db_path = test_path("counting-stream-complete", "sqlite3");
    let file_path = test_path("counting-stream-complete-file", "bin");
    let db = AuthDb::connect(&db_path).await.unwrap();
    let user = db
        .create_user("alice", UserRole::User, "SECRET")
        .await
        .unwrap();
    let data = vec![9_u8; 64 * 1024];
    tokio::fs::write(&file_path, &data).await.unwrap();

    let file = tokio::fs::File::open(&file_path).await.unwrap();
    let event_id = db
        .start_resource_stream_access(RecordResourceAccess {
            user_id: user.id,
            kind: ResourceKind::File,
            path: "movie.bin".to_string(),
            route: "/d",
            status: 200,
            bytes_served: 0,
            file_size: Some(data.len() as i64),
            range_start: None,
            range_end: None,
        })
        .await
        .unwrap();
    let recorder = FileAccessRecorder::new(db.clone(), event_id);
    let mut stream = CountingFileStream::new(file.take(data.len() as u64), recorder);
    let mut total = 0;
    while let Some(chunk) = stream.next().await {
        total += chunk.unwrap().len();
    }
    assert_eq!(total, data.len());

    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = db
        .list_access_events_page(Some(user.id), 10, 0)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].bytes_served, data.len() as i64);
    assert_eq!(events[0].transfer_state, "completed");

    let _ = std::fs::remove_file(db_path);
    let _ = std::fs::remove_file(file_path);
}

#[tokio::test]
async fn counting_stream_marks_failed_on_read_error() {
    let db_path = test_path("counting-stream-failed", "sqlite3");
    let db = AuthDb::connect(&db_path).await.unwrap();
    let user = db
        .create_user("alice", UserRole::User, "SECRET")
        .await
        .unwrap();

    let event_id = db
        .start_resource_stream_access(RecordResourceAccess {
            user_id: user.id,
            kind: ResourceKind::File,
            path: "movie.bin".to_string(),
            route: "/d",
            status: 200,
            bytes_served: 0,
            file_size: Some(128),
            range_start: None,
            range_end: None,
        })
        .await
        .unwrap();
    let recorder = FileAccessRecorder::new(db.clone(), event_id);
    let mut stream = CountingFileStream::new(FailingReader, recorder);
    assert!(stream.next().await.unwrap().is_err());
    drop(stream);

    tokio::time::sleep(Duration::from_millis(50)).await;
    let events = db
        .list_access_events_page(Some(user.id), 10, 0)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].bytes_served, 0);
    assert_eq!(events[0].transfer_state, "failed");

    let _ = std::fs::remove_file(db_path);
}

#[test]
fn x_forwarded_for_uses_first_valid_ip() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "unknown, 203.0.113.8".parse().unwrap());

    let ip = parse_x_forwarded_for(&headers).unwrap();
    assert_eq!(ip, "203.0.113.8".parse::<IpAddr>().unwrap());
}

#[test]
fn x_forwarded_for_accepts_socket_address_tokens() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "198.51.100.1:45321".parse().unwrap());

    let ip = parse_x_forwarded_for(&headers).unwrap();
    assert_eq!(ip, "198.51.100.1".parse::<IpAddr>().unwrap());
}

#[test]
fn x_forwarded_for_returns_none_for_invalid_values() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "unknown, garbage".parse().unwrap());
    assert!(parse_x_forwarded_for(&headers).is_none());
}

#[test]
fn etag_is_weak_and_encodes_size_and_mtime() {
    let mtime = UNIX_EPOCH + Duration::from_secs(0x123);
    let tag = make_etag(0x4a, mtime);
    assert!(tag.starts_with("W/\""), "etag should be weak: {tag}");
    assert!(tag.contains("4a-"), "etag should embed size: {tag}");
    assert!(tag.contains("p123."), "etag should embed mtime: {tag}");
}

#[test]
fn http_date_format_is_imf_fixdate() {
    let t = UNIX_EPOCH + Duration::from_secs(784_111_777);
    let s = format_http_date(t).unwrap();
    assert_eq!(s, "Sun, 06 Nov 1994 08:49:37 GMT");
}

#[test]
fn if_none_match_handles_star_and_weak() {
    assert!(if_none_match_matches("*", "W/\"abc\""));
    assert!(if_none_match_matches("W/\"abc\"", "W/\"abc\""));
    assert!(if_none_match_matches("\"abc\"", "W/\"abc\""));
    assert!(if_none_match_matches(
        "\"xyz\", W/\"abc\" , \"foo\"",
        "W/\"abc\""
    ));
    assert!(!if_none_match_matches("\"xyz\"", "W/\"abc\""));
}

#[test]
fn if_range_accepts_matching_etag() {
    assert!(if_range_matches(
        "W/\"abc\"",
        Some("W/\"abc\""),
        Some("Sun, 06 Nov 1994 08:49:37 GMT"),
    ));
    assert!(!if_range_matches(
        "W/\"other\"",
        Some("W/\"abc\""),
        Some("Sun, 06 Nov 1994 08:49:37 GMT"),
    ));
}

#[test]
fn if_range_accepts_matching_date() {
    let lm = "Sun, 06 Nov 1994 08:49:37 GMT";
    assert!(if_range_matches(lm, Some("W/\"abc\""), Some(lm)));
    assert!(!if_range_matches(
        "Mon, 07 Nov 1994 08:49:37 GMT",
        Some("W/\"abc\""),
        Some(lm),
    ));
}
