use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::UNIX_EPOCH;

use async_zip::tokio::write::ZipFileWriter;
use async_zip::{Compression, ZipEntryBuilder};
use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use futures_core::Stream;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio_util::compat::FuturesAsyncWriteCompatExt;
use tokio_util::io::ReaderStream;
use tracing::error;

use crate::auth::{find_private_anchor, has_private_hide_marker};
use crate::db::{
    AuthDb, AuthSession, BatchTokenPayload, RecordResourceAccess, ResourceKind,
    ResourceTransferState,
};
use crate::errors::{ApiError, ApiResult};
use crate::path_guard::{
    ensure_not_marker_path, is_private_marker_name, normalize_relative_path, resolve_existing_path,
};
use crate::session::now_unix;

use super::helpers::{file_name_is_marker, file_session_for_request, require_session};
use super::http_util::{
    ByteRange, build_not_modified, build_range_not_satisfiable, content_disposition_attachment,
    content_disposition_inline, format_http_date, if_none_match_matches, if_range_matches,
    make_etag, parse_range_header, signed_direct_file_url,
};
use super::types::{
    AppState, DirectBatchQuery, DirectFileQuery, ListEntry, ListResponse, PathQuery,
    SignedBatchLinkRequest, SignedBatchLinkResponse, SignedFileLinkRequest, SignedFileLinkResponse,
};
use crate::session::unix_to_rfc3339;

pub async fn list_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PathQuery>,
) -> ApiResult<Json<ListResponse>> {
    let session = require_session(&state, &headers).await?;
    let relative_path = normalize_relative_path(query.path.as_deref())?;
    ensure_not_marker_path(&relative_path)?;

    let root = &state.config.root_dir;
    let resolved = resolve_existing_path(root, &relative_path).await?;
    let metadata = fs::metadata(&resolved)
        .await
        .map_err(|err| ApiError::from_io(err, "directory"))?;

    if !metadata.is_dir() {
        return Err(ApiError::bad_request("Path is not a directory."));
    }

    let anchor = find_private_anchor(root, &resolved, true).await?;
    if let Some(private_anchor) = &anchor {
        if !session.user.role.is_admin() {
            tracing::info!(
                user = session.user.username,
                scope = private_anchor.scope_rel,
                marker = private_anchor.marker_file,
                "non-admin private directory access denied"
            );
            return Err(ApiError::not_found("Path not found."));
        }
    }

    let favorites_only = query.favorites_only.unwrap_or(false);
    let search = query.search.as_deref().map(str::trim).filter(|value| !value.is_empty());
    let search_lower = search.map(|value| value.to_lowercase());
    let fav_set = state.db.list_favorite_paths(session.user.id).await?;

    let mut entries = Vec::new();
    let mut read_dir = fs::read_dir(&resolved)
        .await
        .map_err(|err| ApiError::from_io(err, "directory"))?;

    while let Some(entry) = read_dir
        .next_entry()
        .await
        .map_err(|err| ApiError::from_io(err, "directory entry"))?
    {
        let name = entry.file_name().to_string_lossy().to_string();
        if is_private_marker_name(&name) {
            continue;
        }
        if let Some(search) = &search_lower {
            if !name.to_lowercase().contains(search) {
                continue;
            }
        }

        let file_type = entry
            .file_type()
            .await
            .map_err(|err| ApiError::from_io(err, "directory entry"))?;

        if file_type.is_symlink() {
            continue;
        }

        if !file_type.is_dir() && !file_type.is_file() {
            continue;
        }

        let entry_path = if relative_path.is_empty() {
            name.clone()
        } else {
            format!("{relative_path}/{name}")
        };

        if favorites_only {
            if !visible_in_favorites_view(&entry_path, file_type.is_dir(), &fav_set) {
                continue;
            }
        }

        let resolved_entry = resolve_existing_path(root, &entry_path).await?;
        let entry_meta = fs::metadata(&resolved_entry)
            .await
            .map_err(|err| ApiError::from_io(err, "directory entry"))?;

        if file_type.is_dir()
            && has_private_hide_marker(&resolved_entry).await?
            && !session.user.role.is_admin()
        {
            continue;
        }

        let entry_anchor = find_private_anchor(root, &resolved_entry, file_type.is_dir()).await?;
        let requires_auth = entry_anchor.is_some();
        let authorized = entry_anchor
            .as_ref()
            .map(|_| session.user.role.is_admin())
            .unwrap_or(true);
        if requires_auth && !authorized {
            continue;
        }

        let mime = if file_type.is_file() {
            Some(
                mime_guess::from_path(&name)
                    .first_or_octet_stream()
                    .essence_str()
                    .to_string(),
            )
        } else {
            None
        };

        entries.push(ListEntry {
            name,
            path: entry_path.clone(),
            kind: if file_type.is_dir() {
                super::types::EntryKind::Dir
            } else {
                super::types::EntryKind::File
            },
            size: file_type.is_file().then_some(entry_meta.len()),
            mtime: entry_meta
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|value| value.as_secs()),
            mime,
            requires_auth,
            authorized,
            favorite: fav_set.contains(&entry_path),
        });
    }

    let sort_field = query.sort.as_deref().unwrap_or("name");
    let order_desc = matches!(query.order.as_deref(), Some("desc"));
    let explicit_sort = query.sort.is_some() || query.order.is_some();

    entries.sort_by(|a, b| {
        if !explicit_sort {
            let type_order = match (&a.kind, &b.kind) {
                (super::types::EntryKind::Dir, super::types::EntryKind::File) => std::cmp::Ordering::Less,
                (super::types::EntryKind::File, super::types::EntryKind::Dir) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            };
            if type_order != std::cmp::Ordering::Equal {
                return type_order;
            }
            return a.name.to_lowercase().cmp(&b.name.to_lowercase());
        }

        let ordering = match sort_field {
            "size" => {
                let (av, bv) = (a.size.unwrap_or(0), b.size.unwrap_or(0));
                av.cmp(&bv).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            }
            "mtime" => {
                let (av, bv) = (a.mtime.unwrap_or(0), b.mtime.unwrap_or(0));
                av.cmp(&bv).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            }
            _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        };
        if order_desc { ordering.reverse() } else { ordering }
    });

    let total = entries.len();
    let limit = query.limit.unwrap_or(50).clamp(1, 200) as usize;
    let offset = query.offset.unwrap_or(0).max(0) as usize;
    let has_more = offset.saturating_add(limit) < total;
    let offset = offset.min(total);
    let end = offset.saturating_add(limit).min(total);
    let entries = entries[offset..end].to_vec();

    state
        .db
        .record_resource_access(RecordResourceAccess {
            user_id: session.user.id,
            kind: ResourceKind::Directory,
            path: relative_path.clone(),
            route: "/api/list",
            status: StatusCode::OK.as_u16(),
            bytes_served: 0,
            file_size: None,
            range_start: None,
            range_end: None,
        })
        .await?;

    Ok(Json(ListResponse {
        path: relative_path,
        entries,
        requires_auth: anchor.is_some(),
        authorized: true,
        total,
        has_more,
    }))
}

pub(super) fn visible_in_favorites_view(
    entry_path: &str,
    is_dir: bool,
    fav_set: &std::collections::HashSet<String>,
) -> bool {
    if fav_set.contains(entry_path) {
        return true;
    }

    if fav_set
        .iter()
        .any(|fav| path_is_descendant_of(entry_path, fav))
    {
        return true;
    }

    is_dir
        && fav_set
            .iter()
            .any(|fav| path_is_descendant_of(fav, entry_path))
}

fn path_is_descendant_of(path: &str, parent: &str) -> bool {
    path.strip_prefix(parent)
        .is_some_and(|rest| rest.starts_with('/'))
}

pub async fn direct_file_handler(
    State(state): State<AppState>,
    AxumPath(raw_path): AxumPath<String>,
    Query(query): Query<DirectFileQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let relative_path = normalize_relative_path(Some(&raw_path))?;
    serve_file_response(
        &state,
        &headers,
        relative_path,
        "/d",
        query.token.as_deref(),
    )
    .await
}

pub async fn create_file_link_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SignedFileLinkRequest>,
) -> ApiResult<Json<SignedFileLinkResponse>> {
    let session = require_session(&state, &headers).await?;
    let path = normalize_relative_path(Some(&payload.path))?;
    ensure_file_accessible(&state, &session, &path).await?;

    let token = uuid::Uuid::new_v4().simple().to_string();
    let expires_at = state
        .db
        .create_signed_file_token(
            session.user.id,
            &path,
            &token,
            state.config.signed_file_link_ttl_seconds,
        )
        .await?;

    Ok(Json(SignedFileLinkResponse {
        url: signed_direct_file_url(&path, &token),
        expires_at: unix_to_rfc3339(expires_at as u64),
    }))
}

pub async fn create_batch_link_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SignedBatchLinkRequest>,
) -> ApiResult<Json<SignedBatchLinkResponse>> {
    let session = require_session(&state, &headers).await?;
    if payload.paths.is_empty() {
        return Err(ApiError::bad_request("Paths cannot be empty."));
    }
    if payload.paths.len() > 1000 {
        return Err(ApiError::bad_request(
            "Too many paths in a single batch request (max 1000).",
        ));
    }

    let base_path = match payload.base_path.as_deref() {
        Some(bp) if !bp.trim().is_empty() => Some(normalize_relative_path(Some(bp))?),
        _ => None,
    };

    let mut normalized_paths = Vec::with_capacity(payload.paths.len());
    let root = &state.config.root_dir;

    for raw_path in &payload.paths {
        let norm = normalize_relative_path(Some(raw_path))?;
        ensure_not_marker_path(&norm)?;

        let resolved = resolve_existing_path(root, &norm).await?;
        let metadata = fs::metadata(&resolved)
            .await
            .map_err(|err| ApiError::from_io(err, "file or directory"))?;

        let anchor = find_private_anchor(root, &resolved, metadata.is_dir()).await?;
        if anchor.is_some() && !session.user.role.is_admin() {
            return Err(ApiError::not_found("Path not found or access denied."));
        }
        normalized_paths.push(norm);
    }

    let token = uuid::Uuid::new_v4().simple().to_string();
    let batch_payload = BatchTokenPayload {
        paths: normalized_paths,
        base_path,
        name: payload.name,
    };

    let expires_at = state
        .db
        .create_signed_batch_token(
            session.user.id,
            &batch_payload,
            &token,
            state.config.signed_file_link_ttl_seconds,
        )
        .await?;

    Ok(Json(SignedBatchLinkResponse {
        url: format!("/api/batch-download?token={token}"),
        expires_at: unix_to_rfc3339(expires_at as u64),
    }))
}

pub async fn batch_download_handler(
    State(state): State<AppState>,
    Query(query): Query<DirectBatchQuery>,
) -> ApiResult<Response> {
    let Some((session, batch_payload)) = state.db.signed_batch_session(&query.token).await? else {
        return Err(ApiError::unauthorized("Invalid or expired download token."));
    };

    let root = &state.config.root_dir;
    let is_admin = session.user.role.is_admin();
    let files = collect_files_for_zip(
        root,
        is_admin,
        &batch_payload.paths,
        batch_payload.base_path.as_deref(),
    )
    .await?;

    if files.is_empty() {
        return Err(ApiError::bad_request("No accessible files to download."));
    }

    let raw_zip_name = if let Some(custom_name) = batch_payload.name {
        if custom_name.to_lowercase().ends_with(".zip") {
            custom_name
        } else {
            format!("{custom_name}.zip")
        }
    } else if batch_payload.paths.len() == 1 {
        let single = &batch_payload.paths[0];
        let file_stem = single.rsplit_once('/').map(|(_, name)| name).unwrap_or(single);
        format!("{file_stem}.zip")
    } else {
        "download.zip".to_string()
    };

    let (mut duplex_writer, duplex_reader) = tokio::io::duplex(64 * 1024);

    tokio::spawn(async move {
        let mut zip_writer = ZipFileWriter::with_tokio(&mut duplex_writer);
        for item in files {
            let file = match tokio::fs::File::open(&item.resolved_path).await {
                Ok(f) => f,
                Err(err) => {
                    tracing::warn!(path = ?item.resolved_path, "failed to open file for streaming zip: {err}");
                    continue;
                }
            };

            let builder = ZipEntryBuilder::new(item.zip_rel_path.into(), Compression::Deflate);
            let entry_writer = match zip_writer.write_entry_stream(builder).await {
                Ok(w) => w,
                Err(err) => {
                    tracing::warn!("failed to create zip entry stream: {err}");
                    break;
                }
            };

            let mut compat_writer = entry_writer.compat_write();
            let mut file_reader = file;
            if let Err(err) = tokio::io::copy(&mut file_reader, &mut compat_writer).await {
                tracing::warn!("failed to stream file into zip: {err}");
                break;
            }

            let entry_writer = compat_writer.into_inner();
            if let Err(err) = entry_writer.close().await {
                tracing::warn!("failed to close zip entry writer: {err}");
                break;
            }
        }

        if let Err(err) = zip_writer.close().await {
            tracing::warn!("failed to close zip archive writer: {err}");
        }
    });

    let audit_path = if batch_payload.paths.len() == 1 {
        batch_payload.paths[0].clone()
    } else {
        format!("batch:{} items", batch_payload.paths.len())
    };

    let event_id = state
        .db
        .start_resource_stream_access(RecordResourceAccess {
            user_id: session.user.id,
            kind: ResourceKind::File,
            path: audit_path,
            route: "/api/batch-download",
            status: StatusCode::OK.as_u16(),
            bytes_served: 0,
            file_size: None,
            range_start: None,
            range_end: None,
        })
        .await?;
    let recorder = FileAccessRecorder::new(state.db.clone(), event_id);

    let stream = CountingFileStream::new(duplex_reader, recorder);
    let body = Body::from_stream(stream);

    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&content_disposition_attachment(&raw_zip_name))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment; filename=\"download.zip\"")),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );

    Ok(response)
}

struct ZipItem {
    resolved_path: PathBuf,
    zip_rel_path: String,
}

async fn collect_files_for_zip(
    root: &Path,
    is_admin: bool,
    paths: &[String],
    base_path: Option<&str>,
) -> ApiResult<Vec<ZipItem>> {
    let mut items = Vec::new();
    let mut seen_zip_paths = HashSet::new();

    for raw_path in paths {
        let norm = normalize_relative_path(Some(raw_path))?;
        ensure_not_marker_path(&norm)?;

        let resolved = resolve_existing_path(root, &norm).await?;
        let metadata = fs::metadata(&resolved)
            .await
            .map_err(|err| ApiError::from_io(err, "file or directory"))?;

        let anchor = find_private_anchor(root, &resolved, metadata.is_dir()).await?;
        if anchor.is_some() && !is_admin {
            continue;
        }

        if metadata.is_file() {
            let zip_rel = make_zip_path(&norm, base_path, true);
            let unique_zip_path = make_unique_path(zip_rel, &mut seen_zip_paths);
            items.push(ZipItem {
                resolved_path: resolved,
                zip_rel_path: unique_zip_path,
            });
        } else if metadata.is_dir() {
            let mut queue = VecDeque::new();
            queue.push_back((resolved.clone(), norm.clone()));

            while let Some((dir_resolved, dir_rel)) = queue.pop_front() {
                let mut read_dir = match fs::read_dir(&dir_resolved).await {
                    Ok(rd) => rd,
                    Err(err) => {
                        tracing::warn!("failed to read directory for zip: {err}");
                        continue;
                    }
                };

                while let Ok(Some(entry)) = read_dir.next_entry().await {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    if is_private_marker_name(&file_name) {
                        continue;
                    }

                    let entry_resolved = entry.path();
                    let entry_rel = if dir_rel.is_empty() {
                        file_name.clone()
                    } else {
                        format!("{dir_rel}/{file_name}")
                    };

                    let entry_type = match entry.file_type().await {
                        Ok(ft) => ft,
                        Err(_) => continue,
                    };

                    let anchor =
                        find_private_anchor(root, &entry_resolved, entry_type.is_dir()).await?;
                    if anchor.is_some() && !is_admin {
                        continue;
                    }

                    if entry_type.is_dir() {
                        queue.push_back((entry_resolved, entry_rel));
                    } else if entry_type.is_file() {
                        let zip_rel = make_zip_path(&entry_rel, base_path, false);
                        let unique_zip_path = make_unique_path(zip_rel, &mut seen_zip_paths);
                        items.push(ZipItem {
                            resolved_path: entry_resolved,
                            zip_rel_path: unique_zip_path,
                        });
                    }
                }
            }
        }
    }

    Ok(items)
}

fn make_zip_path(rel_path: &str, base_path: Option<&str>, is_direct_file: bool) -> String {
    if let Some(base) = base_path {
        let trimmed_base = base.trim_matches('/');
        if !trimmed_base.is_empty() {
            if let Some(stripped) = rel_path.strip_prefix(trimmed_base) {
                let clean = stripped.trim_matches('/');
                if !clean.is_empty() {
                    return clean.to_string();
                }
            }
        }
    }

    if is_direct_file {
        if let Some((_, name)) = rel_path.rsplit_once('/') {
            return name.to_string();
        }
    }

    rel_path.trim_matches('/').to_string()
}

fn make_unique_path(path: String, seen: &mut HashSet<String>) -> String {
    if seen.insert(path.clone()) {
        return path;
    }
    let (stem, ext) = match path.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (path.clone(), String::new()),
    };
    let mut counter = 1;
    loop {
        let candidate = format!("{stem} ({counter}){ext}");
        if seen.insert(candidate.clone()) {
            return candidate;
        }
        counter += 1;
    }
}

async fn serve_file_response(
    state: &AppState,
    headers: &HeaderMap,
    relative_path: String,
    route: &'static str,
    signed_token: Option<&str>,
) -> ApiResult<Response> {
    let session = file_session_for_request(state, &relative_path, signed_token).await?;
    let accessible = ensure_file_accessible(state, &session, &relative_path).await?;
    let resolved = accessible.resolved;
    let metadata = accessible.metadata;

    let file_size = metadata.len();
    let mime = mime_guess::from_path(&resolved)
        .first_or_octet_stream()
        .essence_str()
        .to_string();
    let content_disposition = content_disposition_inline(&resolved);

    let modified = metadata.modified().ok();
    let etag = modified.map(|m| make_etag(file_size, m));
    let last_modified = modified.and_then(format_http_date);

    // RFC 7232: If-None-Match 优先，命中则 304；仅在 If-None-Match 缺失时才退到 If-Modified-Since。
    let inm_header = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    if let (Some(raw), Some(tag)) = (inm_header, etag.as_deref()) {
        if if_none_match_matches(raw, tag) {
            record_file_access(
                state,
                &session,
                &relative_path,
                route,
                StatusCode::NOT_MODIFIED,
                0,
                file_size,
                None,
            )
            .await?;
            return build_not_modified(etag.as_deref(), last_modified.as_deref());
        }
    } else if inm_header.is_none() {
        let ims_header = headers
            .get(header::IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok());
        if let (Some(raw), Some(lm)) = (ims_header, last_modified.as_deref()) {
            if raw.trim() == lm {
                record_file_access(
                    state,
                    &session,
                    &relative_path,
                    route,
                    StatusCode::NOT_MODIFIED,
                    0,
                    file_size,
                    None,
                )
                .await?;
                return build_not_modified(etag.as_deref(), last_modified.as_deref());
            }
        }
    }

    // RFC 7233: If-Range 不匹配时必须忽略 Range，退回 200 完整响应。
    let if_range_ok = match headers.get(header::IF_RANGE).and_then(|v| v.to_str().ok()) {
        Some(raw) => if_range_matches(raw, etag.as_deref(), last_modified.as_deref()),
        None => true,
    };

    let range_header = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let range = if if_range_ok {
        match range_header.map(|value| parse_range_header(value, file_size)) {
            Some(Ok(value)) => Some(value),
            Some(Err(_)) => {
                return build_range_not_satisfiable(
                    file_size,
                    etag.as_deref(),
                    last_modified.as_deref(),
                );
            }
            None => None,
        }
    } else {
        None
    };

    let mut file = fs::File::open(&resolved)
        .await
        .map_err(|err| ApiError::from_io(err, "file"))?;

    let (status, content_length, content_range_header) = match range {
        Some(value) => {
            file.seek(SeekFrom::Start(value.start))
                .await
                .map_err(|err| ApiError::from_io(err, "file"))?;
            (
                StatusCode::PARTIAL_CONTENT,
                value.len(),
                Some(format!("bytes {}-{}/{}", value.start, value.end, file_size)),
            )
        }
        None => (StatusCode::OK, file_size, None),
    };

    let reader = match range {
        Some(value) => file.take(value.len()),
        None => file.take(file_size),
    };
    let event_id = state
        .db
        .start_resource_stream_access(RecordResourceAccess {
            user_id: session.user.id,
            kind: ResourceKind::File,
            path: relative_path.clone(),
            route,
            status: status.as_u16(),
            bytes_served: 0,
            file_size: Some(u64_to_i64(file_size)),
            range_start: range.map(|value| u64_to_i64(value.start)),
            range_end: range.map(|value| u64_to_i64(value.end)),
        })
        .await?;
    let recorder = FileAccessRecorder::new(state.db.clone(), event_id);
    let stream = CountingFileStream::new(reader, recorder);
    let body = Body::from_stream(stream);

    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_DISPOSITION, content_disposition)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, content_length.to_string());

    if let Some(content_range) = content_range_header {
        builder = builder.header(header::CONTENT_RANGE, content_range);
    }
    if let Some(ref tag) = etag {
        builder = builder.header(header::ETAG, tag);
    }
    if let Some(ref lm) = last_modified {
        builder = builder.header(header::LAST_MODIFIED, lm);
    }

    builder
        .body(body)
        .map_err(|_| ApiError::internal("Failed to build file response."))
}

pub(super) struct FileAccessRecorder {
    db: AuthDb,
    event_id: i64,
    bytes_served: AtomicU64,
    last_progress_at: AtomicI64,
    finalized: AtomicBool,
}

const STREAM_PROGRESS_FLUSH_INTERVAL_SECONDS: i64 = 5;

impl FileAccessRecorder {
    pub(super) fn new(db: AuthDb, event_id: i64) -> Arc<Self> {
        Arc::new(Self {
            db,
            event_id,
            bytes_served: AtomicU64::new(0),
            last_progress_at: AtomicI64::new(now_unix() as i64),
            finalized: AtomicBool::new(false),
        })
    }

    fn add_bytes(self: &Arc<Self>, len: usize) {
        let added = u64::try_from(len).unwrap_or(u64::MAX);
        let _ = self
            .bytes_served
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(added))
            });
        self.maybe_flush_progress();
    }

    fn maybe_flush_progress(self: &Arc<Self>) {
        if self.finalized.load(Ordering::Acquire) {
            return;
        }

        let now = now_unix() as i64;
        let previous = self.last_progress_at.load(Ordering::Acquire);
        if now.saturating_sub(previous) < STREAM_PROGRESS_FLUSH_INTERVAL_SECONDS {
            return;
        }
        if self
            .last_progress_at
            .compare_exchange(previous, now, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let recorder = Arc::clone(self);
        tokio::spawn(async move {
            let bytes_served = u64_to_i64(recorder.bytes_served.load(Ordering::Acquire));
            if let Err(err) = recorder
                .db
                .update_resource_stream_progress(recorder.event_id, bytes_served)
                .await
            {
                error!("failed to update file stream progress: {err:?}");
            }
        });
    }

    fn finalize_in_background(self: Arc<Self>, transfer_state: ResourceTransferState) {
        if self.finalized.swap(true, Ordering::AcqRel) {
            return;
        }

        tokio::spawn(async move {
            let bytes_served = u64_to_i64(self.bytes_served.load(Ordering::Acquire));
            if let Err(err) = self
                .db
                .finish_resource_stream_access(self.event_id, transfer_state, bytes_served)
                .await
            {
                error!("failed to finalize file stream access: {err:?}");
            }
        });
    }
}

pub(super) struct CountingFileStream<R> {
    inner: Pin<Box<ReaderStream<R>>>,
    recorder: Arc<FileAccessRecorder>,
}

impl<R> CountingFileStream<R>
where
    R: AsyncRead + Unpin,
{
    pub(super) fn new(reader: R, recorder: Arc<FileAccessRecorder>) -> Self {
        Self {
            inner: Box::pin(ReaderStream::new(reader)),
            recorder,
        }
    }
}

impl<R> Stream for CountingFileStream<R>
where
    R: AsyncRead + Unpin,
{
    type Item = std::io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                self.recorder.add_bytes(bytes.len());
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(err))) => {
                self.recorder
                    .clone()
                    .finalize_in_background(ResourceTransferState::Failed);
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                self.recorder
                    .clone()
                    .finalize_in_background(ResourceTransferState::Completed);
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<R> Drop for CountingFileStream<R> {
    fn drop(&mut self) {
        self.recorder
            .clone()
            .finalize_in_background(ResourceTransferState::Aborted);
    }
}

pub(super) struct AccessibleFile {
    resolved: PathBuf,
    metadata: std::fs::Metadata,
}

pub(super) async fn ensure_file_accessible(
    state: &AppState,
    session: &AuthSession,
    relative_path: &str,
) -> ApiResult<AccessibleFile> {
    ensure_not_marker_path(relative_path)?;
    if relative_path.is_empty() {
        return Err(ApiError::bad_request("Path must reference a file."));
    }

    let root = &state.config.root_dir;
    let resolved = resolve_existing_path(root, relative_path).await?;
    let metadata = fs::metadata(&resolved)
        .await
        .map_err(|err| ApiError::from_io(err, "file"))?;
    if !metadata.is_file() {
        return Err(ApiError::bad_request("Path is not a file."));
    }

    if file_name_is_marker(&resolved) {
        return Err(ApiError::not_found("File not found."));
    }

    if let Some(anchor) = find_private_anchor(root, &resolved, false).await? {
        if !session.user.role.is_admin() {
            tracing::info!(
                user = session.user.username,
                scope = anchor.scope_rel,
                marker = anchor.marker_file,
                "non-admin private file access denied"
            );
            return Err(ApiError::not_found("File not found."));
        }
    }

    Ok(AccessibleFile { resolved, metadata })
}

async fn record_file_access(
    state: &AppState,
    session: &AuthSession,
    path: &str,
    route: &'static str,
    status: StatusCode,
    bytes_served: u64,
    file_size: u64,
    range: Option<ByteRange>,
) -> ApiResult<()> {
    state
        .db
        .record_resource_access(RecordResourceAccess {
            user_id: session.user.id,
            kind: ResourceKind::File,
            path: path.to_string(),
            route,
            status: status.as_u16(),
            bytes_served: u64_to_i64(bytes_served),
            file_size: Some(u64_to_i64(file_size)),
            range_start: range.map(|value| u64_to_i64(value.start)),
            range_end: range.map(|value| u64_to_i64(value.end)),
        })
        .await
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
