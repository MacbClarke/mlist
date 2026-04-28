use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use time::{Month, OffsetDateTime, UtcOffset, Weekday};
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio_util::io::ReaderStream;
use totp_rs::{Algorithm, Secret, TOTP};
use tracing::{error, info};

use crate::auth::{find_private_anchor, has_private_hide_marker};
use crate::config::AppConfig;
use crate::db::{
    AuthDb, AuthSession, RecordResourceAccess, ResourceAccessEventView, ResourceKind,
    ResourceTransferState, ResourceUsageView, UserFileStateView, UserRole, UserRoleInput, UserView,
};
use crate::errors::{ApiError, ApiResult};
use crate::path_guard::{
    ensure_not_marker_path, is_private_marker_name, normalize_relative_path, resolve_existing_path,
};
use crate::session::{LoginRateLimiter, SESSION_COOKIE_NAME, now_unix, unix_to_rfc3339};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: AuthDb,
    pub login_limiter: LoginRateLimiter,
}

#[derive(Debug, Deserialize)]
pub struct PathQuery {
    pub path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DirectFileQuery {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditQuery {
    pub user_id: Option<i64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
    pub path: String,
    pub entries: Vec<ListEntry>,
    pub requires_auth: bool,
    pub authorized: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListEntry {
    pub name: String,
    pub path: String,
    pub kind: EntryKind,
    pub size: Option<u64>,
    pub mtime: Option<u64>,
    pub mime: Option<String>,
    pub requires_auth: bool,
    pub authorized: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    Dir,
    File,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub ok: bool,
    pub expires_at: String,
    pub user: UserView,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeResponse {
    pub authenticated: bool,
    pub user: Option<UserView>,
    pub expires_at: Option<String>,
    pub needs_bootstrap: bool,
}

#[derive(Debug, Deserialize)]
pub struct BootstrapStartRequest {
    pub username: String,
}

#[derive(Debug, Deserialize)]
pub struct BootstrapFinishRequest {
    pub username: String,
    pub secret: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub role: UserRoleInput,
}

#[derive(Debug, Deserialize)]
pub struct FileStateRequest {
    pub path: String,
    pub highlighted: bool,
}

#[derive(Debug, Deserialize)]
pub struct SignedFileLinkRequest {
    pub path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedFileLinkResponse {
    pub url: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpBindingResponse {
    pub user: UserView,
    pub secret: String,
    pub otpauth_url: String,
    pub qr_data_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapStartResponse {
    pub username: String,
    pub secret: String,
    pub otpauth_url: String,
    pub qr_data_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsersResponse {
    pub users: Vec<UserView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventsResponse {
    pub events: Vec<ResourceAccessEventView>,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditResourcesResponse {
    pub resources: Vec<ResourceUsageView>,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileStatesResponse {
    pub files: Vec<UserFileStateView>,
}

#[derive(Debug, Serialize)]
pub struct GenericOkResponse {
    pub ok: bool,
}

#[derive(Debug, Clone, Copy)]
struct ByteRange {
    start: u64,
    end: u64,
}

impl ByteRange {
    fn len(self) -> u64 {
        self.end - self.start + 1
    }
}

pub async fn list_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<PathQuery>,
) -> ApiResult<Json<ListResponse>> {
    let session = require_session(&state, &jar).await?;
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
            info!(
                user = session.user.username,
                scope = private_anchor.scope_rel,
                marker = private_anchor.marker_file,
                "non-admin private directory access denied"
            );
            return Err(ApiError::not_found("Path not found."));
        }
    }

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
            path: entry_path,
            kind: if file_type.is_dir() {
                EntryKind::Dir
            } else {
                EntryKind::File
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
        });
    }

    entries.sort_by(|a, b| {
        let type_order = match (&a.kind, &b.kind) {
            (EntryKind::Dir, EntryKind::File) => std::cmp::Ordering::Less,
            (EntryKind::File, EntryKind::Dir) => std::cmp::Ordering::Greater,
            _ => std::cmp::Ordering::Equal,
        };
        if type_order != std::cmp::Ordering::Equal {
            return type_order;
        }

        a.name.to_lowercase().cmp(&b.name.to_lowercase())
    });

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
    }))
}

pub async fn direct_file_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    AxumPath(raw_path): AxumPath<String>,
    Query(query): Query<DirectFileQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let relative_path = normalize_relative_path(Some(&raw_path))?;
    serve_file_response(
        &state,
        &jar,
        &headers,
        relative_path,
        "/d",
        query.token.as_deref(),
    )
    .await
}

async fn serve_file_response(
    state: &AppState,
    jar: &CookieJar,
    headers: &HeaderMap,
    relative_path: String,
    route: &'static str,
    signed_token: Option<&str>,
) -> ApiResult<Response> {
    let session = file_session_for_request(state, jar, &relative_path, signed_token).await?;
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

struct FileAccessRecorder {
    db: AuthDb,
    event_id: i64,
    bytes_served: AtomicU64,
    last_progress_at: AtomicI64,
    finalized: AtomicBool,
}

const STREAM_PROGRESS_FLUSH_INTERVAL_SECONDS: i64 = 5;

impl FileAccessRecorder {
    fn new(db: AuthDb, event_id: i64) -> Arc<Self> {
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

struct CountingFileStream<R> {
    inner: Pin<Box<ReaderStream<R>>>,
    recorder: Arc<FileAccessRecorder>,
}

impl<R> CountingFileStream<R>
where
    R: AsyncRead + Unpin,
{
    fn new(reader: R, recorder: Arc<FileAccessRecorder>) -> Self {
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

struct AccessibleFile {
    resolved: PathBuf,
    metadata: std::fs::Metadata,
}

async fn ensure_file_accessible(
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
            info!(
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

fn build_not_modified(etag: Option<&str>, last_modified: Option<&str>) -> ApiResult<Response> {
    let mut builder = Response::builder().status(StatusCode::NOT_MODIFIED);
    if let Some(tag) = etag {
        builder = builder.header(header::ETAG, tag);
    }
    if let Some(lm) = last_modified {
        builder = builder.header(header::LAST_MODIFIED, lm);
    }
    builder
        .body(Body::empty())
        .map_err(|_| ApiError::internal("Failed to build 304 response."))
}

fn build_range_not_satisfiable(
    file_size: u64,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> ApiResult<Response> {
    let mut builder = Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(header::CONTENT_RANGE, format!("bytes */{file_size}"))
        .header(header::ACCEPT_RANGES, "bytes");
    if let Some(tag) = etag {
        builder = builder.header(header::ETAG, tag);
    }
    if let Some(lm) = last_modified {
        builder = builder.header(header::LAST_MODIFIED, lm);
    }
    builder
        .body(Body::empty())
        .map_err(|_| ApiError::internal("Failed to build 416 response."))
}

pub async fn login_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    ConnectInfo(connect_info): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> ApiResult<(CookieJar, Json<LoginResponse>)> {
    let now = now_unix();
    let client_ip = client_ip_for_request(&headers, connect_info.ip()).to_string();
    let username = payload.username.trim();
    let limiter_key = format!("{client_ip}:{}", username.to_lowercase());

    if let Some(until) = state.login_limiter.blocked_until(&limiter_key, now).await {
        let remaining = until.saturating_sub(now);
        return Err(ApiError::rate_limited(format!(
            "Too many login failures. Retry in {remaining} seconds."
        )));
    }

    let user = state
        .db
        .user_by_username(username)
        .await?
        .filter(|value| value.enabled);

    let valid = match user.as_ref() {
        Some(user) => verify_totp(&user.username, &user.totp_secret, &payload.code)?,
        None => false,
    };

    if !valid {
        if let Some(until) = state.login_limiter.record_failure(&limiter_key, now).await {
            let remaining = until.saturating_sub(now);
            return Err(ApiError::rate_limited(format!(
                "Too many login failures. Retry in {remaining} seconds."
            )));
        }
        return Err(ApiError::unauthorized("Invalid username or code."));
    }

    let user = user.ok_or_else(|| ApiError::unauthorized("Invalid username or code."))?;
    state.login_limiter.record_success(&limiter_key).await;

    let session_token = uuid::Uuid::new_v4().simple().to_string();
    let expires_at = state
        .db
        .create_session(user.id, &session_token, state.config.session_ttl_seconds)
        .await?;
    state.db.record_login(user.id).await?;

    info!(ip = client_ip, user = user.username, "login succeeded");

    let cookie = build_session_cookie(&session_token, state.config.session_ttl_seconds);
    let updated_jar = jar.add(cookie);

    Ok((
        updated_jar,
        Json(LoginResponse {
            ok: true,
            expires_at: unix_to_rfc3339(expires_at as u64),
            user: user.view(),
        }),
    ))
}

pub async fn bootstrap_start_handler(
    State(state): State<AppState>,
    Json(payload): Json<BootstrapStartRequest>,
) -> ApiResult<Json<BootstrapStartResponse>> {
    if !state.db.needs_bootstrap().await? {
        return Err(ApiError::forbidden("Bootstrap has already been completed."));
    }

    let username = payload.username.trim();
    validate_login_name(username)?;
    let secret = generate_totp_secret();
    let binding = build_totp_binding(username, &secret)?;
    Ok(Json(BootstrapStartResponse {
        username: username.to_string(),
        secret,
        otpauth_url: binding.otpauth_url,
        qr_data_url: binding.qr_data_url,
    }))
}

pub async fn bootstrap_finish_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<BootstrapFinishRequest>,
) -> ApiResult<(CookieJar, Json<LoginResponse>)> {
    if !state.db.needs_bootstrap().await? {
        return Err(ApiError::forbidden("Bootstrap has already been completed."));
    }

    let username = payload.username.trim();
    validate_login_name(username)?;
    if !verify_totp(username, &payload.secret, &payload.code)? {
        return Err(ApiError::unauthorized("Invalid verification code."));
    }

    let user = state.db.bootstrap_admin(username, &payload.secret).await?;
    let session_token = uuid::Uuid::new_v4().simple().to_string();
    let expires_at = state
        .db
        .create_session(user.id, &session_token, state.config.session_ttl_seconds)
        .await?;
    state.db.record_login(user.id).await?;
    info!(user = user.username, "bootstrap admin created");

    let cookie = build_session_cookie(&session_token, state.config.session_ttl_seconds);
    let updated_jar = jar.add(cookie);

    Ok((
        updated_jar,
        Json(LoginResponse {
            ok: true,
            expires_at: unix_to_rfc3339(expires_at as u64),
            user: user.view(),
        }),
    ))
}

pub async fn logout_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<(CookieJar, Json<GenericOkResponse>)> {
    if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        state.db.remove_session(cookie.value()).await?;
    }

    let removal = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(0))
        .build();

    Ok((jar.remove(removal), Json(GenericOkResponse { ok: true })))
}

pub async fn me_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<MeResponse>> {
    let needs_bootstrap = state.db.needs_bootstrap().await?;
    let Some(session) = current_session(&state, &jar).await? else {
        return Ok(Json(MeResponse {
            authenticated: false,
            user: None,
            expires_at: None,
            needs_bootstrap,
        }));
    };

    Ok(Json(MeResponse {
        authenticated: true,
        user: Some(session.user.view()),
        expires_at: Some(unix_to_rfc3339(session.expires_at as u64)),
        needs_bootstrap,
    }))
}

pub async fn admin_users_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<UsersResponse>> {
    require_admin(&state, &jar).await?;
    Ok(Json(UsersResponse {
        users: state.db.list_users().await?,
    }))
}

pub async fn admin_audit_events_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<AuditEventsResponse>> {
    require_admin(&state, &jar).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let offset = query.offset.unwrap_or(0).max(0);
    let mut events = state
        .db
        .list_access_events_page(query.user_id, limit + 1, offset)
        .await?;
    let has_more = events.len() > limit as usize;
    if has_more {
        events.truncate(limit as usize);
    }
    Ok(Json(AuditEventsResponse { events, has_more }))
}

pub async fn admin_audit_resources_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<AuditResourcesResponse>> {
    require_admin(&state, &jar).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let offset = query.offset.unwrap_or(0).max(0);
    let mut resources = state
        .db
        .list_resource_usage_page(query.user_id, limit + 1, offset)
        .await?;
    let has_more = resources.len() > limit as usize;
    if has_more {
        resources.truncate(limit as usize);
    }
    Ok(Json(AuditResourcesResponse {
        resources,
        has_more,
    }))
}

pub async fn admin_create_user_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<CreateUserRequest>,
) -> ApiResult<Json<TotpBindingResponse>> {
    require_admin(&state, &jar).await?;
    let username = payload.username.trim();
    validate_login_name(username)?;
    let secret = generate_totp_secret();
    let user = state
        .db
        .create_user(username, UserRole::from(payload.role), &secret)
        .await?;
    Ok(Json(binding_response(user.view(), &secret)?))
}

pub async fn admin_disable_user_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    AxumPath(user_id): AxumPath<i64>,
) -> ApiResult<Json<UserView>> {
    require_admin(&state, &jar).await?;
    Ok(Json(state.db.set_user_enabled(user_id, false).await?))
}

pub async fn admin_enable_user_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    AxumPath(user_id): AxumPath<i64>,
) -> ApiResult<Json<UserView>> {
    require_admin(&state, &jar).await?;
    Ok(Json(state.db.set_user_enabled(user_id, true).await?))
}

pub async fn admin_delete_user_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    AxumPath(user_id): AxumPath<i64>,
) -> ApiResult<Json<GenericOkResponse>> {
    require_admin(&state, &jar).await?;
    state.db.delete_user(user_id).await?;
    Ok(Json(GenericOkResponse { ok: true }))
}

pub async fn admin_reset_totp_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    AxumPath(user_id): AxumPath<i64>,
) -> ApiResult<Json<TotpBindingResponse>> {
    require_admin(&state, &jar).await?;
    let secret = generate_totp_secret();
    let user = state.db.reset_totp(user_id, &secret).await?;
    Ok(Json(binding_response(user.view(), &secret)?))
}

pub async fn create_file_link_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<SignedFileLinkRequest>,
) -> ApiResult<Json<SignedFileLinkResponse>> {
    let session = require_session(&state, &jar).await?;
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

pub async fn file_states_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<FileStatesResponse>> {
    let session = require_session(&state, &jar).await?;
    Ok(Json(FileStatesResponse {
        files: state.db.list_highlighted_files(session.user.id).await?,
    }))
}

pub async fn set_file_state_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<FileStateRequest>,
) -> ApiResult<Json<UserFileStateView>> {
    let session = require_session(&state, &jar).await?;
    let path = normalize_relative_path(Some(&payload.path))?;
    ensure_file_accessible(&state, &session, &path).await?;

    Ok(Json(
        state
            .db
            .set_file_highlighted(session.user.id, &path, payload.highlighted)
            .await?,
    ))
}

fn client_ip_for_request(headers: &HeaderMap, peer_ip: IpAddr) -> IpAddr {
    parse_x_forwarded_for(headers)
        .or_else(|| parse_x_real_ip(headers))
        .unwrap_or(peer_ip)
}

fn parse_x_forwarded_for(headers: &HeaderMap) -> Option<IpAddr> {
    let raw = headers.get("x-forwarded-for")?.to_str().ok()?;
    raw.split(',')
        .map(str::trim)
        .find_map(parse_forwarded_ip_token)
}

fn parse_x_real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let raw = headers.get("x-real-ip")?.to_str().ok()?;
    parse_forwarded_ip_token(raw.trim())
}

fn parse_forwarded_ip_token(raw: &str) -> Option<IpAddr> {
    if raw.is_empty() {
        return None;
    }

    raw.parse::<IpAddr>()
        .ok()
        .or_else(|| raw.parse::<SocketAddr>().ok().map(|value| value.ip()))
}

fn build_session_cookie(session_id: &str, ttl_seconds: u64) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, session_id.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(ttl_seconds as i64))
        .build()
}

async fn current_session(state: &AppState, jar: &CookieJar) -> ApiResult<Option<AuthSession>> {
    let Some(cookie) = jar.get(SESSION_COOKIE_NAME) else {
        return Ok(None);
    };
    let sid = cookie.value().to_string();
    state.db.session_by_token(&sid).await
}

async fn file_session_for_request(
    state: &AppState,
    jar: &CookieJar,
    relative_path: &str,
    signed_token: Option<&str>,
) -> ApiResult<AuthSession> {
    if let Some(session) = current_session(state, jar).await? {
        return Ok(session);
    }

    let Some(token) = signed_token
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(ApiError::auth_required());
    };

    state
        .db
        .signed_file_session(token, relative_path)
        .await?
        .ok_or_else(ApiError::auth_required)
}

async fn require_session(state: &AppState, jar: &CookieJar) -> ApiResult<AuthSession> {
    current_session(state, jar)
        .await?
        .ok_or_else(ApiError::auth_required)
}

async fn require_admin(state: &AppState, jar: &CookieJar) -> ApiResult<AuthSession> {
    let session = require_session(state, jar).await?;
    if !session.user.role.is_admin() {
        return Err(ApiError::forbidden("Administrator privileges required."));
    }
    Ok(session)
}

fn validate_login_name(username: &str) -> ApiResult<()> {
    if username.trim().len() < 2 || username.trim().len() > 64 {
        return Err(ApiError::bad_request(
            "Username must be between 2 and 64 characters.",
        ));
    }
    if username.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad_request(
            "Username contains disallowed control characters.",
        ));
    }
    Ok(())
}

fn generate_totp_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

struct TotpBinding {
    otpauth_url: String,
    qr_data_url: String,
}

fn build_totp(username: &str, secret: &str) -> ApiResult<TOTP> {
    let secret_bytes = Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|_| ApiError::bad_request("Invalid TOTP secret."))?;
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("mlist".to_string()),
        username.to_string(),
    )
    .map_err(|_| ApiError::bad_request("Invalid TOTP configuration."))
}

fn build_totp_binding(username: &str, secret: &str) -> ApiResult<TotpBinding> {
    let totp = build_totp(username, secret)?;
    let otpauth_url = totp.get_url();
    let qr_data_url = format!(
        "data:image/png;base64,{}",
        totp.get_qr_base64()
            .map_err(|_| ApiError::internal("Failed to generate QR code."))?
    );
    Ok(TotpBinding {
        otpauth_url,
        qr_data_url,
    })
}

fn binding_response(user: UserView, secret: &str) -> ApiResult<TotpBindingResponse> {
    let binding = build_totp_binding(&user.username, secret)?;
    Ok(TotpBindingResponse {
        user,
        secret: secret.to_string(),
        otpauth_url: binding.otpauth_url,
        qr_data_url: binding.qr_data_url,
    })
}

fn verify_totp(username: &str, secret: &str, code: &str) -> ApiResult<bool> {
    let trimmed = code.trim();
    if trimmed.len() != 6 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Ok(false);
    }
    build_totp(username, secret)?
        .check_current(trimmed)
        .map_err(|_| ApiError::internal("Failed to verify TOTP code."))
}

fn file_name_is_marker(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(is_private_marker_name)
}

fn signed_direct_file_url(path: &str, token: &str) -> String {
    let encoded_path = path
        .split('/')
        .map(url_path_segment_encode)
        .collect::<Vec<_>>()
        .join("/");
    format!("/d/{encoded_path}?token={token}")
}

fn url_path_segment_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if is_url_unreserved(*byte) {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            encoded.push(to_hex_upper(byte >> 4));
            encoded.push(to_hex_upper(byte & 0x0F));
        }
    }
    encoded
}

fn is_url_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn content_disposition_inline(path: &Path) -> String {
    let raw_name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let fallback = ascii_filename_fallback(&raw_name);
    let escaped_fallback = escape_quoted_string(&fallback);
    let encoded = rfc5987_encode(&raw_name);
    format!("inline; filename=\"{escaped_fallback}\"; filename*=UTF-8''{encoded}")
}

fn ascii_filename_fallback(raw_name: &str) -> String {
    let mut out = String::with_capacity(raw_name.len());
    for ch in raw_name.chars() {
        if ch.is_ascii() && !ch.is_ascii_control() && ch != '"' && ch != '\\' {
            out.push(ch);
        } else if ch.is_whitespace() {
            out.push(' ');
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        "file".to_string()
    } else {
        trimmed.to_string()
    }
}

fn escape_quoted_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn rfc5987_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if is_rfc5987_attr_char(*byte) {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            encoded.push(to_hex_upper(byte >> 4));
            encoded.push(to_hex_upper(byte & 0x0F));
        }
    }
    encoded
}

fn is_rfc5987_attr_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&byte)
}

fn to_hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0' + nibble),
        10..=15 => char::from(b'A' + (nibble - 10)),
        _ => '0',
    }
}

fn make_etag(size: u64, mtime: SystemTime) -> String {
    let (sign, sec, nanos) = match mtime.duration_since(UNIX_EPOCH) {
        Ok(d) => ('p', d.as_secs(), d.subsec_nanos()),
        Err(err) => ('n', err.duration().as_secs(), err.duration().subsec_nanos()),
    };
    format!("W/\"{size:x}-{sign}{sec:x}.{nanos:x}\"")
}

fn format_http_date(t: SystemTime) -> Option<String> {
    let dt = OffsetDateTime::from(t).to_offset(UtcOffset::UTC);
    let weekday = match dt.weekday() {
        Weekday::Monday => "Mon",
        Weekday::Tuesday => "Tue",
        Weekday::Wednesday => "Wed",
        Weekday::Thursday => "Thu",
        Weekday::Friday => "Fri",
        Weekday::Saturday => "Sat",
        Weekday::Sunday => "Sun",
    };
    let month = match dt.month() {
        Month::January => "Jan",
        Month::February => "Feb",
        Month::March => "Mar",
        Month::April => "Apr",
        Month::May => "May",
        Month::June => "Jun",
        Month::July => "Jul",
        Month::August => "Aug",
        Month::September => "Sep",
        Month::October => "Oct",
        Month::November => "Nov",
        Month::December => "Dec",
    };
    Some(format!(
        "{weekday}, {day:02} {month} {year:04} {hour:02}:{minute:02}:{second:02} GMT",
        day = dt.day(),
        year = dt.year(),
        hour = dt.hour(),
        minute = dt.minute(),
        second = dt.second(),
    ))
}

fn if_none_match_matches(raw: &str, etag: &str) -> bool {
    raw.split(',').any(|part| {
        let part = part.trim();
        part == "*" || weak_etag_equal(part, etag)
    })
}

fn weak_etag_equal(a: &str, b: &str) -> bool {
    strip_weak_prefix(a.trim()) == strip_weak_prefix(b.trim())
}

fn strip_weak_prefix(s: &str) -> &str {
    s.strip_prefix("W/").unwrap_or(s)
}

fn if_range_matches(raw: &str, etag: Option<&str>, last_modified: Option<&str>) -> bool {
    let raw = raw.trim();
    if raw.starts_with('"') || raw.starts_with("W/") {
        return etag.is_some_and(|e| weak_etag_equal(raw, e));
    }
    // 日期形式：RFC 7233 要求与我们发出的 Last-Modified 精确匹配
    last_modified.is_some_and(|lm| raw == lm)
}

fn parse_range_header(raw_header: &str, file_size: u64) -> ApiResult<ByteRange> {
    if file_size == 0 {
        return Err(ApiError::invalid_range(
            "Range request cannot be satisfied for an empty file.",
        ));
    }

    let raw = raw_header.trim();
    let Some(raw_range) = raw.strip_prefix("bytes=") else {
        return Err(ApiError::invalid_range("Only bytes ranges are supported."));
    };

    if raw_range.contains(',') {
        return Err(ApiError::invalid_range(
            "Multiple ranges are not supported.",
        ));
    }

    let (start_part, end_part) = raw_range
        .split_once('-')
        .ok_or_else(|| ApiError::invalid_range("Malformed Range header."))?;

    if start_part.is_empty() {
        let suffix_len = end_part
            .parse::<u64>()
            .map_err(|_| ApiError::invalid_range("Malformed suffix byte range."))?;
        if suffix_len == 0 {
            return Err(ApiError::invalid_range(
                "Suffix byte range must be greater than zero.",
            ));
        }
        let read_len = suffix_len.min(file_size);
        let start = file_size - read_len;
        let end = file_size - 1;
        return Ok(ByteRange { start, end });
    }

    let start = start_part
        .parse::<u64>()
        .map_err(|_| ApiError::invalid_range("Malformed start byte range."))?;
    if start >= file_size {
        return Err(ApiError::invalid_range(
            "Range start is beyond end of file.",
        ));
    }

    let mut end = if end_part.is_empty() {
        file_size - 1
    } else {
        end_part
            .parse::<u64>()
            .map_err(|_| ApiError::invalid_range("Malformed end byte range."))?
    };

    if end >= file_size {
        end = file_size - 1;
    }
    if end < start {
        return Err(ApiError::invalid_range(
            "Range end cannot be smaller than range start.",
        ));
    }

    Ok(ByteRange { start, end })
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::IpAddr;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::{Duration, UNIX_EPOCH};

    use axum::http::HeaderMap;
    use futures_util::StreamExt;
    use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

    use crate::db::{AuthDb, RecordResourceAccess, ResourceKind, UserRole};

    use super::{
        CountingFileStream, FileAccessRecorder, content_disposition_inline, format_http_date,
        if_none_match_matches, if_range_matches, make_etag, parse_range_header,
        parse_x_forwarded_for, signed_direct_file_url,
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
}
