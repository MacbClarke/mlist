use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use axum::Json;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio_util::io::ReaderStream;
use tracing::info;

use crate::auth::{find_private_anchor, has_private_hide_marker};
use crate::config::AppConfig;
use crate::errors::{ApiError, ApiResult};
use crate::path_guard::{
    ensure_not_marker_path, is_private_marker_name, normalize_relative_path, resolve_existing_path,
};
use crate::session::{
    LoginRateLimiter, SESSION_COOKIE_NAME, SessionData, SessionStore, SessionView, now_unix,
    unix_to_rfc3339,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub sessions: SessionStore,
    pub login_limiter: LoginRateLimiter,
}

#[derive(Debug, Deserialize)]
pub struct PathQuery {
    pub path: Option<String>,
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
    pub path: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub ok: bool,
    pub scope: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeResponse {
    pub authenticated: bool,
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
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

    let session = current_session(&state, &jar).await;
    let anchor = find_private_anchor(root, &resolved, true).await?;
    if let Some(private_anchor) = &anchor {
        if !is_scope_authorized(session.as_ref(), &private_anchor.scope_rel) {
            return Err(ApiError::auth_required());
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

        if file_type.is_dir() && has_private_hide_marker(&resolved_entry).await? {
            continue;
        }

        let entry_anchor = find_private_anchor(root, &resolved_entry, file_type.is_dir()).await?;
        let requires_auth = entry_anchor.is_some();
        let authorized = entry_anchor
            .as_ref()
            .map(|value| is_scope_authorized(session.as_ref(), &value.scope_rel))
            .unwrap_or(true);

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

    Ok(Json(ListResponse {
        path: relative_path,
        entries,
        requires_auth: anchor.is_some(),
        authorized: true,
    }))
}

pub async fn file_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<PathQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let relative_path = normalize_relative_path(query.path.as_deref())?;
    serve_file_response(&state, &jar, &headers, relative_path).await
}

pub async fn direct_file_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    AxumPath(raw_path): AxumPath<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let relative_path = normalize_relative_path(Some(&raw_path))?;
    serve_file_response(&state, &jar, &headers, relative_path).await
}

async fn serve_file_response(
    state: &AppState,
    jar: &CookieJar,
    headers: &HeaderMap,
    relative_path: String,
) -> ApiResult<Response> {
    ensure_not_marker_path(&relative_path)?;
    if relative_path.is_empty() {
        return Err(ApiError::bad_request("Path must reference a file."));
    }

    let root = &state.config.root_dir;
    let resolved = resolve_existing_path(root, &relative_path).await?;
    let metadata = fs::metadata(&resolved)
        .await
        .map_err(|err| ApiError::from_io(err, "file"))?;
    if !metadata.is_file() {
        return Err(ApiError::bad_request("Path is not a file."));
    }

    if file_name_is_marker(&resolved) {
        return Err(ApiError::not_found("File not found."));
    }

    let session = current_session(&state, &jar).await;
    if let Some(anchor) = find_private_anchor(root, &resolved, false).await? {
        if !is_scope_authorized(session.as_ref(), &anchor.scope_rel) {
            return Err(ApiError::auth_required());
        }
    }

    let mut file = fs::File::open(&resolved)
        .await
        .map_err(|err| ApiError::from_io(err, "file"))?;
    let file_size = metadata.len();
    let mime = mime_guess::from_path(&resolved)
        .first_or_octet_stream()
        .essence_str()
        .to_string();
    let content_disposition = content_disposition_inline(&resolved);

    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .map(|value| parse_range_header(value, file_size))
        .transpose()?;

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
    let stream = ReaderStream::new(reader);
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

    builder
        .body(body)
        .map_err(|_| ApiError::internal("Failed to build file response."))
}

pub async fn login_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    ConnectInfo(connect_info): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> ApiResult<(CookieJar, Json<LoginResponse>)> {
    let relative_path = normalize_relative_path(Some(&payload.path))?;
    ensure_not_marker_path(&relative_path)?;

    let root = &state.config.root_dir;
    let resolved = resolve_existing_path(root, &relative_path).await?;
    let metadata = fs::metadata(&resolved)
        .await
        .map_err(|err| ApiError::from_io(err, "path"))?;

    let Some(anchor) = find_private_anchor(root, &resolved, metadata.is_dir()).await? else {
        return Err(ApiError::bad_request("The target path is public."));
    };

    let now = now_unix();
    let client_ip = connect_info.ip().to_string();
    let limiter_key = format!("{client_ip}:{}", anchor.scope_rel);

    if let Some(until) = state.login_limiter.blocked_until(&limiter_key, now).await {
        let remaining = until.saturating_sub(now);
        return Err(ApiError::rate_limited(format!(
            "Too many login failures. Retry in {remaining} seconds."
        )));
    }

    if payload.password != anchor.password {
        if let Some(until) = state.login_limiter.record_failure(&limiter_key, now).await {
            let remaining = until.saturating_sub(now);
            return Err(ApiError::rate_limited(format!(
                "Too many login failures. Retry in {remaining} seconds."
            )));
        }
        return Err(ApiError::unauthorized("Invalid password."));
    }

    state.login_limiter.record_success(&limiter_key).await;

    let current_sid = jar.get(SESSION_COOKIE_NAME).map(|value| value.value());
    let (session_id, session_data) = state
        .sessions
        .create_or_update(
            current_sid,
            &anchor.scope_rel,
            state.config.session_ttl_seconds,
            now,
        )
        .await;

    info!(
        ip = client_ip,
        scope = anchor.scope_rel,
        marker = anchor.marker_file,
        "login succeeded"
    );

    let cookie = build_session_cookie(
        &session_id,
        state.config.session_ttl_seconds,
        state.config.secure_cookies,
    );
    let updated_jar = jar.add(cookie);

    Ok((
        updated_jar,
        Json(LoginResponse {
            ok: true,
            scope: anchor.scope_rel,
            expires_at: unix_to_rfc3339(session_data.expires_at),
        }),
    ))
}

pub async fn logout_handler(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<(CookieJar, Json<GenericOkResponse>)> {
    if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        state.sessions.remove(cookie.value()).await;
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
    let Some(session) = current_session(&state, &jar).await else {
        return Ok(Json(MeResponse {
            authenticated: false,
            scopes: Vec::new(),
            expires_at: None,
        }));
    };

    let session_view: SessionView = session.into();
    Ok(Json(MeResponse {
        authenticated: true,
        scopes: session_view.scopes,
        expires_at: Some(session_view.expires_at),
    }))
}

fn build_session_cookie(
    session_id: &str,
    ttl_seconds: u64,
    secure_cookie: bool,
) -> Cookie<'static> {
    let mut builder = Cookie::build((SESSION_COOKIE_NAME, session_id.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(ttl_seconds as i64));

    if secure_cookie {
        builder = builder.secure(true);
    }

    builder.build()
}

async fn current_session(state: &AppState, jar: &CookieJar) -> Option<SessionData> {
    let sid = jar.get(SESSION_COOKIE_NAME)?.value().to_string();
    state.sessions.get_valid(&sid, now_unix()).await
}

fn is_scope_authorized(session: Option<&SessionData>, scope: &str) -> bool {
    session
        .map(|value| value.scopes.contains(scope))
        .unwrap_or(false)
}

fn file_name_is_marker(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(is_private_marker_name)
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
    use std::path::Path;

    use super::{content_disposition_inline, parse_range_header};

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
}
