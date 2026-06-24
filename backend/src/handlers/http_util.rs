use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{StatusCode, header};
use time::{Month, OffsetDateTime, UtcOffset, Weekday};

use crate::errors::{ApiError, ApiResult};

#[derive(Debug, Clone, Copy)]
pub(super) struct ByteRange {
    pub(super) start: u64,
    pub(super) end: u64,
}

impl ByteRange {
    pub(super) fn len(self) -> u64 {
        self.end - self.start + 1
    }
}

pub(super) fn signed_direct_file_url(path: &str, token: &str) -> String {
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

pub(super) fn content_disposition_inline(path: &Path) -> String {
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

pub(super) fn make_etag(size: u64, mtime: SystemTime) -> String {
    let (sign, sec, nanos) = match mtime.duration_since(UNIX_EPOCH) {
        Ok(d) => ('p', d.as_secs(), d.subsec_nanos()),
        Err(err) => ('n', err.duration().as_secs(), err.duration().subsec_nanos()),
    };
    format!("W/\"{size:x}-{sign}{sec:x}.{nanos:x}\"")
}

pub(super) fn format_http_date(t: SystemTime) -> Option<String> {
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

pub(super) fn if_none_match_matches(raw: &str, etag: &str) -> bool {
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

pub(super) fn if_range_matches(raw: &str, etag: Option<&str>, last_modified: Option<&str>) -> bool {
    let raw = raw.trim();
    if raw.starts_with('"') || raw.starts_with("W/") {
        return etag.is_some_and(|e| weak_etag_equal(raw, e));
    }
    // 日期形式：RFC 7233 要求与我们发出的 Last-Modified 精确匹配
    last_modified.is_some_and(|lm| raw == lm)
}

pub(super) fn parse_range_header(raw_header: &str, file_size: u64) -> ApiResult<ByteRange> {
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

pub(super) fn build_not_modified(etag: Option<&str>, last_modified: Option<&str>) -> ApiResult<axum::response::Response> {
    let mut builder = axum::response::Response::builder().status(StatusCode::NOT_MODIFIED);
    if let Some(tag) = etag {
        builder = builder.header(header::ETAG, tag);
    }
    if let Some(lm) = last_modified {
        builder = builder.header(header::LAST_MODIFIED, lm);
    }
    builder
        .body(axum::body::Body::empty())
        .map_err(|_| ApiError::internal("Failed to build 304 response."))
}

pub(super) fn build_range_not_satisfiable(
    file_size: u64,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> ApiResult<axum::response::Response> {
    let mut builder = axum::response::Response::builder()
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
        .body(axum::body::Body::empty())
        .map_err(|_| ApiError::internal("Failed to build 416 response."))
}
