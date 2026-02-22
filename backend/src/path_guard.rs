use crate::errors::{ApiError, ApiResult};
use std::path::{Component, Path, PathBuf};

pub const PRIVATE_MARKER_FILE: &str = ".private";
pub const PASSWORD_MARKER_FILE: &str = ".password";

pub fn is_private_marker_name(name: &str) -> bool {
    matches!(name, PRIVATE_MARKER_FILE | PASSWORD_MARKER_FILE)
}

pub fn normalize_relative_path(raw: Option<&str>) -> ApiResult<String> {
    let path = raw.unwrap_or_default().trim();
    if path.is_empty() || path == "/" {
        return Ok(String::new());
    }

    if path.starts_with('/') {
        return Err(ApiError::bad_request("Path must be relative."));
    }

    if path.contains('\\') {
        return Err(ApiError::bad_request("Backslash is not allowed in path."));
    }

    let mut segments = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ApiError::bad_request("Invalid path segment."));
        }
        if segment.chars().any(|c| c.is_control()) {
            return Err(ApiError::bad_request(
                "Path contains disallowed control characters.",
            ));
        }
        segments.push(segment);
    }

    Ok(segments.join("/"))
}

pub fn ensure_not_marker_path(path: &str) -> ApiResult<()> {
    if path.rsplit('/').next().is_some_and(is_private_marker_name) {
        return Err(ApiError::not_found("File not found."));
    }
    Ok(())
}

pub async fn resolve_existing_path(root: &Path, relative_path: &str) -> ApiResult<PathBuf> {
    check_symlink_segments(root, relative_path).await?;

    let candidate = if relative_path.is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative_path)
    };

    let candidate_meta = tokio::fs::symlink_metadata(&candidate)
        .await
        .map_err(|err| ApiError::from_io(err, "path"))?;

    if candidate_meta.file_type().is_symlink() {
        return Err(ApiError::forbidden("Symbolic links are not allowed."));
    }

    let canonical = tokio::fs::canonicalize(&candidate)
        .await
        .map_err(|err| ApiError::from_io(err, "path"))?;

    if !canonical.starts_with(root) {
        return Err(ApiError::forbidden(
            "Path escapes configured root directory.",
        ));
    }

    Ok(canonical)
}

pub fn relative_string_from_root(root: &Path, absolute_path: &Path) -> ApiResult<String> {
    let stripped = absolute_path
        .strip_prefix(root)
        .map_err(|_| ApiError::forbidden("Path is outside configured root directory."))?;

    if stripped.as_os_str().is_empty() {
        return Ok(String::new());
    }

    let mut parts = Vec::new();
    for component in stripped.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().to_string()),
            _ => return Err(ApiError::forbidden("Invalid path component.")),
        }
    }

    Ok(parts.join("/"))
}

async fn check_symlink_segments(root: &Path, relative_path: &str) -> ApiResult<()> {
    if relative_path.is_empty() {
        return Ok(());
    }

    let mut cursor = root.to_path_buf();
    for segment in relative_path.split('/') {
        cursor.push(segment);
        let metadata = tokio::fs::symlink_metadata(&cursor)
            .await
            .map_err(|err| ApiError::from_io(err, "path"))?;
        if metadata.file_type().is_symlink() {
            return Err(ApiError::forbidden("Symbolic links are not allowed."));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::normalize_relative_path;

    #[test]
    fn normalize_accepts_root() {
        assert_eq!(normalize_relative_path(Some("")).unwrap(), "");
        assert_eq!(normalize_relative_path(Some("/")).unwrap(), "");
        assert_eq!(normalize_relative_path(None).unwrap(), "");
    }

    #[test]
    fn normalize_rejects_traversal() {
        assert!(normalize_relative_path(Some("../a")).is_err());
        assert!(normalize_relative_path(Some("a/../b")).is_err());
        assert!(normalize_relative_path(Some("a//b")).is_err());
        assert!(normalize_relative_path(Some("/etc/passwd")).is_err());
    }

    #[test]
    fn normalize_rejects_windows_style() {
        assert!(normalize_relative_path(Some(r"a\b")).is_err());
    }

    #[test]
    fn normalize_keeps_valid_path() {
        assert_eq!(
            normalize_relative_path(Some("movies/2026/trailer.mp4")).unwrap(),
            "movies/2026/trailer.mp4"
        );
    }
}
