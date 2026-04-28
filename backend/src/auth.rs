use std::path::{Path, PathBuf};

use tokio::fs;

use crate::errors::{ApiError, ApiResult};
use crate::path_guard::{PRIVATE_MARKER_FILE, relative_string_from_root};

#[derive(Debug, Clone)]
pub struct PrivateAnchor {
    pub scope_rel: String,
    pub marker_file: &'static str,
}

pub async fn find_private_anchor(
    root: &Path,
    target_path: &Path,
    target_is_dir: bool,
) -> ApiResult<Option<PrivateAnchor>> {
    if !target_path.starts_with(root) {
        return Err(ApiError::forbidden(
            "Path is outside configured root directory.",
        ));
    }

    let mut current = if target_is_dir {
        target_path.to_path_buf()
    } else {
        target_path.parent().unwrap_or(root).to_path_buf()
    };

    loop {
        if marker_exists(&current, PRIVATE_MARKER_FILE).await? {
            return Ok(Some(PrivateAnchor {
                scope_rel: relative_string_from_root(root, &current)?,
                marker_file: PRIVATE_MARKER_FILE,
            }));
        }

        if current == root {
            break;
        }

        current = parent_within_root(&current, root)?;
    }

    Ok(None)
}

pub async fn has_private_hide_marker(dir: &Path) -> ApiResult<bool> {
    marker_exists(dir, PRIVATE_MARKER_FILE).await
}

fn parent_within_root(current: &Path, root: &Path) -> ApiResult<PathBuf> {
    let parent = current
        .parent()
        .ok_or_else(|| ApiError::forbidden("Path is outside configured root directory."))?;

    if !parent.starts_with(root) {
        return Err(ApiError::forbidden(
            "Path is outside configured root directory.",
        ));
    }

    Ok(parent.to_path_buf())
}

async fn marker_exists(dir: &Path, marker_name: &'static str) -> ApiResult<bool> {
    let marker_path = dir.join(marker_name);
    let metadata = match fs::symlink_metadata(&marker_path).await {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(ApiError::from_io(err, "marker file")),
    };

    if metadata.file_type().is_symlink() {
        return Err(ApiError::forbidden(
            "Private marker file cannot be a symbolic link.",
        ));
    }

    if !metadata.is_file() {
        return Err(ApiError::forbidden(
            "Private marker file must be a regular file.",
        ));
    }

    Ok(true)
}
