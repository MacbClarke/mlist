use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use tokio::fs;
use tracing::info;

use crate::auth::{find_private_anchor, has_private_hide_marker};
use crate::db::{AuthSession, UserFavoriteView, UserFileStateView};
use crate::errors::{ApiError, ApiResult};
use crate::path_guard::{ensure_not_marker_path, normalize_relative_path, resolve_existing_path};
use crate::session::now_unix;

use super::files::ensure_file_accessible;
use super::helpers::{file_name_is_marker, require_session};
use super::types::{
    AppState, FavoriteRequest, FavoritesResponse, FileStateRequest, FileStatesResponse,
};

pub async fn file_states_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<FileStatesResponse>> {
    let session = require_session(&state, &headers).await?;
    Ok(Json(FileStatesResponse {
        files: state.db.list_highlighted_files(session.user.id).await?,
    }))
}

pub async fn set_file_state_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<FileStateRequest>,
) -> ApiResult<Json<UserFileStateView>> {
    let session = require_session(&state, &headers).await?;
    let path = normalize_relative_path(Some(&payload.path))?;
    ensure_file_accessible(&state, &session, &path).await?;

    Ok(Json(
        state
            .db
            .set_file_highlighted(session.user.id, &path, payload.highlighted)
            .await?,
    ))
}

pub async fn favorites_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<FavoritesResponse>> {
    let session = require_session(&state, &headers).await?;
    let favorites = state.db.list_favorites(session.user.id).await?;

    let mut valid = Vec::with_capacity(favorites.len());
    for fav in favorites {
        if favorite_path_valid(&state, &session, &fav.path).await {
            valid.push(fav);
        } else {
            state.db.delete_favorite(session.user.id, &fav.path).await?;
        }
    }

    Ok(Json(FavoritesResponse { paths: valid }))
}

pub async fn set_favorite_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<FavoriteRequest>,
) -> ApiResult<Json<UserFavoriteView>> {
    let session = require_session(&state, &headers).await?;
    let path = normalize_relative_path(Some(&payload.path))?;
    ensure_path_favorite_accessible(&state, &session, &path).await?;

    let now = now_unix() as i64;
    state
        .db
        .set_file_favorite(session.user.id, &path, payload.favorite)
        .await?;

    Ok(Json(UserFavoriteView { path, created_at: now }))
}

async fn ensure_path_favorite_accessible(
    state: &AppState,
    session: &AuthSession,
    relative_path: &str,
) -> ApiResult<()> {
    ensure_not_marker_path(relative_path)?;
    if relative_path.is_empty() {
        return Err(ApiError::bad_request("Path must reference a file or directory."));
    }

    let root = &state.config.root_dir;
    let resolved = resolve_existing_path(root, relative_path).await?;
    let metadata = fs::metadata(&resolved)
        .await
        .map_err(|err| ApiError::from_io(err, "path"))?;
    if !metadata.is_dir() && !metadata.is_file() {
        return Err(ApiError::bad_request("Path is neither a file nor a directory."));
    }

    if file_name_is_marker(&resolved) {
        return Err(ApiError::not_found("Path not found."));
    }

    if metadata.is_dir()
        && has_private_hide_marker(&resolved).await?
        && !session.user.role.is_admin()
    {
        return Err(ApiError::not_found("Path not found."));
    }

    if let Some(anchor) = find_private_anchor(root, &resolved, metadata.is_dir()).await? {
        if !session.user.role.is_admin() {
            info!(
                user = session.user.username,
                scope = anchor.scope_rel,
                marker = anchor.marker_file,
                "non-admin favorite path access denied"
            );
            return Err(ApiError::not_found("Path not found."));
        }
    }

    Ok(())
}

async fn favorite_path_valid(
    state: &AppState,
    session: &AuthSession,
    relative_path: &str,
) -> bool {
    if ensure_not_marker_path(relative_path).is_err() || relative_path.is_empty() {
        return false;
    }
    let root = &state.config.root_dir;
    let resolved = match resolve_existing_path(root, relative_path).await {
        Ok(p) => p,
        Err(_) => return false,
    };
    let metadata = match fs::metadata(&resolved).await {
        Ok(m) => m,
        Err(_) => return false,
    };
    if !metadata.is_dir() && !metadata.is_file() {
        return false;
    }
    if file_name_is_marker(&resolved) {
        return false;
    }
    if metadata.is_dir() {
        match has_private_hide_marker(&resolved).await {
            Ok(true) if !session.user.role.is_admin() => return false,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    match find_private_anchor(root, &resolved, metadata.is_dir()).await {
        Ok(Some(_)) => session.user.role.is_admin(),
        Ok(None) => true,
        Err(_) => false,
    }
}
