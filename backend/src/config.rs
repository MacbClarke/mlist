use std::{env, fs, path::PathBuf};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub root_dir: PathBuf,
    pub database_path: PathBuf,
    pub bind_addr: String,
    pub session_ttl_seconds: u64,
    pub signed_file_link_ttl_seconds: u64,
    pub login_max_failures: u32,
    pub login_block_seconds: u64,
    pub content_security_policy: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from("/mlist-files"),
            database_path: PathBuf::from("/mlist-data/mlist.sqlite3"),
            bind_addr: "0.0.0.0:3000".to_string(),
            session_ttl_seconds: 2_592_000,
            signed_file_link_ttl_seconds: 604_800,
            login_max_failures: 5,
            login_block_seconds: 60,
            content_security_policy:
                "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; object-src 'none'; frame-ancestors 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
                    .to_string(),
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, String> {
        let mut cfg = AppConfig::default();
        cfg.apply_env()?;

        if !cfg.root_dir.is_absolute() {
            return Err("MLIST_ROOT_DIR must be an absolute path.".to_string());
        }
        if !cfg.database_path.is_absolute() {
            return Err("MLIST_DATABASE_PATH must be an absolute path.".to_string());
        }

        let canonical_root = fs::canonicalize(&cfg.root_dir).map_err(|err| {
            format!(
                "Failed to canonicalize root_dir {}: {err}",
                cfg.root_dir.display()
            )
        })?;

        let metadata = fs::metadata(&canonical_root).map_err(|err| {
            format!(
                "Failed to read metadata for root_dir {}: {err}",
                canonical_root.display()
            )
        })?;

        if !metadata.is_dir() {
            return Err(format!(
                "Configured root_dir {} is not a directory.",
                canonical_root.display()
            ));
        }

        cfg.root_dir = canonical_root;
        Ok(cfg)
    }

    fn apply_env(&mut self) -> Result<(), String> {
        if let Some(value) = read_env_path("MLIST_ROOT_DIR")? {
            self.root_dir = value;
        }
        if let Some(value) = read_env_path("MLIST_DATABASE_PATH")? {
            self.database_path = value;
        }
        if let Some(value) = read_env_string("MLIST_BIND_ADDR")? {
            self.bind_addr = value;
        }
        if let Some(value) = read_env_u64("MLIST_SESSION_TTL_SECONDS")? {
            self.session_ttl_seconds = value;
        }
        if let Some(value) = read_env_u64("MLIST_SIGNED_FILE_LINK_TTL_SECONDS")? {
            self.signed_file_link_ttl_seconds = value;
        }
        if let Some(value) = read_env_u32("MLIST_LOGIN_MAX_FAILURES")? {
            self.login_max_failures = value;
        }
        if let Some(value) = read_env_u64("MLIST_LOGIN_BLOCK_SECONDS")? {
            self.login_block_seconds = value;
        }
        if let Some(value) = read_env_string("MLIST_CONTENT_SECURITY_POLICY")? {
            self.content_security_policy = value;
        }
        Ok(())
    }
}

fn read_env_path(name: &'static str) -> Result<Option<PathBuf>, String> {
    Ok(read_env_string(name)?.map(PathBuf::from))
}

fn read_env_string(name: &'static str) -> Result<Option<String>, String> {
    let Ok(raw) = env::var(name) else {
        return Ok(None);
    };
    let value = raw.trim();
    if value.is_empty() {
        return Err(format!("{name} must not be empty."));
    }
    Ok(Some(value.to_string()))
}

fn read_env_u32(name: &'static str) -> Result<Option<u32>, String> {
    let Ok(raw) = env::var(name) else {
        return Ok(None);
    };
    let value = raw
        .trim()
        .parse::<u32>()
        .map_err(|_| format!("{name} must be an unsigned integer number."))?;
    if value == 0 {
        return Err(format!("{name} must be greater than zero."));
    }
    Ok(Some(value))
}

fn read_env_u64(name: &'static str) -> Result<Option<u64>, String> {
    let Ok(raw) = env::var(name) else {
        return Ok(None);
    };
    let value = raw
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("{name} must be an unsigned integer number of seconds."))?;
    if value == 0 {
        return Err(format!("{name} must be greater than zero."));
    }
    Ok(Some(value))
}
