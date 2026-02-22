use serde::Deserialize;
use std::{env, fs, path::PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub root_dir: PathBuf,
    pub bind_addr: String,
    pub session_ttl_seconds: u64,
    pub secure_cookies: bool,
    pub login_max_failures: u32,
    pub login_block_seconds: u64,
    pub content_security_policy: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from("/tmp/mlist-files"),
            bind_addr: "0.0.0.0:3000".to_string(),
            session_ttl_seconds: 1800,
            secure_cookies: false,
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
        let config_path = env::var("MLIST_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
        let raw = fs::read_to_string(&config_path)
            .map_err(|err| format!("Failed to read config file {config_path}: {err}"))?;
        let mut cfg: AppConfig = toml::from_str(&raw)
            .map_err(|err| format!("Failed to parse config file {config_path}: {err}"))?;

        if !cfg.root_dir.is_absolute() {
            return Err("root_dir must be an absolute path.".to_string());
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
}
