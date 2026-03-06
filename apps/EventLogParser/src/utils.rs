use config::{Config, Environment, File};
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub db_path: String,
    pub bind_addr: String,
    pub ingest_threads: usize,
    pub page_limit: usize,
    pub stats_limit: usize,
    pub sqlite_busy_timeout_secs: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            db_path: "events.db".to_string(),
            bind_addr: "0.0.0.0:8080".to_string(),
            ingest_threads: 0,
            page_limit: 500,
            stats_limit: 50,
            sqlite_busy_timeout_secs: 30,
        }
    }
}

pub fn load_config() -> AppConfig {
    dotenvy::dotenv().ok();
    let builder = Config::builder()
        .add_source(File::with_name("config").required(false))
        .add_source(File::with_name("config.local").required(false))
        .add_source(Environment::with_prefix("EVTX").separator("__"))
        .set_default("db_path", AppConfig::default().db_path)
        .unwrap()
        .set_default("bind_addr", AppConfig::default().bind_addr)
        .unwrap()
        .set_default("ingest_threads", AppConfig::default().ingest_threads as i64)
        .unwrap()
        .set_default("page_limit", AppConfig::default().page_limit as i64)
        .unwrap()
        .set_default("stats_limit", AppConfig::default().stats_limit as i64)
        .unwrap()
        .set_default(
            "sqlite_busy_timeout_secs",
            AppConfig::default().sqlite_busy_timeout_secs as i64,
        )
        .unwrap();

    builder
        .build()
        .ok()
        .and_then(|c| c.try_deserialize::<AppConfig>().ok())
        .unwrap_or_default()
}

pub fn clamp_limit(input: Option<usize>, max: usize) -> usize {
    input.unwrap_or(max).clamp(1, max)
}

pub fn sqlite_busy_timeout(config: &AppConfig) -> Duration {
    Duration::from_secs(config.sqlite_busy_timeout_secs)
}
