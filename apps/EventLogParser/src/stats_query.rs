use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct StatsQuery {
    pub ingest_path: Option<String>,
}
