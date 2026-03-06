use crate::db::DbPool;
use crate::utils::AppConfig;

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub config: AppConfig,
}

impl AppState {
    pub fn new(db: DbPool, config: AppConfig) -> Self {
        Self { db, config }
    }
}
