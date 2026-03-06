mod detection;
mod search;

use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use detection::{
    DeleteRuleResponse, DetectionError, ExportHitsRequest, ExportHitsResponse, ListHitsQuery, ListHitsResponse, MarkFalsePositiveRequest,
    MarkFalsePositiveResponse, PersistedRule, RunDetectionsRequest, RunDetectionsResponse,
    UpsertRuleRequest, disable_rule, export_hits_csv, list_hits, list_rules, mark_false_positive, run_and_store_detections,
    upsert_rule,
};
use search::{
    ContextRequest, ContextResponse, SearchError, SearchRequest, SearchResponse, fetch_context,
    execute_search, execute_ip_summary, IpSummaryResponse,
};
use std::{
    env,
    fs::{self, OpenOptions},
    net::SocketAddr,
    path::PathBuf,
};
use tokio::task;
use tower_http::{services::ServeDir, trace::TraceLayer};
use tracing::Level;

#[tokio::main]
async fn main() {
    init_tracing();

    if let Err(err) = run().await {
        tracing::error!(error = %err, "server exited with error");
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let static_dir = ServeDir::new("web").append_index_html_on_directories(true);
    let exports_path = resolve_exports_dir();
    let exports_dir = ServeDir::new(exports_path.clone());
    tracing::info!(exports_dir = %exports_path.display(), "serving exports directory");

    let app = Router::new()
        .route("/healthz", get(health_check))
        .route("/detection", get(detection_page))
        .route("/search", post(search_handler))
        .route("/ip_summary", post(ip_summary_handler))
        .route("/context", post(context_handler))
        .route("/detections/run", post(detections_run_handler))
        .route("/detections/rules", get(detections_rules_handler))
        .route("/detections/rules", post(detections_upsert_rule_handler))
        .route(
            "/detections/rules/:id/delete",
            post(detections_delete_rule_handler),
        )
        .route("/detections/hits", get(detections_hits_handler))
        .route("/detections/export", post(detections_export_handler))
        .route(
            "/detections/hits/:id/false_positive",
            post(detections_false_positive_handler),
        )
        .nest_service("/exports", exports_dir)
        .fallback_service(static_dir)
        .layer(TraceLayer::new_for_http());

    let addr = bind_address();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_check() -> &'static str {
    "ok"
}

async fn detection_page() -> Html<&'static str> {
    Html(include_str!("../web/detection.html"))
}

async fn search_handler(
    Json(payload): Json<SearchRequest>,
) -> Result<Json<SearchResponse>, ApiError> {
    let query = payload.into_query().map_err(ApiError::from)?;
    let response = task::spawn_blocking(move || execute_search(query))
        .await
        .map_err(|err| ApiError::internal(format!("search task failed: {err}")))??;
    Ok(Json(response))
}

async fn context_handler(
    Json(payload): Json<ContextRequest>,
) -> Result<Json<ContextResponse>, ApiError> {
    let response = fetch_context(payload).map_err(ApiError::from)?;
    Ok(Json(response))
}

async fn ip_summary_handler(
    Json(payload): Json<SearchRequest>,
) -> Result<Json<IpSummaryResponse>, ApiError> {
    let query = payload.into_query().map_err(ApiError::from)?;
    let response = task::spawn_blocking(move || execute_ip_summary(query))
        .await
        .map_err(|err| ApiError::internal(format!("ip summary task failed: {err}")))??;
    Ok(Json(response))
}

async fn detections_run_handler(
    Json(payload): Json<RunDetectionsRequest>,
) -> Result<Json<RunDetectionsResponse>, ApiError> {
    let response = task::spawn_blocking(move || run_and_store_detections(payload))
        .await
        .map_err(|err| ApiError::internal(format!("detections task failed: {err}")))??;
    Ok(Json(response))
}

async fn detections_rules_handler() -> Result<Json<Vec<PersistedRule>>, ApiError> {
    let response = task::spawn_blocking(list_rules)
        .await
        .map_err(|err| ApiError::internal(format!("list rules task failed: {err}")))??;
    Ok(Json(response))
}

async fn detections_upsert_rule_handler(
    Json(payload): Json<UpsertRuleRequest>,
) -> Result<Json<PersistedRule>, ApiError> {
    let response = task::spawn_blocking(move || upsert_rule(payload))
        .await
        .map_err(|err| ApiError::internal(format!("upsert rule task failed: {err}")))??;
    Ok(Json(response))
}

async fn detections_delete_rule_handler(
    Path(id): Path<String>,
) -> Result<Json<DeleteRuleResponse>, ApiError> {
    let response = task::spawn_blocking(move || disable_rule(id))
        .await
        .map_err(|err| ApiError::internal(format!("delete rule task failed: {err}")))??;
    Ok(Json(response))
}

async fn detections_hits_handler(
    Query(query): Query<ListHitsQuery>,
) -> Result<Json<ListHitsResponse>, ApiError> {
    let response = task::spawn_blocking(move || list_hits(query))
        .await
        .map_err(|err| ApiError::internal(format!("list hits task failed: {err}")))??;
    Ok(Json(response))
}

async fn detections_false_positive_handler(
    Path(id): Path<i64>,
    Json(payload): Json<MarkFalsePositiveRequest>,
) -> Result<Json<MarkFalsePositiveResponse>, ApiError> {
    let response = task::spawn_blocking(move || mark_false_positive(id, payload))
        .await
        .map_err(|err| ApiError::internal(format!("false-positive task failed: {err}")))??;
    Ok(Json(response))
}

async fn detections_export_handler(
    Json(payload): Json<ExportHitsRequest>,
) -> Result<Json<ExportHitsResponse>, ApiError> {
    let response = task::spawn_blocking(move || export_hits_csv(payload))
        .await
        .map_err(|err| ApiError::internal(format!("detections export task failed: {err}")))??;
    Ok(Json(response))
}

fn bind_address() -> SocketAddr {
    env::var("BIND_ADDRESS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 8800)))
}

fn resolve_exports_dir() -> PathBuf {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let preferred = cwd.join("exports");
    if ensure_writable_directory(&preferred) {
        return preferred;
    }

    let fallback = cwd.join("exports_local");
    if ensure_writable_directory(&fallback) {
        tracing::warn!(
            preferred = %preferred.display(),
            fallback = %fallback.display(),
            "exports directory is not writable; using fallback directory"
        );
        return fallback;
    }

    preferred
}

fn ensure_writable_directory(path: &PathBuf) -> bool {
    if fs::create_dir_all(path).is_err() {
        return false;
    }

    let probe = path.join(".write_probe");
    match OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = fs::remove_file(probe);
            true
        }
        Err(_) => false,
    }
}

fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,axum=info,tower_http=info"));
    let _ = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_env_filter(env_filter)
        .try_init();
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.message });
        (self.status, Json(body)).into_response()
    }
}

impl From<SearchError> for ApiError {
    fn from(err: SearchError) -> Self {
        match err {
            SearchError::InvalidRoot(message) => ApiError::new(StatusCode::BAD_REQUEST, message),
            SearchError::InvalidRule(message) => ApiError::new(StatusCode::BAD_REQUEST, message),
            SearchError::Io { path, source } => ApiError::internal(format!(
                "I/O error while reading {}: {source}",
                path.display()
            )),
            SearchError::OutsideRoot(path) => ApiError::new(
                StatusCode::BAD_REQUEST,
                format!("file outside root: {path}"),
            ),
            SearchError::WalkDir(inner) => {
                ApiError::internal(format!("failed to traverse directories: {inner}"))
            }
            SearchError::Csv { path, source } => ApiError::internal(format!(
                "failed to write CSV export {}: {source}",
                path.display()
            )),
            SearchError::ExportLock => {
                ApiError::internal("failed to acquire lock for CSV export writer")
            }
            SearchError::Regex(err) => {
                ApiError::internal(format!("regex construction failed: {err}"))
            }
        }
    }
}

impl From<DetectionError> for ApiError {
    fn from(err: DetectionError) -> Self {
        match err {
            DetectionError::Search(inner) => ApiError::from(inner),
            DetectionError::InvalidRequest(message) => {
                ApiError::new(StatusCode::BAD_REQUEST, message)
            }
            DetectionError::InvalidCursor => {
                ApiError::new(StatusCode::BAD_REQUEST, "invalid cursor")
            }
            DetectionError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "record not found"),
            DetectionError::Db(inner) => ApiError::internal(format!("database error: {inner}")),
            DetectionError::Serde(inner) => {
                ApiError::new(StatusCode::BAD_REQUEST, format!("serialization error: {inner}"))
            }
            DetectionError::Io(inner) => ApiError::internal(format!("I/O error: {inner}")),
            DetectionError::Csv(inner) => ApiError::internal(format!("CSV error: {inner}")),
        }
    }
}
