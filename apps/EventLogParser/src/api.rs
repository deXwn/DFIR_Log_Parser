use crate::db;
use crate::error::AppError;
use crate::ingest::{self, IngestStats};
use crate::models::{
    AggregatedLogon, CorrelatedLogon, Event, EventQuery, IngestRequest, IngestResponse,
    ListEvtxFile, ListEvtxRequest, ListEvtxResponse, Paginated, ReportRequest, ReportResponse, SearchQuery,
    StatsResponse, SuspiciousEvent, TimelineBucket, TimelineQuery, DeleteRequest, DeleteResponse,
    DetectionMatch, CustomReportRequest, CustomReportResponse, CustomReportHtmlResponse,
};
use crate::state::AppState;
use crate::stats_query::StatsQuery;
use crate::utils::clamp_limit;
use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use std::path::PathBuf;
use std::thread;
use tokio::task;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(root_handler))
        .route("/ingest", post(ingest_handler))
        .route("/list-evtx", post(list_evtx_handler))
        .route("/events", get(events_handler))
        .route("/search", get(search_handler))
        .route("/stats", get(stats_handler))
        .route("/timeline", get(timeline_handler))
        .route("/event/:id", get(event_handler))
        .route("/logon-failures", get(logon_failures_handler))
        .route("/logon-success", get(logon_success_handler))
        .route("/suspicious", get(suspicious_handler))
        .route("/correlate/4624-4625", get(correlate_handler))
        .route("/delete", post(delete_handler))
        .route("/report", post(report_handler))
        .route("/reports/custom/html", post(custom_report_html_handler))
        .route("/reports/custom", post(custom_report_handler))
        .route("/processes", get(processes_handler))
        .route("/detections", get(detections_handler))
        .with_state(state)
}

async fn root_handler() -> &'static str {
    "EventLogParser API is running. UI: http://localhost:3000"
}

async fn ingest_handler(
    State(state): State<AppState>,
    Json(body): Json<IngestRequest>,
) -> Result<Json<IngestResponse>, AppError> {
    let path = PathBuf::from(&body.path);
    if !path.exists() || !path.is_file() {
        return Err(AppError::NotFound(format!(
            "EVTX file not found at {}",
            path.display()
        )));
    }

    let threads = match body.threads {
        Some(t) if t > 0 => t,
        _ if state.config.ingest_threads > 0 => state.config.ingest_threads,
        _ => thread::available_parallelism()
            .ok()
            .map(|v| v.get())
            .unwrap_or(4),
    };

    let channel_hint = body.channel.clone();
    let pool = state.db.clone();
    let log_path = path.clone();

    let stats: IngestStats = task::spawn_blocking(move || ingest::ingest_file(&path, pool, threads, channel_hint))
        .await
        .map_err(|e| AppError::Join(e.to_string()))??;

    tracing::info!(
        "ingest complete for {} => parsed {} inserted {}",
        log_path.display(),
        stats.parsed,
        stats.ingested
    );

    Ok(Json(IngestResponse {
        path: body.path,
        ingested: stats.ingested,
        duration_ms: stats.duration_ms,
        threads,
        parsed: stats.parsed,
    }))
}

async fn delete_handler(
    State(state): State<AppState>,
    Json(body): Json<DeleteRequest>,
) -> Result<Json<DeleteResponse>, AppError> {
    let pool = state.db.clone();
    let deleted = task::spawn_blocking(move || db::delete_events(&pool, &body))
        .await
        .map_err(|e| AppError::Join(e.to_string()))??;
    Ok(Json(DeleteResponse { deleted }))
}

async fn report_handler(
    State(state): State<AppState>,
    Json(body): Json<ReportRequest>,
) -> Result<Json<ReportResponse>, AppError> {
    let pool = state.db.clone();
    let report = task::spawn_blocking(move || db::generate_report(&pool, &body))
        .await
        .map_err(|e| AppError::Join(e.to_string()))??;
    Ok(Json(report))
}

async fn custom_report_handler(
    State(state): State<AppState>,
    Json(req): Json<CustomReportRequest>,
) -> Result<Json<CustomReportResponse>, AppError> {
    let pool = state.db.clone();
    let resp = task::spawn_blocking(move || db::generate_custom_report(&pool, &req))
        .await
        .map_err(|e| AppError::Join(e.to_string()))??;
    Ok(Json(resp))
}

async fn custom_report_html_handler(
    State(state): State<AppState>,
    Json(req): Json<CustomReportRequest>,
) -> Result<Json<CustomReportHtmlResponse>, AppError> {
    let pool = state.db.clone();
    let resp = task::spawn_blocking(move || db::generate_custom_report_html(&pool, &req))
        .await
        .map_err(|e| AppError::Join(e.to_string()))??;
    Ok(Json(resp))
}

async fn detections_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<DetectionMatch>>, AppError> {
    let pool = state.db.clone();
    let rules_path = std::env::var("DETECTION_RULES_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("rules/detections.yml"));

    let detections =
        task::spawn_blocking(move || db::run_detections(&pool, &rules_path))
            .await
            .map_err(|e| AppError::Join(e.to_string()))??;
    Ok(Json(detections))
}

async fn list_evtx_handler(
    State(_state): State<AppState>,
    Json(body): Json<ListEvtxRequest>,
) -> Result<Json<ListEvtxResponse>, AppError> {
    let raw_path = std::path::PathBuf::from(&body.path);
    let resolved = if raw_path.is_absolute() {
        raw_path
    } else {
        std::env::current_dir()
            .map_err(|e| AppError::BadRequest(format!("cannot read current dir: {e}")))?
            .join(raw_path)
    };
    let canonical = resolved
        .canonicalize()
        .map_err(|e| AppError::NotFound(format!("path not found: {} ({e})", resolved.display())))?;

    if !canonical.is_dir() {
        return Err(AppError::NotFound(format!(
            "Directory not found at {}",
            canonical.display()
        )));
    }

    let dir = canonical.clone();
    let files = tokio::task::spawn_blocking(move || -> Result<Vec<ListEvtxFile>, AppError> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let p = entry.path();
                if p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|s| s.eq_ignore_ascii_case("evtx"))
                    .unwrap_or(false)
                {
                    entries.push(ListEvtxFile {
                        path: p.to_string_lossy().to_string(),
                        size_bytes: entry.metadata()?.len(),
                    });
                }
            }
        }
        entries.sort_by(|a, b| {
            b.size_bytes
                .cmp(&a.size_bytes)
                .then_with(|| a.path.cmp(&b.path))
        });
        Ok(entries)
    })
    .await
    .map_err(|e| AppError::Join(e.to_string()))??;

    Ok(Json(ListEvtxResponse {
        path: canonical.to_string_lossy().to_string(),
        files,
    }))
}

async fn events_handler(
    State(state): State<AppState>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Paginated<Event>>, AppError> {
    let limit = clamp_limit(query.limit, state.config.page_limit);
    let offset = query.offset.unwrap_or(0);
    let pool = state.db.clone();
    let events = task::spawn_blocking(move || {
        db::fetch_events(
            &pool,
            query.event_id,
            query.channel,
            query.user,
            query.sid,
            query.ip,
            query.keyword,
            query.exclude,
            query.from,
            query.to,
            limit,
            offset,
        )
    })
        .await
        .map_err(|e| AppError::Join(e.to_string()))??;

    Ok(Json(Paginated {
        data: events,
        limit,
        offset,
    }))
}

async fn processes_handler(
    State(state): State<AppState>,
    Query(query): Query<crate::models::Paging>,
) -> Result<Json<Paginated<Event>>, AppError> {
    let limit = clamp_limit(query.limit, state.config.page_limit);
    let offset = query.offset.unwrap_or(0);
    let pool = state.db.clone();
    let events = task::spawn_blocking(move || db::fetch_process_events(&pool, limit, offset))
        .await
        .map_err(|e| AppError::Join(e.to_string()))??;

    Ok(Json(Paginated {
        data: events,
        limit,
        offset,
    }))
}

async fn search_handler(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Paginated<Event>>, AppError> {
    if query.query.trim().is_empty() {
        return Err(AppError::BadRequest("query cannot be empty".into()));
    }

    let limit = clamp_limit(query.limit, state.config.page_limit);
    let offset = query.offset.unwrap_or(0);
    let pool = state.db.clone();

    let events =
        task::spawn_blocking(move || {
            db::search_events(
                &pool,
                &query.query,
                limit,
                offset,
                query.logon_type,
                query.ip.clone(),
                query.exclude.clone(),
            )
        })
            .await
            .map_err(|e| AppError::Join(e.to_string()))??;

    Ok(Json(Paginated {
        data: events,
        limit,
        offset,
    }))
}

async fn stats_handler(
    State(state): State<AppState>,
    Query(q): Query<StatsQuery>,
) -> Result<Json<StatsResponse>, AppError> {
    let pool = state.db.clone();
    let limit = state.config.stats_limit;
    let stats = task::spawn_blocking(move || db::stats(&pool, limit, q.ingest_path.clone()))
        .await
        .map_err(|e| AppError::Join(e.to_string()))??;
    Ok(Json(stats))
}

async fn timeline_handler(
    State(state): State<AppState>,
    Query(q): Query<TimelineQuery>,
) -> Result<Json<Vec<TimelineBucket>>, AppError> {
    let from = parse_ts(&q.from)?;
    let to = parse_ts(&q.to)?;
    if to <= from {
        return Err(AppError::BadRequest("to must be after from".into()));
    }

    let bucket = q
        .bucket
        .as_deref()
        .map(|b| if b == "hour" { "hour" } else { "minute" })
        .unwrap_or("minute");

    let pool = state.db.clone();
    let ingest_path = q.ingest_path.clone();
    let buckets =
        task::spawn_blocking(move || db::timeline(&pool, &from, &to, bucket, ingest_path))
            .await
            .map_err(|e| AppError::Join(e.to_string()))??;
    Ok(Json(buckets))
}

async fn event_handler(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Event>, AppError> {
    let pool = state.db.clone();
    let event = task::spawn_blocking(move || db::get_event(&pool, id))
        .await
        .map_err(|e| AppError::Join(e.to_string()))??;
    Ok(Json(event))
}

async fn logon_failures_handler(
    State(state): State<AppState>,
    Query(p): Query<crate::models::Paging>,
) -> Result<Json<Paginated<AggregatedLogon>>, AppError> {
    let limit = clamp_limit(p.limit, state.config.page_limit);
    let offset = p.offset.unwrap_or(0);
    let pool = state.db.clone();
    let items = task::spawn_blocking(move || db::logon_failures(&pool, limit, offset))
        .await
        .map_err(|e| AppError::Join(e.to_string()))??;
    Ok(Json(Paginated {
        data: items,
        limit,
        offset,
    }))
}

async fn logon_success_handler(
    State(state): State<AppState>,
    Query(p): Query<crate::models::Paging>,
) -> Result<Json<Paginated<AggregatedLogon>>, AppError> {
    let limit = clamp_limit(p.limit, state.config.page_limit);
    let offset = p.offset.unwrap_or(0);
    let pool = state.db.clone();
    let items = task::spawn_blocking(move || db::logon_success(&pool, limit, offset))
        .await
        .map_err(|e| AppError::Join(e.to_string()))??;
    Ok(Json(Paginated {
        data: items,
        limit,
        offset,
    }))
}

async fn suspicious_handler(
    State(state): State<AppState>,
    Query(p): Query<crate::models::Paging>,
) -> Result<Json<Paginated<SuspiciousEvent>>, AppError> {
    let limit = clamp_limit(p.limit, state.config.page_limit);
    let offset = p.offset.unwrap_or(0);
    let pool = state.db.clone();
    let items = task::spawn_blocking(move || db::suspicious_events(&pool, limit, offset))
        .await
        .map_err(|e| AppError::Join(e.to_string()))??;
    Ok(Json(Paginated {
        data: items,
        limit,
        offset,
    }))
}

async fn correlate_handler(
    State(state): State<AppState>,
    Query(p): Query<crate::models::Paging>,
) -> Result<Json<Paginated<CorrelatedLogon>>, AppError> {
    let limit = clamp_limit(p.limit, state.config.page_limit);
    let offset = p.offset.unwrap_or(0);
    let pool = state.db.clone();
    let items = task::spawn_blocking(move || db::correlate_logons(&pool, limit, offset))
        .await
        .map_err(|e| AppError::Join(e.to_string()))??;
    Ok(Json(Paginated {
        data: items,
        limit,
        offset,
    }))
}

fn parse_ts(ts: &str) -> Result<String, AppError> {
    let parsed = chrono::DateTime::parse_from_rfc3339(ts)
        .map_err(|e| AppError::BadRequest(format!("invalid timestamp: {e}")))?;
    Ok(parsed.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::time::Duration;
    use tower::util::ServiceExt;

    fn memory_state() -> AppState {
        let manager = r2d2_sqlite::SqliteConnectionManager::memory()
            .with_init(|conn| {
                conn.busy_timeout(Duration::from_secs(5))?;
                conn.execute_batch("PRAGMA journal_mode=WAL;")?;
                Ok(())
            });
        let pool = r2d2::Pool::builder().max_size(2).build(manager).unwrap();
        db::init_schema(&pool).unwrap();

        let config = crate::utils::AppConfig {
            db_path: ":memory:".to_string(),
            bind_addr: "127.0.0.1:0".to_string(),
            ingest_threads: 0,
            page_limit: 100,
            stats_limit: 10,
            sqlite_busy_timeout_secs: 5,
        };

        AppState::new(pool, config)
    }

    fn seed_event(state: &AppState) {
        let conn = state.db.get().unwrap();
        conn.execute(
            "INSERT INTO events (event_id, timestamp, computer, channel, record_id, event_data_json, raw_xml)
             VALUES (4624, '2024-01-01T00:00:00Z', 'host', 'Security', 1, '{\"Event\":{}}', '<Event/>')",
            [],
        )
        .unwrap();
    }

    #[tokio::test]
    async fn stats_endpoint_returns_data() {
        let state = memory_state();
        seed_event(&state);
        let app = router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(response.status().is_success());
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert!(value.get("by_event_id").is_some());
    }
}
