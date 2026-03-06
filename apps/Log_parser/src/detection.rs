use crate::search::{
    DetectionScanResponse, RuleFilter, RuleSeverity, SearchRequest, execute_detection_scan,
};
use csv::Writer;
use rusqlite::{Connection, OptionalExtension, Transaction, params, params_from_iter, types::Value};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const DEFAULT_DB_FILE: &str = "detections.sqlite";
const EXPORT_DIR: &str = "exports";
const EXPORT_FALLBACK_DIR: &str = "exports_local";

#[derive(Debug, Error)]
pub enum DetectionError {
    #[error(transparent)]
    Search(#[from] crate::search::SearchError),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
    #[error("{0}")]
    InvalidRequest(String),
    #[error("invalid cursor")]
    InvalidCursor,
    #[error("record not found")]
    NotFound,
}

#[derive(Debug, Deserialize)]
pub struct RunDetectionsRequest {
    #[serde(flatten)]
    pub search: SearchRequest,
}

#[derive(Debug, Serialize)]
pub struct RunDetectionsResponse {
    pub run_id: i64,
    pub total_hits: u64,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub duration_ms: u128,
}

#[derive(Debug, Serialize)]
pub struct PersistedRule {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub definition_json: String,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct DeleteRuleResponse {
    pub id: String,
    pub deleted: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpsertRuleRequest {
    pub rule: RuleFilter,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HitSortOrder {
    Asc,
    Desc,
}

impl Default for HitSortOrder {
    fn default() -> Self {
        HitSortOrder::Desc
    }
}

#[derive(Debug, Deserialize)]
pub struct ListHitsQuery {
    #[serde(default = "default_hits_page_size")]
    pub page_size: usize,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub sort_order: HitSortOrder,
    #[serde(default)]
    pub include_false_positives: bool,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct DetectionHitRecord {
    pub id: i64,
    pub run_id: i64,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub file_path: String,
    pub line_number: u64,
    pub byte_offset: u64,
    pub line: String,
    pub window_start: Option<i64>,
    pub window_end: Option<i64>,
    pub created_at: i64,
    pub false_positive: bool,
    pub false_positive_note: Option<String>,
    pub false_positive_marked_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ListHitsResponse {
    pub hits: Vec<DetectionHitRecord>,
    pub next_cursor: Option<String>,
    pub page_size: usize,
    pub sort_order: HitSortOrder,
}

#[derive(Debug, Deserialize)]
pub struct MarkFalsePositiveRequest {
    pub value: bool,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MarkFalsePositiveResponse {
    pub hit_id: i64,
    pub false_positive: bool,
}

#[derive(Debug, Deserialize)]
pub struct ExportHitsRequest {
    pub run_id: i64,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub include_false_positives: bool,
}

#[derive(Debug, Serialize)]
pub struct ExportHitsResponse {
    pub export_path: String,
    pub total_rows: u64,
    pub run_id: i64,
    pub rule_id: Option<String>,
}

#[derive(Clone)]
struct NormalizedRule {
    id: String,
    name: String,
    severity: RuleSeverity,
    definition_json: String,
}

#[derive(Clone, Copy)]
struct Cursor {
    created_at: i64,
    id: i64,
}

pub fn run_and_store_detections(
    request: RunDetectionsRequest,
) -> Result<RunDetectionsResponse, DetectionError> {
    let query = request.search.into_query()?;
    let normalized_rules = normalize_rules(&query.rules)?;
    if normalized_rules.is_empty() {
        return Err(DetectionError::InvalidRequest(
            "at least one rule is required".to_string(),
        ));
    }
    let root_path = query.root_path.display().to_string();
    let scan_result = execute_detection_scan(query)?;
    persist_detection_scan(&root_path, &normalized_rules, scan_result)
}

pub fn list_rules() -> Result<Vec<PersistedRule>, DetectionError> {
    let conn = open_connection()?;
    let mut stmt = conn.prepare(
        "SELECT id, name, severity, definition_json, enabled, created_at, updated_at
         FROM rules
         WHERE enabled = 1
         ORDER BY updated_at DESC, id DESC",
    )?;
    let rules = stmt
        .query_map([], |row| {
            Ok(PersistedRule {
                id: row.get(0)?,
                name: row.get(1)?,
                severity: row.get(2)?,
                definition_json: row.get(3)?,
                enabled: row.get::<_, i64>(4)? != 0,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rules)
}

pub fn disable_rule(id: String) -> Result<DeleteRuleResponse, DetectionError> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(DetectionError::InvalidRequest(
            "rule id cannot be empty".to_string(),
        ));
    }

    let conn = open_connection()?;
    let affected = conn.execute(
        "UPDATE rules
         SET enabled = 0, updated_at = ?
         WHERE id = ? AND enabled = 1",
        params![now_epoch_seconds(), trimmed],
    )?;

    if affected == 0 {
        return Err(DetectionError::NotFound);
    }

    Ok(DeleteRuleResponse {
        id: trimmed.to_string(),
        deleted: true,
    })
}

pub fn upsert_rule(request: UpsertRuleRequest) -> Result<PersistedRule, DetectionError> {
    let mut normalized = normalize_single_rule(&request.rule, 0)?;
    if normalized.id.is_empty() {
        return Err(DetectionError::InvalidRequest(
            "rule id cannot be empty".to_string(),
        ));
    }

    let mut conn = open_connection()?;
    let tx = conn.transaction()?;
    upsert_rule_in_tx(&tx, &normalized, request.enabled)?;
    let persisted = get_rule_in_tx(&tx, &normalized.id)?.ok_or(DetectionError::NotFound)?;
    tx.commit()?;

    // Keep compiler aware normalized is used mutably for future updates
    normalized.name = persisted.name.clone();
    Ok(persisted)
}

pub fn list_hits(query: ListHitsQuery) -> Result<ListHitsResponse, DetectionError> {
    let conn = open_connection()?;
    let mut sql = String::from(
        "SELECT id, run_id, rule_id, rule_name, severity, file_path, line_number, byte_offset, line, \
         window_start, window_end, created_at, false_positive, false_positive_note, false_positive_marked_at \
         FROM detection_hits WHERE 1=1",
    );

    let mut values: Vec<Value> = Vec::new();
    if !query.include_false_positives {
        sql.push_str(" AND false_positive = 0");
    }
    if let Some(run_id) = query.run_id {
        sql.push_str(" AND run_id = ?");
        values.push(Value::Integer(run_id));
    }
    if let Some(rule_id) = query.rule_id.as_deref() {
        sql.push_str(" AND rule_id = ?");
        values.push(Value::Text(rule_id.to_string()));
    }

    let cursor = query
        .cursor
        .as_deref()
        .map(parse_cursor)
        .transpose()?;
    if let Some(cursor) = cursor {
        match query.sort_order {
            HitSortOrder::Desc => {
                sql.push_str(" AND (created_at < ? OR (created_at = ? AND id < ?))");
                values.push(Value::Integer(cursor.created_at));
                values.push(Value::Integer(cursor.created_at));
                values.push(Value::Integer(cursor.id));
            }
            HitSortOrder::Asc => {
                sql.push_str(" AND (created_at > ? OR (created_at = ? AND id > ?))");
                values.push(Value::Integer(cursor.created_at));
                values.push(Value::Integer(cursor.created_at));
                values.push(Value::Integer(cursor.id));
            }
        }
    }

    let page_size = query.page_size.clamp(1, 200);
    match query.sort_order {
        HitSortOrder::Desc => sql.push_str(" ORDER BY created_at DESC, id DESC"),
        HitSortOrder::Asc => sql.push_str(" ORDER BY created_at ASC, id ASC"),
    }
    sql.push_str(" LIMIT ?");
    values.push(Value::Integer((page_size + 1) as i64));

    let mut stmt = conn.prepare(&sql)?;
    let mut hits = stmt
        .query_map(params_from_iter(values), |row| {
            Ok(DetectionHitRecord {
                id: row.get(0)?,
                run_id: row.get(1)?,
                rule_id: row.get(2)?,
                rule_name: row.get(3)?,
                severity: row.get(4)?,
                file_path: row.get(5)?,
                line_number: row.get::<_, i64>(6)? as u64,
                byte_offset: row.get::<_, i64>(7)? as u64,
                line: row.get(8)?,
                window_start: row.get(9)?,
                window_end: row.get(10)?,
                created_at: row.get(11)?,
                false_positive: row.get::<_, i64>(12)? != 0,
                false_positive_note: row.get(13)?,
                false_positive_marked_at: row.get(14)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let has_more = hits.len() > page_size;
    if has_more {
        hits.pop();
    }
    let next_cursor = if has_more {
        hits.last().map(|item| encode_cursor(Cursor {
            created_at: item.created_at,
            id: item.id,
        }))
    } else {
        None
    };

    Ok(ListHitsResponse {
        hits,
        next_cursor,
        page_size,
        sort_order: query.sort_order,
    })
}

pub fn mark_false_positive(
    hit_id: i64,
    request: MarkFalsePositiveRequest,
) -> Result<MarkFalsePositiveResponse, DetectionError> {
    let conn = open_connection()?;
    let affected = if request.value {
        conn.execute(
            "UPDATE detection_hits
             SET false_positive = 1, false_positive_note = ?, false_positive_marked_at = ?
             WHERE id = ?",
            params![request.note, now_epoch_seconds(), hit_id],
        )?
    } else {
        conn.execute(
            "UPDATE detection_hits
             SET false_positive = 0, false_positive_note = NULL, false_positive_marked_at = NULL
             WHERE id = ?",
            params![hit_id],
        )?
    };

    if affected == 0 {
        return Err(DetectionError::NotFound);
    }

    Ok(MarkFalsePositiveResponse {
        hit_id,
        false_positive: request.value,
    })
}

pub fn export_hits_csv(request: ExportHitsRequest) -> Result<ExportHitsResponse, DetectionError> {
    if request.run_id <= 0 {
        return Err(DetectionError::InvalidRequest(
            "run_id must be greater than zero".to_string(),
        ));
    }

    let export_dir = resolve_exports_dir();
    let timestamp = now_epoch_seconds();
    let rule_token = request
        .rule_id
        .as_deref()
        .map(sanitize_filename_token)
        .filter(|token| !token.is_empty())
        .unwrap_or_else(|| "all_rules".to_string());
    let file_name = format!("detection_{rule_token}_{timestamp}.csv");
    let file_path = export_dir.join(&file_name);

    let mut writer = Writer::from_path(&file_path)?;
    writer.write_record([
        "run_id",
        "hit_id",
        "rule_id",
        "rule_name",
        "severity",
        "file_path",
        "line_number",
        "byte_offset",
        "window_start",
        "window_end",
        "created_at",
        "false_positive",
        "false_positive_note",
        "false_positive_marked_at",
        "line",
    ])?;

    let conn = open_connection()?;
    let mut sql = String::from(
        "SELECT id, run_id, rule_id, rule_name, severity, file_path, line_number, byte_offset, \
         line, window_start, window_end, created_at, false_positive, false_positive_note, \
         false_positive_marked_at \
         FROM detection_hits WHERE run_id = ?",
    );
    let mut values: Vec<Value> = vec![Value::Integer(request.run_id)];

    if !request.include_false_positives {
        sql.push_str(" AND false_positive = 0");
    }
    if let Some(rule_id) = request.rule_id.as_deref() {
        let trimmed = rule_id.trim();
        if !trimmed.is_empty() {
            sql.push_str(" AND rule_id = ?");
            values.push(Value::Text(trimmed.to_string()));
        }
    }
    sql.push_str(" ORDER BY created_at DESC, id DESC");

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params_from_iter(values))?;
    let mut total_rows = 0u64;

    while let Some(row) = rows.next()? {
        let hit_id: i64 = row.get(0)?;
        let run_id: i64 = row.get(1)?;
        let rule_id: String = row.get(2)?;
        let rule_name: String = row.get(3)?;
        let severity: String = row.get(4)?;
        let file_path: String = row.get(5)?;
        let line_number: i64 = row.get(6)?;
        let byte_offset: i64 = row.get(7)?;
        let line: String = row.get(8)?;
        let window_start: Option<i64> = row.get(9)?;
        let window_end: Option<i64> = row.get(10)?;
        let created_at: i64 = row.get(11)?;
        let false_positive: i64 = row.get(12)?;
        let false_positive_note: Option<String> = row.get(13)?;
        let false_positive_marked_at: Option<i64> = row.get(14)?;

        writer.write_record([
            run_id.to_string(),
            hit_id.to_string(),
            rule_id,
            rule_name,
            severity,
            file_path,
            line_number.to_string(),
            byte_offset.to_string(),
            window_start.map(|v| v.to_string()).unwrap_or_default(),
            window_end.map(|v| v.to_string()).unwrap_or_default(),
            created_at.to_string(),
            (false_positive != 0).to_string(),
            false_positive_note.unwrap_or_default(),
            false_positive_marked_at
                .map(|v| v.to_string())
                .unwrap_or_default(),
            line,
        ])?;
        total_rows += 1;
    }

    writer.flush()?;

    Ok(ExportHitsResponse {
        export_path: format!("/exports/{file_name}"),
        total_rows,
        run_id: request.run_id,
        rule_id: request.rule_id,
    })
}

fn persist_detection_scan(
    root_path: &str,
    rules: &[NormalizedRule],
    scan: DetectionScanResponse,
) -> Result<RunDetectionsResponse, DetectionError> {
    let mut conn = open_connection()?;
    let tx = conn.transaction()?;

    let now = now_epoch_seconds();
    tx.execute(
        "INSERT INTO detection_runs (root_path, started_at, finished_at, total_hits)
         VALUES (?, ?, NULL, 0)",
        params![root_path, now],
    )?;
    let run_id = tx.last_insert_rowid();

    for rule in rules {
        upsert_rule_in_tx(&tx, rule, true)?;
    }

    let mut rule_index = std::collections::HashMap::new();
    for rule in rules {
        rule_index.insert(rule.id.as_str(), rule);
    }

    let mut insert_stmt = tx.prepare(
        "INSERT INTO detection_hits
         (run_id, rule_id, rule_name, severity, file_path, line_number, byte_offset, line,
          window_start, window_end, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )?;

    let mut total_hits = 0u64;
    for hit in &scan.matches {
        for rule_id in &hit.matched_rule_ids {
            let (rule_name, severity) = match rule_index.get(rule_id.as_str()) {
                Some(rule) => (rule.name.as_str(), severity_as_str(rule.severity)),
                None => (rule_id.as_str(), severity_as_str(RuleSeverity::Medium)),
            };

            insert_stmt.execute(params![
                run_id,
                rule_id,
                rule_name,
                severity,
                hit.file_path,
                hit.line_number as i64,
                hit.byte_offset as i64,
                hit.line,
                hit.timestamp_epoch,
                hit.timestamp_epoch,
                now,
            ])?;
            total_hits += 1;
        }
    }
    drop(insert_stmt);

    tx.execute(
        "UPDATE detection_runs SET finished_at = ?, total_hits = ? WHERE id = ?",
        params![now_epoch_seconds(), total_hits as i64, run_id],
    )?;
    tx.commit()?;

    Ok(RunDetectionsResponse {
        run_id,
        total_hits,
        files_scanned: scan.files_scanned,
        bytes_scanned: scan.bytes_scanned,
        duration_ms: scan.duration_ms,
    })
}

fn normalize_rules(rules: &[RuleFilter]) -> Result<Vec<NormalizedRule>, DetectionError> {
    let mut normalized = Vec::with_capacity(rules.len());
    for (idx, rule) in rules.iter().enumerate() {
        normalized.push(normalize_single_rule(rule, idx)?);
    }
    Ok(normalized)
}

fn normalize_single_rule(rule: &RuleFilter, idx: usize) -> Result<NormalizedRule, DetectionError> {
    let id = rule
        .id
        .clone()
        .unwrap_or_else(|| format!("rule_{}", idx + 1))
        .trim()
        .to_string();
    if id.is_empty() {
        return Err(DetectionError::InvalidRequest(
            "rule id cannot be empty".to_string(),
        ));
    }
    let name = rule
        .name
        .clone()
        .unwrap_or_else(|| id.clone())
        .trim()
        .to_string();
    let severity = rule.severity.unwrap_or_default();
    let definition_json = serde_json::to_string(rule)?;
    Ok(NormalizedRule {
        id,
        name,
        severity,
        definition_json,
    })
}

fn upsert_rule_in_tx(
    tx: &Transaction<'_>,
    rule: &NormalizedRule,
    enabled: bool,
) -> Result<(), DetectionError> {
    let now = now_epoch_seconds();
    tx.execute(
        "INSERT INTO rules (id, name, severity, definition_json, enabled, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
            name = excluded.name,
            severity = excluded.severity,
            definition_json = excluded.definition_json,
            enabled = excluded.enabled,
            updated_at = excluded.updated_at",
        params![
            rule.id,
            rule.name,
            severity_as_str(rule.severity),
            rule.definition_json,
            if enabled { 1i64 } else { 0i64 },
            now,
            now,
        ],
    )?;
    Ok(())
}

fn get_rule_in_tx(tx: &Transaction<'_>, id: &str) -> Result<Option<PersistedRule>, DetectionError> {
    let rule = tx
        .query_row(
            "SELECT id, name, severity, definition_json, enabled, created_at, updated_at
             FROM rules WHERE id = ?",
            params![id],
            |row| {
                Ok(PersistedRule {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    severity: row.get(2)?,
                    definition_json: row.get(3)?,
                    enabled: row.get::<_, i64>(4)? != 0,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            },
        )
        .optional()?;
    Ok(rule)
}

fn severity_as_str(severity: RuleSeverity) -> &'static str {
    match severity {
        RuleSeverity::Low => "low",
        RuleSeverity::Medium => "medium",
        RuleSeverity::High => "high",
        RuleSeverity::Critical => "critical",
    }
}

fn parse_cursor(raw: &str) -> Result<Cursor, DetectionError> {
    let (created_at, id) = raw.split_once(':').ok_or(DetectionError::InvalidCursor)?;
    let created_at = created_at
        .parse::<i64>()
        .map_err(|_| DetectionError::InvalidCursor)?;
    let id = id
        .parse::<i64>()
        .map_err(|_| DetectionError::InvalidCursor)?;
    Ok(Cursor { created_at, id })
}

fn encode_cursor(cursor: Cursor) -> String {
    format!("{}:{}", cursor.created_at, cursor.id)
}

fn open_connection() -> Result<Connection, DetectionError> {
    let path = db_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(path)?;
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            severity TEXT NOT NULL,
            definition_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS detection_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            root_path TEXT NOT NULL,
            started_at INTEGER NOT NULL,
            finished_at INTEGER,
            total_hits INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS detection_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER NOT NULL,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            file_path TEXT NOT NULL,
            line_number INTEGER NOT NULL,
            byte_offset INTEGER NOT NULL,
            line TEXT NOT NULL,
            window_start INTEGER,
            window_end INTEGER,
            created_at INTEGER NOT NULL,
            false_positive INTEGER NOT NULL DEFAULT 0,
            false_positive_note TEXT,
            false_positive_marked_at INTEGER,
            FOREIGN KEY(run_id) REFERENCES detection_runs(id),
            FOREIGN KEY(rule_id) REFERENCES rules(id)
        );

        CREATE INDEX IF NOT EXISTS idx_detection_hits_sort_desc
        ON detection_hits(created_at DESC, id DESC);

        CREATE INDEX IF NOT EXISTS idx_detection_hits_sort_asc
        ON detection_hits(created_at ASC, id ASC);

        CREATE INDEX IF NOT EXISTS idx_detection_hits_rule
        ON detection_hits(rule_id, created_at DESC, id DESC);
        ",
    )?;
    Ok(conn)
}

fn db_path() -> Result<PathBuf, DetectionError> {
    if let Ok(path) = env::var("DETECTIONS_DB_PATH") {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return Err(DetectionError::InvalidRequest(
                "DETECTIONS_DB_PATH cannot be empty".to_string(),
            ));
        }
        return Ok(PathBuf::from(trimmed));
    }
    Ok(env::current_dir()?.join(DEFAULT_DB_FILE))
}

fn now_epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn resolve_exports_dir() -> PathBuf {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let preferred = cwd.join(EXPORT_DIR);
    if ensure_writable_directory(&preferred) {
        return preferred;
    }

    let fallback = cwd.join(EXPORT_FALLBACK_DIR);
    if ensure_writable_directory(&fallback) {
        return fallback;
    }

    preferred
}

fn ensure_writable_directory(path: &Path) -> bool {
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

fn sanitize_filename_token(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_underscore = false;
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_underscore = false;
        } else if !last_underscore {
            out.push('_');
            last_underscore = true;
        }
    }
    out.trim_matches('_').to_string()
}

fn default_hits_page_size() -> usize {
    50
}

fn default_true() -> bool {
    true
}
