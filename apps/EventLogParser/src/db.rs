use crate::error::AppError;
use crate::models::{
    AggregatedLogon, CorrelatedLogon, CorrelationConfig, CorrelationStep, CorrelationTimeFilter,
    CountEntry, CustomReportHtmlResponse, CustomReportRequest, CustomReportResponse, DeleteRequest,
    DetectionMatch, DetectionRule, Event, ReportFiltersOut, ReportMeta, ReportRequest,
    ReportResponse, ReportSummary, StatsResponse, SuspiciousEvent, TimelineBucket,
};
use chrono::{DateTime, Datelike, FixedOffset, NaiveDateTime, TimeZone, Timelike};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use regex::Regex;
use rusqlite::{
    functions::FunctionFlags,
    params,
    types::{Type, Value as SqlValue},
    OpenFlags,
};
use serde_json::{self, Value};
use std::fs;
use std::fmt::Write;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::time::Duration;

pub type DbPool = Pool<SqliteConnectionManager>;

pub fn init_pool(path: impl AsRef<Path>, busy_timeout: Duration) -> Result<DbPool, AppError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_FULL_MUTEX;

    let manager = SqliteConnectionManager::file(path)
        .with_flags(flags)
        .with_init(move |conn| {
            conn.busy_timeout(busy_timeout)?;
            // Try WAL; if the filesystem rejects it (e.g., NFS/permissions), fall back to DELETE.
            if let Err(e) = conn.pragma_update(None, "journal_mode", "WAL") {
                tracing::warn!("WAL mode failed ({e}); falling back to DELETE journal mode");
                conn.pragma_update(None, "journal_mode", "DELETE")?;
            }
            conn.execute_batch(
                r#"
                PRAGMA synchronous=NORMAL;
                PRAGMA temp_store=MEMORY;
                PRAGMA mmap_size=134217728;
                "#,
            )?;
            register_regexp_function(conn)?;
            Ok(())
        });

    let pool = Pool::builder().max_size(16).build(manager)?;
    Ok(pool)
}

pub fn init_schema(pool: &DbPool) -> Result<(), AppError> {
    run_migrations(pool)
}

fn split_csv_values(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn register_regexp_function(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    conn.create_scalar_function(
        "regexp",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let pattern = match ctx.get_raw(0).as_str() {
                Ok(p) => p,
                Err(_) => return Ok(false),
            };
            let value = match ctx.get_raw(1).as_str() {
                Ok(v) => v,
                Err(_) => return Ok(false),
            };

            match Regex::new(pattern) {
                Ok(re) => Ok(re.is_match(value)),
                Err(_) => Ok(false),
            }
        },
    )?;
    Ok(())
}

pub fn fetch_events(
    pool: &DbPool,
    event_id: Option<u32>,
    channel: Option<String>,
    user: Option<String>,
    sid: Option<String>,
    ip: Option<String>,
    keyword: Option<String>,
    exclude: Option<String>,
    from: Option<String>,
    to: Option<String>,
    limit: usize,
    offset: usize,
) -> Result<Vec<Event>, AppError> {
    let conn = pool.get()?;
    let mut conditions = Vec::new();
    let mut dyn_params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(id) = event_id {
        conditions.push("event_id = ?".to_string());
        dyn_params.push(Box::new(id as i64));
    }

    if let Some(value) = channel {
        let values = split_csv_values(&value);
        if !values.is_empty() {
            let mut group = Vec::new();
            for v in values {
                group.push("channel LIKE ?".to_string());
                dyn_params.push(Box::new(format!("%{}%", v)));
            }
            conditions.push(format!("({})", group.join(" OR ")));
        }
    }
    if let Some(value) = user {
        let values = split_csv_values(&value);
        if !values.is_empty() {
            let mut group = Vec::new();
            for v in values {
                group.push("COALESCE(user, '') LIKE ?".to_string());
                dyn_params.push(Box::new(format!("%{}%", v)));
            }
            conditions.push(format!("({})", group.join(" OR ")));
        }
    }
    if let Some(value) = sid {
        let values = split_csv_values(&value);
        if !values.is_empty() {
            let mut group = Vec::new();
            for v in values {
                group.push("COALESCE(sid, '') LIKE ?".to_string());
                dyn_params.push(Box::new(format!("%{}%", v)));
            }
            conditions.push(format!("({})", group.join(" OR ")));
        }
    }

    if let Some(value) = ip {
        let values = split_csv_values(&value);
        if !values.is_empty() {
            let mut group = Vec::new();
            for v in values {
                group.push(
                    "(COALESCE(json_extract(event_data_json, '$.Event.EventData.IpAddress'), '') LIKE ? \
                      OR COALESCE(json_extract(event_data_json, '$.Event.EventData.SourceAddress'), '') LIKE ? \
                      OR COALESCE(json_extract(event_data_json, '$.Event.EventData.DestAddress'), '') LIKE ?)"
                        .to_string(),
                );
                let ip_pattern = format!("%{}%", v);
                dyn_params.push(Box::new(ip_pattern.clone()));
                dyn_params.push(Box::new(ip_pattern.clone()));
                dyn_params.push(Box::new(ip_pattern));
            }
            conditions.push(format!("({})", group.join(" OR ")));
        }
    }
    if let Some(value) = keyword {
        let values = split_csv_values(&value);
        if !values.is_empty() {
            let mut group = Vec::new();
            for v in values {
                group.push(
                    "(COALESCE(keywords, '') LIKE ? OR event_data_json LIKE ? OR raw_xml LIKE ?)"
                        .to_string(),
                );
                let pattern = format!("%{}%", v);
                dyn_params.push(Box::new(pattern.clone()));
                dyn_params.push(Box::new(pattern.clone()));
                dyn_params.push(Box::new(pattern));
            }
            conditions.push(format!("({})", group.join(" OR ")));
        }
    }
    if let Some(value) = exclude {
        let values = split_csv_values(&value);
        if !values.is_empty() {
            let mut group = Vec::new();
            for v in values {
                group.push(
                    "(COALESCE(channel, '') NOT LIKE ? \
                      AND COALESCE(user, '') NOT LIKE ? \
                      AND COALESCE(sid, '') NOT LIKE ? \
                      AND COALESCE(computer, '') NOT LIKE ? \
                      AND COALESCE(source, '') NOT LIKE ? \
                      AND COALESCE(keywords, '') NOT LIKE ? \
                      AND COALESCE(json_extract(event_data_json, '$.Event.EventData.IpAddress'), '') NOT LIKE ? \
                      AND COALESCE(json_extract(event_data_json, '$.Event.EventData.SourceAddress'), '') NOT LIKE ? \
                      AND COALESCE(json_extract(event_data_json, '$.Event.EventData.DestAddress'), '') NOT LIKE ? \
                      AND event_data_json NOT LIKE ? \
                      AND raw_xml NOT LIKE ?)"
                        .to_string(),
                );
                let pattern = format!("%{}%", v);
                for _ in 0..11 {
                    dyn_params.push(Box::new(pattern.clone()));
                }
            }
            conditions.push(format!("({})", group.join(" AND ")));
        }
    }
    if let Some(value) = from.filter(|v| !v.trim().is_empty()) {
        conditions.push("timestamp >= ?".to_string());
        dyn_params.push(Box::new(value));
    }
    if let Some(value) = to.filter(|v| !v.trim().is_empty()) {
        conditions.push("timestamp <= ?".to_string());
        dyn_params.push(Box::new(value));
    }

    let where_clause = if conditions.is_empty() {
        "1=1".to_string()
    } else {
        conditions.join(" AND ")
    };

    let mut stmt = conn.prepare(&format!(
        r#"
        SELECT id, event_id, timestamp, computer, channel, record_id, level, opcode, task,
               user, sid, keywords, source, ingest_path, event_data_json, raw_xml
        FROM events
        WHERE {where_clause}
        ORDER BY datetime(timestamp) DESC, timestamp DESC
        LIMIT ? OFFSET ?;
        "#
    ))?;

    dyn_params.push(Box::new(limit as i64));
    dyn_params.push(Box::new(offset as i64));
    let mut rows = stmt.query(rusqlite::params_from_iter(dyn_params.iter()))?;

    let mut results = Vec::new();
    while let Some(row) = rows.next()? {
        let data: String = row.get(14)?;
        results.push(Event {
            id: row.get(0)?,
            event_id: row.get::<_, i64>(1)? as u32,
            timestamp: row.get(2)?,
            computer: row.get(3)?,
            channel: row.get(4)?,
            record_id: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
            level: row.get::<_, Option<i64>>(6)?.map(|v| v as u32),
            opcode: row.get::<_, Option<i64>>(7)?.map(|v| v as u32),
            task: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
            user: row.get(9)?,
            sid: row.get(10)?,
            keywords: row.get(11)?,
            source: row.get(12)?,
            ingest_path: row.get(13)?,
            event_data_json: serde_json::from_str(&data)?,
            raw_xml: row.get(15)?,
        });
    }

    Ok(results)
}

pub fn fetch_process_events(
    pool: &DbPool,
    limit: usize,
    offset: usize,
) -> Result<Vec<Event>, AppError> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        SELECT id, event_id, timestamp, computer, channel, record_id, level, opcode, task,
               user, sid, keywords, source, ingest_path, event_data_json, raw_xml
        FROM events
        WHERE event_id IN (4688, 1)
        ORDER BY timestamp DESC
        LIMIT ?1 OFFSET ?2;
        "#,
    )?;

    let mut rows = stmt.query(params![limit as i64, offset as i64])?;
    let mut results = Vec::new();
    while let Some(row) = rows.next()? {
        let data: String = row.get(14)?;
        results.push(Event {
            id: row.get(0)?,
            event_id: row.get::<_, i64>(1)? as u32,
            timestamp: row.get(2)?,
            computer: row.get(3)?,
            channel: row.get(4)?,
            record_id: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
            level: row.get::<_, Option<i64>>(6)?.map(|v| v as u32),
            opcode: row.get::<_, Option<i64>>(7)?.map(|v| v as u32),
            task: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
            user: row.get(9)?,
            sid: row.get(10)?,
            keywords: row.get(11)?,
            source: row.get(12)?,
            ingest_path: row.get(13)?,
            event_data_json: serde_json::from_str(&data)?,
            raw_xml: row.get(15)?,
        });
    }

    Ok(results)
}

fn sanitize_fts_query(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        "\"\"".to_string()
    } else {
        let escaped = trimmed.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    }
}

pub fn search_events(
    pool: &DbPool,
    query: &str,
    limit: usize,
    offset: usize,
    logon_type: Option<u32>,
    ip: Option<String>,
    exclude: Option<String>,
) -> Result<Vec<Event>, AppError> {
    let conn = pool.get()?;
    let mut conditions = vec!["event_text MATCH ?".to_string()];
    let mut dyn_params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(sanitize_fts_query(query))];

    if let Some(lt) = logon_type {
        conditions.push(
            "json_extract(e.event_data_json,'$.Event.EventData.LogonType') = ?".to_string(),
        );
        dyn_params.push(Box::new(lt as i64));
    }
    if let Some(value) = ip {
        let values = split_csv_values(&value);
        if !values.is_empty() {
            let mut group = Vec::new();
            for v in values {
                group.push(
                    "(COALESCE(json_extract(e.event_data_json, '$.Event.EventData.IpAddress'), '') LIKE ? \
                      OR COALESCE(json_extract(e.event_data_json, '$.Event.EventData.SourceAddress'), '') LIKE ? \
                      OR COALESCE(json_extract(e.event_data_json, '$.Event.EventData.DestAddress'), '') LIKE ?)"
                        .to_string(),
                );
                let pattern = format!("%{}%", v);
                dyn_params.push(Box::new(pattern.clone()));
                dyn_params.push(Box::new(pattern.clone()));
                dyn_params.push(Box::new(pattern));
            }
            conditions.push(format!("({})", group.join(" OR ")));
        }
    }
    if let Some(value) = exclude {
        let values = split_csv_values(&value);
        if !values.is_empty() {
            let mut group = Vec::new();
            for v in values {
                group.push(
                    "(COALESCE(e.channel, '') NOT LIKE ? \
                      AND COALESCE(e.user, '') NOT LIKE ? \
                      AND COALESCE(e.sid, '') NOT LIKE ? \
                      AND COALESCE(e.computer, '') NOT LIKE ? \
                      AND COALESCE(e.source, '') NOT LIKE ? \
                      AND COALESCE(e.keywords, '') NOT LIKE ? \
                      AND COALESCE(json_extract(e.event_data_json, '$.Event.EventData.IpAddress'), '') NOT LIKE ? \
                      AND COALESCE(json_extract(e.event_data_json, '$.Event.EventData.SourceAddress'), '') NOT LIKE ? \
                      AND COALESCE(json_extract(e.event_data_json, '$.Event.EventData.DestAddress'), '') NOT LIKE ? \
                      AND e.event_data_json NOT LIKE ? \
                      AND e.raw_xml NOT LIKE ?)"
                        .to_string(),
                );
                let pattern = format!("%{}%", v);
                for _ in 0..11 {
                    dyn_params.push(Box::new(pattern.clone()));
                }
            }
            conditions.push(format!("({})", group.join(" AND ")));
        }
    }

    let where_clause = conditions.join(" AND ");
    let mut stmt = conn.prepare(&format!(
        r#"
        SELECT e.id, e.event_id, e.timestamp, e.computer, e.channel, e.record_id, e.level,
               e.opcode, e.task, e.user, e.sid, e.keywords, e.source, e.ingest_path, e.event_data_json, e.raw_xml
        FROM event_text f
        JOIN events e ON e.id = f.rowid
        WHERE {where_clause}
        ORDER BY datetime(e.timestamp) DESC, e.timestamp DESC
        LIMIT ? OFFSET ?;
        "#
    ))?;

    dyn_params.push(Box::new(limit as i64));
    dyn_params.push(Box::new(offset as i64));

    let mut rows = stmt.query(rusqlite::params_from_iter(dyn_params.iter()))?;
    let mut results = Vec::new();
    while let Some(row) = rows.next()? {
        let data: String = row.get(14)?;
        results.push(Event {
            id: row.get(0)?,
            event_id: row.get::<_, i64>(1)? as u32,
            timestamp: row.get(2)?,
            computer: row.get(3)?,
            channel: row.get(4)?,
            record_id: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
            level: row.get::<_, Option<i64>>(6)?.map(|v| v as u32),
            opcode: row.get::<_, Option<i64>>(7)?.map(|v| v as u32),
            task: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
            user: row.get(9)?,
            sid: row.get(10)?,
            keywords: row.get(11)?,
            source: row.get(12)?,
            ingest_path: row.get(13)?,
            event_data_json: serde_json::from_str(&data)?,
            raw_xml: row.get(15)?,
        });
    }

    Ok(results)
}

pub fn generate_custom_report(
    pool: &DbPool,
    req: &CustomReportRequest,
) -> Result<CustomReportResponse, AppError> {
    let conn = pool.get()?;
    if req.items.is_empty() {
        return Ok(CustomReportResponse {
            markdown: format!(
                "# {}\n\nAnalyst: {}\n\n_Summary:_ {}\n\n_No events selected._",
                req.title, req.analyst, req.summary
            ),
        });
    }

    let mut placeholders = Vec::new();
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    for (idx, item) in req.items.iter().enumerate() {
        placeholders.push(format!("?{}", idx + 1));
        params.push(rusqlite::types::Value::Integer(item.event_id));
    }
    let sql = format!(
        r#"
        SELECT id, event_id, timestamp, computer, channel, record_id, level, opcode, task,
               user, sid, keywords, source, ingest_path, event_data_json, raw_xml
        FROM events
        WHERE id IN ({})
        ORDER BY timestamp DESC;
        "#,
        placeholders.join(",")
    );

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params.iter()))?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        let data: String = row.get(14)?;
        events.push(Event {
            id: row.get(0)?,
            event_id: row.get::<_, i64>(1)? as u32,
            timestamp: row.get(2)?,
            computer: row.get(3)?,
            channel: row.get(4)?,
            record_id: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
            level: row.get::<_, Option<i64>>(6)?.map(|v| v as u32),
            opcode: row.get::<_, Option<i64>>(7)?.map(|v| v as u32),
            task: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
            user: row.get(9)?,
            sid: row.get(10)?,
            keywords: row.get(11)?,
            source: row.get(12)?,
            ingest_path: row.get(13)?,
            event_data_json: serde_json::from_str(&data)?,
            raw_xml: row.get(15)?,
        });
    }

    let mut md = String::new();
    md.push_str(&format!("# {}\n\n", req.title));
    md.push_str(&format!("Analyst: {}\n\n", req.analyst));
    md.push_str(&format!("## Summary\n\n{}\n\n", req.summary));
    md.push_str("## Evidence\n\n");

    for item in &req.items {
        if let Some(ev) = events.iter().find(|e| e.id == item.event_id) {
            md.push_str(&format!(
                "### Event {} (ID: {})\n", ev.id, ev.event_id
            ));
            md.push_str(&format!(
                "- Time: {}\n- Host: {}\n- Channel: {}\n- User: {}\n- Source: {}\n",
                ev.timestamp,
                ev.computer,
                ev.channel,
                ev.user.clone().unwrap_or_else(|| "-".into()),
                ev.source.clone().unwrap_or_else(|| "-".into())
            ));
            if let Some(note) = &item.notes {
                md.push_str(&format!("- Analyst note: {}\n", note));
            }
            md.push_str("\n```\n");
            md.push_str(&serde_json::to_string_pretty(&ev.event_data_json)?);
            md.push_str("\n```\n\n");
        } else {
            md.push_str(&format!("### Event {} (not found)\n\n", item.event_id));
        }
    }

    Ok(CustomReportResponse { markdown: md })
}

pub fn generate_custom_report_html(
    pool: &DbPool,
    req: &CustomReportRequest,
) -> Result<CustomReportHtmlResponse, AppError> {
    let conn = pool.get()?;
    if req.items.is_empty() {
        return Ok(CustomReportHtmlResponse {
            html: "<html><body><h1>No events selected</h1></body></html>".to_string(),
        });
    }

    let mut placeholders = Vec::new();
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    for (idx, item) in req.items.iter().enumerate() {
        placeholders.push(format!("?{}", idx + 1));
        params.push(rusqlite::types::Value::Integer(item.event_id));
    }

    let sql = format!(
        r#"
        SELECT id, event_id, timestamp, computer, channel, record_id, level, opcode, task,
               user, sid, keywords, source, ingest_path, event_data_json, raw_xml
        FROM events
        WHERE id IN ({})
        ORDER BY timestamp DESC;
        "#,
        placeholders.join(",")
    );

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(rusqlite::params_from_iter(params.iter()))?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        let data: String = row.get(14)?;
        events.push(Event {
            id: row.get(0)?,
            event_id: row.get::<_, i64>(1)? as u32,
            timestamp: row.get(2)?,
            computer: row.get(3)?,
            channel: row.get(4)?,
            record_id: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
            level: row.get::<_, Option<i64>>(6)?.map(|v| v as u32),
            opcode: row.get::<_, Option<i64>>(7)?.map(|v| v as u32),
            task: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
            user: row.get(9)?,
            sid: row.get(10)?,
            keywords: row.get(11)?,
            source: row.get(12)?,
            ingest_path: row.get(13)?,
            event_data_json: serde_json::from_str(&data)?,
            raw_xml: row.get(15)?,
        });
    }

    let mut html = String::new();
    let _ = writeln!(
        &mut html,
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><style>
        @page {{ size: A4; margin: 20mm 15mm; }}
        body {{ font-family: Arial, sans-serif; font-size: 11pt; color: #111; line-height: 1.5; }}
        .cover {{ text-align: center; margin-top: 60px; page-break-after: always; }}
        .event-card {{ border: 1px solid #e0e0e0; border-radius: 6px; padding: 12px; margin-top: 12px; page-break-inside: avoid; background: #fafafa; }}
        .event-card h4 {{ margin: -12px -12px 8px -12px; padding: 8px; background: #f0f0f0; border-bottom: 1px solid #e0e0e0; }}
        .notes {{ background: #fffbe6; border-left: 4px solid #facc15; padding: 10px; font-style: italic; }}
        pre {{ background: #1f2937; color: #e5e7eb; padding: 8px; border-radius: 6px; font-size: 10pt; overflow: auto; }}
        h2 {{ margin-bottom: 6px; }}
        </style></head><body>"#
    );
    let _ = writeln!(
        &mut html,
        r#"<div class="cover"><h1>{}</h1><h3>Case Report</h3><p><strong>Analyst:</strong> {}<br><strong>Date:</strong> {}</p></div>"#,
        req.title,
        req.analyst,
        chrono::Utc::now().to_rfc3339()
    );
    let _ = writeln!(
        &mut html,
        r#"<h2>Executive Summary</h2><p>{}</p><hr style="page-break-after:always;">"#,
        req.summary
    );
    let _ = writeln!(&mut html, r#"<h2>Reviewed Evidence</h2>"#);
    for item in &req.items {
        if let Some(ev) = events.iter().find(|e| e.id == item.event_id) {
            let _ = writeln!(
                &mut html,
                r#"<div class="event-card"><h4>Event {} • {} • {}</h4>
                <p><strong>Time:</strong> {}<br><strong>Channel:</strong> {} | <strong>User:</strong> {}</p>"#,
                ev.event_id,
                ev.computer,
                ev.channel,
                ev.timestamp,
                ev.channel,
                ev.user.clone().unwrap_or_else(|| "—".into())
            );
            if let Some(notes) = &item.notes {
                let _ = writeln!(
                    &mut html,
                    r#"<div class="notes"><strong>Analyst Note:</strong><br>{}</div>"#,
                    notes
                );
            }
            let _ = writeln!(
                &mut html,
                r#"<pre>{}</pre></div>"#,
                serde_json::to_string_pretty(&ev.event_data_json)?
            );
        }
    }
    let _ = writeln!(&mut html, "</body></html>");

    Ok(CustomReportHtmlResponse { html })
}

pub fn stats(
    pool: &DbPool,
    limit: usize,
    ingest_path: Option<String>,
) -> Result<StatsResponse, AppError> {
    let conn = pool.get()?;
    let mut where_clause = "1=1".to_string();
    let mut params: Vec<SqlValue> = Vec::new();
    if let Some(p) = ingest_path {
        where_clause = "ingest_path = ?".to_string();
        params.push(SqlValue::Text(p));
    }

    let add_limit = |mut v: Vec<SqlValue>| {
        v.push(SqlValue::Integer(limit as i64));
        v
    };

    let by_event_id = conn
        .prepare(&format!(
            "SELECT event_id, COUNT(*) as c FROM events WHERE {where_clause} GROUP BY event_id ORDER BY c DESC LIMIT ?"
        ))?
        .query_map(rusqlite::params_from_iter(add_limit(params.clone()).iter()), |row| {
            Ok(CountEntry {
                key: row.get::<_, i64>(0)? as u32,
                count: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let by_channel = conn
        .prepare(&format!(
            "SELECT channel, COUNT(*) as c FROM events WHERE {where_clause} GROUP BY channel ORDER BY c DESC LIMIT ?"
        ))?
        .query_map(rusqlite::params_from_iter(add_limit(params.clone()).iter()), |row| {
            Ok(CountEntry {
                key: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let by_source = conn
        .prepare(&format!(
            "SELECT source, COUNT(*) as c FROM events WHERE source IS NOT NULL AND {where_clause} GROUP BY source ORDER BY c DESC LIMIT ?"
        ))?
        .query_map(rusqlite::params_from_iter(add_limit(params.clone()).iter()), |row| {
            Ok(CountEntry {
                key: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let by_user = conn
        .prepare(&format!(
            "SELECT user, COUNT(*) as c FROM events WHERE user IS NOT NULL AND {where_clause} GROUP BY user ORDER BY c DESC LIMIT ?"
        ))?
        .query_map(rusqlite::params_from_iter(add_limit(params.clone()).iter()), |row| {
            Ok(CountEntry {
                key: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let by_source_ip = conn
        .prepare(&format!(
            "SELECT ip, COUNT(*) as c FROM (
                SELECT json_extract(event_data_json, '$.Event.EventData.SourceAddress') AS ip
                FROM events
                WHERE {where_clause}
            ) t
            WHERE ip IS NOT NULL AND ip <> ''
            GROUP BY ip
            ORDER BY c DESC
            LIMIT ?"
        ))?
        .query_map(rusqlite::params_from_iter(add_limit(params.clone()).iter()), |row| {
            Ok(CountEntry {
                key: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let by_dest_ip = conn
        .prepare(&format!(
            "SELECT ip, COUNT(*) as c FROM (
                SELECT json_extract(event_data_json, '$.Event.EventData.DestAddress') AS ip
                FROM events
                WHERE {where_clause}
            ) t
            WHERE ip IS NOT NULL AND ip <> ''
            GROUP BY ip
            ORDER BY c DESC
            LIMIT ?"
        ))?
        .query_map(rusqlite::params_from_iter(add_limit(params.clone()).iter()), |row| {
            Ok(CountEntry {
                key: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let ingest_paths = conn
        .prepare("SELECT DISTINCT ingest_path FROM events WHERE ingest_path IS NOT NULL ORDER BY ingest_path")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;

    Ok(StatsResponse {
        by_event_id,
        by_channel,
        by_source,
        by_user,
        by_source_ip,
        by_dest_ip,
        ingest_paths,
    })
}

pub fn timeline(
    pool: &DbPool,
    from: &str,
    to: &str,
    bucket: &str,
    ingest_path: Option<String>,
) -> Result<Vec<TimelineBucket>, AppError> {
    let conn = pool.get()?;
    let fmt = match bucket {
        "hour" => "%Y-%m-%dT%H:00:00Z",
        _ => "%Y-%m-%dT%H:%M:00Z",
    };

    let mut conditions = vec!["timestamp >= ?1".to_string(), "timestamp <= ?2".to_string()];
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(from.to_string()), Box::new(to.to_string())];
    if let Some(p) = ingest_path {
        conditions.push("ingest_path = ?3".to_string());
        params.push(Box::new(p));
    }
    let where_clause = conditions.join(" AND ");

    let mut stmt = conn.prepare(&format!(
        "SELECT strftime('{}', timestamp) as bucket, COUNT(*) FROM events WHERE {where_clause} GROUP BY bucket ORDER BY bucket",
        fmt
    ))?;

    let buckets = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok(TimelineBucket {
                bucket: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(buckets)
}

pub fn get_event(pool: &DbPool, id: i64) -> Result<Event, AppError> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        SELECT id, event_id, timestamp, computer, channel, record_id, level, opcode, task,
               user, sid, keywords, source, ingest_path, event_data_json, raw_xml
        FROM events WHERE id = ?1
        "#,
    )?;

    let event = stmt.query_row(params![id], |row| {
        let data: String = row.get(14)?;
        Ok(Event {
            id: row.get(0)?,
            event_id: row.get::<_, i64>(1)? as u32,
            timestamp: row.get(2)?,
            computer: row.get(3)?,
            channel: row.get(4)?,
            record_id: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
            level: row.get::<_, Option<i64>>(6)?.map(|v| v as u32),
            opcode: row.get::<_, Option<i64>>(7)?.map(|v| v as u32),
            task: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
            user: row.get(9)?,
            sid: row.get(10)?,
            keywords: row.get(11)?,
            source: row.get(12)?,
            ingest_path: row.get(13)?,
            event_data_json: parse_json_field(data)?,
            raw_xml: row.get(15)?,
        })
    })?;

    Ok(event)
}

pub fn logon_failures(
    pool: &DbPool,
    limit: usize,
    offset: usize,
) -> Result<Vec<AggregatedLogon>, AppError> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        SELECT user,
               sid,
               computer,
               json_extract(event_data_json, '$.Event.EventData.IpAddress') AS ip,
               COUNT(*) as c
        FROM events
        WHERE event_id = 4625
        GROUP BY user, sid, computer, ip
        ORDER BY c DESC
        LIMIT ?1 OFFSET ?2
        "#,
    )?;

    let items = stmt
        .query_map(params![limit as i64, offset as i64], |row| {
            Ok(AggregatedLogon {
                user: row.get(0)?,
                sid: row.get(1)?,
                computer: row.get(2)?,
                ip: row.get(3)?,
                count: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(items)
}

pub fn logon_success(
    pool: &DbPool,
    limit: usize,
    offset: usize,
) -> Result<Vec<AggregatedLogon>, AppError> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        SELECT user,
               sid,
               computer,
               json_extract(event_data_json, '$.Event.EventData.IpAddress') AS ip,
               COUNT(*) as c
        FROM events
        WHERE event_id = 4624
        GROUP BY user, sid, computer, ip
        ORDER BY c DESC
        LIMIT ?1 OFFSET ?2
        "#,
    )?;

    let items = stmt
        .query_map(params![limit as i64, offset as i64], |row| {
            Ok(AggregatedLogon {
                user: row.get(0)?,
                sid: row.get(1)?,
                computer: row.get(2)?,
                ip: row.get(3)?,
                count: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(items)
}

pub fn suspicious_events(
    pool: &DbPool,
    limit: usize,
    offset: usize,
) -> Result<Vec<SuspiciousEvent>, AppError> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        WITH suspicious AS (
            SELECT id, event_id, timestamp, computer, channel, 'Security log cleared' as desc_text, event_data_json
            FROM events WHERE event_id = 1102
            UNION ALL
            SELECT id, event_id, timestamp, computer, channel, 'Service creation', event_data_json
            FROM events WHERE event_id = 7045
            UNION ALL
            SELECT id, event_id, timestamp, computer, channel, 'Suspicious process start', event_data_json
            FROM events
            WHERE event_id = 4688 AND (
                lower(json_extract(event_data_json, '$.Event.EventData.NewProcessName')) LIKE '%powershell%' OR
                lower(json_extract(event_data_json, '$.Event.EventData.CommandLine')) LIKE '%-enc%' OR
                lower(json_extract(event_data_json, '$.Event.EventData.CommandLine')) LIKE '%cmd.exe /c%' OR
                lower(json_extract(event_data_json, '$.Event.EventData.CommandLine')) LIKE '%certutil%' OR
                lower(json_extract(event_data_json, '$.Event.EventData.CommandLine')) LIKE '%rundll32%'
            )
        )
        SELECT id, event_id, timestamp, computer, channel, desc_text, event_data_json
        FROM suspicious
        ORDER BY timestamp DESC
        LIMIT ?1 OFFSET ?2
        "#,
    )?;

    let items = stmt
        .query_map(params![limit as i64, offset as i64], |row| {
            let data: String = row.get(6)?;
            Ok(SuspiciousEvent {
                id: row.get(0)?,
                event_id: row.get::<_, i64>(1)? as u32,
                timestamp: row.get(2)?,
                computer: row.get(3)?,
                channel: row.get(4)?,
                description: row.get(5)?,
                event_data_json: parse_json_field(data)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(items)
}

pub fn correlate_logons(
    pool: &DbPool,
    limit: usize,
    offset: usize,
) -> Result<Vec<CorrelatedLogon>, AppError> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        r#"
        WITH fails AS (
            SELECT user,
                   json_extract(event_data_json, '$.Event.EventData.IpAddress') AS ip,
                   computer,
                   strftime('%s', timestamp) AS ts
            FROM events WHERE event_id = 4625
        ),
        succ AS (
            SELECT user,
                   json_extract(event_data_json, '$.Event.EventData.IpAddress') AS ip,
                   computer,
                   strftime('%s', timestamp) AS ts
            FROM events WHERE event_id = 4624
        )
        SELECT f.user,
               f.ip,
               f.computer,
               COUNT(*) FILTER (WHERE f.user IS NOT NULL) as failures,
               (
                   SELECT COUNT(*) FROM succ s
                   WHERE s.user = f.user
                     AND (s.ip = f.ip OR s.ip IS NULL OR f.ip IS NULL)
                     AND abs(s.ts - f.ts) <= 600
               ) as successes
        FROM fails f
        GROUP BY f.user, f.ip, f.computer
        ORDER BY failures DESC
        LIMIT ?1 OFFSET ?2
        "#,
    )?;

    let items = stmt
        .query_map(params![limit as i64, offset as i64], |row| {
            Ok(CorrelatedLogon {
                account: row.get(0)?,
                ip: row.get(1)?,
                computer: row.get(2)?,
                failures: row.get(3)?,
                successes: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(items)
}

pub fn delete_events(pool: &DbPool, filters: &DeleteRequest) -> Result<usize, AppError> {
    let mut conn = pool.get()?;
    let mut conditions = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(id) = filters.id {
        conditions.push("id = ?".to_string());
        params.push(Box::new(id));
    }
    if let Some(channel) = &filters.channel {
        conditions.push("channel = ?".to_string());
        params.push(Box::new(channel.to_owned()));
    }
    if let Some(event_id) = filters.event_id {
        conditions.push("event_id = ?".to_string());
        params.push(Box::new(event_id as i64));
    }
    if let Some(before) = &filters.before {
        conditions.push("timestamp < ?".to_string());
        params.push(Box::new(before.to_owned()));
    }

    // If no filters, wipe everything with contentless FTS delete-all + base table delete.
    if conditions.is_empty() {
        let tx = conn.transaction()?;
        let total: i64 = tx.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        // contentless FTS delete-all
        tx.execute("INSERT INTO event_text(event_text) VALUES('delete-all')", [])?;
        tx.execute("DELETE FROM events", [])?;
        tx.commit()?;
        return Ok(total as usize);
    }

    let where_clause = conditions.join(" AND ");

    let tx = conn.transaction()?;
    let ids = {
        let mut ids_stmt = tx.prepare(&format!("SELECT id FROM events WHERE {where_clause}"))?;
        let mut rows = ids_stmt.query(rusqlite::params_from_iter(params.iter()))?;
        let mut ids_local = Vec::new();
        while let Some(row) = rows.next()? {
            ids_local.push(row.get::<_, i64>(0)?);
        }
        ids_local
    };

    if ids.is_empty() {
        tx.commit()?;
        return Ok(0);
    }

    // Delete from FTS5 (contentless) using delete pseudo-ops
    {
        let mut stmt_delete_fts =
            tx.prepare("INSERT INTO event_text(event_text, rowid) VALUES('delete', ?)")?;
        for id in ids.iter() {
            stmt_delete_fts.execute([id])?;
        }
    }

    let placeholders = vec!["?"; ids.len()].join(",");
    tx.execute(
        &format!("DELETE FROM events WHERE id IN ({})", placeholders),
        rusqlite::params_from_iter(ids.iter()),
    )?;

    tx.commit()?;
    Ok(ids.len())
}

pub fn generate_report(pool: &DbPool, req: &ReportRequest) -> Result<ReportResponse, AppError> {
    let conn = pool.get()?;
    let mut conditions = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(from) = &req.from {
        conditions.push("timestamp >= ?".to_string());
        params.push(Box::new(from.clone()));
    }
    if let Some(to) = &req.to {
        conditions.push("timestamp <= ?".to_string());
        params.push(Box::new(to.clone()));
    }
    if let Some(host) = &req.host {
        conditions.push("computer = ?".to_string());
        params.push(Box::new(host.clone()));
    }
    if let Some(user) = &req.user {
        conditions.push("user = ?".to_string());
        params.push(Box::new(user.clone()));
    }
    if let Some(ioc) = &req.ioc {
        conditions.push("(event_data_json LIKE ? OR raw_xml LIKE ?)".to_string());
        let patt = format!("%{}%", ioc);
        params.push(Box::new(patt.clone()));
        params.push(Box::new(patt));
    }

    let where_clause = if conditions.is_empty() {
        "1=1".to_string()
    } else {
        conditions.join(" AND ")
    };

    let total_events: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM events WHERE {where_clause}"),
        rusqlite::params_from_iter(params.iter()),
        |r| r.get(0),
    )?;
    let unique_users: i64 = conn.query_row(
        &format!("SELECT COUNT(DISTINCT user) FROM events WHERE {where_clause}"),
        rusqlite::params_from_iter(params.iter()),
        |r| r.get(0),
    )?;
    let unique_hosts: i64 = conn.query_row(
        &format!("SELECT COUNT(DISTINCT computer) FROM events WHERE {where_clause}"),
        rusqlite::params_from_iter(params.iter()),
        |r| r.get(0),
    )?;

    let logons: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM events WHERE {where_clause} AND event_id IN (4624,4625)"),
        rusqlite::params_from_iter(params.iter()),
        |r| r.get(0),
    )?;
    let process_creations: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM events WHERE {where_clause} AND event_id IN (4688)"),
        rusqlite::params_from_iter(params.iter()),
        |r| r.get(0),
    )?;
    let clear_logs: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM events WHERE {where_clause} AND event_id IN (1102)"),
        rusqlite::params_from_iter(params.iter()),
        |r| r.get(0),
    )?;
    let services: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM events WHERE {where_clause} AND event_id IN (7045)"),
        rusqlite::params_from_iter(params.iter()),
        |r| r.get(0),
    )?;

    let mut timeline_stmt = conn.prepare(&format!(
        "SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) AS bucket, COUNT(*) as c
         FROM events WHERE {where_clause} GROUP BY bucket ORDER BY bucket"
    ))?;
    let timeline = timeline_stmt
        .query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok(TimelineBucket {
                bucket: row.get(0)?,
                count: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut key_stmt = conn.prepare(&format!(
        "SELECT id, event_id, timestamp, computer, channel, record_id, level, opcode, task,
                user, sid, keywords, source, ingest_path, event_data_json, raw_xml
         FROM events
         WHERE {where_clause} AND event_id IN (4624,4625,4688,7045,1102)
         ORDER BY timestamp DESC
         LIMIT 200"
    ))?;
    let mut key_rows = key_stmt.query(rusqlite::params_from_iter(params.iter()))?;
    let mut key_events = Vec::new();
    while let Some(row) = key_rows.next()? {
        let data: String = row.get(14)?;
        key_events.push(Event {
            id: row.get(0)?,
            event_id: row.get::<_, i64>(1)? as u32,
            timestamp: row.get(2)?,
            computer: row.get(3)?,
            channel: row.get(4)?,
            record_id: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
            level: row.get::<_, Option<i64>>(6)?.map(|v| v as u32),
            opcode: row.get::<_, Option<i64>>(7)?.map(|v| v as u32),
            task: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
            user: row.get(9)?,
            sid: row.get(10)?,
            keywords: row.get(11)?,
            source: row.get(12)?,
            ingest_path: row.get(13)?,
            event_data_json: serde_json::from_str(&data)?,
            raw_xml: row.get(15)?,
        });
    }

    let suspicious = suspicious_events(pool, 100, 0)?;

    let summary = ReportSummary {
        total_events,
        unique_users,
        unique_hosts,
        logons,
        process_creations,
        clear_logs,
        services,
    };

    let meta = ReportMeta {
        case_name: req.case_name.clone().unwrap_or_else(|| "Case".to_string()),
        analyst: req.analyst.clone().unwrap_or_else(|| "Analyst".to_string()),
        generated_at: chrono::Utc::now().to_rfc3339(),
        filters: ReportFiltersOut {
            from: req.from.clone(),
            to: req.to.clone(),
            host: req.host.clone(),
            user: req.user.clone(),
            ioc: req.ioc.clone(),
        },
    };

    Ok(ReportResponse {
        metadata: meta,
        summary,
        timeline,
        key_events,
        suspicious,
    })
}

const PROCESS_NAME_EXPR: &str = "COALESCE(json_extract(event_data_json,'$.Event.EventData.NewProcessName'), \
    json_extract(event_data_json,'$.Event.EventData.ProcessName'), \
    json_extract(event_data_json,'$.Event.EventData.Image'), '')";
const PROCESS_ORIGINAL_NAME_EXPR: &str = "COALESCE(json_extract(event_data_json,'$.Event.EventData.OriginalFileName'), \
    json_extract(event_data_json,'$.Event.EventData.OriginalName'), '')";
const PROCESS_CMDLINE_EXPR: &str = "COALESCE(json_extract(event_data_json,'$.Event.EventData.CommandLine'), \
    json_extract(event_data_json,'$.Event.EventData.ProcessCommandLine'), \
    json_extract(event_data_json,'$.Event.EventData.ScriptBlockText'), \
    json_extract(event_data_json,'$.Event.EventData.Payload'), \
    event_data_json, raw_xml, '')";
const SCRIPT_BLOCK_EXPR: &str = "COALESCE(json_extract(event_data_json,'$.Event.EventData.ScriptBlockText'), \
    json_extract(event_data_json,'$.Event.EventData.Payload'), \
    event_data_json, raw_xml, '')";
const SHARE_NAME_EXPR: &str =
    "COALESCE(json_extract(event_data_json,'$.Event.EventData.ShareName'), '')";
const AUTH_PACKAGE_EXPR: &str = "COALESCE(json_extract(event_data_json,'$.Event.EventData.AuthenticationPackageName'), '')";
const WORKSTATION_NAME_EXPR: &str =
    "COALESCE(json_extract(event_data_json,'$.Event.EventData.WorkstationName'), '')";
const TICKET_ENCRYPTION_EXPR: &str = "COALESCE(json_extract(event_data_json,'$.Event.EventData.TicketEncryptionType'), \
    json_extract(event_data_json,'$.Event.EventData.TicketEncryption'), '')";
const FAILURE_CODE_EXPR: &str = "COALESCE(json_extract(event_data_json,'$.Event.EventData.FailureCode'), \
    json_extract(event_data_json,'$.Event.EventData.Status'), '')";
const PRE_AUTH_TYPE_EXPR: &str =
    "COALESCE(json_extract(event_data_json,'$.Event.EventData.PreAuthType'), '')";
const LOGON_GUID_EXPR: &str =
    "COALESCE(json_extract(event_data_json,'$.Event.EventData.LogonGuid'), '')";
const TARGET_DOMAIN_NAME_EXPR: &str = "COALESCE(json_extract(event_data_json,'$.Event.EventData.TargetDomainName'), \
    json_extract(event_data_json,'$.Event.EventData.SubjectDomainName'), '')";
const PROPERTIES_EXPR: &str =
    "COALESCE(json_extract(event_data_json,'$.Event.EventData.Properties'), '')";
const OBJECT_NAME_EXPR: &str =
    "COALESCE(json_extract(event_data_json,'$.Event.EventData.ObjectName'), '')";
const OBJECT_DN_EXPR: &str = "COALESCE(json_extract(event_data_json,'$.Event.EventData.ObjectDN'), \
    json_extract(event_data_json,'$.Event.EventData.ObjectDn'), '')";
const PRIVILEGE_LIST_EXPR: &str =
    "COALESCE(json_extract(event_data_json,'$.Event.EventData.PrivilegeList'), '')";
const PRIVILEGE_NAME_EXPR: &str =
    "COALESCE(json_extract(event_data_json,'$.Event.EventData.PrivilegeName'), '')";
const PARENT_PROCESS_EXPR: &str = "COALESCE(json_extract(event_data_json,'$.Event.EventData.ParentProcessName'), \
    json_extract(event_data_json,'$.Event.EventData.ParentImage'), '')";
const IP_ADDRESS_EXPR: &str = "COALESCE(json_extract(event_data_json,'$.Event.EventData.IpAddress'), \
    json_extract(event_data_json,'$.Event.EventData.SourceAddress'), \
    json_extract(event_data_json,'$.Event.EventData.DestAddress'), '')";

const DETECTION_UI_LIMIT: usize = 200;
const CORRELATION_SCAN_LIMIT: usize = 20_000;

#[derive(Debug, Clone, Default)]
struct DetectionFilter {
    event_id: Option<Vec<u32>>,
    channel: Option<Vec<String>>,
    user: Option<Vec<String>>,
    exclude_user: Option<Vec<String>>,
    process_name: Option<Vec<String>>,
    process_cmdline_regex: Option<String>,
    process_name_regex: Option<String>,
    process_original_name_regex: Option<String>,
    script_block_regex: Option<String>,
    share_name_regex: Option<String>,
    auth_package_regex: Option<String>,
    workstation_name_regex: Option<String>,
    ticket_encryption_regex: Option<String>,
    failure_code_regex: Option<String>,
    pre_auth_type_regex: Option<String>,
    logon_guid_regex: Option<String>,
    target_domain_name_regex: Option<String>,
    properties_regex: Option<String>,
    object_name_regex: Option<String>,
    object_dn_regex: Option<String>,
    privilege_list_regex: Option<String>,
    privilege_name_regex: Option<String>,
    parent_process_regex: Option<String>,
    ip_address_regex: Option<String>,
    exclude_process: Option<Vec<String>>,
    keywords: Option<Vec<String>>,
    ip: Option<Vec<String>>,
    logon_type: Option<Vec<u32>>,
}

impl DetectionFilter {
    fn from_rule(rule: &DetectionRule) -> Self {
        Self {
            event_id: rule.event_id.clone(),
            channel: rule.channel.clone(),
            user: rule.user.clone(),
            exclude_user: rule.exclude_user.clone(),
            process_name: rule.process_name.clone(),
            process_cmdline_regex: rule.process_cmdline_regex.clone(),
            process_name_regex: rule.process_name_regex.clone(),
            process_original_name_regex: rule.process_original_name_regex.clone(),
            script_block_regex: rule.script_block_regex.clone(),
            share_name_regex: rule.share_name_regex.clone(),
            auth_package_regex: rule.auth_package_regex.clone(),
            workstation_name_regex: rule.workstation_name_regex.clone(),
            ticket_encryption_regex: rule.ticket_encryption_regex.clone(),
            failure_code_regex: rule.failure_code_regex.clone(),
            pre_auth_type_regex: rule.pre_auth_type_regex.clone(),
            logon_guid_regex: rule.logon_guid_regex.clone(),
            target_domain_name_regex: rule.target_domain_name_regex.clone(),
            properties_regex: rule.properties_regex.clone(),
            object_name_regex: rule.object_name_regex.clone(),
            object_dn_regex: rule.object_dn_regex.clone(),
            privilege_list_regex: rule.privilege_list_regex.clone(),
            privilege_name_regex: rule.privilege_name_regex.clone(),
            parent_process_regex: rule.parent_process_regex.clone(),
            ip_address_regex: rule.ip_address_regex.clone(),
            exclude_process: rule.exclude_process.clone(),
            keywords: rule.keywords.clone(),
            ip: rule.ip.clone(),
            logon_type: rule.logon_type.clone(),
        }
    }

    fn from_step(step: &CorrelationStep) -> Self {
        Self {
            event_id: step.event_id.clone(),
            channel: step.channel.clone(),
            user: step.user.clone(),
            exclude_user: step.exclude_user.clone(),
            process_name: step.process_name.clone(),
            process_cmdline_regex: step.process_cmdline_regex.clone(),
            process_name_regex: step.process_name_regex.clone(),
            process_original_name_regex: step.process_original_name_regex.clone(),
            script_block_regex: step.script_block_regex.clone(),
            share_name_regex: step.share_name_regex.clone(),
            auth_package_regex: step.auth_package_regex.clone(),
            workstation_name_regex: step.workstation_name_regex.clone(),
            ticket_encryption_regex: step.ticket_encryption_regex.clone(),
            failure_code_regex: step.failure_code_regex.clone(),
            pre_auth_type_regex: step.pre_auth_type_regex.clone(),
            logon_guid_regex: step.logon_guid_regex.clone(),
            target_domain_name_regex: step.target_domain_name_regex.clone(),
            properties_regex: step.properties_regex.clone(),
            object_name_regex: step.object_name_regex.clone(),
            object_dn_regex: step.object_dn_regex.clone(),
            privilege_list_regex: step.privilege_list_regex.clone(),
            privilege_name_regex: step.privilege_name_regex.clone(),
            parent_process_regex: step.parent_process_regex.clone(),
            ip_address_regex: step.ip_address_regex.clone(),
            exclude_process: step.exclude_process.clone(),
            keywords: step.keywords.clone(),
            ip: step.ip.clone(),
            logon_type: step.logon_type.clone(),
        }
    }

    fn from_correlation(cfg: &CorrelationConfig) -> Self {
        Self {
            event_id: cfg.event_id.clone(),
            logon_type: cfg.logon_type.clone(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
struct CorrEvent {
    event: Event,
    ts: i64,
}

fn append_detection_filter_conditions(
    filter: &DetectionFilter,
    conds: &mut Vec<String>,
    params: &mut Vec<Box<dyn rusqlite::ToSql>>,
) {
    if let Some(ids) = &filter.event_id {
        let list = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        conds.push(format!("event_id IN ({list})"));
        for id in ids {
            params.push(Box::new(*id as i64));
        }
    }
    if let Some(channels) = &filter.channel {
        let list = channels.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        conds.push(format!("channel IN ({list})"));
        for c in channels {
            params.push(Box::new(c.clone()));
        }
    }
    if let Some(users) = &filter.user {
        let list = users.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        conds.push(format!("user IN ({list})"));
        for u in users {
            params.push(Box::new(u.clone()));
        }
    }
    if let Some(exclude_users) = &filter.exclude_user {
        for u in exclude_users {
            conds.push("LOWER(COALESCE(user, '')) <> LOWER(?)".to_string());
            params.push(Box::new(u.clone()));
        }
    }
    if let Some(proc_names) = &filter.process_name {
        let mut proc_conds = Vec::new();
        for p in proc_names {
            proc_conds.push(format!("{PROCESS_NAME_EXPR} LIKE ?"));
            params.push(Box::new(format!("%{p}%")));
        }
        if !proc_conds.is_empty() {
            conds.push(format!("({})", proc_conds.join(" OR ")));
        }
    }
    if let Some(exclude_process) = &filter.exclude_process {
        for p in exclude_process {
            conds.push(format!("{PROCESS_NAME_EXPR} NOT LIKE ?"));
            params.push(Box::new(format!("%{p}%")));
        }
    }
    if let Some(keys) = &filter.keywords {
        let mut key_conds = Vec::new();
        for k in keys {
            key_conds.push("COALESCE(keywords, '') LIKE ?".to_string());
            params.push(Box::new(format!("%{k}%")));
        }
        if !key_conds.is_empty() {
            conds.push(format!("({})", key_conds.join(" OR ")));
        }
    }
    if let Some(ips) = &filter.ip {
        let mut ip_conds = Vec::new();
        for ip in ips {
            ip_conds.push(
                "(COALESCE(json_extract(event_data_json,'$.Event.EventData.IpAddress'), '') = ? \
                  OR COALESCE(json_extract(event_data_json,'$.Event.EventData.SourceAddress'), '') = ? \
                  OR COALESCE(json_extract(event_data_json,'$.Event.EventData.DestAddress'), '') = ?)"
                    .to_string(),
            );
            params.push(Box::new(ip.clone()));
            params.push(Box::new(ip.clone()));
            params.push(Box::new(ip.clone()));
        }
        if !ip_conds.is_empty() {
            conds.push(format!("({})", ip_conds.join(" OR ")));
        }
    }
    if let Some(types) = &filter.logon_type {
        let mut type_conds = Vec::new();
        for t in types {
            type_conds.push(
                "CAST(COALESCE(json_extract(event_data_json,'$.Event.EventData.LogonType'), '') AS INTEGER) = ?"
                    .to_string(),
            );
            params.push(Box::new(*t as i64));
        }
        if !type_conds.is_empty() {
            conds.push(format!("({})", type_conds.join(" OR ")));
        }
    }

    let add_regex = |conds: &mut Vec<String>,
                     params: &mut Vec<Box<dyn rusqlite::ToSql>>,
                     pattern: &Option<String>,
                     expr: &str| {
        if let Some(value) = pattern {
            conds.push(format!("REGEXP(?, {expr})"));
            params.push(Box::new(value.clone()));
        }
    };

    add_regex(
        conds,
        params,
        &filter.process_cmdline_regex,
        PROCESS_CMDLINE_EXPR,
    );
    add_regex(conds, params, &filter.process_name_regex, PROCESS_NAME_EXPR);
    add_regex(
        conds,
        params,
        &filter.process_original_name_regex,
        PROCESS_ORIGINAL_NAME_EXPR,
    );
    add_regex(conds, params, &filter.script_block_regex, SCRIPT_BLOCK_EXPR);
    add_regex(conds, params, &filter.share_name_regex, SHARE_NAME_EXPR);
    add_regex(conds, params, &filter.auth_package_regex, AUTH_PACKAGE_EXPR);
    add_regex(
        conds,
        params,
        &filter.workstation_name_regex,
        WORKSTATION_NAME_EXPR,
    );
    add_regex(
        conds,
        params,
        &filter.ticket_encryption_regex,
        TICKET_ENCRYPTION_EXPR,
    );
    add_regex(conds, params, &filter.failure_code_regex, FAILURE_CODE_EXPR);
    add_regex(conds, params, &filter.pre_auth_type_regex, PRE_AUTH_TYPE_EXPR);
    add_regex(conds, params, &filter.logon_guid_regex, LOGON_GUID_EXPR);
    add_regex(
        conds,
        params,
        &filter.target_domain_name_regex,
        TARGET_DOMAIN_NAME_EXPR,
    );
    add_regex(conds, params, &filter.properties_regex, PROPERTIES_EXPR);
    add_regex(conds, params, &filter.object_name_regex, OBJECT_NAME_EXPR);
    add_regex(conds, params, &filter.object_dn_regex, OBJECT_DN_EXPR);
    add_regex(conds, params, &filter.privilege_list_regex, PRIVILEGE_LIST_EXPR);
    add_regex(conds, params, &filter.privilege_name_regex, PRIVILEGE_NAME_EXPR);
    add_regex(conds, params, &filter.parent_process_regex, PARENT_PROCESS_EXPR);
    add_regex(conds, params, &filter.ip_address_regex, IP_ADDRESS_EXPR);
}

fn query_detection_events(
    conn: &rusqlite::Connection,
    filter: &DetectionFilter,
    limit: usize,
    desc: bool,
) -> Result<Vec<Event>, AppError> {
    let mut conds = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    append_detection_filter_conditions(filter, &mut conds, &mut params);
    let where_clause = if conds.is_empty() {
        "1=1".to_string()
    } else {
        conds.join(" AND ")
    };

    let order_by = if desc {
        "ORDER BY datetime(timestamp) DESC, timestamp DESC"
    } else {
        "ORDER BY datetime(timestamp) ASC, timestamp ASC"
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT id, event_id, timestamp, computer, channel, record_id, level, opcode, task,
                user, sid, keywords, source, ingest_path, event_data_json, raw_xml
         FROM events
         WHERE {where_clause}
         {order_by}
         LIMIT ?"
    ))?;
    params.push(Box::new(limit as i64));

    let mut rows = stmt.query(rusqlite::params_from_iter(params.iter()))?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        events.push(map_event_row(row)?);
    }
    Ok(events)
}

fn count_detection_events(
    conn: &rusqlite::Connection,
    filter: &DetectionFilter,
) -> Result<usize, AppError> {
    let mut conds = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    append_detection_filter_conditions(filter, &mut conds, &mut params);
    let where_clause = if conds.is_empty() {
        "1=1".to_string()
    } else {
        conds.join(" AND ")
    };
    let count: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM events WHERE {where_clause}"),
        rusqlite::params_from_iter(params.iter()),
        |row| row.get(0),
    )?;
    Ok(count.max(0) as usize)
}

fn map_event_row(row: &rusqlite::Row<'_>) -> Result<Event, AppError> {
    let data: String = row.get(14)?;
    Ok(Event {
        id: row.get(0)?,
        event_id: row.get::<_, i64>(1)? as u32,
        timestamp: row.get(2)?,
        computer: row.get(3)?,
        channel: row.get(4)?,
        record_id: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
        level: row.get::<_, Option<i64>>(6)?.map(|v| v as u32),
        opcode: row.get::<_, Option<i64>>(7)?.map(|v| v as u32),
        task: row.get::<_, Option<i64>>(8)?.map(|v| v as u32),
        user: row.get(9)?,
        sid: row.get(10)?,
        keywords: row.get(11)?,
        source: row.get(12)?,
        ingest_path: row.get(13)?,
        event_data_json: serde_json::from_str(&data)?,
        raw_xml: row.get(15)?,
    })
}

fn detection_filter_has_criteria(filter: &DetectionFilter) -> bool {
    filter.event_id.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
        || filter.channel.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
        || filter.user.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
        || filter.exclude_user.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
        || filter
            .process_name
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        || filter.process_cmdline_regex.is_some()
        || filter.process_name_regex.is_some()
        || filter.process_original_name_regex.is_some()
        || filter.script_block_regex.is_some()
        || filter.share_name_regex.is_some()
        || filter.auth_package_regex.is_some()
        || filter.workstation_name_regex.is_some()
        || filter.ticket_encryption_regex.is_some()
        || filter.failure_code_regex.is_some()
        || filter.pre_auth_type_regex.is_some()
        || filter.logon_guid_regex.is_some()
        || filter.target_domain_name_regex.is_some()
        || filter.properties_regex.is_some()
        || filter.object_name_regex.is_some()
        || filter.object_dn_regex.is_some()
        || filter.privilege_list_regex.is_some()
        || filter.privilege_name_regex.is_some()
        || filter.parent_process_regex.is_some()
        || filter.ip_address_regex.is_some()
        || filter
            .exclude_process
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        || filter
            .keywords
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false)
        || filter.ip.as_ref().map(|v| !v.is_empty()).unwrap_or(false)
        || filter
            .logon_type
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false)
}

fn parse_event_datetime(timestamp: &str) -> Option<DateTime<FixedOffset>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(timestamp) {
        return Some(dt);
    }

    let offset = FixedOffset::east_opt(3 * 60 * 60)?;
    for fmt in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(timestamp, fmt) {
            if let Some(dt) = offset.from_local_datetime(&naive).single() {
                return Some(dt);
            }
        }
    }

    None
}

fn parse_event_timestamp(timestamp: &str) -> Option<i64> {
    parse_event_datetime(timestamp).map(|dt| dt.timestamp())
}

fn parse_hhmm_minutes(value: &str) -> Option<u32> {
    let mut parts = value.trim().split(':');
    let hour = parts.next()?.trim().parse::<u32>().ok()?;
    let minute = parts.next()?.trim().parse::<u32>().ok()?;
    if hour < 24 && minute < 60 {
        Some(hour * 60 + minute)
    } else {
        None
    }
}

fn matches_time_filter(event: &CorrEvent, filter: Option<&CorrelationTimeFilter>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let Some(dt) = parse_event_datetime(&event.event.timestamp) else {
        return false;
    };

    let mut has_condition = false;
    let mut matched = false;

    if filter.or_weekends.unwrap_or(false) {
        has_condition = true;
        matched |= dt.weekday().number_from_monday() >= 6;
    }

    if let Some(hours) = &filter.hours_outside {
        if hours.len() >= 2 {
            if let (Some(start), Some(end)) = (
                parse_hhmm_minutes(&hours[0]),
                parse_hhmm_minutes(&hours[1]),
            ) {
                has_condition = true;
                let current = dt.hour() * 60 + dt.minute();
                let inside_business = if start <= end {
                    current >= start && current < end
                } else {
                    current >= start || current < end
                };
                matched |= !inside_business;
            }
        }
    }

    if has_condition {
        matched
    } else {
        true
    }
}

fn clean_value(value: Option<String>) -> Option<String> {
    let raw = value?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "-" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn extract_json_string(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }

    match current {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Object(map) => map
            .get("#text")
            .or_else(|| map.get("#value"))
            .or_else(|| map.get("value"))
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            }),
        _ => None,
    }
}

fn event_field_value(event: &Event, field: &str) -> Option<String> {
    let key = field.trim().to_ascii_lowercase();
    let data = &event.event_data_json;

    match key.as_str() {
        "host" => clean_value(Some(event.computer.clone())),
        "user" => clean_value(event.user.clone())
            .or_else(|| clean_value(extract_json_string(data, &["Event", "EventData", "TargetUserName"])))
            .or_else(|| clean_value(extract_json_string(data, &["Event", "EventData", "SubjectUserName"]))),
        "target_user" => clean_value(extract_json_string(
            data,
            &["Event", "EventData", "TargetUserName"],
        ))
        .or_else(|| clean_value(event.user.clone())),
        "subject_user" => clean_value(extract_json_string(
            data,
            &["Event", "EventData", "SubjectUserName"],
        ))
        .or_else(|| clean_value(event.user.clone())),
        "source_host" => clean_value(extract_json_string(
            data,
            &["Event", "EventData", "WorkstationName"],
        ))
        .or_else(|| clean_value(extract_json_string(data, &["Event", "EventData", "SourceWorkstation"])))
        .or_else(|| clean_value(extract_json_string(data, &["Event", "EventData", "IpAddress"])))
        .or_else(|| clean_value(extract_json_string(data, &["Event", "EventData", "SourceAddress"])))
        .or_else(|| clean_value(Some(event.computer.clone()))),
        "event_id" => Some(event.event_id.to_string()),
        "channel" => clean_value(Some(event.channel.clone())),
        other => clean_value(extract_json_string(data, &["Event", "EventData", other]))
            .or_else(|| clean_value(extract_json_string(data, &["Event", "EventData", field]))),
    }
}

fn build_group_key(event: &Event, group_by: &[String]) -> String {
    if group_by.is_empty() {
        return "__all__".to_string();
    }

    group_by
        .iter()
        .map(|field| {
            let value = event_field_value(event, field)
                .unwrap_or_else(|| "<null>".to_string())
                .to_ascii_lowercase();
            format!("{}={value}", field.to_ascii_lowercase())
        })
        .collect::<Vec<_>>()
        .join("\u{1f}")
}

fn to_corr_events(events: Vec<Event>) -> Vec<CorrEvent> {
    events
        .into_iter()
        .filter_map(|event| {
            parse_event_timestamp(&event.timestamp).map(|ts| CorrEvent { event, ts })
        })
        .collect()
}

fn dedupe_corr_events(mut events: Vec<CorrEvent>) -> Vec<CorrEvent> {
    let mut seen = HashSet::new();
    events.retain(|item| seen.insert(item.event.id));
    events.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.event.id.cmp(&b.event.id)));
    events
}

fn build_correlation_result_events(mut events: Vec<CorrEvent>) -> Vec<Event> {
    let mut seen = HashSet::new();
    events.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.event.id.cmp(&a.event.id)));
    events
        .into_iter()
        .filter(|item| seen.insert(item.event.id))
        .take(DETECTION_UI_LIMIT)
        .map(|item| item.event)
        .collect()
}

fn upper_bound_ts(events: &[CorrEvent], ts: i64) -> usize {
    let mut low = 0usize;
    let mut high = events.len();
    while low < high {
        let mid = (low + high) / 2;
        if events[mid].ts <= ts {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    low
}

fn select_step_window(
    events: &[CorrEvent],
    start_ts: i64,
    end_ts: i64,
    min_count: usize,
) -> Option<(i64, Vec<CorrEvent>)> {
    let required = min_count.max(1);
    let mut matched = Vec::new();

    for item in events {
        if item.ts < start_ts {
            continue;
        }
        if item.ts > end_ts {
            break;
        }
        matched.push(item.clone());
        if matched.len() == required {
            let last_ts = matched.last().map(|v| v.ts).unwrap_or(start_ts);
            return Some((last_ts, matched));
        }
    }

    None
}

fn collect_rule_reference_events(
    conn: &rusqlite::Connection,
    rule_id: &str,
    simple_rules_by_id: &HashMap<String, Vec<DetectionRule>>,
    cache: &mut HashMap<String, Vec<CorrEvent>>,
) -> Result<Vec<CorrEvent>, AppError> {
    if let Some(cached) = cache.get(rule_id) {
        return Ok(cached.clone());
    }

    let mut events = Vec::new();
    if let Some(rules) = simple_rules_by_id.get(rule_id) {
        for rule in rules {
            let filter = DetectionFilter::from_rule(rule);
            let queried = query_detection_events(conn, &filter, CORRELATION_SCAN_LIMIT, false)?;
            events.extend(to_corr_events(queried));
        }
    }

    let events = dedupe_corr_events(events);
    cache.insert(rule_id.to_string(), events.clone());
    Ok(events)
}

fn load_sequence_step_events(
    conn: &rusqlite::Connection,
    step: &CorrelationStep,
    simple_rules_by_id: &HashMap<String, Vec<DetectionRule>>,
    cache: &mut HashMap<String, Vec<CorrEvent>>,
) -> Result<Vec<CorrEvent>, AppError> {
    if let Some(rule_id) = &step.rule_id {
        let mut referenced = collect_rule_reference_events(conn, rule_id, simple_rules_by_id, cache)?;
        let step_filter = DetectionFilter::from_step(step);
        if detection_filter_has_criteria(&step_filter) {
            let step_events = query_detection_events(conn, &step_filter, CORRELATION_SCAN_LIMIT, false)?;
            let allowed_ids: HashSet<i64> = step_events.into_iter().map(|e| e.id).collect();
            referenced.retain(|e| allowed_ids.contains(&e.event.id));
        }
        return Ok(referenced);
    }

    let step_filter = DetectionFilter::from_step(step);
    if !detection_filter_has_criteria(&step_filter) {
        return Ok(Vec::new());
    }

    let queried = query_detection_events(conn, &step_filter, CORRELATION_SCAN_LIMIT, false)?;
    Ok(to_corr_events(queried))
}

fn evaluate_sequence_correlation(
    conn: &rusqlite::Connection,
    cfg: &CorrelationConfig,
    simple_rules_by_id: &HashMap<String, Vec<DetectionRule>>,
    cache: &mut HashMap<String, Vec<CorrEvent>>,
) -> Result<(usize, Vec<Event>), AppError> {
    let Some(steps) = &cfg.steps else {
        return Ok((0, Vec::new()));
    };
    if steps.is_empty() {
        return Ok((0, Vec::new()));
    }

    let mut indexed_steps: Vec<(usize, CorrelationStep)> = steps.iter().cloned().enumerate().collect();
    indexed_steps.sort_by_key(|(index, step)| (step.step.unwrap_or((*index + 1) as u32), *index));
    let ordered_steps: Vec<CorrelationStep> = indexed_steps.into_iter().map(|(_, step)| step).collect();

    let group_by = cfg.group_by.clone().unwrap_or_default();
    let window_seconds = cfg.window.unwrap_or(300).max(1);
    let mut grouped_per_step: Vec<HashMap<String, Vec<CorrEvent>>> = Vec::new();

    for (index, step) in ordered_steps.iter().enumerate() {
        let mut step_events = load_sequence_step_events(conn, step, simple_rules_by_id, cache)?;
        if index == 0 {
            step_events.retain(|event| matches_time_filter(event, cfg.time_filter.as_ref()));
        }

        let mut grouped: HashMap<String, Vec<CorrEvent>> = HashMap::new();
        for event in step_events {
            let key = build_group_key(&event.event, &group_by);
            grouped.entry(key).or_default().push(event);
        }
        for entries in grouped.values_mut() {
            entries.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.event.id.cmp(&b.event.id)));
        }
        grouped_per_step.push(grouped);
    }

    let Some(first_grouped) = grouped_per_step.first() else {
        return Ok((0, Vec::new()));
    };

    let mut hits = 0usize;
    let mut matched_events = Vec::new();

    for (group_key, first_step_events) in first_grouped {
        let mut cursor = 0usize;
        while cursor < first_step_events.len() {
            let anchor = &first_step_events[cursor];
            let window_end = anchor.ts + window_seconds;
            let first_need = ordered_steps[0].min_count.unwrap_or(1);

            let Some((mut current_ts, mut chain_events)) =
                select_step_window(first_step_events, anchor.ts, window_end, first_need)
            else {
                cursor += 1;
                continue;
            };

            let first_step_end = current_ts;
            let mut ok = true;

            for (step_index, step) in ordered_steps.iter().enumerate().skip(1) {
                let needed = step.min_count.unwrap_or(1);
                let Some(step_group_events) = grouped_per_step[step_index].get(group_key) else {
                    ok = false;
                    break;
                };
                let Some((step_ts, step_matches)) =
                    select_step_window(step_group_events, current_ts, window_end, needed)
                else {
                    ok = false;
                    break;
                };
                current_ts = step_ts;
                chain_events.extend(step_matches);
            }

            if ok {
                hits += 1;
                matched_events.extend(chain_events);
                cursor = upper_bound_ts(first_step_events, first_step_end);
            } else {
                cursor += 1;
            }
        }
    }

    Ok((hits, build_correlation_result_events(dedupe_corr_events(matched_events))))
}

fn evaluate_threshold_correlation(
    conn: &rusqlite::Connection,
    cfg: &CorrelationConfig,
    simple_rules_by_id: &HashMap<String, Vec<DetectionRule>>,
    cache: &mut HashMap<String, Vec<CorrEvent>>,
) -> Result<(usize, Vec<Event>), AppError> {
    let window_seconds = cfg.window.unwrap_or(300).max(1);
    let min_count = cfg.min_count.unwrap_or(1).max(1);
    let group_by = cfg.group_by.clone().unwrap_or_default();

    let mut base_events = if let Some(rule_ids) = &cfg.rules {
        let mut events = Vec::new();
        for rule_id in rule_ids {
            events.extend(collect_rule_reference_events(
                conn,
                rule_id,
                simple_rules_by_id,
                cache,
            )?);
        }
        dedupe_corr_events(events)
    } else {
        let filter = DetectionFilter::from_correlation(cfg);
        if !detection_filter_has_criteria(&filter) {
            return Ok((0, Vec::new()));
        }
        to_corr_events(query_detection_events(
            conn,
            &filter,
            CORRELATION_SCAN_LIMIT,
            false,
        )?)
    };

    base_events.retain(|event| matches_time_filter(event, cfg.time_filter.as_ref()));
    if base_events.is_empty() {
        return Ok((0, Vec::new()));
    }

    let mut grouped: HashMap<String, Vec<CorrEvent>> = HashMap::new();
    for event in base_events {
        let key = build_group_key(&event.event, &group_by);
        grouped.entry(key).or_default().push(event);
    }
    for events in grouped.values_mut() {
        events.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.event.id.cmp(&b.event.id)));
    }

    let mut hits = 0usize;
    let mut matched_events = Vec::new();
    let distinct_field = cfg.count_distinct.as_deref().map(str::trim).filter(|v| !v.is_empty());

    for events in grouped.values() {
        if let Some(field) = distinct_field {
            let mut window: VecDeque<(CorrEvent, String)> = VecDeque::new();
            let mut frequencies: HashMap<String, usize> = HashMap::new();

            for event in events.iter().cloned() {
                let distinct_value = event_field_value(&event.event, field)
                    .unwrap_or_else(|| "<null>".to_string())
                    .to_ascii_lowercase();
                window.push_back((event.clone(), distinct_value.clone()));
                *frequencies.entry(distinct_value).or_insert(0) += 1;

                while let Some((front, front_value)) = window.front() {
                    if event.ts - front.ts > window_seconds {
                        let key = front_value.clone();
                        window.pop_front();
                        if let Some(count) = frequencies.get_mut(&key) {
                            *count -= 1;
                            if *count == 0 {
                                frequencies.remove(&key);
                            }
                        }
                    } else {
                        break;
                    }
                }

                if frequencies.len() >= min_count {
                    hits += 1;
                    matched_events.extend(window.iter().map(|(ev, _)| ev.clone()));
                    window.clear();
                    frequencies.clear();
                }
            }
        } else {
            let mut window: VecDeque<CorrEvent> = VecDeque::new();

            for event in events.iter().cloned() {
                window.push_back(event.clone());
                while let Some(front) = window.front() {
                    if event.ts - front.ts > window_seconds {
                        window.pop_front();
                    } else {
                        break;
                    }
                }

                if window.len() >= min_count {
                    hits += 1;
                    matched_events.extend(window.iter().cloned());
                    window.clear();
                }
            }
        }
    }

    Ok((hits, build_correlation_result_events(dedupe_corr_events(matched_events))))
}

pub fn run_detections(pool: &DbPool, rules_path: &Path) -> Result<Vec<DetectionMatch>, AppError> {
    let rules_text = fs::read_to_string(rules_path)
        .map_err(|e| AppError::BadRequest(format!("cannot read rules file: {e}")))?;
    let rules: Vec<DetectionRule> = if rules_path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
    {
        serde_json::from_str(&rules_text)?
    } else {
        serde_yaml::from_str(&rules_text)?
    };

    let conn = pool.get()?;
    let mut results = Vec::with_capacity(rules.len());
    let mut simple_rules_by_id: HashMap<String, Vec<DetectionRule>> = HashMap::new();
    let mut referenced_rule_ids = HashSet::new();

    for rule in &rules {
        if rule.correlation.is_none() {
            simple_rules_by_id
                .entry(rule.id.clone())
                .or_default()
                .push(rule.clone());
        }
        if let Some(cfg) = &rule.correlation {
            if let Some(steps) = &cfg.steps {
                for step in steps {
                    if let Some(rule_id) = &step.rule_id {
                        referenced_rule_ids.insert(rule_id.clone());
                    }
                }
            }
            if let Some(rule_ids) = &cfg.rules {
                for rule_id in rule_ids {
                    referenced_rule_ids.insert(rule_id.clone());
                }
            }
        }
    }

    let mut reference_cache: HashMap<String, Vec<CorrEvent>> = HashMap::new();
    for rule_id in referenced_rule_ids {
        let _ = collect_rule_reference_events(
            &conn,
            &rule_id,
            &simple_rules_by_id,
            &mut reference_cache,
        )?;
    }

    for rule in rules {
        if let Some(cfg) = &rule.correlation {
            let (hits, events) = match cfg.r#type.to_ascii_lowercase().as_str() {
                "sequence" => evaluate_sequence_correlation(
                    &conn,
                    cfg,
                    &simple_rules_by_id,
                    &mut reference_cache,
                )?,
                "threshold" => evaluate_threshold_correlation(
                    &conn,
                    cfg,
                    &simple_rules_by_id,
                    &mut reference_cache,
                )?,
                _ => (0, Vec::new()),
            };

            results.push(DetectionMatch { rule, hits, events });
            continue;
        }

        let filter = DetectionFilter::from_rule(&rule);
        let hits = count_detection_events(&conn, &filter)?;
        let events = query_detection_events(&conn, &filter, DETECTION_UI_LIMIT, true)?;
        results.push(DetectionMatch { rule, hits, events });
    }

    results.sort_by(|a, b| {
        b.hits.cmp(&a.hits).then_with(|| {
            if a.hits == 0 && b.hits == 0 {
                severity_rank(a.rule.severity.as_deref())
                    .cmp(&severity_rank(b.rule.severity.as_deref()))
            } else {
                a.rule.id.cmp(&b.rule.id)
            }
        })
    });

    Ok(results)
}

fn parse_json_field(data: String) -> Result<Value, rusqlite::Error> {
    serde_json::from_str(&data).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, Type::Text, Box::new(e))
    })
}

fn severity_rank(severity: Option<&str>) -> usize {
    match severity.unwrap_or("info").to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn memory_pool() -> DbPool {
        let manager = SqliteConnectionManager::memory()
            .with_init(|conn| {
                conn.busy_timeout(Duration::from_secs(5))?;
                conn.execute_batch("PRAGMA journal_mode=WAL;")?;
                register_regexp_function(conn)?;
                Ok(())
            });
        r2d2::Pool::builder().max_size(2).build(manager).unwrap()
    }

    fn write_temp_rules(contents: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("detections-test-{suffix}.yml"));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn stats_counts_records() {
        let pool = memory_pool();
        init_schema(&pool).unwrap();
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO events (event_id, timestamp, computer, channel, record_id, event_data_json, raw_xml) VALUES
             (4624, '2024-01-01T00:00:00Z', 'host', 'Security', 1, '{}', '<Event/>'),
             (4625, '2024-01-01T00:01:00Z', 'host', 'Security', 2, '{}', '<Event/>')",
            [],
        )
        .unwrap();

        let stats = stats(&pool, 10, None).unwrap();
        assert_eq!(stats.by_event_id.len(), 2);
    }

    #[test]
    fn detections_rules_file_parses_with_current_model() {
        let rules_text = std::fs::read_to_string("rules/detections.yml").unwrap();
        let rules: Vec<DetectionRule> = serde_yaml::from_str(&rules_text).unwrap();
        assert!(!rules.is_empty());
    }

    #[test]
    fn detections_support_process_cmdline_regex() {
        let pool = memory_pool();
        init_schema(&pool).unwrap();
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO events (event_id, timestamp, computer, channel, record_id, event_data_json, raw_xml)
             VALUES (4688, '2026-01-01T10:00:00+03:00', 'host1', 'Security', 10,
                     '{\"Event\":{\"EventData\":{\"NewProcessName\":\"powershell.exe\",\"CommandLine\":\"powershell.exe -enc AAAABBBB\"}}}',
                     '<Event/>')",
            [],
        )
        .unwrap();

        let rules = r#"
- id: ps-enc
  name: PowerShell Encoded
  event_id: [4688]
  process_cmdline_regex: "(?i)-enc\\s+[A-Za-z0-9+/]+"
"#;
        let path = write_temp_rules(rules);
        let res = run_detections(&pool, &path).unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].hits, 1);
        assert_eq!(res[0].events.len(), 1);
    }

    #[test]
    fn detections_support_auth_and_workstation_regex() {
        let pool = memory_pool();
        init_schema(&pool).unwrap();
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO events (event_id, timestamp, computer, channel, record_id, event_data_json, raw_xml)
             VALUES (4624, '2026-01-01T10:00:00+03:00', 'host2', 'Security', 20,
                     '{\"Event\":{\"EventData\":{\"LogonType\":\"3\",\"AuthenticationPackageName\":\"NTLM\",\"WorkstationName\":\"-\"}}}',
                     '<Event/>')",
            [],
        )
        .unwrap();

        let rules = r#"
- id: pth
  name: Pass the Hash Indicator
  event_id: [4624]
  logon_type: [3]
  auth_package_regex: "(?i)NTLM"
  workstation_name_regex: "^.{0,1}$"
"#;
        let path = write_temp_rules(rules);
        let res = run_detections(&pool, &path).unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].hits, 1);
        assert_eq!(res[0].events[0].event_id, 4624);
    }

    #[test]
    fn detections_zero_hits_are_sorted_by_severity() {
        let pool = memory_pool();
        init_schema(&pool).unwrap();

        let rules = r#"
- id: low-rule
  name: Low Rule
  severity: low
  event_id: [999999]
- id: critical-rule
  name: Critical Rule
  severity: critical
  event_id: [999998]
- id: high-rule
  name: High Rule
  severity: high
  event_id: [999997]
"#;
        let path = write_temp_rules(rules);
        let res = run_detections(&pool, &path).unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(res.len(), 3);
        assert_eq!(res[0].hits, 0);
        assert_eq!(res[1].hits, 0);
        assert_eq!(res[2].hits, 0);
        assert_eq!(res[0].rule.id, "critical-rule");
        assert_eq!(res[1].rule.id, "high-rule");
        assert_eq!(res[2].rule.id, "low-rule");
    }

    #[test]
    fn detections_support_sequence_correlation() {
        let pool = memory_pool();
        init_schema(&pool).unwrap();
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO events (event_id, timestamp, computer, channel, record_id, event_data_json, raw_xml) VALUES
             (4688, '2026-01-01T10:00:00+03:00', 'host-a', 'Security', 1,
              '{\"Event\":{\"EventData\":{\"NewProcessName\":\"net.exe\"}}}', '<Event/>'),
             (4624, '2026-01-01T10:02:00+03:00', 'host-a', 'Security', 2,
              '{\"Event\":{\"EventData\":{\"LogonType\":\"3\",\"TargetUserName\":\"alice\"}}}', '<Event/>'),
             (4688, '2026-01-01T11:00:00+03:00', 'host-b', 'Security', 3,
              '{\"Event\":{\"EventData\":{\"NewProcessName\":\"net.exe\"}}}', '<Event/>')",
            [],
        )
        .unwrap();

        let rules = r#"
- id: corr-seq
  name: Sequence Rule
  severity: critical
  correlation:
    type: sequence
    window: 300
    group_by: [host]
    steps:
      - step: 1
        event_id: [4688]
        process_name: ["net.exe"]
      - step: 2
        event_id: [4624]
        logon_type: [3]
"#;
        let path = write_temp_rules(rules);
        let res = run_detections(&pool, &path).unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].hits, 1);
        assert_eq!(res[0].rule.id, "corr-seq");
        assert_eq!(res[0].events.len(), 2);
    }

    #[test]
    fn detections_support_threshold_distinct_correlation() {
        let pool = memory_pool();
        init_schema(&pool).unwrap();
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO events (event_id, timestamp, computer, channel, record_id, event_data_json, raw_xml) VALUES
             (4625, '2026-01-01T10:00:00+03:00', 'dc1', 'Security', 10,
              '{\"Event\":{\"EventData\":{\"WorkstationName\":\"WS1\",\"TargetUserName\":\"alice\",\"LogonType\":\"3\"}}}', '<Event/>'),
             (4625, '2026-01-01T10:00:20+03:00', 'dc1', 'Security', 11,
              '{\"Event\":{\"EventData\":{\"WorkstationName\":\"WS1\",\"TargetUserName\":\"bob\",\"LogonType\":\"3\"}}}', '<Event/>'),
             (4625, '2026-01-01T10:00:40+03:00', 'dc1', 'Security', 12,
              '{\"Event\":{\"EventData\":{\"WorkstationName\":\"WS1\",\"TargetUserName\":\"charlie\",\"LogonType\":\"3\"}}}', '<Event/>')",
            [],
        )
        .unwrap();

        let rules = r#"
- id: corr-threshold
  name: Threshold Rule
  severity: high
  correlation:
    type: threshold
    window: 120
    group_by: [source_host]
    count_distinct: target_user
    min_count: 3
    event_id: [4625]
    logon_type: [3]
"#;
        let path = write_temp_rules(rules);
        let res = run_detections(&pool, &path).unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].hits, 1);
        assert_eq!(res[0].rule.id, "corr-threshold");
        assert_eq!(res[0].events.len(), 3);
    }

    #[test]
    fn detections_correlation_without_filters_does_not_match_all_events() {
        let pool = memory_pool();
        init_schema(&pool).unwrap();
        let conn = pool.get().unwrap();
        conn.execute(
            "INSERT INTO events (event_id, timestamp, computer, channel, record_id, event_data_json, raw_xml) VALUES
             (4688, '2026-01-01T10:00:00+03:00', 'host-a', 'Security', 1, '{}', '<Event/>'),
             (4624, '2026-01-01T10:00:10+03:00', 'host-a', 'Security', 2, '{}', '<Event/>')",
            [],
        )
        .unwrap();

        let rules = r#"
- id: corr-empty
  name: Empty Correlation
  severity: critical
  correlation:
    type: threshold
    window: 60
    group_by: [host]
    min_count: 2
"#;
        let path = write_temp_rules(rules);
        let res = run_detections(&pool, &path).unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(res.len(), 1);
        assert_eq!(res[0].rule.id, "corr-empty");
        assert_eq!(res[0].hits, 0);
        assert!(res[0].events.is_empty());
    }
}

fn run_migrations(pool: &DbPool) -> Result<(), AppError> {
    const MIGRATIONS: &[(u32, &str)] = &[
        (
            1,
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                computer TEXT NOT NULL,
                channel TEXT NOT NULL,
                record_id INTEGER,
                level INTEGER,
                opcode INTEGER,
                task INTEGER,
                user TEXT,
                sid TEXT,
                keywords TEXT,
                source TEXT,
                ingest_path TEXT,
                event_data_json TEXT NOT NULL,
                raw_xml TEXT NOT NULL
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS event_text USING fts5(
                event_data_json,
                raw_xml,
                content='',
                tokenize='porter'
            );

            CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_sid ON events(sid);
            CREATE INDEX IF NOT EXISTS idx_events_computer ON events(computer);
            "#,
        ),
        (
            2,
            r#"
            CREATE UNIQUE INDEX IF NOT EXISTS idx_events_channel_record
            ON events(channel, record_id)
            WHERE record_id IS NOT NULL;
            "#,
        ),
        (
            3,
            r#"
            DROP INDEX IF EXISTS idx_events_channel_record;
            CREATE INDEX IF NOT EXISTS idx_events_channel_record ON events(channel, record_id);
            "#,
        ),
        (
            4,
            r##"
            UPDATE events
            SET timestamp =
                substr(
                    strftime(
                        '%Y-%m-%dT%H:%M:%f',
                        COALESCE(
                            json_extract(event_data_json, '$.Event.System.TimeCreated."#attributes".SystemTime'),
                            json_extract(event_data_json, '$.Event.System.TimeCreated."@SystemTime"')
                        ),
                        '+3 hours'
                    ),
                    1,
                    23
                ) || '+03:00'
            WHERE COALESCE(
                    json_extract(event_data_json, '$.Event.System.TimeCreated."#attributes".SystemTime'),
                    json_extract(event_data_json, '$.Event.System.TimeCreated."@SystemTime"')
                ) IS NOT NULL;
            "##,
        ),
    ];

    let conn = pool.get()?;
    ensure_event_columns(&conn)?;
    let current_version: u32 = conn.query_row("PRAGMA user_version;", [], |row| row.get(0))?;

    for (version, sql) in MIGRATIONS {
        if current_version < *version {
            conn.execute_batch(sql)?;
            conn.pragma_update(None, "user_version", version)?;
        }
    }

    Ok(())
}

fn ensure_event_columns(conn: &rusqlite::Connection) -> Result<(), AppError> {
    let mut stmt = conn.prepare("PRAGMA table_info(events);")?;
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<_, _>>()?;

    if columns.is_empty() {
        return Ok(()); // table not created yet
    }

    let existing: HashSet<String> = columns.into_iter().collect();

    let add_column = |name: &str, ddl: &str| -> Result<(), AppError> {
        if !existing.contains(name) {
            conn.execute(&format!("ALTER TABLE events ADD COLUMN {ddl};"), [])?;
        }
        Ok(())
    };

    add_column("record_id", "record_id INTEGER")?;
    add_column("level", "level INTEGER")?;
    add_column("opcode", "opcode INTEGER")?;
    add_column("task", "task INTEGER")?;
    add_column("user", "user TEXT")?;
    add_column("sid", "sid TEXT")?;
    add_column("keywords", "keywords TEXT")?;
    add_column("source", "source TEXT")?;
    add_column("ingest_path", "ingest_path TEXT")?;
    add_column("event_data_json", "event_data_json TEXT NOT NULL DEFAULT '{}'")?;
    add_column("raw_xml", "raw_xml TEXT NOT NULL DEFAULT ''")?;

    Ok(())
}
