use crate::db::DbPool;
use crate::error::AppError;
use crate::models::Event;
use crate::parser::{map_record, ParsedRecord};
use crossbeam_channel::bounded;
use evtx::{EvtxParser, ParserSettings};
use rusqlite::params;
use std::path::Path;
use std::time::Instant;

const BATCH_SIZE: usize = 10_000;
const CHANNEL_BOUND: usize = 32;

pub struct IngestStats {
    pub ingested: usize,
    pub duration_ms: u128,
    pub parsed: usize,
}

pub fn ingest_file(
    path: &Path,
    pool: DbPool,
    threads: usize,
    channel_hint: Option<String>,
) -> Result<IngestStats, AppError> {
    let settings_json = ParserSettings::default().indent(false).num_threads(threads);
    let settings_xml = ParserSettings::default().indent(false).num_threads(threads);
    let mut parser_json = EvtxParser::from_path(path)?.with_configuration(settings_json);
    let mut parser_xml = EvtxParser::from_path(path)?.with_configuration(settings_xml);

    let start = Instant::now();
    let mut parsed_count = 0usize;
    let default_channel = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string());

    let (pool_tx, pool_rx) = bounded::<Vec<Event>>(CHANNEL_BOUND);
    for _ in 0..CHANNEL_BOUND {
        pool_tx
            .send(Vec::with_capacity(BATCH_SIZE))
            .map_err(|e| AppError::BadRequest(format!("pool send failed: {e}")))?;
    }

    let (sender, receiver) = bounded::<Vec<Event>>(CHANNEL_BOUND);
    let writer_pool = pool.clone();
    let writer_pool_tx = pool_tx.clone();
    let writer_handle = std::thread::spawn(move || -> Result<usize, AppError> {
        let mut conn = writer_pool.get()?;
        let mut inserted_total = 0usize;

        while let Ok(mut batch) = receiver.recv() {
            inserted_total += flush_batch(&mut conn, &mut batch)?;
            batch.clear();
            if writer_pool_tx.send(batch).is_err() {
                break;
            }
        }

        Ok(inserted_total)
    });

    let mut current_batch = pool_rx
        .recv()
        .map_err(|e| AppError::BadRequest(format!("pool recv failed: {e}")))?;

    let mut json_iter = parser_json.records_json_value();
    let mut xml_iter = parser_xml.records();
    let mut skipped = 0usize;

    loop {
        let next_json = json_iter.next();
        let next_xml = xml_iter.next();
        match (next_json, next_xml) {
            (Some(j), Some(x)) => match (j, x) {
                (Ok(json_record), Ok(xml_record)) => {
                    let parsed_record = ParsedRecord {
                        event_record_id: json_record.event_record_id,
                        timestamp: json_record.timestamp,
                        json: json_record.data,
                        raw_xml: xml_record.data,
                    };

                    let event = map_record(
                        parsed_record,
                        channel_hint.as_deref(),
                        default_channel.as_deref(),
                        Some(path.to_string_lossy().to_string()),
                    );
                    parsed_count += 1;
                    current_batch.push(event);
                    if current_batch.len() >= BATCH_SIZE {
                        sender
                            .send(current_batch)
                            .map_err(|e| AppError::BadRequest(format!("channel send failed: {e}")))?;
                        current_batch = pool_rx
                            .recv()
                            .map_err(|e| AppError::BadRequest(format!("pool recv failed: {e}")))?;
                    }
                }
                (Err(ej), Ok(_)) => {
                    skipped += 1;
                    tracing::warn!("evtx parse error (json) in {}: {ej}; record skipped", path.display());
                }
                (Ok(_), Err(ex)) => {
                    skipped += 1;
                    tracing::warn!("evtx parse error (xml) in {}: {ex}; record skipped", path.display());
                }
                (Err(ej), Err(ex)) => {
                    skipped += 1;
                    tracing::warn!(
                        "evtx parse error (json/xml) in {}: {ej}; {ex}; record skipped",
                        path.display()
                    );
                }
            },
            (None, None) => break,
            (Some(Ok(_)), None) | (None, Some(Ok(_))) => {
                tracing::warn!(
                    "evtx iterator mismatch for {}; remaining records dropped",
                    path.display()
                );
                break;
            }
            (Some(Err(e)), None) | (None, Some(Err(e))) => {
                skipped += 1;
                tracing::warn!(
                    "evtx parse error with iterator exhaustion in {}: {e}; stopping",
                    path.display()
                );
                break;
            }
        }
    }

    if !current_batch.is_empty() {
        sender
            .send(current_batch)
            .map_err(|e| AppError::BadRequest(format!("channel send failed: {e}")))?;
    } else {
        // return empty buffer to pool for reuse
        pool_tx
            .send(current_batch)
            .map_err(|e| AppError::BadRequest(format!("pool send failed: {e}")))?;
    }

    drop(sender);

    let inserted = writer_handle
        .join()
        .map_err(|_| AppError::Join("writer thread panicked".into()))??;

    let duration_ms = start.elapsed().as_millis();
    let eps = if duration_ms == 0 {
        inserted as f64
    } else {
        inserted as f64 / (duration_ms as f64 / 1000.0)
    };

    if parsed_count == 0 {
        tracing::warn!(
            "no records parsed from EVTX file {} (channel hint {:?})",
            path.display(),
            channel_hint
        );
    } else if inserted == 0 {
        tracing::warn!(
            "parsed {} records from {} but 0 inserted (possible duplicates or schema issue)",
            parsed_count,
            path.display()
        );
    } else {
        tracing::info!(
            "ingested {} records (parsed: {}, skipped: {}) in {} ms ({:.2} events/sec)",
            inserted,
            parsed_count,
            skipped,
            duration_ms,
            eps
        );
    }

    Ok(IngestStats {
        ingested: inserted,
        duration_ms,
        parsed: parsed_count,
    })
}

fn flush_batch(conn: &mut rusqlite::Connection, batch: &mut Vec<Event>) -> Result<usize, AppError> {
    if batch.is_empty() {
        return Ok(0);
    }

    let tx = conn.transaction()?;
    let mut inserted = 0usize;

    {
        let mut stmt_event = tx.prepare(
            r#"
            INSERT INTO events (
                event_id, timestamp, computer, channel, record_id, level, opcode, task,
                user, sid, keywords, source, ingest_path, event_data_json, raw_xml
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            "#,
        )?;

        let mut stmt_fts = tx.prepare(
            r#"
            INSERT INTO event_text (rowid, event_data_json, raw_xml)
            VALUES (?1, ?2, ?3)
            "#,
        )?;

        for event in batch.iter() {
            let data_string = serde_json::to_string(&event.event_data_json)?;
            let changed = stmt_event.execute(params![
                event.event_id as i64,
                event.timestamp,
                event.computer,
                event.channel,
            event.record_id.map(|v| v as i64),
            event.level.map(|v| v as i64),
            event.opcode.map(|v| v as i64),
            event.task.map(|v| v as i64),
            event.user,
            event.sid,
            event.keywords,
            event.source,
            event.ingest_path,
            &data_string,
            &event.raw_xml
        ])?;

            if changed > 0 {
                let rowid = tx.last_insert_rowid();
                stmt_fts.execute(params![rowid, data_string, event.raw_xml.clone()])?;
                inserted += 1;
            }
        }
    }

    tx.commit()?;
    Ok(inserted)
}
