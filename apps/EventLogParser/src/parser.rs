use crate::models::Event;
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde_json::Value;

#[derive(Debug)]
pub struct ParsedRecord {
    pub event_record_id: u64,
    pub timestamp: chrono::DateTime<Utc>,
    pub json: Value,
    pub raw_xml: String,
}

pub fn map_record(
    record: ParsedRecord,
    channel_hint: Option<&str>,
    default_channel: Option<&str>,
    ingest_path: Option<String>,
) -> Event {
    let event_time_utc = extract_system_time_utc(&record.json).unwrap_or(record.timestamp);
    let timestamp = event_time_utc
        .with_timezone(&utc_plus_three())
        .to_rfc3339_opts(SecondsFormat::Millis, true);

    let event_id = extract_event_id(&record.json).unwrap_or_default();
    let channel = channel_hint
        .map(|s| s.to_string())
        .or_else(|| extract_str(&record.json, &["Event", "System", "Channel"]).map(ToOwned::to_owned))
        .or_else(|| default_channel.map(ToOwned::to_owned))
        .unwrap_or_else(|| "Unknown".to_string());

    let computer = extract_str(&record.json, &["Event", "System", "Computer"])
        .unwrap_or("Unknown")
        .to_string();

    let user = extract_user(&record.json);
    let sid = extract_sid(&record.json);
    let level = extract_u32(&record.json, &["Event", "System", "Level"]);
    let opcode = extract_u32(&record.json, &["Event", "System", "Opcode"]);
    let task = extract_u32(&record.json, &["Event", "System", "Task"]);
    let keywords = extract_keywords(&record.json);
    let source = extract_source(&record.json);

    Event {
        id: 0,
        event_id,
        timestamp,
        computer,
        channel,
        record_id: Some(record.event_record_id),
        level,
        opcode,
        task,
        user,
        sid,
        keywords,
        source,
        ingest_path,
        event_data_json: record.json,
        raw_xml: record.raw_xml,
    }
}

fn extract_event_id(value: &Value) -> Option<u32> {
    extract_u32(value, &["Event", "System", "EventID"])
}

fn extract_user(value: &Value) -> Option<String> {
    let candidates: &[&[&str]] = &[
        &["Event", "EventData", "TargetUserName"],
        &["Event", "EventData", "SubjectUserName"],
        &["Event", "System", "Security", "@UserID"],
        &["Event", "System", "Security", "UserID"],
        &["Event", "EventData", "TargetUserSid"],
        &["Event", "EventData", "SubjectUserSid"],
    ];

    for path in candidates.iter() {
        if let Some(val) = extract_str(value, path) {
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }

    None
}

fn extract_sid(value: &Value) -> Option<String> {
    let candidates: &[&[&str]] = &[
        &["Event", "System", "Security", "@UserID"],
        &["Event", "System", "Security", "UserID"],
        &["Event", "EventData", "TargetUserSid"],
        &["Event", "EventData", "SubjectUserSid"],
    ];

    for path in candidates.iter() {
        if let Some(val) = extract_str(value, path) {
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }

    None
}

fn extract_keywords(value: &Value) -> Option<String> {
    extract_u64(value, &["Event", "System", "Keywords"]).map(|v| format!("0x{v:x}"))
}

fn extract_source(value: &Value) -> Option<String> {
    extract_str(value, &["Event", "System", "Provider", "#attributes", "Name"])
        .or_else(|| extract_str(value, &["Event", "System", "Provider", "@Name"]))
        .map(ToOwned::to_owned)
}

fn extract_system_time_utc(value: &Value) -> Option<DateTime<Utc>> {
    let raw = extract_str(value, &["Event", "System", "TimeCreated", "#attributes", "SystemTime"])
        .or_else(|| extract_str(value, &["Event", "System", "TimeCreated", "@SystemTime"]))?;

    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn utc_plus_three() -> FixedOffset {
    // UTC+3 display/storage format requested by analyst workflow.
    FixedOffset::east_opt(3 * 60 * 60).expect("valid UTC+3 offset")
}

fn extract_u32<'a>(value: &'a Value, path: &[&str]) -> Option<u32> {
    extract_u64(value, path).and_then(|v| u32::try_from(v).ok())
}

fn extract_u64<'a>(value: &'a Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }

    match current {
        Value::Number(num) => num.as_u64(),
        Value::String(s) => s.parse::<u64>().ok(),
        Value::Object(map) => map
            .get("#text")
            .or_else(|| map.get("value"))
            .and_then(|v| extract_u64(v, &[])),
        _ => None,
    }
}

fn extract_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }

    match current {
        Value::String(s) => Some(s.as_str()),
        Value::Object(map) => map
            .get("#text")
            .or_else(|| map.get("#value"))
            .and_then(|v| v.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_basic_fields() {
        let parsed = ParsedRecord {
            event_record_id: 123,
            timestamp: Utc::now(),
            json: json!({
                "Event": {
                    "System": {
                        "EventID": 4624,
                        "Channel": "Security",
                        "Computer": "WINBOX",
                        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                        "Security": {"@UserID": "S-1-5-18"},
                        "Level": 0,
                        "Task": 12544,
                        "Opcode": 0,
                        "Keywords": "0x8010000000000000"
                    },
                    "EventData": {
                        "TargetUserName": "alice",
                        "IpAddress": "10.0.0.1"
                    }
                }
            }),
            raw_xml: "<Event></Event>".to_string(),
        };

        let mapped = map_record(parsed, None, None, None);
        assert_eq!(mapped.event_id, 4624);
        assert_eq!(mapped.channel, "Security");
        assert_eq!(mapped.computer, "WINBOX");
        assert_eq!(mapped.user.as_deref(), Some("alice"));
        assert_eq!(mapped.sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(mapped.source.as_deref(), Some("Microsoft-Windows-Security-Auditing"));
    }

    #[test]
    fn prefers_system_time_and_formats_utc_plus_three() {
        let parsed = ParsedRecord {
            event_record_id: 1,
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-01-30T00:34:25.317Z")
                .unwrap()
                .with_timezone(&Utc),
            json: json!({
                "Event": {
                    "System": {
                        "EventID": 4648,
                        "TimeCreated": {"#attributes": {"SystemTime": "2026-01-30T00:34:23.757721Z"}},
                        "Channel": "Security",
                        "Computer": "dbtekno-PC"
                    }
                }
            }),
            raw_xml: "<Event/>".to_string(),
        };

        let mapped = map_record(parsed, None, None, None);
        assert_eq!(mapped.timestamp, "2026-01-30T03:34:23.757+03:00");
    }
}
