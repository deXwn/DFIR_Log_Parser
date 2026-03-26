use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Clone)]
pub struct Event {
    pub id: i64,
    pub event_id: u32,
    pub timestamp: String,
    pub computer: String,
    pub channel: String,
    pub record_id: Option<u64>,
    pub level: Option<u32>,
    pub opcode: Option<u32>,
    pub task: Option<u32>,
    pub user: Option<String>,
    pub sid: Option<String>,
    pub keywords: Option<String>,
    pub source: Option<String>,
    pub ingest_path: Option<String>,
    pub event_data_json: Value,
    pub raw_xml: String,
}

#[derive(Debug, Deserialize)]
pub struct IngestRequest {
    pub path: String,
    pub channel: Option<String>,
    pub threads: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct ListEvtxRequest {
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct ListEvtxResponse {
    pub path: String,
    pub files: Vec<ListEvtxFile>,
}

#[derive(Debug, Serialize)]
pub struct ListEvtxFile {
    pub path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Deserialize)]
pub struct DeleteRequest {
    pub id: Option<i64>,
    pub channel: Option<String>,
    pub event_id: Option<u32>,
    pub before: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub deleted: usize,
}

#[derive(Debug, Serialize)]
pub struct IngestResponse {
    pub path: String,
    pub ingested: usize,
    pub duration_ms: u128,
    pub threads: usize,
    pub parsed: usize,
}

#[derive(Debug, Deserialize)]
pub struct ReportRequest {
    pub from: Option<String>,
    pub to: Option<String>,
    pub host: Option<String>,
    pub user: Option<String>,
    pub ioc: Option<String>,
    pub case_name: Option<String>,
    pub analyst: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReportResponse {
    pub metadata: ReportMeta,
    pub summary: ReportSummary,
    pub timeline: Vec<TimelineBucket>,
    pub key_events: Vec<Event>,
    pub suspicious: Vec<SuspiciousEvent>,
}

#[derive(Debug, Serialize)]
pub struct ReportMeta {
    pub case_name: String,
    pub analyst: String,
    pub generated_at: String,
    pub filters: ReportFiltersOut,
}

#[derive(Debug, Serialize)]
pub struct ReportFiltersOut {
    pub from: Option<String>,
    pub to: Option<String>,
    pub host: Option<String>,
    pub user: Option<String>,
    pub ioc: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReportSummary {
    pub total_events: i64,
    pub unique_users: i64,
    pub unique_hosts: i64,
    pub logons: i64,
    pub process_creations: i64,
    pub clear_logs: i64,
    pub services: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CustomReportItem {
    pub event_id: i64,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CustomReportRequest {
    pub title: String,
    pub analyst: String,
    pub summary: String,
    pub items: Vec<CustomReportItem>,
}

#[derive(Debug, Serialize)]
pub struct CustomReportResponse {
    pub markdown: String,
}

#[derive(Debug, Serialize)]
pub struct CustomReportHtmlResponse {
    pub html: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub mitre: Option<Vec<String>>,
    pub event_id: Option<Vec<u32>>,
    pub channel: Option<Vec<String>>,
    pub user: Option<Vec<String>>,
    pub exclude_user: Option<Vec<String>>,
    pub process_name: Option<Vec<String>>,
    pub process_cmdline_regex: Option<String>,
    pub process_name_regex: Option<String>,
    pub process_original_name_regex: Option<String>,
    pub script_block_regex: Option<String>,
    pub share_name_regex: Option<String>,
    pub auth_package_regex: Option<String>,
    pub workstation_name_regex: Option<String>,
    pub ticket_encryption_regex: Option<String>,
    pub failure_code_regex: Option<String>,
    pub pre_auth_type_regex: Option<String>,
    pub logon_guid_regex: Option<String>,
    pub target_domain_name_regex: Option<String>,
    pub properties_regex: Option<String>,
    pub object_name_regex: Option<String>,
    pub object_dn_regex: Option<String>,
    pub privilege_list_regex: Option<String>,
    pub privilege_name_regex: Option<String>,
    pub parent_process_regex: Option<String>,
    pub ip_address_regex: Option<String>,
    pub exclude_process: Option<Vec<String>>,
    pub keywords: Option<Vec<String>>,
    pub ip: Option<Vec<String>>,
    pub logon_type: Option<Vec<u32>>,
    pub correlation: Option<CorrelationConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CorrelationConfig {
    pub r#type: String,
    pub window: Option<i64>,
    pub group_by: Option<Vec<String>>,
    pub steps: Option<Vec<CorrelationStep>>,
    pub time_filter: Option<CorrelationTimeFilter>,
    pub min_count: Option<usize>,
    pub rules: Option<Vec<String>>,
    pub count_distinct: Option<String>,
    pub event_id: Option<Vec<u32>>,
    pub logon_type: Option<Vec<u32>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CorrelationStep {
    pub step: Option<u32>,
    pub name: Option<String>,
    pub rule_id: Option<String>,
    pub min_count: Option<usize>,
    pub event_id: Option<Vec<u32>>,
    pub channel: Option<Vec<String>>,
    pub user: Option<Vec<String>>,
    pub exclude_user: Option<Vec<String>>,
    pub process_name: Option<Vec<String>>,
    pub process_cmdline_regex: Option<String>,
    pub process_name_regex: Option<String>,
    pub process_original_name_regex: Option<String>,
    pub script_block_regex: Option<String>,
    pub share_name_regex: Option<String>,
    pub auth_package_regex: Option<String>,
    pub workstation_name_regex: Option<String>,
    pub ticket_encryption_regex: Option<String>,
    pub failure_code_regex: Option<String>,
    pub pre_auth_type_regex: Option<String>,
    pub logon_guid_regex: Option<String>,
    pub target_domain_name_regex: Option<String>,
    pub properties_regex: Option<String>,
    pub object_name_regex: Option<String>,
    pub object_dn_regex: Option<String>,
    pub privilege_list_regex: Option<String>,
    pub privilege_name_regex: Option<String>,
    pub parent_process_regex: Option<String>,
    pub ip_address_regex: Option<String>,
    pub exclude_process: Option<Vec<String>>,
    pub keywords: Option<Vec<String>>,
    pub ip: Option<Vec<String>>,
    pub logon_type: Option<Vec<u32>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CorrelationTimeFilter {
    pub hours_outside: Option<Vec<String>>,
    pub or_weekends: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct DetectionCorrelationGroupEvent {
    pub event: Event,
    pub step: Option<u32>,
    pub step_label: Option<String>,
    pub matched_rule_ids: Vec<String>,
    pub matched_rule_names: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DetectionCorrelationGroup {
    pub group_key: Option<String>,
    pub window_start: Option<String>,
    pub window_end: Option<String>,
    pub events: Vec<DetectionCorrelationGroupEvent>,
}

#[derive(Debug, Serialize)]
pub struct DetectionMatch {
    pub rule: DetectionRule,
    pub hits: usize,
    pub events: Vec<Event>,
    pub correlation_groups: Option<Vec<DetectionCorrelationGroup>>,
}

#[derive(Debug, Deserialize)]
pub struct EventQuery {
    pub event_id: Option<u32>,
    pub channel: Option<String>,
    pub user: Option<String>,
    pub sid: Option<String>,
    pub ip: Option<String>,
    pub keyword: Option<String>,
    pub exclude: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub query: String,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub logon_type: Option<u32>,
    pub ip: Option<String>,
    pub exclude: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TimelineQuery {
    pub from: String,
    pub to: String,
    pub bucket: Option<String>, // "minute" | "hour"
    pub ingest_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Paging {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct Paginated<T> {
    pub data: Vec<T>,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Debug, Serialize)]
pub struct CountEntry<T> {
    pub key: T,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub by_event_id: Vec<CountEntry<u32>>,
    pub by_channel: Vec<CountEntry<String>>,
    pub by_source: Vec<CountEntry<String>>,
    pub by_user: Vec<CountEntry<String>>,
    pub by_source_ip: Vec<CountEntry<String>>,
    pub by_dest_ip: Vec<CountEntry<String>>,
    pub ingest_paths: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct TimelineBucket {
    pub bucket: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct AggregatedLogon {
    pub user: Option<String>,
    pub sid: Option<String>,
    pub computer: Option<String>,
    pub ip: Option<String>,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct SuspiciousEvent {
    pub id: i64,
    pub event_id: u32,
    pub timestamp: String,
    pub computer: String,
    pub channel: String,
    pub description: String,
    pub event_data_json: Value,
}

#[derive(Debug, Serialize)]
pub struct CorrelatedLogon {
    pub account: Option<String>,
    pub ip: Option<String>,
    pub computer: Option<String>,
    pub failures: i64,
    pub successes: i64,
}

// ── Forensics (Evidence Collection) ──

#[derive(Debug, Deserialize)]
pub struct ForensicItemCreate {
    pub event_id: i64,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub severity: Option<String>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique_id: Option<String>,
    pub mitre_technique_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ForensicItemUpdate {
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub severity: Option<String>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique_id: Option<String>,
    pub mitre_technique_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ForensicItem {
    pub id: i64,
    pub event_id: i64,
    pub notes: String,
    pub tags: Vec<String>,
    pub severity: String,
    pub mitre_tactic: String,
    pub mitre_technique_id: String,
    pub mitre_technique_name: String,
    pub created_at: String,
    pub event: Option<Event>,
}

#[derive(Debug, Serialize)]
pub struct ForensicStats {
    pub total: i64,
    pub by_severity: Vec<CountEntry<String>>,
    pub by_tactic: Vec<CountEntry<String>>,
}
