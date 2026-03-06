use csv::Writer;
use rayon::prelude::*;
use regex::{Regex, RegexBuilder, RegexSet};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::{BinaryHeap, HashMap, VecDeque},
    env,
    fs::{self, File},
    io::{self, BufRead, BufReader},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::{debug, info};
use walkdir::WalkDir;

const DEFAULT_PAGE_SIZE: usize = 200;
const MAX_PAGE_SIZE: usize = 2000;
const EXPORT_DIR: &str = "exports";
const EXPORT_FALLBACK_DIR: &str = "exports_local";

#[derive(Debug, Deserialize)]
pub struct SearchRequest {
    pub root_path: PathBuf,
    #[serde(default)]
    pub terms: Vec<String>,
    #[serde(default)]
    pub none: Vec<String>,
    #[serde(default = "default_page")]
    pub page: usize,
    #[serde(default = "default_page_size")]
    pub page_size: usize,
    #[serde(default)]
    pub export_csv: bool,
    #[serde(default)]
    pub status_code: Option<u16>,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default)]
    pub ip_scope: Option<IpScope>,
    #[serde(default)]
    pub match_mode: MatchMode,
    #[serde(default, deserialize_with = "deserialize_opt_u64")]
    pub min_bytes_received: Option<u64>,
    #[serde(default)]
    pub sort_mode: SortMode,
    #[serde(default)]
    pub rules: Vec<RuleFilter>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleFilter {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub severity: Option<RuleSeverity>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub conditions: Vec<RuleCondition>,
    #[serde(default)]
    pub threshold: Option<u64>,
    #[serde(default)]
    pub time_window_seconds: Option<u64>,
    #[serde(default)]
    pub group_by: RuleGroupBy,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for RuleSeverity {
    fn default() -> Self {
        RuleSeverity::Medium
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleCondition {
    pub field: RuleField,
    pub op: RuleOperator,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleField {
    Line,
    Timestamp,
    SrcIp,
    DstIp,
    Status,
    BytesReceived,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleOperator {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleGroupBy {
    Global,
    SrcIp,
    DstIp,
    Status,
}

impl Default for RuleGroupBy {
    fn default() -> Self {
        RuleGroupBy::Global
    }
}

impl SearchRequest {
    pub fn into_query(self) -> Result<SearchQuery, SearchError> {
        if self.root_path.as_os_str().is_empty() {
            return Err(SearchError::InvalidRoot(
                "root_path cannot be empty".to_string(),
            ));
        }

        let page = if self.page == 0 { 1 } else { self.page };
        let mut page_size = if self.page_size == 0 {
            DEFAULT_PAGE_SIZE
        } else {
            self.page_size
        };
        if page_size > MAX_PAGE_SIZE {
            page_size = MAX_PAGE_SIZE;
        }

        let terms = clean_terms(self.terms);
        let none = clean_terms(self.none);

        Ok(SearchQuery {
            root_path: self.root_path,
            terms,
            none,
            page,
            page_size,
            export_csv: self.export_csv,
            status_code: self.status_code,
            case_sensitive: self.case_sensitive,
            ip_scope: self.ip_scope,
            match_mode: self.match_mode,
            min_bytes_received: self.min_bytes_received,
            sort_mode: self.sort_mode,
            rules: self.rules,
        })
    }
}

fn clean_terms(raw: Vec<String>) -> Vec<String> {
    raw.into_iter()
        .map(|term| term.trim().to_string())
        .filter(|term| !term.is_empty())
        .collect()
}

#[derive(Debug, Clone)]
pub struct SearchQuery {
    pub root_path: PathBuf,
    pub terms: Vec<String>,
    pub none: Vec<String>,
    pub page: usize,
    pub page_size: usize,
    pub export_csv: bool,
    pub status_code: Option<u16>,
    pub case_sensitive: bool,
    pub ip_scope: Option<IpScope>,
    pub match_mode: MatchMode,
    pub min_bytes_received: Option<u64>,
    pub sort_mode: SortMode,
    pub rules: Vec<RuleFilter>,
}

impl SearchQuery {
    pub fn start_index(&self) -> usize {
        self.page.saturating_sub(1).saturating_mul(self.page_size)
    }

    pub fn max_results_to_keep(&self) -> usize {
        self.start_index()
            .saturating_add(self.page_size)
            .max(self.page_size)
    }
}

fn cmp_by_sort_mode(mode: SortMode, a: &LogMatch, b: &LogMatch) -> Ordering {
    match mode {
        SortMode::FilePosition => file_position_cmp(a, b),
        SortMode::BytesReceivedAsc => {
            let lhs = a.bytes_received.unwrap_or(0);
            let rhs = b.bytes_received.unwrap_or(0);
            lhs.cmp(&rhs).then_with(|| file_position_cmp(a, b))
        }
        SortMode::BytesReceivedDesc => {
            let lhs = a.bytes_received.unwrap_or(0);
            let rhs = b.bytes_received.unwrap_or(0);
            rhs.cmp(&lhs).then_with(|| file_position_cmp(a, b))
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub total_matches: u64,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub page: usize,
    pub page_size: usize,
    pub has_more: bool,
    pub duration_ms: u128,
    pub results: Vec<LogMatch>,
    pub applied_sort_mode: SortMode,
    pub applied_rules: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_min_bytes_received: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_total: Option<u64>,
}

#[derive(Debug, Serialize, Clone)]
pub struct IpSummaryEntry {
    pub ip: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct IpSummaryResponse {
    pub total_matches: u64,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub duration_ms: u128,
    pub unique_ips: usize,
    pub unique_src_ips: usize,
    pub unique_dst_ips: usize,
    pub ips: Vec<IpSummaryEntry>,
    pub src_ips: Vec<IpSummaryEntry>,
    pub dst_ips: Vec<IpSummaryEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export_path: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct DetectionMatch {
    pub file_path: String,
    pub line_number: u64,
    pub byte_offset: u64,
    pub line: String,
    pub timestamp_epoch: Option<i64>,
    pub matched_rule_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DetectionScanResponse {
    pub total_matches: u64,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub duration_ms: u128,
    pub matches: Vec<DetectionMatch>,
}

#[derive(Debug, Serialize, Clone, Eq, PartialEq)]
pub struct LogMatch {
    pub file_path: String,
    pub line_number: u64,
    pub byte_offset: u64,
    pub line: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_received: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rules: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct ContextRequest {
    pub root_path: PathBuf,
    pub file_path: String,
    pub line: u64,
    #[serde(default = "default_radius")]
    pub radius: u64,
}

#[derive(Debug, Serialize)]
pub struct ContextResponse {
    pub file_path: String,
    pub start_line: u64,
    pub end_line: u64,
    pub lines: Vec<ContextLine>,
}

#[derive(Debug, Serialize)]
pub struct ContextLine {
    pub line_number: u64,
    pub line: String,
}

impl Ord for LogMatch {
    fn cmp(&self, other: &Self) -> Ordering {
        file_position_cmp(self, other)
    }
}

impl PartialOrd for LogMatch {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn file_position_cmp(a: &LogMatch, b: &LogMatch) -> Ordering {
    match a.file_path.cmp(&b.file_path) {
        Ordering::Equal => match a.line_number.cmp(&b.line_number) {
            Ordering::Equal => a.byte_offset.cmp(&b.byte_offset),
            other => other,
        },
        other => other,
    }
}

#[derive(Clone)]
struct MatchedLine {
    line: String,
    parsed: ParsedLogLine,
    matched_rule_ids: Vec<String>,
}

#[derive(Clone, Default)]
struct ParsedLogLine {
    timestamp_epoch: Option<i64>,
    status: Option<u16>,
    bytes_received: Option<u64>,
    src_ip: Option<Ipv4Addr>,
    dst_ip: Option<Ipv4Addr>,
    all_ips: Vec<Ipv4Addr>,
    last_ip: Option<Ipv4Addr>,
}

#[derive(Clone)]
struct CompiledRule {
    id: String,
    regex: Option<Regex>,
    conditions: Vec<CompiledRuleCondition>,
    threshold: Option<u64>,
    time_window_seconds: Option<u64>,
    group_by: RuleGroupBy,
}

#[derive(Clone)]
struct CompiledRuleCondition {
    field: RuleField,
    op: RuleOperator,
    value: CompiledRuleValue,
}

#[derive(Clone)]
enum CompiledRuleValue {
    Text(String),
    Number(u64),
    Status(u16),
    Ip(Ipv4Addr),
    Timestamp(i64),
}

#[derive(Default)]
struct RuleRuntime {
    states: Vec<RuleRuntimeState>,
}

#[derive(Default)]
struct RuleRuntimeState {
    buckets: HashMap<String, VecDeque<i64>>,
    synthetic_clock: i64,
}

impl RuleRuntime {
    fn with_rule_count(rule_count: usize) -> Self {
        Self {
            states: (0..rule_count).map(|_| RuleRuntimeState::default()).collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SortMode {
    FilePosition,
    BytesReceivedAsc,
    BytesReceivedDesc,
}

impl SortMode {
    fn requires_bytes(self) -> bool {
        matches!(self, SortMode::BytesReceivedAsc | SortMode::BytesReceivedDesc)
    }
}

impl Default for SortMode {
    fn default() -> Self {
        SortMode::FilePosition
    }
}

#[derive(Clone, Eq, PartialEq)]
struct RankedLogMatch {
    entry: LogMatch,
    sort_mode: SortMode,
}

impl RankedLogMatch {
    fn new(entry: LogMatch, sort_mode: SortMode) -> Self {
        Self { entry, sort_mode }
    }

    fn into_log_match(self) -> LogMatch {
        self.entry
    }
}

impl Ord for RankedLogMatch {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.sort_mode {
            SortMode::FilePosition => file_position_cmp(&self.entry, &other.entry),
            SortMode::BytesReceivedAsc => {
                let lhs = self.entry.bytes_received.unwrap_or(0);
                let rhs = other.entry.bytes_received.unwrap_or(0);
                lhs.cmp(&rhs)
                    .then_with(|| file_position_cmp(&self.entry, &other.entry))
            }
            SortMode::BytesReceivedDesc => {
                let lhs = self.entry.bytes_received.unwrap_or(0);
                let rhs = other.entry.bytes_received.unwrap_or(0);
                rhs.cmp(&lhs)
                    .then_with(|| file_position_cmp(&self.entry, &other.entry))
            }
        }
    }
}

impl PartialOrd for RankedLogMatch {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Error)]
pub enum SearchError {
    #[error("{0}")]
    InvalidRoot(String),
    #[error("invalid rule: {0}")]
    InvalidRule(String),
    #[error("failed to walk directory: {0}")]
    WalkDir(#[from] walkdir::Error),
    #[error("I/O error while reading {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write CSV export at {path}: {source}")]
    Csv { path: PathBuf, source: csv::Error },
    #[error("failed to acquire export writer lock")]
    ExportLock,
    #[error("requested file is outside root: {0}")]
    OutsideRoot(String),
    #[error("failed to build regex: {0}")]
    Regex(#[from] regex::Error),
}

pub fn execute_search(query: SearchQuery) -> Result<SearchResponse, SearchError> {
    if !query.root_path.exists() || !query.root_path.is_dir() {
        return Err(SearchError::InvalidRoot(format!(
            "{} is not a valid directory",
            query.root_path.display()
        )));
    }

    info!(
        root = %query.root_path.display(),
        terms = query.terms.len(),
        none_terms = query.none.len(),
        rules = query.rules.len(),
        page = query.page,
        page_size = query.page_size,
        match_mode = ?query.match_mode,
        sort_mode = ?query.sort_mode,
        min_bytes_received = ?query.min_bytes_received,
        "starting log search"
    );

    let started = Instant::now();
    let log_files = collect_log_files(&query.root_path)?;
    let files_scanned = log_files.len();
    info!(files_scanned, "discovered log files to scan");

    let matcher = KeywordMatcher::new(&query)?;
    let results_to_keep = query.max_results_to_keep();
    let display_root = Arc::new(determine_display_root(&query.root_path));
    let export_sink = if query.export_csv {
        Some(Arc::new(ExportSink::new(Path::new(EXPORT_DIR))?))
    } else {
        None
    };
    let progress = Arc::new(ProgressTracker::new(files_scanned));

    let file_results = log_files
        .par_iter()
        .map({
            let exporter = export_sink.clone();
            let progress_clone = progress.clone();
            let display_root = display_root.clone();
            move |path| {
                let sink = exporter.clone();
                let tracker = progress_clone.clone();
                let display = display_root.clone();
                search_file(path, &matcher, results_to_keep, sink, tracker, display)
            }
        })
        .collect::<Result<Vec<_>, SearchError>>()?;

    let mut total_matches = 0u64;
    let mut bytes_scanned = 0u64;
    let mut heap: BinaryHeap<RankedLogMatch> = BinaryHeap::new();

    for file_result in file_results {
        bytes_scanned += file_result.bytes_scanned;
        total_matches += file_result.total_matches;

        for record in file_result.matches {
            if results_to_keep > 0 {
                heap.push(record);
                if heap.len() > results_to_keep {
                    heap.pop();
                }
            }
        }
    }

    let ordered: Vec<LogMatch> = if results_to_keep == 0 {
        Vec::new()
    } else {
        let mut sorted = heap.into_vec();
        sorted.sort();
        let mut items = sorted
            .into_iter()
            .map(RankedLogMatch::into_log_match)
            .collect::<Vec<_>>();

        items.sort_by(|a, b| cmp_by_sort_mode(query.sort_mode, a, b));
        items
    };

    let skip = query.start_index().min(ordered.len());
    let mut page_results = ordered.into_iter().skip(skip).collect::<Vec<_>>();
    if page_results.len() > query.page_size {
        page_results.truncate(query.page_size);
    }

    let shown = query.start_index().saturating_add(page_results.len());
    let has_more = total_matches > shown as u64;
    let duration_ms = started.elapsed().as_millis();

    let export_report = match export_sink {
        Some(ref sink) => Some(sink.finalize()?),
        None => None,
    };

    let (export_path, export_total) = match export_report {
        Some(report) => (
            Some(export_download_path(&report.path)),
            Some(report.total_rows),
        ),
        None => (None, None),
    };

    let response = SearchResponse {
        total_matches,
        files_scanned,
        bytes_scanned,
        page: query.page,
        page_size: query.page_size,
        has_more,
        duration_ms,
        results: page_results,
        applied_sort_mode: query.sort_mode,
        applied_rules: query.rules.len(),
        applied_min_bytes_received: query.min_bytes_received,
        export_path,
        export_total,
    };

    info!(
        total_matches,
        files_scanned, bytes_scanned, duration_ms, "log search completed"
    );

    Ok(response)
}

pub fn execute_detection_scan(query: SearchQuery) -> Result<DetectionScanResponse, SearchError> {
    if !query.root_path.exists() || !query.root_path.is_dir() {
        return Err(SearchError::InvalidRoot(format!(
            "{} is not a valid directory",
            query.root_path.display()
        )));
    }
    if query.rules.is_empty() {
        return Err(SearchError::InvalidRule(
            "at least one detection rule is required".to_string(),
        ));
    }

    info!(
        root = %query.root_path.display(),
        rules = query.rules.len(),
        terms = query.terms.len(),
        "starting detection scan"
    );

    let started = Instant::now();
    let log_files = collect_log_files(&query.root_path)?;
    let files_scanned = log_files.len();
    let matcher = KeywordMatcher::new(&query)?;
    let display_root = Arc::new(determine_display_root(&query.root_path));
    let progress = Arc::new(ProgressTracker::new(files_scanned));

    let file_results = log_files
        .par_iter()
        .map({
            let progress_clone = progress.clone();
            let display_root = display_root.clone();
            move |path| {
                detection_scan_file(
                    path,
                    &matcher,
                    progress_clone.clone(),
                    display_root.clone(),
                )
            }
        })
        .collect::<Result<Vec<_>, SearchError>>()?;

    let mut bytes_scanned = 0u64;
    let mut matches = Vec::new();
    for result in file_results {
        bytes_scanned += result.bytes_scanned;
        matches.extend(result.matches);
    }

    let duration_ms = started.elapsed().as_millis();
    let total_matches = matches.len() as u64;
    info!(
        total_matches,
        files_scanned,
        bytes_scanned,
        duration_ms,
        "detection scan completed"
    );

    Ok(DetectionScanResponse {
        total_matches,
        files_scanned,
        bytes_scanned,
        duration_ms,
        matches,
    })
}

pub fn execute_ip_summary(query: SearchQuery) -> Result<IpSummaryResponse, SearchError> {
    if !query.root_path.exists() || !query.root_path.is_dir() {
        return Err(SearchError::InvalidRoot(format!(
            "{} is not a valid directory",
            query.root_path.display()
        )));
    }

    info!(
        root = %query.root_path.display(),
        terms = query.terms.len(),
        none_terms = query.none.len(),
        rules = query.rules.len(),
        match_mode = ?query.match_mode,
        min_bytes_received = ?query.min_bytes_received,
        "starting ip summary"
    );

    let started = Instant::now();
    let log_files = collect_log_files(&query.root_path)?;
    let files_scanned = log_files.len();
    info!(files_scanned, "discovered log files to scan for ip summary");

    let matcher = KeywordMatcher::new(&query)?;
    let progress = Arc::new(ProgressTracker::new(files_scanned));

    let file_results = log_files
        .par_iter()
        .map({
            let progress_clone = progress.clone();
            move |path| {
                search_file_ips(
                    path,
                    &matcher,
                    progress_clone.clone(),
                )
            }
        })
        .collect::<Result<Vec<_>, SearchError>>()?;

    let mut bytes_scanned = 0u64;
    let mut total_matches = 0u64;
    let mut counts: HashMap<Ipv4Addr, u64> = HashMap::new();
    let mut src_counts: HashMap<Ipv4Addr, u64> = HashMap::new();
    let mut dst_counts: HashMap<Ipv4Addr, u64> = HashMap::new();

    for result in file_results {
        bytes_scanned += result.bytes_scanned;
        total_matches += result.total_matches;
        for (ip, count) in result.counts {
            *counts.entry(ip).or_insert(0) += count;
        }
        for (ip, count) in result.src_counts {
            *src_counts.entry(ip).or_insert(0) += count;
        }
        for (ip, count) in result.dst_counts {
            *dst_counts.entry(ip).or_insert(0) += count;
        }
    }

    let ips_full = counts
        .into_iter()
        .map(|(ip, count)| IpSummaryEntry {
            ip: ip.to_string(),
            count,
        })
        .collect::<Vec<_>>();

    let src_full = src_counts
        .into_iter()
        .map(|(ip, count)| IpSummaryEntry {
            ip: ip.to_string(),
            count,
        })
        .collect::<Vec<_>>();

    let dst_full = dst_counts
        .into_iter()
        .map(|(ip, count)| IpSummaryEntry {
            ip: ip.to_string(),
            count,
        })
        .collect::<Vec<_>>();

    let unique_ips = ips_full.len();
    let unique_src_ips = src_full.len();
    let unique_dst_ips = dst_full.len();

    let mut ips = ips_full.clone();
    ips.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ip.cmp(&b.ip)));
    ips.truncate(300);

    let mut src_ips = src_full.clone();
    src_ips.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ip.cmp(&b.ip)));
    src_ips.truncate(300);

    let mut dst_ips = dst_full.clone();
    dst_ips.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ip.cmp(&b.ip)));
    dst_ips.truncate(300);

    let duration_ms = started.elapsed().as_millis();

    let export_path = if query.export_csv {
        let mut export_all = ips_full.clone();
        export_all.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ip.cmp(&b.ip)));
        let mut export_src = src_full.clone();
        export_src.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ip.cmp(&b.ip)));
        let mut export_dst = dst_full.clone();
        export_dst.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ip.cmp(&b.ip)));
        Some(write_ip_summary_csv(
            &export_all,
            &export_src,
            &export_dst,
            unique_ips,
            unique_src_ips,
            unique_dst_ips,
        )?)
    } else {
        None
    };

    Ok(IpSummaryResponse {
        total_matches,
        files_scanned,
        bytes_scanned,
        duration_ms,
        unique_ips,
        unique_src_ips,
        unique_dst_ips,
        ips,
        src_ips,
        dst_ips,
        export_path,
    })
}

fn collect_log_files(root: &Path) -> Result<Vec<PathBuf>, SearchError> {
    let mut files = Vec::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| entry.file_type().is_dir() || is_log_file(entry.path()))
    {
        let entry = entry?;
        if entry.file_type().is_file() && is_log_file(entry.path()) {
            files.push(entry.path().to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

fn determine_display_root(root_path: &Path) -> PathBuf {
    root_path.to_path_buf()
}

fn is_log_file(path: &Path) -> bool {
    // Accept common log patterns: *.log, *.txt, access.log.1, and extension-less files
    if let Some(ext) = path.extension().and_then(|ext| ext.to_str()) {
        if ext.eq_ignore_ascii_case("log") || ext.eq_ignore_ascii_case("txt") {
            return true;
        }

        // Rotated files like access.log.1 or error.log.3
        if ext.chars().all(|c| c.is_ascii_digit()) {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                return name.to_ascii_lowercase().contains(".log");
            }
        }
    } else {
        // Files without an extension (common in DFIR collections)
        return true;
    }

    false
}

struct FileMatches {
    total_matches: u64,
    matches: Vec<RankedLogMatch>,
    bytes_scanned: u64,
}

struct DetectionFileMatches {
    matches: Vec<DetectionMatch>,
    bytes_scanned: u64,
}

struct IpFileSummary {
    counts: HashMap<Ipv4Addr, u64>,
    src_counts: HashMap<Ipv4Addr, u64>,
    dst_counts: HashMap<Ipv4Addr, u64>,
    total_matches: u64,
    bytes_scanned: u64,
}

fn search_file(
    path: &Path,
    matcher: &KeywordMatcher,
    max_entries: usize,
    exporter: Option<Arc<ExportSink>>,
    progress: Arc<ProgressTracker>,
    display_root: Arc<PathBuf>,
) -> Result<FileMatches, SearchError> {
    progress.mark_start(path);
    debug!(file = %path.display(), "scanning log file");

    let file = File::open(path).map_err(|source| SearchError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::with_capacity(128 * 1024, file);

    let mut buffer = Vec::with_capacity(8 * 1024);
    let mut line_number = 0u64;
    let mut byte_offset = 0u64;
    let mut total_matches = 0u64;
    let mut bytes_scanned = 0u64;
    let display_path = make_display_path(path, &display_root);
    let mut heap = if max_entries == 0 {
        None
    } else {
        Some(BinaryHeap::with_capacity(max_entries.saturating_add(1)))
    };
    let mut rule_runtime = matcher.new_rule_runtime();

    loop {
        buffer.clear();
        let bytes = reader
            .read_until(b'\n', &mut buffer)
            .map_err(|source| SearchError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes == 0 {
            break;
        }

        bytes_scanned += bytes as u64;
        line_number += 1;
        let current_offset = byte_offset;
        byte_offset += bytes as u64;

        let line_bytes = trim_line_bytes(&buffer);
        let Some(matched) = matcher.evaluate(line_bytes, &mut rule_runtime) else {
            continue;
        };

        total_matches += 1;
        let src_ip = matched.parsed.src_ip.map(|ip| ip.to_string());
        let dst_ip = matched.parsed.dst_ip.map(|ip| ip.to_string());
        if let Some(ref sink) = exporter {
            sink.record(
                &display_path,
                line_number,
                current_offset,
                &matched.line,
                src_ip.as_deref(),
                dst_ip.as_deref(),
                matched.parsed.last_ip,
            )?;
        }

        if let Some(ref mut heap) = heap {
            let record = LogMatch {
                file_path: display_path.clone(),
                line_number,
                byte_offset: current_offset,
                line: matched.line,
                bytes_received: matched.parsed.bytes_received,
                src_ip,
                dst_ip,
                matched_rules: if matched.matched_rule_ids.is_empty() {
                    None
                } else {
                    Some(matched.matched_rule_ids)
                },
            };

            heap.push(RankedLogMatch::new(record, matcher.sort_mode));
            if heap.len() > max_entries {
                heap.pop();
            }
        }
    }

    let matches = heap
        .map(|heap| {
            let mut matches = heap.into_vec();
            matches.sort();
            matches
        })
        .unwrap_or_default();

    debug!(
        file = %path.display(),
        matches = total_matches,
        bytes_scanned,
        "completed scanning file"
    );
    progress.mark_finish(path, total_matches, bytes_scanned);

    Ok(FileMatches {
        total_matches,
        matches,
        bytes_scanned,
    })
}

fn detection_scan_file(
    path: &Path,
    matcher: &KeywordMatcher,
    progress: Arc<ProgressTracker>,
    display_root: Arc<PathBuf>,
) -> Result<DetectionFileMatches, SearchError> {
    progress.mark_start(path);
    debug!(file = %path.display(), "scanning log file for detections");

    let file = File::open(path).map_err(|source| SearchError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::with_capacity(128 * 1024, file);

    let mut buffer = Vec::with_capacity(8 * 1024);
    let mut line_number = 0u64;
    let mut byte_offset = 0u64;
    let mut bytes_scanned = 0u64;
    let mut matches = Vec::new();
    let display_path = make_display_path(path, &display_root);
    let mut rule_runtime = matcher.new_rule_runtime();

    loop {
        buffer.clear();
        let bytes = reader
            .read_until(b'\n', &mut buffer)
            .map_err(|source| SearchError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes == 0 {
            break;
        }

        bytes_scanned += bytes as u64;
        line_number += 1;
        let current_offset = byte_offset;
        byte_offset += bytes as u64;

        let line_bytes = trim_line_bytes(&buffer);
        let Some(matched) = matcher.evaluate(line_bytes, &mut rule_runtime) else {
            continue;
        };
        if matched.matched_rule_ids.is_empty() {
            continue;
        }

        matches.push(DetectionMatch {
            file_path: display_path.clone(),
            line_number,
            byte_offset: current_offset,
            line: matched.line,
            timestamp_epoch: matched.parsed.timestamp_epoch,
            matched_rule_ids: matched.matched_rule_ids,
        });
    }

    debug!(
        file = %path.display(),
        matches = matches.len(),
        bytes_scanned,
        "completed scanning file (detections)"
    );
    progress.mark_finish(path, matches.len() as u64, bytes_scanned);

    Ok(DetectionFileMatches {
        matches,
        bytes_scanned,
    })
}

fn search_file_ips(
    path: &Path,
    matcher: &KeywordMatcher,
    progress: Arc<ProgressTracker>,
) -> Result<IpFileSummary, SearchError> {
    progress.mark_start(path);
    debug!(file = %path.display(), "scanning log file for ip summary");

    let file = File::open(path).map_err(|source| SearchError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::with_capacity(128 * 1024, file);

    let mut buffer = Vec::with_capacity(8 * 1024);
    let mut total_matches = 0u64;
    let mut bytes_scanned = 0u64;
    let mut counts: HashMap<Ipv4Addr, u64> = HashMap::new();
    let mut src_counts: HashMap<Ipv4Addr, u64> = HashMap::new();
    let mut dst_counts: HashMap<Ipv4Addr, u64> = HashMap::new();
    let mut rule_runtime = matcher.new_rule_runtime();

    loop {
        buffer.clear();
        let bytes = reader
            .read_until(b'\n', &mut buffer)
            .map_err(|source| SearchError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes == 0 {
            break;
        }

        bytes_scanned += bytes as u64;
        let line_bytes = trim_line_bytes(&buffer);
        let Some(matched) = matcher.evaluate(line_bytes, &mut rule_runtime) else {
            continue;
        };

        total_matches += 1;

        for ip in &matched.parsed.all_ips {
            *counts.entry(*ip).or_insert(0) += 1;
        }

        if let Some(src) = matched.parsed.src_ip {
            *src_counts.entry(src).or_insert(0) += 1;
        }
        if let Some(dst) = matched.parsed.dst_ip {
            *dst_counts.entry(dst).or_insert(0) += 1;
        }
    }

    debug!(
        file = %path.display(),
        matches = total_matches,
        bytes_scanned,
        "completed scanning file (ip summary)"
    );
    progress.mark_finish(path, total_matches, bytes_scanned);

    Ok(IpFileSummary {
        counts,
        src_counts,
        dst_counts,
        total_matches,
        bytes_scanned,
    })
}

fn trim_line_bytes(input: &[u8]) -> &[u8] {
    let mut end = input.len();
    while end > 0 && (input[end - 1] == b'\n' || input[end - 1] == b'\r') {
        end -= 1;
    }
    &input[..end]
}

fn decode_line(buffer: &[u8]) -> Cow<'_, str> {
    String::from_utf8_lossy(trim_line_bytes(buffer))
}

fn extract_status(line: &str) -> Option<u16> {
    if let Some(code) = STATUS_KV_REGEX
        .get_or_init(|| {
            Regex::new(r#"status(?:_code)?="?(\d{3})"?"#).expect("valid status kv regex")
        })
        .captures(line)
        .and_then(|caps| caps.get(1))
        .and_then(|m| m.as_str().parse::<u16>().ok())
    {
        return Some(code);
    }

    let tokens = line.split_whitespace().collect::<Vec<_>>();
    if tokens.len() < 3 {
        return None;
    }

    let mut candidate = None;
    for window in tokens.windows(3) {
        let [status, next_a, next_b] = [window[0], window[1], window[2]];
        if status.len() == 3
            && status.chars().all(|c| c.is_ascii_digit())
            && next_a.chars().all(|c| c.is_ascii_digit())
            && next_b.chars().all(|c| c.is_ascii_digit())
        {
            candidate = status.parse::<u16>().ok();
        }
    }
    candidate
}

fn extract_bytes_received(line: &str) -> Option<u64> {
    BYTES_RECEIVED_REGEX
        .get_or_init(|| {
            Regex::new(r"bytes_received=(\d+)").expect("valid bytes_received regex")
        })
        .captures(line)
        .and_then(|caps| caps.get(1))
        .and_then(|m| m.as_str().parse::<u64>().ok())
}

fn matches_ip_scope(parsed: &ParsedLogLine, scope: IpScope) -> bool {
    let ip = parsed.last_ip;
    match (ip, scope) {
        (Some(addr), IpScope::Private) => is_private(addr),
        (Some(addr), IpScope::Public) => !is_private(addr),
        _ => true,
    }
}

fn all_ipv4(line: &str) -> impl Iterator<Item = Ipv4Addr> + '_ {
    IP_REGEX
        .get_or_init(|| {
            Regex::new(r"(?:\d{1,3}\.){3}\d{1,3}").expect("valid candidate ip regex")
        })
        .find_iter(line)
        .filter(|m| is_standalone_ipv4_token(line, m.start(), m.end()))
        .filter(|m| !is_version_like_context(line, m.start()))
        .filter_map(|m| m.as_str().parse::<Ipv4Addr>().ok())
}

fn is_standalone_ipv4_token(line: &str, start: usize, end: usize) -> bool {
    let bytes = line.as_bytes();
    let prev = start
        .checked_sub(1)
        .and_then(|idx| bytes.get(idx))
        .copied();
    let prev2 = start
        .checked_sub(2)
        .and_then(|idx| bytes.get(idx))
        .copied();
    let next = bytes.get(end).copied();
    let next2 = bytes.get(end + 1).copied();

    // Reject partial captures from long dotted numeric chains (e.g., 1.2.3.4.5).
    let starts_inside_chain =
        prev == Some(b'.') && prev2.map(|ch| ch.is_ascii_digit()).unwrap_or(false);
    let ends_inside_chain =
        next == Some(b'.') && next2.map(|ch| ch.is_ascii_digit()).unwrap_or(false);

    !starts_inside_chain && !ends_inside_chain
}

fn is_version_like_context(line: &str, start: usize) -> bool {
    let bytes = line.as_bytes();
    let prev = start
        .checked_sub(1)
        .and_then(|idx| bytes.get(idx))
        .copied();
    let prev2 = start
        .checked_sub(2)
        .and_then(|idx| bytes.get(idx))
        .copied();
    let prev3 = start
        .checked_sub(3)
        .and_then(|idx| bytes.get(idx))
        .copied();

    // Common user-agent/app version forms:
    // - Chrome/123.45.67.89
    // - rv:11.0.0.0
    // - v1.2.3.4
    if prev == Some(b'/') && prev2.map(|ch| ch.is_ascii_alphanumeric()).unwrap_or(false) {
        return true;
    }
    if prev == Some(b':') && prev2.map(|ch| ch.is_ascii_alphabetic()).unwrap_or(false) {
        return true;
    }
    if matches!(prev, Some(b'v') | Some(b'V'))
        && prev2.map(|ch| !ch.is_ascii_alphanumeric()).unwrap_or(true)
    {
        return true;
    }
    if prev == Some(b'.')
        && prev2.map(|ch| ch.is_ascii_alphabetic()).unwrap_or(false)
        && prev3.map(|ch| !ch.is_ascii_alphanumeric()).unwrap_or(true)
    {
        return true;
    }

    false
}

fn extract_src_dst(line: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
    let src = SRC_IP_REGEX
        .get_or_init(|| {
            Regex::new(r#"src_ip="?((?:\d{1,3}\.){3}\d{1,3})"?"#).expect("valid src_ip regex")
        })
        .captures(line)
        .and_then(|caps| caps.get(1))
        .and_then(|m| m.as_str().parse::<Ipv4Addr>().ok());

    let dst = DST_IP_REGEX
        .get_or_init(|| {
            Regex::new(r#"dst_ip="?((?:\d{1,3}\.){3}\d{1,3})"?"#).expect("valid dst_ip regex")
        })
        .captures(line)
        .and_then(|caps| caps.get(1))
        .and_then(|m| m.as_str().parse::<Ipv4Addr>().ok());

    (src, dst)
}

fn is_private(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    match octets {
        [10, ..] => true,
        [172, 16..=31, ..] => true,
        [192, 168, ..] => true,
        _ => false,
    }
}

fn extract_timestamp_key(line: &str) -> Option<String> {
    if line.len() < 19 {
        return None;
    }
    let candidate = &line[..19];
    let bytes = candidate.as_bytes();
    if bytes.len() == 19
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b' '
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes
            .iter()
            .enumerate()
            .filter(|(i, _)| ![4, 7, 10, 13, 16].contains(i))
            .all(|(_, c)| (*c as char).is_ascii_digit())
    {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn parse_log_line(line: &str) -> ParsedLogLine {
    let timestamp = extract_timestamp_key(line);
    let timestamp_epoch = timestamp
        .as_deref()
        .and_then(parse_timestamp_epoch_seconds);
    let status = extract_status(line);
    let bytes_received = extract_bytes_received(line);
    let all_ips = all_ipv4(line).collect::<Vec<_>>();
    let last_ip = all_ips.last().copied();
    let (src_ip, dst_ip) = extract_src_dst(line);

    ParsedLogLine {
        timestamp_epoch,
        status,
        bytes_received,
        src_ip,
        dst_ip,
        all_ips,
        last_ip,
    }
}

fn parse_timestamp_epoch_seconds(input: &str) -> Option<i64> {
    if input.len() != 19 {
        return None;
    }
    let bytes = input.as_bytes();
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b' '
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }

    let year: i32 = input[0..4].parse().ok()?;
    let month: u32 = input[5..7].parse().ok()?;
    let day: u32 = input[8..10].parse().ok()?;
    let hour: u32 = input[11..13].parse().ok()?;
    let minute: u32 = input[14..16].parse().ok()?;
    let second: u32 = input[17..19].parse().ok()?;

    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let max_day = days_in_month(year, month);
    if day == 0 || day > max_day {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    Some(days * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    let month_i = month as i32;
    let year_adj = year - i32::from(month <= 2);
    let era = if year_adj >= 0 {
        year_adj
    } else {
        year_adj - 399
    } / 400;
    let yoe = year_adj - era * 400;
    let doy = (153 * (month_i + if month_i > 2 { -3 } else { 9 }) + 2) / 5 + day as i32 - 1;
    if doy < 0 {
        return None;
    }
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era as i64 * 146_097 + doe as i64 - 719_468)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn make_display_path(path: &Path, base: &Path) -> String {
    let cleaned = path.strip_prefix(base).unwrap_or(path);
    let text = cleaned.to_string_lossy();
    text.trim_start_matches(std::path::MAIN_SEPARATOR)
        .to_string()
}

static STATUS_KV_REGEX: OnceLock<Regex> = OnceLock::new();
static IP_REGEX: OnceLock<Regex> = OnceLock::new();
static BYTES_RECEIVED_REGEX: OnceLock<Regex> = OnceLock::new();
static SRC_IP_REGEX: OnceLock<Regex> = OnceLock::new();
static DST_IP_REGEX: OnceLock<Regex> = OnceLock::new();

fn build_set(terms: &[String], case_sensitive: bool) -> Result<Option<RegexSet>, regex::Error> {
    if terms.is_empty() {
        return Ok(None);
    }
    let patterns = terms.iter().map(|t| regex::escape(t));
    regex::RegexSetBuilder::new(patterns)
        .case_insensitive(!case_sensitive)
        .build()
        .map(Some)
}

fn deserialize_opt_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| serde::de::Error::custom("expected positive integer"))
            .map(Some),
        Some(serde_json::Value::String(s)) => {
            let cleaned: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
            if cleaned.is_empty() {
                return Ok(None);
            }
            cleaned
                .parse::<u64>()
                .map(Some)
                .map_err(|_| serde::de::Error::custom("invalid integer string"))
        }
        Some(other) => Err(serde::de::Error::custom(format!(
            "unexpected type for min_bytes_received: {other:?}"
        ))),
    }
}

#[derive(Clone)]
struct KeywordMatcher {
    terms_set: Option<RegexSet>,
    none_set: Option<RegexSet>,
    terms_count: usize,
    status_code: Option<u16>,
    ip_scope: Option<IpScope>,
    match_mode: MatchMode,
    min_bytes_received: Option<u64>,
    sort_mode: SortMode,
    compiled_rules: Vec<CompiledRule>,
}

impl KeywordMatcher {
    fn new(query: &SearchQuery) -> Result<Self, SearchError> {
        let terms_set = build_set(&query.terms, query.case_sensitive)?;
        let none_set = build_set(&query.none, query.case_sensitive)?;
        let compiled_rules = compile_rules(&query.rules, query.case_sensitive)?;

        Ok(Self {
            terms_set,
            none_set,
            terms_count: query.terms.len(),
            status_code: query.status_code,
            ip_scope: query.ip_scope,
            match_mode: query.match_mode,
            min_bytes_received: query.min_bytes_received,
            sort_mode: query.sort_mode,
            compiled_rules,
        })
    }

    fn new_rule_runtime(&self) -> RuleRuntime {
        RuleRuntime::with_rule_count(self.compiled_rules.len())
    }

    fn requires_bytes(&self) -> bool {
        self.min_bytes_received.is_some() || self.sort_mode.requires_bytes()
    }

    fn evaluate(&self, line_bytes: &[u8], rule_runtime: &mut RuleRuntime) -> Option<MatchedLine> {
        let line_text = String::from_utf8_lossy(line_bytes);
        let line_str = line_text.as_ref();

        let terms_match = match (self.terms_set.as_ref(), self.match_mode) {
            (None, _) => true,
            (Some(set), MatchMode::Any) => set.is_match(line_str),
            (Some(set), MatchMode::All) => set.matches(line_str).len() == self.terms_count,
        };
        if !terms_match {
            return None;
        }

        if let Some(none) = &self.none_set {
            if none.is_match(line_str) {
                return None;
            }
        }

        let parsed = parse_log_line(line_str);

        if let Some(code) = self.status_code {
            match parsed.status {
                Some(line_code) if line_code == code => {}
                _ => return None,
            }
        }

        if let Some(scope) = self.ip_scope {
            if !matches_ip_scope(&parsed, scope) {
                return None;
            }
        }

        if self.requires_bytes() {
            if let Some(min) = self.min_bytes_received {
                match parsed.bytes_received {
                    Some(value) if value >= min => {}
                    _ => return None,
                }
            }
        }

        let matched_rule_ids = self.evaluate_rules(line_str, &parsed, rule_runtime);
        if !self.compiled_rules.is_empty() && matched_rule_ids.is_empty() {
            return None;
        }

        Some(MatchedLine {
            line: line_text.into_owned(),
            parsed,
            matched_rule_ids,
        })
    }

    fn evaluate_rules(
        &self,
        line: &str,
        parsed: &ParsedLogLine,
        rule_runtime: &mut RuleRuntime,
    ) -> Vec<String> {
        if self.compiled_rules.is_empty() {
            return Vec::new();
        }

        let mut matched = Vec::new();
        for (idx, rule) in self.compiled_rules.iter().enumerate() {
            let Some(state) = rule_runtime.states.get_mut(idx) else {
                continue;
            };
            if !rule.matches_base(line, parsed) {
                continue;
            }
            if rule.matches_threshold(parsed, state) {
                matched.push(rule.id.clone());
            }
        }
        matched
    }
}

impl CompiledRule {
    fn matches_base(&self, line: &str, parsed: &ParsedLogLine) -> bool {
        if let Some(regex) = &self.regex {
            if !regex.is_match(line) {
                return false;
            }
        }
        self.conditions
            .iter()
            .all(|condition| condition.matches(line, parsed))
    }

    fn matches_threshold(&self, parsed: &ParsedLogLine, state: &mut RuleRuntimeState) -> bool {
        if self.threshold.is_none() && self.time_window_seconds.is_none() {
            return true;
        }

        if self.time_window_seconds.is_some() && parsed.timestamp_epoch.is_none() {
            return false;
        }

        let threshold = self.threshold.unwrap_or(1).max(1);
        let event_ts = match parsed.timestamp_epoch {
            Some(ts) => ts,
            None => {
                state.synthetic_clock += 1;
                state.synthetic_clock
            }
        };

        let group_key = self.group_value(parsed);
        let bucket = state.buckets.entry(group_key).or_default();
        if let Some(window) = self.time_window_seconds {
            let window_i64 = window as i64;
            while let Some(front) = bucket.front().copied() {
                if event_ts.saturating_sub(front) > window_i64 {
                    bucket.pop_front();
                } else {
                    break;
                }
            }
        }

        bucket.push_back(event_ts);
        bucket.len() as u64 >= threshold
    }

    fn group_value(&self, parsed: &ParsedLogLine) -> String {
        match self.group_by {
            RuleGroupBy::Global => "global".to_string(),
            RuleGroupBy::SrcIp => parsed
                .src_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            RuleGroupBy::DstIp => parsed
                .dst_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            RuleGroupBy::Status => parsed
                .status
                .map(|code| code.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        }
    }
}

impl CompiledRuleCondition {
    fn matches(&self, line: &str, parsed: &ParsedLogLine) -> bool {
        match self.field {
            RuleField::Line => {
                let CompiledRuleValue::Text(expected) = &self.value else {
                    return false;
                };
                match self.op {
                    RuleOperator::Eq => line == expected,
                    RuleOperator::Ne => line != expected,
                    RuleOperator::Contains => line.contains(expected),
                    _ => false,
                }
            }
            RuleField::Status => compare_u64(
                parsed.status.map(|v| v as u64),
                &self.op,
                match self.value {
                    CompiledRuleValue::Status(v) => v as u64,
                    _ => return false,
                },
            ),
            RuleField::BytesReceived => compare_u64(
                parsed.bytes_received,
                &self.op,
                match self.value {
                    CompiledRuleValue::Number(v) => v,
                    _ => return false,
                },
            ),
            RuleField::Timestamp => compare_i64(
                parsed.timestamp_epoch,
                &self.op,
                match self.value {
                    CompiledRuleValue::Timestamp(v) => v,
                    _ => return false,
                },
            ),
            RuleField::SrcIp => compare_ip(
                parsed.src_ip,
                &self.op,
                match self.value {
                    CompiledRuleValue::Ip(v) => v,
                    _ => return false,
                },
            ),
            RuleField::DstIp => compare_ip(
                parsed.dst_ip,
                &self.op,
                match self.value {
                    CompiledRuleValue::Ip(v) => v,
                    _ => return false,
                },
            ),
        }
    }
}

fn compare_u64(actual: Option<u64>, op: &RuleOperator, expected: u64) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    match op {
        RuleOperator::Eq => actual == expected,
        RuleOperator::Ne => actual != expected,
        RuleOperator::Gt => actual > expected,
        RuleOperator::Gte => actual >= expected,
        RuleOperator::Lt => actual < expected,
        RuleOperator::Lte => actual <= expected,
        RuleOperator::Contains => false,
    }
}

fn compare_i64(actual: Option<i64>, op: &RuleOperator, expected: i64) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    match op {
        RuleOperator::Eq => actual == expected,
        RuleOperator::Ne => actual != expected,
        RuleOperator::Gt => actual > expected,
        RuleOperator::Gte => actual >= expected,
        RuleOperator::Lt => actual < expected,
        RuleOperator::Lte => actual <= expected,
        RuleOperator::Contains => false,
    }
}

fn compare_ip(actual: Option<Ipv4Addr>, op: &RuleOperator, expected: Ipv4Addr) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    match op {
        RuleOperator::Eq => actual == expected,
        RuleOperator::Ne => actual != expected,
        _ => false,
    }
}

fn compile_rules(raw_rules: &[RuleFilter], case_sensitive: bool) -> Result<Vec<CompiledRule>, SearchError> {
    let mut compiled = Vec::with_capacity(raw_rules.len());
    for (idx, rule) in raw_rules.iter().enumerate() {
        if let Some(0) = rule.threshold {
            return Err(SearchError::InvalidRule(format!(
                "rule {} threshold must be greater than zero",
                rule.id.as_deref().unwrap_or("unnamed")
            )));
        }
        if let Some(0) = rule.time_window_seconds {
            return Err(SearchError::InvalidRule(format!(
                "rule {} time_window_seconds must be greater than zero",
                rule.id.as_deref().unwrap_or("unnamed")
            )));
        }

        let regex = if let Some(pattern) = rule.regex.as_deref() {
            if pattern.trim().is_empty() {
                None
            } else {
                Some(
                    RegexBuilder::new(pattern)
                        .case_insensitive(!case_sensitive)
                        .build()
                        .map_err(SearchError::Regex)?,
                )
            }
        } else {
            None
        };

        let mut conditions = Vec::with_capacity(rule.conditions.len());
        for condition in &rule.conditions {
            conditions.push(compile_condition(condition)?);
        }

        compiled.push(CompiledRule {
            id: rule
                .id
                .clone()
                .unwrap_or_else(|| format!("rule_{}", idx + 1)),
            regex,
            conditions,
            threshold: rule.threshold,
            time_window_seconds: rule.time_window_seconds,
            group_by: rule.group_by,
        });
    }
    Ok(compiled)
}

fn compile_condition(raw: &RuleCondition) -> Result<CompiledRuleCondition, SearchError> {
    let value = match raw.field {
        RuleField::Line => CompiledRuleValue::Text(raw.value.clone()),
        RuleField::Status => {
            let parsed = raw.value.parse::<u16>().map_err(|_| {
                SearchError::InvalidRule(format!("status value must be u16: {}", raw.value))
            })?;
            CompiledRuleValue::Status(parsed)
        }
        RuleField::BytesReceived => {
            let parsed = raw.value.parse::<u64>().map_err(|_| {
                SearchError::InvalidRule(format!("bytes_received must be u64: {}", raw.value))
            })?;
            CompiledRuleValue::Number(parsed)
        }
        RuleField::Timestamp => {
            let parsed = parse_timestamp_epoch_seconds(&raw.value).ok_or_else(|| {
                SearchError::InvalidRule(format!(
                    "timestamp must be YYYY-MM-DD HH:MM:SS: {}",
                    raw.value
                ))
            })?;
            CompiledRuleValue::Timestamp(parsed)
        }
        RuleField::SrcIp | RuleField::DstIp => {
            let parsed = raw.value.parse::<Ipv4Addr>().map_err(|_| {
                SearchError::InvalidRule(format!("ip value must be IPv4: {}", raw.value))
            })?;
            CompiledRuleValue::Ip(parsed)
        }
    };

    validate_rule_operator(&raw.field, &raw.op, &raw.value)?;

    Ok(CompiledRuleCondition {
        field: raw.field,
        op: raw.op,
        value,
    })
}

fn validate_rule_operator(
    field: &RuleField,
    op: &RuleOperator,
    value: &str,
) -> Result<(), SearchError> {
    let valid = match field {
        RuleField::Line => matches!(op, RuleOperator::Eq | RuleOperator::Ne | RuleOperator::Contains),
        RuleField::SrcIp | RuleField::DstIp => matches!(op, RuleOperator::Eq | RuleOperator::Ne),
        RuleField::Status | RuleField::BytesReceived | RuleField::Timestamp => {
            matches!(
                op,
                RuleOperator::Eq
                    | RuleOperator::Ne
                    | RuleOperator::Gt
                    | RuleOperator::Gte
                    | RuleOperator::Lt
                    | RuleOperator::Lte
            )
        }
    };
    if valid {
        Ok(())
    } else {
        Err(SearchError::InvalidRule(format!(
            "operator {:?} is not valid for field {:?} (value={})",
            op, field, value
        )))
    }
}

const fn default_page() -> usize {
    1
}

const fn default_page_size() -> usize {
    DEFAULT_PAGE_SIZE
}

const fn default_radius() -> u64 {
    5
}

#[derive(Debug)]
struct ProgressTracker {
    total: usize,
    started: AtomicUsize,
    finished: AtomicUsize,
}

impl ProgressTracker {
    fn new(total: usize) -> Self {
        Self {
            total,
            started: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
        }
    }

    fn mark_start(&self, path: &Path) {
        let current = self.started.fetch_add(1, AtomicOrdering::Relaxed) + 1;
        info!(
            current,
            total = self.total,
            file = %path.display(),
            "starting log scan"
        );
    }

    fn mark_finish(&self, path: &Path, matches: u64, bytes: u64) {
        let done = self.finished.fetch_add(1, AtomicOrdering::Relaxed) + 1;
        info!(
            completed = done,
            total = self.total,
            file = %path.display(),
            matches,
            bytes,
            "finished log scan"
        );
    }
}

struct ExportSink {
    writer: Mutex<Writer<File>>,
    public_counts: Mutex<HashMap<Ipv4Addr, u64>>,
    path: PathBuf,
    total_rows: AtomicU64,
}

impl ExportSink {
    fn new(dir: &Path) -> Result<Self, SearchError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let file_path = resolve_export_path(&format!("log_export_{timestamp}.csv"), dir)?;
        let mut writer = Writer::from_path(&file_path).map_err(|source| SearchError::Csv {
            path: file_path.clone(),
            source,
        })?;
        writer
            .write_record([
                "file_path",
                "line_number",
                "byte_offset",
                "src_ip",
                "dst_ip",
                "line",
            ])
            .map_err(|source| SearchError::Csv {
                path: file_path.clone(),
                source,
            })?;

        Ok(Self {
            writer: Mutex::new(writer),
            public_counts: Mutex::new(HashMap::new()),
            path: file_path,
            total_rows: AtomicU64::new(0),
        })
    }

    fn record(
        &self,
        display_path: &str,
        line_number: u64,
        byte_offset: u64,
        line: &str,
        src_ip: Option<&str>,
        dst_ip: Option<&str>,
        last_ip: Option<Ipv4Addr>,
    ) -> Result<(), SearchError> {
        let mut writer = self.writer.lock().map_err(|_| SearchError::ExportLock)?;
        writer
            .write_record([
                display_path,
                &line_number.to_string(),
                &byte_offset.to_string(),
                src_ip.unwrap_or(""),
                dst_ip.unwrap_or(""),
                line,
            ])
            .map_err(|source| SearchError::Csv {
                path: self.path.clone(),
                source,
            })?;

        if let Some(ip) = last_ip {
            if !is_private(ip) {
                let mut counts = self
                    .public_counts
                    .lock()
                    .map_err(|_| SearchError::ExportLock)?;
                *counts.entry(ip).or_insert(0) += 1;
            }
        }

        self.total_rows.fetch_add(1, AtomicOrdering::Relaxed);
        Ok(())
    }

    fn finalize(&self) -> Result<ExportReport, SearchError> {
        let mut writer = self.writer.lock().map_err(|_| SearchError::ExportLock)?;

        // Append a spacer and public IP counts at EOF.
        if let Ok(public_counts_guard) = self.public_counts.lock() {
            let mut public_counts = public_counts_guard
                .iter()
                .map(|(ip, count)| (ip.to_string(), *count))
                .collect::<Vec<_>>();
            public_counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

            if !public_counts.is_empty() {
                writer
                    .write_record(["", "", "", "", "", ""])
                    .map_err(|source| SearchError::Csv {
                        path: self.path.clone(),
                        source,
                    })?;
                for (ip, count) in public_counts {
                    writer
                        .write_record(["", "", "", "", "", &format!("{ip} - {count}")])
                        .map_err(|source| SearchError::Csv {
                            path: self.path.clone(),
                            source,
                        })?;
                }
            }
        }

        writer.flush().map_err(|source| SearchError::Csv {
            path: self.path.clone(),
            source: source.into(),
        })?;

        let total_rows = self.total_rows.load(AtomicOrdering::Relaxed);
        let absolute = self
            .path
            .canonicalize()
            .unwrap_or_else(|_| self.path.clone());
        Ok(ExportReport {
            path: absolute,
            total_rows,
        })
    }
}

struct ExportReport {
    path: PathBuf,
    total_rows: u64,
}

fn resolve_export_path(file_name: &str, preferred_dir: &Path) -> Result<PathBuf, SearchError> {
    let preferred = if preferred_dir.is_absolute() {
        preferred_dir.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|source| SearchError::Io {
                path: PathBuf::from("."),
                source,
            })?
            .join(preferred_dir)
    };

    if let Some(path) = try_prepare_export_path(&preferred, file_name)? {
        return Ok(path);
    }

    let fallback = preferred
        .parent()
        .map(|parent| parent.join(EXPORT_FALLBACK_DIR))
        .unwrap_or_else(|| PathBuf::from(EXPORT_FALLBACK_DIR));
    if fallback != preferred {
        if let Some(path) = try_prepare_export_path(&fallback, file_name)? {
            info!(
                preferred = %preferred.display(),
                fallback = %fallback.display(),
                "preferred export directory is not writable; using fallback directory"
            );
            return Ok(path);
        }
    }

    Err(SearchError::Io {
        path: preferred,
        source: io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unable to create writable export file",
        ),
    })
}

fn export_download_path(path: &Path) -> String {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("export.csv");
    format!("/exports/{file_name}")
}

fn try_prepare_export_path(base: &Path, file_name: &str) -> Result<Option<PathBuf>, SearchError> {
    match fs::create_dir_all(base) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return Ok(None),
        Err(source) => {
            return Err(SearchError::Io {
                path: base.to_path_buf(),
                source,
            })
        }
    }

    let candidate = base.join(file_name);
    match File::create(&candidate) {
        Ok(_) => {
            // Remove the placeholder; the real writer will recreate it.
            let _ = fs::remove_file(&candidate);
            Ok(Some(candidate))
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(Some(candidate)),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => Ok(None),
        Err(source) => Err(SearchError::Io {
            path: candidate,
            source,
        }),
    }
}

fn write_ip_summary_csv(
    all: &[IpSummaryEntry],
    src: &[IpSummaryEntry],
    dst: &[IpSummaryEntry],
    unique_all: usize,
    unique_src: usize,
    unique_dst: usize,
) -> Result<String, SearchError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let file_path =
        resolve_export_path(&format!("ip_summary_{timestamp}.csv"), Path::new(EXPORT_DIR))?;
    let mut writer = Writer::from_path(&file_path).map_err(|source| SearchError::Csv {
        path: file_path.clone(),
        source,
    })?;

    writer
        .write_record(["scope", "ip", "count"])
        .map_err(|source| SearchError::Csv {
            path: file_path.clone(),
            source,
        })?;

    let mut write_block = |scope: &str, entries: &[IpSummaryEntry]| -> Result<(), SearchError> {
        for entry in entries {
            writer
                .write_record([scope, entry.ip.as_str(), &entry.count.to_string()])
                .map_err(|source| SearchError::Csv {
                    path: file_path.clone(),
                    source,
                })?;
        }
        writer
            .write_record(["", "", ""])
            .map_err(|source| SearchError::Csv {
                path: file_path.clone(),
                source,
            })
    };

    write_block("all", all)?;
    write_block("src", src)?;
    write_block("dst", dst)?;

    // Append totals as a footer block
    writer
        .write_record(["unique_all", &unique_all.to_string(), ""])
        .map_err(|source| SearchError::Csv {
            path: file_path.clone(),
            source,
        })?;
    writer
        .write_record(["unique_src", &unique_src.to_string(), ""])
        .map_err(|source| SearchError::Csv {
            path: file_path.clone(),
            source,
        })?;
    writer
        .write_record(["unique_dst", &unique_dst.to_string(), ""])
        .map_err(|source| SearchError::Csv {
            path: file_path.clone(),
            source,
        })?;

    writer.flush().map_err(|source| SearchError::Csv {
        path: file_path.clone(),
        source: source.into(),
    })?;

    let absolute = file_path
        .canonicalize()
        .unwrap_or_else(|_| file_path.clone());
    Ok(export_download_path(&absolute))
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IpScope {
    Private,
    Public,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    All,
    Any,
}

impl Default for MatchMode {
    fn default() -> Self {
        MatchMode::Any
    }
}

pub fn fetch_context(request: ContextRequest) -> Result<ContextResponse, SearchError> {
    let root = request.root_path.canonicalize().map_err(|source| SearchError::Io {
        path: request.root_path.clone(),
        source,
    })?;
    let requested = PathBuf::from(&request.file_path);
    if requested.is_absolute() {
        return Err(SearchError::OutsideRoot(request.file_path));
    }
    let target = root.join(&request.file_path);
    let canonical = target.canonicalize().map_err(|source| SearchError::Io {
        path: target.clone(),
        source,
    })?;
    if !canonical.starts_with(&root) {
        return Err(SearchError::OutsideRoot(request.file_path));
    }

    let radius = request.radius.min(50);
    let target_line = request.line.max(1);
    let start = target_line.saturating_sub(radius).max(1);
    let end = target_line.saturating_add(radius);

    let file = File::open(&canonical).map_err(|source| SearchError::Io {
        path: canonical.clone(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    let mut line_no = 0u64;
    let mut lines = Vec::new();

    loop {
        buffer.clear();
        let bytes = reader
            .read_until(b'\n', &mut buffer)
            .map_err(|source| SearchError::Io {
                path: canonical.clone(),
                source,
            })?;
        if bytes == 0 {
            break;
        }
        line_no += 1;
        if line_no < start {
            continue;
        }
        if line_no > end {
            break;
        }
        let text = decode_line(&buffer).into_owned();
        lines.push(ContextLine {
            line_number: line_no,
            line: text,
        });
    }

    Ok(ContextResponse {
        file_path: request.file_path,
        start_line: start,
        end_line: end.min(line_no),
        lines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;

    fn write_log(dir: &Path, name: &str, lines: &[&str]) -> PathBuf {
        let path = dir.join(name);
        let mut file = File::create(&path).expect("create log");
        for line in lines {
            writeln!(file, "{line}").expect("write line");
        }
        path
    }

    fn run_search(dir: &Path, min_bytes: Option<u64>, sort_mode: SortMode) -> SearchResponse {
        let request = SearchRequest {
            root_path: dir.to_path_buf(),
            terms: Vec::new(),
            none: Vec::new(),
            page: 1,
            page_size: 50,
            export_csv: false,
            status_code: None,
            case_sensitive: false,
            ip_scope: None,
            match_mode: MatchMode::Any,
            min_bytes_received: min_bytes,
            sort_mode,
            rules: Vec::new(),
        };
        execute_search(request.into_query().unwrap()).expect("search ok")
    }

    #[test]
    fn filters_by_min_bytes_received() {
        let tmp = tempfile::tempdir().unwrap();
        write_log(
            tmp.path(),
            "a.log",
            &[
                r#"bytes_received=100 foo"#,
                r#"bytes_received=5000 bar"#,
                r#"no_bytes_here baz"#,
            ],
        );

        let resp = run_search(tmp.path(), Some(1000), SortMode::FilePosition);
        let lines: Vec<_> = resp.results.iter().map(|r| r.line.as_str()).collect();

        assert_eq!(lines, vec!["bytes_received=5000 bar"]);
    }

    #[test]
    fn sorts_by_bytes_received_desc() {
        let tmp = tempfile::tempdir().unwrap();
        write_log(
            tmp.path(),
            "a.log",
            &[
                r#"bytes_received=100 foo"#,
                r#"bytes_received=5000 bar"#,
                r#"bytes_received=2000 baz"#,
            ],
        );

        let resp = run_search(tmp.path(), None, SortMode::BytesReceivedDesc);
        let lines: Vec<_> = resp.results.iter().map(|r| r.line.as_str()).collect();

        assert_eq!(
            lines,
            vec![
                "bytes_received=5000 bar",
                "bytes_received=2000 baz",
                "bytes_received=100 foo"
            ]
        );
    }

    #[test]
    fn parses_min_bytes_with_separators() {
        let json = r#"
        {
            "root_path": ".",
            "min_bytes_received": "100.000.000",
            "terms": [],
            "none": []
        }
        "#;
        let req: SearchRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.min_bytes_received, Some(100_000_000));
    }

    #[test]
    fn ip_summary_collects_unique_counts() {
        let tmp = tempfile::tempdir().unwrap();
        write_log(
            tmp.path(),
            "a.log",
            &[
                r#"src_ip="10.0.0.1" dst_ip="10.0.0.2" bytes_received=2000"#,
                r#"src_ip="10.0.0.2" dst_ip="8.8.8.8" bytes_received=2000"#,
                r#"no ip here bytes_received=2000"#,
            ],
        );

        let req = SearchRequest {
            root_path: tmp.path().to_path_buf(),
            terms: Vec::new(),
            none: Vec::new(),
            page: 1,
            page_size: 50,
            export_csv: false,
            status_code: None,
            case_sensitive: false,
            ip_scope: None,
            match_mode: MatchMode::Any,
            min_bytes_received: None,
            sort_mode: SortMode::FilePosition,
            rules: Vec::new(),
        };

        let resp = execute_ip_summary(req.into_query().unwrap()).unwrap();
        assert_eq!(resp.total_matches, 3);
        assert_eq!(resp.unique_ips, 3);
        assert_eq!(resp.unique_src_ips, 2);
        assert_eq!(resp.unique_dst_ips, 2);
        let src_map: HashMap<_, _> = resp
            .src_ips
            .iter()
            .map(|e| (e.ip.as_str(), e.count))
            .collect();
        let dst_map: HashMap<_, _> = resp
            .dst_ips
            .iter()
            .map(|e| (e.ip.as_str(), e.count))
            .collect();
        assert_eq!(src_map.get("10.0.0.1"), Some(&1));
        assert_eq!(src_map.get("10.0.0.2"), Some(&1));
        assert_eq!(dst_map.get("10.0.0.2"), Some(&1));
        assert_eq!(dst_map.get("8.8.8.8"), Some(&1));
    }

    #[test]
    fn total_matches_counts_all_matches_beyond_page_window() {
        let tmp = tempfile::tempdir().unwrap();
        write_log(tmp.path(), "a.log", &["line1", "line2", "line3"]);
        write_log(tmp.path(), "b.log", &["line4", "line5", "line6"]);

        let req = SearchRequest {
            root_path: tmp.path().to_path_buf(),
            terms: Vec::new(),
            none: Vec::new(),
            page: 1,
            page_size: 1,
            export_csv: false,
            status_code: None,
            case_sensitive: false,
            ip_scope: None,
            match_mode: MatchMode::Any,
            min_bytes_received: None,
            sort_mode: SortMode::FilePosition,
            rules: Vec::new(),
        };

        let resp = execute_search(req.into_query().unwrap()).unwrap();
        assert_eq!(resp.total_matches, 6);
        assert_eq!(resp.results.len(), 1);
        assert!(resp.has_more);
    }

    #[test]
    fn rule_regex_and_field_conditions_filter_lines() {
        let tmp = tempfile::tempdir().unwrap();
        write_log(
            tmp.path(),
            "a.log",
            &[
                r#"2026-01-01 10:00:00 failed src_ip="10.0.0.1" bytes_received=120 401 1 1"#,
                r#"2026-01-01 10:00:05 failed src_ip="10.0.0.1" bytes_received=90 401 1 1"#,
                r#"2026-01-01 10:00:10 success src_ip="10.0.0.1" bytes_received=300 200 1 1"#,
            ],
        );

        let req = SearchRequest {
            root_path: tmp.path().to_path_buf(),
            terms: Vec::new(),
            none: Vec::new(),
            page: 1,
            page_size: 50,
            export_csv: false,
            status_code: None,
            case_sensitive: false,
            ip_scope: None,
            match_mode: MatchMode::Any,
            min_bytes_received: None,
            sort_mode: SortMode::FilePosition,
            rules: vec![RuleFilter {
                id: Some("failed_with_min_bytes".to_string()),
                name: Some("Failed With Min Bytes".to_string()),
                severity: Some(RuleSeverity::Medium),
                regex: Some("failed".to_string()),
                conditions: vec![RuleCondition {
                    field: RuleField::BytesReceived,
                    op: RuleOperator::Gte,
                    value: "100".to_string(),
                }],
                threshold: None,
                time_window_seconds: None,
                group_by: RuleGroupBy::Global,
            }],
        };

        let resp = execute_search(req.into_query().unwrap()).unwrap();
        assert_eq!(resp.total_matches, 1);
        assert_eq!(resp.results.len(), 1);
        assert_eq!(
            resp.results[0].matched_rules.as_ref().unwrap(),
            &vec!["failed_with_min_bytes".to_string()]
        );
    }

    #[test]
    fn rule_threshold_with_time_window() {
        let tmp = tempfile::tempdir().unwrap();
        write_log(
            tmp.path(),
            "a.log",
            &[
                r#"2026-01-01 10:00:00 failed src_ip="10.0.0.1" bytes_received=120 401 1 1"#,
                r#"2026-01-01 10:00:20 failed src_ip="10.0.0.1" bytes_received=130 401 1 1"#,
                r#"2026-01-01 10:02:00 failed src_ip="10.0.0.1" bytes_received=140 401 1 1"#,
            ],
        );

        let req = SearchRequest {
            root_path: tmp.path().to_path_buf(),
            terms: Vec::new(),
            none: Vec::new(),
            page: 1,
            page_size: 50,
            export_csv: false,
            status_code: None,
            case_sensitive: false,
            ip_scope: None,
            match_mode: MatchMode::Any,
            min_bytes_received: None,
            sort_mode: SortMode::FilePosition,
            rules: vec![RuleFilter {
                id: Some("burst_failed_login".to_string()),
                name: Some("Burst Failed Login".to_string()),
                severity: Some(RuleSeverity::High),
                regex: Some("failed".to_string()),
                conditions: vec![RuleCondition {
                    field: RuleField::Status,
                    op: RuleOperator::Eq,
                    value: "401".to_string(),
                }],
                threshold: Some(2),
                time_window_seconds: Some(60),
                group_by: RuleGroupBy::SrcIp,
            }],
        };

        let resp = execute_search(req.into_query().unwrap()).unwrap();
        assert_eq!(resp.total_matches, 1);
        assert_eq!(resp.results.len(), 1);
        assert!(resp.results[0].line.contains("10:00:20"));
        assert_eq!(
            resp.results[0].matched_rules.as_ref().unwrap(),
            &vec!["burst_failed_login".to_string()]
        );
    }

    #[test]
    fn parser_extracts_status_and_timestamp() {
        let line = r#"2026-01-01 10:00:20 failed src_ip="10.0.0.1" bytes_received=130 401 1 1"#;
        let parsed = parse_log_line(line);
        assert_eq!(parsed.status, Some(401));
        assert!(parsed.timestamp_epoch.is_some());
        assert_eq!(parsed.src_ip, Some("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parser_ignores_user_agent_version_numbers_as_ip() {
        let line = r#"203.0.113.7 - - [07/Jan/2026:22:22:20 +0300] "GET / HTTP/1.1" 200 333 "-" "Chrome/123.45.67.89 rv:11.0.0.0""#;
        let parsed = parse_log_line(line);

        assert!(parsed.all_ips.contains(&"203.0.113.7".parse().unwrap()));
        assert!(!parsed.all_ips.contains(&"123.45.67.89".parse().unwrap()));
        assert!(!parsed.all_ips.contains(&"11.0.0.0".parse().unwrap()));
    }

    #[test]
    fn parser_keeps_url_host_ip_and_skips_dotted_chain_partials() {
        let line = r#"GET http://198.51.100.10/path chain=1.2.3.4.5 "curl/8.17.0""#;
        let parsed = parse_log_line(line);

        assert!(parsed.all_ips.contains(&"198.51.100.10".parse().unwrap()));
        assert!(!parsed.all_ips.contains(&"1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn context_rejects_file_outside_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("logs");
        fs::create_dir_all(&root).unwrap();
        write_log(&root, "a.log", &["inside"]);
        write_log(tmp.path(), "outside.log", &["outside"]);

        let err = fetch_context(ContextRequest {
            root_path: root,
            file_path: "../outside.log".to_string(),
            line: 1,
            radius: 2,
        })
        .unwrap_err();

        assert!(matches!(err, SearchError::OutsideRoot(_)));
    }

    #[test]
    fn export_sink_finalize_writes_consistent_csv_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let sink = ExportSink::new(tmp.path()).expect("create export sink");

        sink.record(
            "a.log",
            1,
            0,
            "sample line",
            Some("10.0.0.1"),
            Some("8.8.8.8"),
            Some("8.8.8.8".parse().unwrap()),
        )
        .expect("record row");

        let report = sink.finalize().expect("finalize export sink");
        let mut reader = csv::Reader::from_path(report.path).expect("open exported csv");
        let rows = reader
            .records()
            .collect::<Result<Vec<_>, _>>()
            .expect("read csv rows");

        assert!(!rows.is_empty());
    }
}
