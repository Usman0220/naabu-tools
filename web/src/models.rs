use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Error,
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStatus::Queued => write!(f, "Queued"),
            ScanStatus::Running => write!(f, "Running"),
            ScanStatus::Completed => write!(f, "Completed"),
            ScanStatus::Error => write!(f, "Error"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub id: u64,
    pub ips: Vec<String>,
    pub ports: String,
    pub settings: ScanSettings,
    pub status: ScanStatus,
    pub results: Vec<ScanResult>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub total_ips: usize,
    pub error_message: Option<String>,
}

impl ScanJob {
    pub fn new(id: u64, ips: Vec<String>, ports: String, settings: ScanSettings) -> Self {
        Self {
            total_ips: ips.len(),
            id,
            ips,
            ports,
            settings,
            status: ScanStatus::Queued,
            results: Vec::new(),
            started_at: None,
            finished_at: None,
            error_message: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanSettings {
    pub port_range: String,
    pub rate_limit: u32,
    pub timeout: u32,
    pub threads: u32,
    pub scan_type: ScanType,
    pub verify: bool,
    pub use_top_ports: bool,
    pub top_ports_count: u32,
}

impl ScanSettings {
    pub fn with_rates(mut self, rate_limit: u32, timeout: u32, threads: u32) -> Self {
        self.rate_limit = rate_limit;
        self.timeout = timeout;
        self.threads = threads;
        self
    }

    pub fn with_verify(mut self, verify: bool) -> Self {
        self.verify = verify;
        self
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    #[default]
    Connect,
    Syn,
    Auto,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Connect => write!(f, "connect"),
            ScanType::Syn => write!(f, "syn"),
            ScanType::Auto => write!(f, "auto"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScanRequest {
    pub ips: Vec<String>,
    pub settings: ScanSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseIpsRequest {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateRequest {
    pub count: usize,
}

#[derive(Clone)]
pub struct AppState {
    pub jobs: Arc<Mutex<HashMap<u64, ScanJob>>>,
    pub next_id: Arc<Mutex<u64>>,
    pub naabu_path: String,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
            naabu_path: "naabu".to_string(),
        }
    }

    pub fn next_id(&self) -> u64 {
        let mut id = self.next_id.lock().unwrap();
        let v = *id;
        *id += 1;
        v
    }

    pub fn insert(&self, job: ScanJob) {
        self.jobs.lock().unwrap().insert(job.id, job);
    }

    pub fn get(&self, id: u64) -> Option<ScanJob> {
        self.jobs.lock().unwrap().get(&id).cloned()
    }

    pub fn list(&self) -> Vec<ScanJob> {
        let mut jobs: Vec<ScanJob> = self.jobs.lock().unwrap().values().cloned().collect();
        jobs.sort_by_key(|j| std::cmp::Reverse(j.id));
        jobs
    }

    pub fn remove(&self, id: u64) -> bool {
        self.jobs.lock().unwrap().remove(&id).is_some()
    }
}

pub fn service_lookup(port: u16) -> (&'static str, &'static str) {
    match port {
        20 => ("FTP Data", "File Transfer Protocol Data"),
        21 => ("FTP", "File Transfer Protocol"),
        22 => ("SSH", "Secure Shell"),
        23 => ("Telnet", "Telnet remote access"),
        25 => ("SMTP", "Simple Mail Transfer Protocol"),
        53 => ("DNS", "Domain Name System"),
        80 => ("HTTP", "Hypertext Transfer Protocol"),
        81 => ("HTTP", "HTTP Alternate"),
        110 => ("POP3", "Post Office Protocol v3"),
        111 => ("RPCBind", "Remote Procedure Call"),
        135 => ("MSRPC", "Microsoft RPC"),
        139 => ("NetBIOS", "NetBIOS Session Service"),
        143 => ("IMAP", "Internet Message Access Protocol"),
        443 => ("HTTPS", "HTTP Secure"),
        445 => ("SMB", "Server Message Block"),
        631 => ("IPP", "Internet Printing Protocol"),
        993 => ("IMAPS", "IMAP over SSL"),
        995 => ("POP3S", "POP3 over SSL"),
        1433 => ("MSSQL", "Microsoft SQL Server"),
        1434 => ("MSSQL Mon", "MSSQL Monitor"),
        1521 => ("Oracle", "Oracle Database"),
        3306 => ("MySQL", "MySQL Database"),
        3389 => ("RDP", "Remote Desktop Protocol"),
        5432 => ("PostgreSQL", "PostgreSQL Database"),
        5900 => ("VNC", "Virtual Network Computing"),
        6379 => ("Redis", "Redis In-Memory Database"),
        8080 => ("HTTP-Alt", "HTTP Alternate"),
        8443 => ("HTTPS-Alt", "HTTPS Alternate"),
        8888 => ("HTTP-Proxy", "HTTP Proxy"),
        9090 => ("Web Console", "Web Management Console"),
        27017 => ("MongoDB", "MongoDB Database"),
        _ => ("Unknown", "Unknown Service"),
    }
}