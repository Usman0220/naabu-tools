use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Idle,
    Running,
    Paused,
    Completed,
    Error,
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStatus::Idle => write!(f, "Idle"),
            ScanStatus::Running => write!(f, "Running"),
            ScanStatus::Paused => write!(f, "Paused"),
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
    pub state: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub id: usize,
    pub ips: Vec<String>,
    pub port_range: String,
    pub status: ScanStatus,
    pub results: Vec<ScanResult>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub total_ips: usize,
    pub scanned_ips: usize,
    pub total_open: usize,
    pub error_message: Option<String>,
}

impl ScanJob {
    pub fn new(id: usize, ips: Vec<String>, port_range: String) -> Self {
        let total = ips.len();
        Self {
            id,
            ips,
            port_range,
            status: ScanStatus::Idle,
            results: Vec::new(),
            started_at: None,
            finished_at: None,
            total_ips: total,
            scanned_ips: 0,
            total_open: 0,
            error_message: None,
        }
    }

    pub fn progress(&self) -> f32 {
        if self.total_ips == 0 {
            return 0.0;
        }
        self.scanned_ips as f32 / self.total_ips as f32
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSettings {
    pub port_range: String,
    pub ip_count: usize,
    pub rate_limit: u32,
    pub timeout: u32,
    pub threads: u32,
    pub exclude_reserved: bool,
    pub output_format: OutputFormat,
    pub use_top_ports: bool,
    pub top_ports_count: u32,
    pub scan_type: ScanType,
    pub verify: bool,
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            port_range: "80,443,8080,8443,22,21,25,53,110,143,993,995,3306,5432,6379,8000,8888,9090".into(),
            ip_count: 10,
            rate_limit: 500,
            timeout: 5000,
            threads: 25,
            exclude_reserved: true,
            output_format: OutputFormat::Csv,
            use_top_ports: false,
            top_ports_count: 100,
            scan_type: ScanType::Connect,
            verify: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OutputFormat {
    Csv,
    Json,
    PlainText,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Csv => write!(f, "CSV"),
            OutputFormat::Json => write!(f, "JSON"),
            OutputFormat::PlainText => write!(f, "Plain Text"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanType {
    Connect,
    Syn,
    Auto,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Connect => write!(f, "Connect Scan"),
            ScanType::Syn => write!(f, "SYN Scan"),
            ScanType::Auto => write!(f, "Auto"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub description: String,
}

impl ServiceInfo {
    pub fn lookup(port: u16) -> Self {
        let (name, desc) = match port {
            20 => ("FTP Data", "File Transfer Protocol Data"),
            21 => ("FTP", "File Transfer Protocol"),
            22 => ("SSH", "Secure Shell"),
            23 => ("Telnet", "Telnet remote access"),
            25 => ("SMTP", "Simple Mail Transfer Protocol"),
            53 => ("DNS", "Domain Name System"),
            80 => ("HTTP", "Hypertext Transfer Protocol"),
            110 => ("POP3", "Post Office Protocol v3"),
            111 => ("RPCBind", "Remote Procedure Call"),
            135 => ("MSRPC", "Microsoft RPC"),
            139 => ("NetBIOS", "NetBIOS Session Service"),
            143 => ("IMAP", "Internet Message Access Protocol"),
            443 => ("HTTPS", "HTTP Secure"),
            445 => ("SMB", "Server Message Block"),
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
            9090 => ("Web-Console", "Web Management Console"),
            27017 => ("MongoDB", "MongoDB Database"),
            _ => ("Unknown", "Unknown Service"),
        };
        Self {
            name: name.to_string(),
            description: desc.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistory {
    pub jobs: Vec<ScanJob>,
    pub max_jobs: usize,
}

impl Default for ScanHistory {
    fn default() -> Self {
        Self {
            jobs: Vec::new(),
            max_jobs: 50,
        }
    }
}

impl ScanHistory {
    pub fn add(&mut self, job: ScanJob) {
        self.jobs.insert(0, job);
        if self.jobs.len() > self.max_jobs {
            self.jobs.truncate(self.max_jobs);
        }
    }
}
