use chrono::Utc;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::thread;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub ports: String,
    pub rate: u32,
    pub threads: u32,
    pub timeout: u32,
    pub scan_type: String,
    pub verify: bool,
    pub top_ports: Option<u32>,
    pub naabu_bin: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanResult {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub timestamp: String,
}

pub struct ScanOutcome {
    pub results: Vec<ScanResult>,
    pub error: Option<String>,
}

pub fn run(ips: &[String], config: &ScanConfig) -> ScanOutcome {
    let ip_file = "/tmp/naabu_cli_ips.txt".to_string();
    if let Err(e) = fs::write(&ip_file, ips.join("\n")) {
        return ScanOutcome {
            results: Vec::new(),
            error: Some(format!("Failed to write IP list: {e}")),
        };
    }

    let mut args: Vec<String> = vec!["-l".into(), ip_file.clone()];

    match config.top_ports {
        Some(n) => {
            args.push("-top-ports".into());
            args.push(n.to_string());
        }
        None => {
            args.push("-p".into());
            args.push(config.ports.clone());
        }
    }

    args.push("-rate".into());
    args.push(config.rate.to_string());
    args.push("-timeout".into());
    args.push(config.timeout.to_string());
    args.push("-c".into());
    args.push(config.threads.to_string());

    match config.scan_type.as_str() {
        "connect" => {
            args.push("-s".into());
            args.push("connect".into());
        }
        "syn" => {
            args.push("-s".into());
            args.push("syn".into());
        }
        _ => {}
    }

    if config.verify {
        args.push("-verify".into());
    }
    args.push("-silent".into());

    let mut child = match Command::new(&config.naabu_bin)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return ScanOutcome {
                results: Vec::new(),
                error: Some(format!("Failed to launch naabu: {e}")),
            };
        }
    };

    // Drain stderr in a background thread to avoid pipe deadlock.
    let stderr_handle = child.stderr.take().map(|stderr| {
        thread::spawn(move || {
            let mut buf = String::new();
            let mut reader = BufReader::new(stderr);
            let _ = reader.read_to_string(&mut buf);
            buf
        })
    });

    let mut results: Vec<ScanResult> = Vec::new();

    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        let stdout_lock = std::io::stdout();
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            let Some((ip, port)) = parse_result_line(&line) else {
                continue;
            };
            let (svc, _desc) = service_lookup(port);
            let timestamp = Utc::now().to_rfc3339();

            results.push(ScanResult {
                ip: ip.clone(),
                port,
                protocol: "tcp".into(),
                service: svc.to_string(),
                timestamp: timestamp.clone(),
            });

            let mut out = stdout_lock.lock();
            let _ = writeln!(out, "{}:{}  {}", ip, port, svc);
            let _ = out.flush();
        }
    }

    let stderr_msg = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();

    let exit_ok = child.wait().map(|s| s.success()).unwrap_or(false);
    let _ = fs::remove_file(&ip_file);

    if !exit_ok {
        let detail = if !stderr_msg.trim().is_empty() {
            stderr_msg.trim()
        } else {
            "naabu exited with an error"
        };
        return ScanOutcome {
            results,
            error: Some(detail.to_string()),
        };
    }

    ScanOutcome {
        results,
        error: None,
    }
}

pub fn write_export(outcome: &ScanOutcome, path: &str, format: &str) -> Result<usize, String> {
    let content = match format {
        "json" => serde_json::to_string_pretty(&outcome.results)
            .map_err(|e| format!("JSON serialization failed: {e}"))?,
        "csv" => {
            let mut c = "ip,port,protocol,service,timestamp\n".to_string();
            for r in &outcome.results {
                c.push_str(&format!(
                    "{},{},{},{},{}\n",
                    r.ip, r.port, r.protocol, r.service, r.timestamp
                ));
            }
            c
        }
        _ => {
            let mut c = format!(
                "naabu-cli scan — {} results\n",
                outcome.results.len()
            );
            c.push_str(&format!("{:<15} {:<6} {:<8} {:<12}\n", "IP", "PORT", "PROTO", "SERVICE"));
            c.push_str(&"-".repeat(48));
            c.push('\n');
            for r in &outcome.results {
                c.push_str(&format!(
                    "{:<15} {:<6} {:<8} {:<12}\n",
                    r.ip, r.port, r.protocol, r.service
                ));
            }
            c
        }
    };
    fs::write(path, &content).map_err(|e| format!("Write failed: {e}"))?;
    Ok(outcome.results.len())
}

fn service_lookup(port: u16) -> (&'static str, &'static str) {
    match port {
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
        631 => ("IPP", "Internet Printing Protocol"),
        993 => ("IMAPS", "IMAP over SSL"),
        995 => ("POP3S", "POP3 over SSL"),
        1433 => ("MSSQL", "Microsoft SQL Server"),
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

fn parse_result_line(line: &str) -> Option<(String, u16)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('/') || line.starts_with('(') {
        return None;
    }
    let body = match line.split_once(']') {
        Some((_, rest)) => rest.trim(),
        None => line,
    };
    let (host, port) = body.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    Some((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_silent_format() {
        assert_eq!(
            parse_result_line("127.0.0.1:631"),
            Some(("127.0.0.1".to_string(), 631))
        );
    }

    #[test]
    fn test_parse_bracket_format() {
        assert_eq!(
            parse_result_line("[tcp] 127.0.0.1:22"),
            Some(("127.0.0.1".to_string(), 22))
        );
    }

    #[test]
    fn test_parse_rejects_garbage() {
        assert_eq!(parse_result_line(""), None);
        assert_eq!(parse_result_line("/usr/bin/foo"), None);
        assert_eq!(parse_result_line("no port here"), None);
    }
}