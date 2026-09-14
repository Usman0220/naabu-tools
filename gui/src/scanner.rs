use crate::models::{OutputFormat, ScanJob, ScanResult, ScanSettings, ScanStatus, ScanType, ServiceInfo};
use chrono::Utc;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;

pub struct NaabuScanner;

impl NaabuScanner {
    pub fn check_naabu() -> Result<String, String> {
        let output = Command::new("naabu")
            .arg("-version")
            .output()
            .map_err(|e| format!("Failed to run naabu: {}. Is it installed?", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if output.status.success() || !stdout.is_empty() {
            Ok(format!("naabu found: {}", stdout.trim()))
        } else if !stderr.is_empty() {
            Ok(format!("naabu: {}", stderr.trim()))
        } else {
            Err("naabu not found".into())
        }
    }

    pub fn run_scan(
        mut job: ScanJob,
        settings: &ScanSettings,
        progress_tx: mpsc::Sender<ScanProgress>,
    ) -> ScanJob {
        job.status = ScanStatus::Running;
        job.started_at = Some(Utc::now());

        let _ = progress_tx.send(ScanProgress {
            found: 0,
            message: format!("Starting naabu scan of {} IPs...", job.total_ips),
        });

        // Write IPs to temp file
        let ip_file = format!("/tmp/naabu_ips_{}.txt", job.id);
        let ip_content = job.ips.join("\n");
        if let Err(e) = fs::write(&ip_file, &ip_content) {
            job.status = ScanStatus::Error;
            job.error_message = Some(format!("Failed to write IP list: {}", e));
            job.finished_at = Some(Utc::now());
            job.scanned_ips = job.total_ips;
            let _ = progress_tx.send(ScanProgress {
                found: 0,
                message: "Failed to write IP list".into(),
            });
            return job;
        }

        let mut args = Vec::new();
        args.push("-l".into());
        args.push(ip_file.clone());

        if settings.use_top_ports {
            args.push("-top-ports".into());
            args.push(settings.top_ports_count.to_string());
        } else {
            args.push("-p".into());
            args.push(settings.port_range.clone());
        }

        args.push("-rate".into());
        args.push(settings.rate_limit.to_string());
        args.push("-timeout".into());
        args.push(settings.timeout.to_string());
        args.push("-c".into());
        args.push(settings.threads.to_string());

        match settings.scan_type {
            ScanType::Connect => {
                args.push("-s".into());
                args.push("connect".into());
            }
            ScanType::Syn => {
                args.push("-s".into());
                args.push("syn".into());
            }
            ScanType::Auto => {}
        }

        if settings.verify {
            args.push("-verify".into());
        }

        args.push("-silent".into());

        let mut child = match Command::new("naabu")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                job.status = ScanStatus::Error;
                job.error_message = Some(format!("Failed to execute naabu: {}", e));
                job.finished_at = Some(Utc::now());
                job.scanned_ips = job.total_ips;
                let _ = progress_tx.send(ScanProgress {
                    found: 0,
                    message: format!("Failed to launch naabu: {}", e),
                });
                return job;
            }
        };

        let stderr = match child.stderr.take() {
            Some(err) => {
                let (tx, rx) = mpsc::channel();
                thread::spawn(move || {
                    let mut buf = String::new();
                    let mut reader = BufReader::new(err);
                    let _ = reader.read_to_string(&mut buf);
                    let _ = tx.send(buf);
                });
                rx
            }
            None => {
                let (_tx, rx) = mpsc::channel();
                rx
            }
        };

        // Stream naabu stdout line-by-line: each result arrives as `ip:port`
        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                let line = line.trim();
                let Some((host, port)) = parse_result_line(line) else {
                    continue;
                };

                let service_info = ServiceInfo::lookup(port);
                let svc_name = service_info.name.clone();

                job.results.push(ScanResult {
                    ip: host.clone(),
                    port,
                    protocol: "tcp".into(),
                    service: service_info.name,
                    state: "open".into(),
                    timestamp: Utc::now(),
                });
                job.total_open = job.results.len();

                let _ = progress_tx.send(ScanProgress {
                    found: job.results.len(),
                    message: format!("Found port {} on {} ({})", port, host, svc_name),
                });
            }
        }

        let mut stderr_msg = String::new();
        if let Ok(err) = stderr.recv() {
            stderr_msg = err;
        }

        let exit_success = child.wait().map(|s| s.success()).unwrap_or(false);
        let _ = fs::remove_file(&ip_file);

        if job.results.is_empty() && exit_success && stderr_msg.trim().is_empty() {
            let _ = progress_tx.send(ScanProgress {
                found: 0,
                message: "Scan finished — 0 open ports found.".into(),
            });
        }

        if !exit_success {
            let detail = if !stderr_msg.trim().is_empty() {
                stderr_msg.trim()
            } else {
                "naabu exited with an error"
            };
            job.status = ScanStatus::Error;
            job.error_message = Some(detail.to_string());
        } else if !stderr_msg.trim().is_empty() {
            let _ = progress_tx.send(ScanProgress {
                found: job.results.len(),
                message: format!("naabu: {}", stderr_msg.trim()),
            });
        }

        job.scanned_ips = job.total_ips;
        job.status = ScanStatus::Completed;
        job.finished_at = Some(Utc::now());

        let _ = progress_tx.send(ScanProgress {
            found: job.total_open,
            message: format!("Scan complete. {} open ports found.", job.total_open),
        });

        job
    }

    pub fn export_results(
        job: &ScanJob,
        path: &str,
        format: &OutputFormat,
    ) -> Result<(), String> {
        match format {
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(&job.results)
                    .map_err(|e| format!("JSON serialization failed: {}", e))?;
                fs::write(path, json).map_err(|e| format!("Write failed: {}", e))?;
            }
            OutputFormat::Csv => {
                let mut content = "ip,port,protocol,service,state,timestamp\n".to_string();
                for r in &job.results {
                    content.push_str(&format!(
                        "{},{},{},{},{},{}\n",
                        r.ip, r.port, r.protocol, r.service, r.state, r.timestamp
                    ));
                }
                fs::write(path, content).map_err(|e| format!("Write failed: {}", e))?;
            }
            OutputFormat::PlainText => {
                let mut content = format!(
                    "Naabu Scan Results — Job #{}\n",
                    job.id
                );
                content.push_str(&format!(
                    "Date: {}\n",
                    job.started_at
                        .map(|d| d.to_rfc3339())
                        .unwrap_or_default()
                ));
                content.push_str(&format!("Total open: {}\n\n", job.total_open));
                content.push_str(&format!(
                    "{:<20} {:<8} {:<10} {:<15}\n",
                    "IP", "PORT", "PROTOCOL", "SERVICE"
                ));
                content.push_str(&"-".repeat(55));
                content.push('\n');
                for r in &job.results {
                    content.push_str(&format!(
                        "{:<20} {:<8} {:<10} {:<15}\n",
                        r.ip, r.port, r.protocol, r.service
                    ));
                }
                fs::write(path, content).map_err(|e| format!("Write failed: {}", e))?;
            }
        }
        Ok(())
    }

    pub fn get_common_ports() -> Vec<(u16, &'static str)> {
        vec![
            (21, "FTP"),
            (22, "SSH"),
            (23, "Telnet"),
            (25, "SMTP"),
            (53, "DNS"),
            (80, "HTTP"),
            (110, "POP3"),
            (111, "RPCBind"),
            (135, "MSRPC"),
            (139, "NetBIOS"),
            (143, "IMAP"),
            (443, "HTTPS"),
            (445, "SMB"),
            (993, "IMAPS"),
            (995, "POP3S"),
            (1433, "MSSQL"),
            (1521, "Oracle"),
            (3306, "MySQL"),
            (3389, "RDP"),
            (5432, "PostgreSQL"),
            (5900, "VNC"),
            (6379, "Redis"),
            (8080, "HTTP-Alt"),
            (8443, "HTTPS-Alt"),
            (27017, "MongoDB"),
        ]
    }
}

pub struct ScanProgress {
    pub found: usize,
    pub message: String,
}

fn parse_result_line(line: &str) -> Option<(String, u16)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('/') || line.starts_with('(') {
        return None;
    }

    // Handle both `ip:port` (silent) and possible `[PROTO] ip:port` formats
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
        assert_eq!(parse_result_line("(banner grab)"), None);
        assert_eq!(parse_result_line("no port here"), None);
        assert_eq!(parse_result_line("10.0.0.1:notaport"), None);
    }
}
