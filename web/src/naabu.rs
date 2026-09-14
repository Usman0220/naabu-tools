use crate::models::{service_lookup, AppState, ScanResult, ScanStatus};
use chrono::Utc;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;

pub async fn run_scan(state: AppState, job_id: u64) {
    let (ips, total_ips, ports) = {
        let guard = state.jobs.lock().unwrap();
        match guard.get(&job_id) {
            Some(j) => (j.ips.clone(), j.total_ips, j.ports.clone()),
            None => return,
        }
    };

    let _ = total_ips;
    let settings = {
        let guard = state.jobs.lock().unwrap();
        guard.get(&job_id).map(|j| j.settings.clone())
    };
    let settings = settings.unwrap_or_default();

    {
        let mut guard = state.jobs.lock().unwrap();
        if let Some(j) = guard.get_mut(&job_id) {
            j.status = ScanStatus::Running;
            j.started_at = Some(Utc::now());
        }
    }

    let ip_file = format!("/tmp/naabu_ips_{}.txt", job_id);
    if let Err(e) = tokio::fs::write(&ip_file, ips.join("\n")).await {
        {
            let mut guard = state.jobs.lock().unwrap();
            if let Some(j) = guard.get_mut(&job_id) {
                j.status = ScanStatus::Error;
                j.error_message = Some(format!("Failed to write IP list: {e}"));
                j.finished_at = Some(Utc::now());
            }
        }
        let _ = tokio::fs::remove_file(&ip_file).await;
        return;
    }

    let mut args: Vec<String> = vec!["-l".into(), ip_file.clone()];

    if settings.use_top_ports {
        args.push("-top-ports".into());
        args.push(settings.top_ports_count.to_string());
    } else {
        args.push("-p".into());
        args.push(if ports.trim().is_empty() {
            settings.port_range.clone()
        } else {
            ports.clone()
        });
    }

    args.push("-rate".into());
    args.push(settings.rate_limit.to_string());
    args.push("-timeout".into());
    args.push(settings.timeout.to_string());
    args.push("-c".into());
    args.push(settings.threads.to_string());

    match settings.scan_type {
        crate::models::ScanType::Connect => {
            args.push("-s".into());
            args.push("connect".into());
        }
        crate::models::ScanType::Syn => {
            args.push("-s".into());
            args.push("syn".into());
        }
        crate::models::ScanType::Auto => {}
    }

    if settings.verify {
        args.push("-verify".into());
    }
    args.push("-silent".into());

    let mut child = match Command::new(&state.naabu_path)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            {
                let mut guard = state.jobs.lock().unwrap();
                if let Some(j) = guard.get_mut(&job_id) {
                    j.status = ScanStatus::Error;
                    j.error_message = Some(format!("Failed to launch naabu: {e}"));
                    j.finished_at = Some(Utc::now());
                }
            }
            let _ = tokio::fs::remove_file(&ip_file).await;
            return;
        }
    };

    // Drain stderr asynchronously
    let mut stderr_msg = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf).await;
        stderr_msg = buf;
    }

    // Stream stdout live
    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim().to_string();
            if let Some((ip, port)) = parse_result_line(&line) {
                let (svc, _desc) = service_lookup(port);
                let mut guard = state.jobs.lock().unwrap();
                if let Some(j) = guard.get_mut(&job_id) {
                    j.results.push(ScanResult {
                        ip,
                        port,
                        protocol: "tcp".into(),
                        service: svc.to_string(),
                        timestamp: Utc::now(),
                    });
                }
            }
        }
    }

    let exit_ok = child.wait().await.map(|s| s.success()).unwrap_or(false);
    let _ = tokio::fs::remove_file(&ip_file).await;

    let mut guard = state.jobs.lock().unwrap();
    if let Some(j) = guard.get_mut(&job_id) {
        if exit_ok && stderr_msg.trim().is_empty() {
            j.status = ScanStatus::Completed;
        } else {
            j.status = ScanStatus::Error;
            j.error_message = Some(if !stderr_msg.trim().is_empty() {
                stderr_msg.trim().to_string()
            } else {
                "naabu exited with an error".into()
            });
        }
        j.finished_at = Some(Utc::now());
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