mod ipgen;
mod models;
mod naabu;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use models::{AppState, CreateScanRequest, GenerateRequest, ParseIpsRequest, ScanJob};
use tower_http::services::ServeDir;

const DEFAULT_PORTS: &str = "80,443,8080,8443,22,21,25,53,110,143,993,995,3306,5432,6379,8000,8888,9090";

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    println!("Starting naabu-web on http://127.0.0.1:{port}");

    let state = AppState::new();

    let app = Router::new()
        .route("/", get(|| async { Redirect::permanent("/index.html") }))
        .route("/api/ipgen/random", get(generate_ips))
        .route("/api/ipgen/cidr", post(expand_cidr))
        .route("/api/ipgen/parse", post(parse_ips))
        .route("/api/naabu/check", get(check_naabu))
        .route("/api/scans", get(list_scans).post(create_scan))
        .route(
            "/api/scans/{id}",
            get(get_scan).delete(delete_scan),
        )
        .route("/api/scans/{id}/export", get(export_scan))
        .fallback_service(ServeDir::new("static"))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn generate_ips(
    State(_state): State<AppState>,
    Query(params): Query<GenerateRequest>,
) -> Json<serde_json::Value> {
    let count = params.count.clamp(1, 10000);
    let ips = ipgen::IpGenerator::generate_batch(count);
    Json(serde_json::json!({
        "count": ips.len(),
        "ips": ips,
        "reserved_ranges": ipgen::IpGenerator::reserved_ranges_display(),
    }))
}

async fn expand_cidr(
    State(_state): State<AppState>,
    Json(req): Json<ParseIpsRequest>,
) -> impl IntoResponse {
    match ipgen::IpGenerator::from_cidr(&req.text.trim()) {
        Ok(ips) => Json(serde_json::json!({ "count": ips.len(), "ips": ips })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

async fn parse_ips(
    State(_state): State<AppState>,
    Json(req): Json<ParseIpsRequest>,
) -> Json<serde_json::Value> {
    let ips = ipgen::IpGenerator::parse_ip_list(&req.text);
    Json(serde_json::json!({ "count": ips.len(), "ips": ips }))
}

async fn check_naabu(State(_state): State<AppState>) -> Json<serde_json::Value> {
    let status = match std::process::Command::new("naabu")
        .arg("-version")
        .output()
    {
        Ok(o) if o.status.success() => "ok",
        Ok(_) => "naabu returned an error",
        Err(_) => "naabu not found",
    };
    Json(serde_json::json!({ "status": status, "binary": "naabu" }))
}

async fn create_scan(
    State(state): State<AppState>,
    Json(req): Json<CreateScanRequest>,
) -> impl IntoResponse {
    if req.ips.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "no target IPs" })),
        )
            .into_response();
    }

    let mut settings = req.settings;
    if settings.port_range.trim().is_empty() {
        settings.port_range = DEFAULT_PORTS.to_string();
    }
    if settings.rate_limit == 0 {
        settings.rate_limit = 500;
    }
    if settings.timeout == 0 {
        settings.timeout = 5000;
    }
    if settings.threads == 0 {
        settings.threads = 25;
    }

    let ports = settings.port_range.clone();
    let job_id = state.next_id();
    let job = ScanJob::new(job_id, req.ips.clone(), ports, settings.clone());

    let state_clone = state.clone();
    tokio::spawn(async move {
        naabu::run_scan(state_clone, job_id).await;
    });

    state.insert(job.clone());

    (StatusCode::CREATED, Json(serde_json::json!({ "id": job_id }))).into_response()
}

async fn list_scans(State(state): State<AppState>) -> Json<serde_json::Value> {
    let jobs = state.list();
    let summaries: Vec<serde_json::Value> = jobs
        .iter()
        .map(|j| {
            serde_json::json!({
                "id": j.id,
                "status": j.status.to_string(),
                "total_ips": j.total_ips,
                "found": j.results.len(),
                "ports": j.ports,
                "started_at": j.started_at.map(|t| t.to_rfc3339()),
                "finished_at": j.finished_at.map(|t| t.to_rfc3339()),
                "error": j.error_message,
            })
        })
        .collect();
    Json(serde_json::json!({ "jobs": summaries }))
}

async fn get_scan(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    match state.get(id) {
        Some(job) => Json(job).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "job not found" })),
        )
            .into_response(),
    }
}

async fn delete_scan(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    if state.remove(id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn export_scan(
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Query(params): Query<ExportParams>,
) -> impl IntoResponse {
    let job = match state.get(id) {
        Some(j) => j,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let (ct, body) = match params.format.as_deref() {
        Some("json") => (
            "application/json",
            serde_json::to_string_pretty(&job.results).unwrap_or_else(|_e| format!("{{}}")),
        ),
        Some("csv") => {
            let mut c = "ip,port,protocol,service,timestamp\n".to_string();
            for r in &job.results {
                c.push_str(&format!(
                    "{},{},{},{},{}\n",
                    r.ip, r.port, r.protocol, r.service, r.timestamp
                ));
            }
            ("text/csv", c)
        }
        _ => {
            let mut t = format!(
                "naabu-web scan #{} — {} open ports on {} IPs\n\n",
                job.id,
                job.results.len(),
                job.total_ips
            );
            t.push_str(&format!("{:<15} {:<6} {:<8} {:<14}\n", "IP", "PORT", "PROTO", "SERVICE"));
            t.push_str(&"-".repeat(50));
            t.push('\n');
            for r in &job.results {
                t.push_str(&format!(
                    "{:<15} {:<6} {:<8} {:<14}\n",
                    r.ip, r.port, r.protocol, r.service
                ));
            }
            ("text/plain", t)
        }
    };

    let filename = format!("scan-{}.{}", id, params.format.as_deref().unwrap_or("txt"));
    (
        StatusCode::OK,
        [("Content-Type", ct), ("Content-Disposition", &format!("attachment; filename=\"{filename}\""))],
        body,
    )
        .into_response()
}

#[derive(serde::Deserialize)]
struct ExportParams {
    format: Option<String>,
}

mod tests {
    #[test]
    fn ipgen_quick() {
        let ips = super::ipgen::IpGenerator::generate_batch(20);
        assert_eq!(ips.len(), 20);
    }
}