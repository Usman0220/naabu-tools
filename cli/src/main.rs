mod ipgen;
mod scan;

use clap::{Parser, Subcommand, ValueEnum};
use scan::{ScanConfig, ScanOutcome};
use std::io::{Read, Write};
use std::path::PathBuf;

const DEFAULT_PORTS: &str = "80,443,8080,8443,22,21,25,53,110,143,993,995,3306,5432,6379,8000,8888,9090";

#[derive(Parser)]
#[command(
    name = "naabu-cli",
    version,
    about = "Generate random public IPs and scan them for open ports with naabu",
    long_about = "naabu-cli — random public IP generation + naabu port scanning.\n\n\
Results are written to stdout (one `ip:port  service` per line) so it can be piped;\n\
status/progress goes to stderr."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print N random public IPs (reserved ranges excluded)
    Gen {
        #[arg(long, default_value_t = 10)]
        count: usize,
    },
    /// Expand a CIDR to individual IPs
    Cidr {
        cidr: String,
    },
    /// Generate/load target IPs and run a naabu port scan
    Scan(ScanArgs),
}

#[derive(clap::Args)]
struct ScanArgs {
    /// Generate N random public IPs as targets
    #[arg(long, conflicts_with_all = ["ips", "cidr", "stdin"])]
    count: Option<usize>,

    /// Use explicit IPs: "ip,ip,..." or @file (one per line)
    #[arg(long, conflicts_with_all = ["count", "cidr", "stdin"])]
    ips: Option<String>,

    /// Expand this CIDR as targets
    #[arg(long, conflicts_with_all = ["count", "ips", "stdin"])]
    cidr: Option<String>,

    /// Read targets from stdin (one IP/CIDR per line)
    #[arg(long, conflicts_with_all = ["count", "ips", "cidr"])]
    stdin: bool,

    /// Port range to scan (comma-separated or 1-1000)
    #[arg(long, default_value = DEFAULT_PORTS)]
    ports: String,

    /// Scan top N ports instead of --ports
    #[arg(long)]
    top_ports: Option<u32>,

    /// Packets per second
    #[arg(long, default_value_t = 500)]
    rate: u32,

    /// Concurrent threads
    #[arg(long, default_value_t = 25)]
    threads: u32,

    /// Per-request timeout in ms
    #[arg(long, default_value_t = 5000)]
    timeout: u32,

    /// Scan technique
    #[arg(long, value_enum, default_value_t = ScanTypeArg::Connect)]
    scan_type: ScanTypeArg,

    /// Verify open ports with a probe
    #[arg(long)]
    verify: bool,

    /// Write results to a file
    #[arg(long)]
    output: Option<PathBuf>,

    /// Output file format
    #[arg(long, value_enum, default_value_t = FmtArg::Text)]
    format: FmtArg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ScanTypeArg {
    Connect,
    Syn,
    Auto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum FmtArg {
    Text,
    Csv,
    Json,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Gen { count } => cmd_gen(count),
        Commands::Cidr { cidr } => cmd_cidr(&cidr),
        Commands::Scan(args) => cmd_scan(args),
    }
}

fn cmd_gen(count: usize) {
    let ips = ipgen::IpGenerator::generate_batch(count);
    let mut out = std::io::stdout().lock();
    for ip in &ips {
        let _ = writeln!(out, "{ip}");
    }
}

fn cmd_cidr(cidr: &str) {
    match ipgen::IpGenerator::from_cidr(cidr) {
        Ok(ips) => {
            let mut out = std::io::stdout().lock();
            for ip in &ips {
                let _ = writeln!(out, "{ip}");
            }
            if ips.is_empty() {
                eprintln!("CIDR {cidr} contained no public IPs");
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

fn resolve_targets(args: &ScanArgs) -> Result<Vec<String>, String> {
    let mut ips: Vec<String> = Vec::new();

    if args.stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("failed to read stdin: {e}"))?;
        ips = ipgen::IpGenerator::parse_list(&buf);
    } else if let Some(ips_list) = &args.ips {
        if let Some(file) = ips_list.strip_prefix('@') {
            let txt = std::fs::read_to_string(file)
                .map_err(|e| format!("cannot read {file}: {e}"))?;
            ips = ipgen::IpGenerator::parse_list(&txt);
        } else {
            ips = ipgen::IpGenerator::parse_list(&ips_list.replace(',', "\n"));
        }
    } else if let Some(cidr) = &args.cidr {
        ips = ipgen::IpGenerator::from_cidr(cidr)?;
    } else if let Some(count) = args.count {
        ips = ipgen::IpGenerator::generate_batch(count);
    }

    if ips.is_empty() {
        return Err("no target IPs (use --count, --ips, --cidr, or --stdin)".into());
    }
    Ok(ips)
}

fn cmd_scan(args: ScanArgs) {
    let ips = match resolve_targets(&args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };

    let config = ScanConfig {
        naabu_bin: "naabu".into(),
        ports: args.ports.clone(),
        top_ports: args.top_ports,
        rate: args.rate,
        threads: args.threads,
        timeout: args.timeout,
        scan_type: match args.scan_type {
            ScanTypeArg::Connect => "connect".into(),
            ScanTypeArg::Syn => "syn".into(),
            ScanTypeArg::Auto => "auto".into(),
        },
        verify: args.verify,
    };

    let target_desc = match config.top_ports {
        Some(n) => format!("top-{n}"),
        None => config.ports.clone(),
    };
    eprintln!(
        "naabu-cli: scanning {} IP(s) on {} [rate={}, threads={}, timeout={}ms, type={}]",
        ips.len(),
        target_desc,
        config.rate,
        config.threads,
        config.timeout,
        config.scan_type,
    );

    let outcome: ScanOutcome = scan::run(&ips, &config);

    if let Some(err) = &outcome.error {
        eprintln!("naabu-cli: error: {err}");
        std::process::exit(1);
    }

    eprintln!("naabu-cli: done — {} open port(s)", outcome.results.len());

    if let Some(path) = args.output {
        let fmt = match args.format {
            FmtArg::Text => "txt",
            FmtArg::Csv => "csv",
            FmtArg::Json => "json",
        };
        match scan::write_export(&outcome, &path.to_string_lossy(), fmt) {
            Ok(n) => eprintln!("naabu-cli: wrote {n} result(s) to {}", path.display()),
            Err(e) => {
                eprintln!("naabu-cli: export error: {e}");
                std::process::exit(1);
            }
        }
    }
}