use crate::ip_generator::IpGenerator;
use crate::models::*;
use crate::scanner::NaabuScanner;
use chrono::Utc;
use eframe::egui;
use std::collections::HashMap;
use std::sync::mpsc;
use std::thread;

pub struct NaabuGuiApp {
    pub settings: ScanSettings,
    pub ip_list_text: String,
    pub generated_ips: Vec<String>,
    pub current_job: Option<ScanJob>,
    pub history: ScanHistory,
    pub active_tab: Tab,
    pub status_msg: String,
    pub naabu_status: Option<String>,
    pub naabu_ok: bool,
    pub filter_text: String,
    pub filter_service: String,
    pub show_settings: bool,
    pub progress_rx: Option<mpsc::Receiver<crate::scanner::ScanProgress>>,
    pub done_rx: Option<mpsc::Receiver<ScanJob>>,
    pub ip_count_input: String,
    pub port_checkboxes: Vec<(u16, &'static str, bool)>,
    pub custom_port_input: String,
    pub log_messages: Vec<String>,
    pub service_stats: HashMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Tab {
    Generator,
    Scanner,
    Results,
    History,
    Settings,
}

impl Default for NaabuGuiApp {
    fn default() -> Self {
        let mut port_checkboxes: Vec<(u16, &str, bool)> = NaabuScanner::get_common_ports()
            .into_iter()
            .map(|(p, n)| (p, n, true))
            .collect();
        port_checkboxes.iter_mut().for_each(|x| x.2 = true);

        Self {
            settings: ScanSettings::default(),
            ip_list_text: String::new(),
            generated_ips: Vec::new(),
            current_job: None,
            history: ScanHistory::default(),
            active_tab: Tab::Generator,
            status_msg: "Ready".into(),
            naabu_status: None,
            naabu_ok: false,
            filter_text: String::new(),
            filter_service: String::new(),
            show_settings: false,
            progress_rx: None,
            done_rx: None,
            ip_count_input: "10".into(),
            port_checkboxes,
            custom_port_input: String::new(),
            log_messages: Vec::new(),
            service_stats: HashMap::new(),
        }
    }
}

impl NaabuGuiApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self::default();
        app.check_naabu();
        app
    }

    fn check_naabu(&mut self) {
        match NaabuScanner::check_naabu() {
            Ok(msg) => {
                self.naabu_status = Some(msg);
                self.naabu_ok = true;
            }
            Err(msg) => {
                self.naabu_status = Some(msg);
                self.naabu_ok = false;
            }
        }
    }

    fn log(&mut self, msg: String) {
        self.log_messages.push(msg);
        if self.log_messages.len() > 200 {
            self.log_messages.remove(0);
        }
    }

    fn build_port_string(&self) -> String {
        let selected: Vec<String> = self
            .port_checkboxes
            .iter()
            .filter(|(_, _, selected)| *selected)
            .map(|(port, _, _)| port.to_string())
            .collect();

        let mut ports = selected.join(",");
        if !self.custom_port_input.trim().is_empty() {
            if !ports.is_empty() {
                ports.push(',');
            }
            ports.push_str(self.custom_port_input.trim());
        }

        if ports.is_empty() {
            ports = "80,443".into();
        }
        ports
    }

    fn update_service_stats(&mut self) {
        self.service_stats.clear();
        if let Some(ref job) = self.current_job {
            for r in &job.results {
                *self.service_stats.entry(r.service.clone()).or_insert(0) += 1;
            }
        }
    }
}

impl eframe::App for NaabuGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check for scan progress
        let progress_updates: Vec<_> = self
            .progress_rx
            .as_ref()
            .map(|rx| std::iter::from_fn(|| rx.try_recv().ok()).collect())
            .unwrap_or_default();

        for progress in progress_updates {
            self.status_msg = progress.message.clone();
            if let Some(ref mut job) = self.current_job {
                if job.status == ScanStatus::Idle {
                    job.status = ScanStatus::Running;
                }
                job.total_open = progress.found;
            }
            ctx.request_repaint();
        }

        // Check for completed job
        let completed: Option<ScanJob> = self
            .done_rx
            .as_ref()
            .and_then(|rx| rx.try_recv().ok());

        if let Some(completed_job) = completed {
            let job_id = completed_job.id;
            let status_txt = completed_job.status.to_string();
            let open_count = completed_job.total_open;
            self.history.add(completed_job.clone());
            self.current_job = Some(completed_job);
            self.update_service_stats();
            self.status_msg = format!(
                "Scan #{} {} — {} open ports",
                job_id, status_txt, open_count
            );
            self.log(format!("Scan finished: {} open ports", open_count));
            self.done_rx = None;
            ctx.request_repaint();
        }

        // Status bar
        self.top_status_bar(ctx);

        // Main layout
        egui::SidePanel::left("side_panel").show(ctx, |ui| {
            self.side_panel(ui);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| match self.active_tab {
                    Tab::Generator => self.generator_tab(ui),
                    Tab::Scanner => self.scanner_tab(ui),
                    Tab::Results => self.results_tab(ui),
                    Tab::History => self.history_tab(ui),
                    Tab::Settings => self.settings_tab(ui),
                });
        });

        // Settings modal
        if self.show_settings {
            egui::Window::new("Quick Settings")
                .collapsible(false)
                .resizable(true)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Port Range:");
                        ui.text_edit_singleline(&mut self.settings.port_range);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Rate Limit (pps):");
                        ui.add(egui::DragValue::new(&mut self.settings.rate_limit).range(1..=10000));
                    });
                    ui.horizontal(|ui| {
                        ui.label("Threads:");
                        ui.add(egui::DragValue::new(&mut self.settings.threads).range(1..=500));
                    });
                    ui.horizontal(|ui| {
                        ui.label("Timeout (ms):");
                        ui.add(egui::DragValue::new(&mut self.settings.timeout).range(100..=30000));
                    });
                    if ui.button("Close").clicked() {
                        self.show_settings = false;
                    }
                });
        }
    }
}

impl NaabuGuiApp {
    fn top_status_bar(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Naabu GUI Scanner")
                        .strong()
                        .size(16.0),
                );
                ui.separator();

                let naabu_indicator = if self.naabu_ok {
                    egui::RichText::new("● naabu OK").color(egui::Color32::from_rgb(80, 200, 80))
                } else {
                    egui::RichText::new("● naabu NOT FOUND").color(egui::Color32::from_rgb(200, 80, 80))
                };
                ui.label(naabu_indicator);

                ui.separator();

                if let Some(ref job) = self.current_job {
                    let status_color = match job.status {
                        ScanStatus::Running => egui::Color32::from_rgb(80, 180, 255),
                        ScanStatus::Completed => egui::Color32::from_rgb(80, 200, 80),
                        ScanStatus::Error => egui::Color32::from_rgb(200, 80, 80),
                        _ => egui::Color32::GRAY,
                    };
                    ui.label(
                        egui::RichText::new(format!("Status: {}", job.status))
                            .color(status_color),
                    );
                    ui.separator();

                    if job.status == ScanStatus::Running {
                        ui.add(
                            egui::ProgressBar::new(job.progress())
                                .animate(true)
                                .desired_width(120.0)
                                .text(format!("{} open", job.total_open)),
                        );
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(&self.status_msg)
                            .small()
                            .color(egui::Color32::from_rgb(160, 160, 160)),
                    );
                });
            });
        });
    }

    fn side_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("Navigation");
        ui.add_space(8.0);

        let tabs = [
            (Tab::Generator, "🌐 IP Generator"),
            (Tab::Scanner, "🔍 Scanner"),
            (Tab::Results, "📊 Results"),
            (Tab::History, "📜 History"),
            (Tab::Settings, "⚙ Settings"),
        ];

        for (tab, label) in &tabs {
            let is_active = self.active_tab == *tab;
            let btn = ui.selectable_label(is_active, *label);
            if btn.clicked() {
                self.active_tab = tab.clone();
            }
        }

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(8.0);

        // IP count
        ui.label("IP Pool Size");
        ui.add(egui::TextEdit::singleline(&mut self.ip_count_input).desired_width(120.0));

        if ui.button("Generate Random IPs").clicked() {
            if let Ok(count) = self.ip_count_input.parse::<usize>() {
                if count > 0 && count <= 10000 {
                    self.generated_ips = IpGenerator::generate_batch(count);
                    self.ip_list_text = self.generated_ips.join("\n");
                    self.status_msg = format!("Generated {} random public IPs", count);
                } else {
                    self.status_msg = "Count must be 1-10000".into();
                }
            } else {
                self.status_msg = "Invalid number".into();
            }
        }

        ui.add_space(8.0);

        if ui.button("📋 Copy IPs").clicked() {
            ui.ctx().copy_text(self.ip_list_text.clone());
            self.status_msg = "IPs copied to clipboard".into();
        }

        ui.add_space(8.0);

        // Quick stats
        if let Some(ref job) = self.current_job {
            ui.separator();
            ui.label("Current Job");
            ui.monospace(format!("  IP Pool: {}", job.total_ips));
            ui.monospace(format!("  Open: {}", job.total_open));
            ui.monospace(format!("  Status: {}", job.status));
        }

        ui.add_space(8.0);

        if !self.service_stats.is_empty() {
            ui.separator();
            ui.label("Service Distribution");
            egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                let mut stats: Vec<_> = self.service_stats.iter().collect();
                stats.sort_by(|a, b| b.1.cmp(a.1));
                for (svc, count) in &stats {
                    ui.monospace(format!("  {:<15} {}", svc, count));
                }
            });
        }
    }

    fn generator_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Public IP Generator");
        ui.add_space(8.0);

        ui.label("Generate random public IPs (reserved ranges excluded):");
        ui.add_space(4.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut self.ip_list_text)
                    .desired_width(f32::INFINITY)
                    .desired_rows(20)
                    .font(egui::TextStyle::Monospace)
                    .hint_text("Generated IPs appear here...\nOr paste custom IPs/CIDRs (one per line)"),
            );
        });

        ui.add_space(8.0);

        ui.horizontal(|ui| {
            if ui.button("🔄 Generate New Batch").clicked() {
                if let Ok(count) = self.ip_count_input.parse::<usize>() {
                    if count > 0 && count <= 10000 {
                        self.generated_ips = IpGenerator::generate_batch(count);
                        self.ip_list_text = self.generated_ips.join("\n");
                        self.status_msg = format!("Generated {} random public IPs", count);
                    }
                }
            }

            if ui.button("📝 From CIDR").clicked() {
                let cidrs: Vec<String> = self
                    .ip_list_text
                    .lines()
                    .filter(|l| l.contains('/'))
                    .map(|l| l.trim().to_string())
                    .collect();

                let mut all_ips = Vec::new();
                for cidr in &cidrs {
                    match IpGenerator::generate_from_cidr(cidr) {
                        Ok(ips) => all_ips.extend(ips),
                        Err(e) => {
                            self.status_msg = format!("CIDR error: {}", e);
                        }
                    }
                }

                if !all_ips.is_empty() {
                    self.generated_ips = all_ips.clone();
                    self.ip_list_text = all_ips.join("\n");
                    self.status_msg = format!("Expanded to {} IPs from CIDRs", all_ips.len());
                }
            }

            if ui.button("🧹 Clear").clicked() {
                self.ip_list_text.clear();
                self.generated_ips.clear();
                self.status_msg = "Cleared".into();
            }
        });

        ui.add_space(8.0);
        ui.label("Reserved ranges excluded:");
        egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
            for (range, label) in IpGenerator::reserved_ranges_display() {
                ui.monospace(format!("  {} ({})", range, label));
            }
        });
    }

    fn scanner_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Port Scanner (naabu)");
        ui.add_space(8.0);

        if !self.naabu_ok {
            ui.colored_label(egui::Color32::from_rgb(200, 80, 80), "naabu is not installed or not in PATH");
            ui.label("Install: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest");
            ui.add_space(8.0);
        }

        ui.horizontal(|ui| {
            if ui.button("🔄 Check naabu").clicked() {
                self.check_naabu();
            }
            if let Some(ref status) = self.naabu_status {
                ui.label(status.as_str());
            }
        });

        ui.add_space(8.0);
        ui.label("IPs to scan (one per line, or use generated pool):");
        ui.add(
            egui::TextEdit::multiline(&mut self.ip_list_text)
                .desired_width(f32::INFINITY)
                .desired_rows(8)
                .font(egui::TextStyle::Monospace),
        );

        ui.add_space(8.0);

        // Port selection
        ui.label("Port Selection:");
        egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
            egui::Grid::new("port_grid").num_columns(6).show(ui, |ui| {
                for i in 0..self.port_checkboxes.len() {
                    let (port, name, selected) = &mut self.port_checkboxes[i];
                    let label = format!("{} ({})", port, name);
                    ui.checkbox(selected, &label);
                    if (i + 1) % 3 == 0 {
                        ui.end_row();
                    }
                }
            });
        });

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("Custom ports:");
            ui.add(egui::TextEdit::singleline(&mut self.custom_port_input)
                .hint_text("e.g. 8000,9090,3000"));
        });

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button("✅ Select All").clicked() {
                self.port_checkboxes.iter_mut().for_each(|x| x.2 = true);
            }
            if ui.button("❌ Deselect All").clicked() {
                self.port_checkboxes.iter_mut().for_each(|x| x.2 = false);
            }
            if ui.button("🌐 Web Only").clicked() {
                let web_ports: Vec<u16> = vec![80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090];
                self.port_checkboxes
                    .iter_mut()
                    .for_each(|(p, _, s)| *s = web_ports.contains(p));
            }
            if ui.button("🔒 Common").clicked() {
                let common: Vec<u16> = vec![21, 22, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080];
                self.port_checkboxes
                    .iter_mut()
                    .for_each(|(p, _, s)| *s = common.contains(p));
            }
        });

        ui.add_space(12.0);
        ui.label(format!("Selected ports: {}", self.build_port_string()));

        ui.add_space(8.0);

        // Scan settings inline
        ui.collapsing("Scan Settings", |ui| {
            egui::Grid::new("scan_settings_grid").show(ui, |ui| {
                ui.label("Rate (pps):");
                ui.add(egui::DragValue::new(&mut self.settings.rate_limit).range(1..=10000));
                ui.end_row();

                ui.label("Threads:");
                ui.add(egui::DragValue::new(&mut self.settings.threads).range(1..=500));
                ui.end_row();

                ui.label("Timeout (ms):");
                ui.add(egui::DragValue::new(&mut self.settings.timeout).range(100..=30000));
                ui.end_row();

                ui.label("Scan Type:");
                egui::ComboBox::from_id_salt("scan_type")
                    .selected_text(self.settings.scan_type.to_string())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.settings.scan_type, ScanType::Connect, "Connect Scan");
                        ui.selectable_value(&mut self.settings.scan_type, ScanType::Syn, "SYN Scan");
                        ui.selectable_value(&mut self.settings.scan_type, ScanType::Auto, "Auto");
                    });
                ui.end_row();

                ui.label("Verify:");
                ui.checkbox(&mut self.settings.verify, "Verify open ports");
                ui.end_row();

                ui.label("Top Ports:");
                ui.checkbox(&mut self.settings.use_top_ports, "Use top ports");
                ui.end_row();

                if self.settings.use_top_ports {
                    ui.label("Count:");
                    ui.add(egui::DragValue::new(&mut self.settings.top_ports_count).range(10..=10000));
                    ui.end_row();
                }
            });
        });

        ui.add_space(12.0);

        // Start scan button
        let can_scan = self.naabu_ok
            && !self.ip_list_text.trim().is_empty()
            && self
                .current_job
                .as_ref()
                .map_or(true, |j| j.status != ScanStatus::Running);

        let btn_text = if self.current_job.as_ref().map_or(false, |j| j.status == ScanStatus::Running) {
            "⏳ Scanning..."
        } else {
            "🚀 Start Scan"
        };

        if ui
            .add_enabled(can_scan, egui::Button::new(
                egui::RichText::new(btn_text).strong().size(16.0),
            ).min_size(egui::vec2(200.0, 40.0)))
            .clicked()
        {
            let ips = IpGenerator::parse_ip_list(&self.ip_list_text);
            if ips.is_empty() {
                self.status_msg = "No valid IPs to scan".into();
            } else {
                self.settings.port_range = self.build_port_string();
                let job_id = self.history.jobs.len() + 1;
                let mut job = ScanJob::new(job_id, ips, self.settings.port_range.clone());
                job.status = ScanStatus::Running;
                job.started_at = Some(Utc::now());

                let (tx, rx) = mpsc::channel();
                self.progress_rx = Some(rx);

                let (done_tx, done_rx) = mpsc::channel();
                self.done_rx = Some(done_rx);

                let settings = self.settings.clone();
                let job_for_thread = job.clone();

                thread::spawn(move || {
                    let completed = NaabuScanner::run_scan(job_for_thread, &settings, tx);
                    let _ = done_tx.send(completed);
                });

                self.current_job = Some(job);
                self.status_msg = "Scan started...".into();
                self.log(format!("Scan #{} started", job_id));
            }
        }

        ui.add_space(8.0);

        // Progress display
        if let Some(ref job) = self.current_job {
            if job.status == ScanStatus::Running {
                ui.add(
                    egui::ProgressBar::new(job.progress())
                        .animate(true)
                        .text(format!("{} open ports found so far", job.total_open)),
                );
                ui.small(egui::RichText::new(
                    "Streaming results live — ports appear as naabu discovers them.",
                ).color(egui::Color32::from_rgb(140, 140, 140)));
            }
        }
    }

    fn results_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scan Results");
        ui.add_space(8.0);

        let job = match self.current_job {
            Some(ref job) => job,
            None => {
                ui.label("No scan results yet. Run a scan first.");
                return;
            }
        };

        // Summary
        ui.horizontal(|ui| {
            ui.label(format!("Total Open: {}", job.total_open));
            ui.separator();
            ui.label(format!("IPs Scanned: {}/{}", job.scanned_ips, job.total_ips));
            ui.separator();
            ui.label(format!("Status: {}", job.status));
        });

        ui.add_space(8.0);

        // Filters
        ui.horizontal(|ui| {
            ui.label("Filter IP:");
            ui.add(egui::TextEdit::singleline(&mut self.filter_text).desired_width(150.0));
            ui.label("Filter Service:");
            ui.add(egui::TextEdit::singleline(&mut self.filter_service).desired_width(120.0));
        });

        ui.add_space(4.0);

        // Export buttons
        ui.horizontal(|ui| {
            if ui.button("💾 Export CSV").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("CSV", &["csv"])
                    .save_file()
                {
                    let path_str = path.to_string_lossy().to_string();
                    if let Err(e) = NaabuScanner::export_results(job, &path_str, &OutputFormat::Csv) {
                        self.status_msg = format!("Export error: {}", e);
                    } else {
                        self.status_msg = format!("Exported to {}", path_str);
                    }
                }
            }
            if ui.button("💾 Export JSON").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("JSON", &["json"])
                    .save_file()
                {
                    let path_str = path.to_string_lossy().to_string();
                    if let Err(e) = NaabuScanner::export_results(job, &path_str, &OutputFormat::Json) {
                        self.status_msg = format!("Export error: {}", e);
                    } else {
                        self.status_msg = format!("Exported to {}", path_str);
                    }
                }
            }
            if ui.button("💾 Export Text").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Text", &["txt"])
                    .save_file()
                {
                    let path_str = path.to_string_lossy().to_string();
                    if let Err(e) = NaabuScanner::export_results(job, &path_str, &OutputFormat::PlainText) {
                        self.status_msg = format!("Export error: {}", e);
                    } else {
                        self.status_msg = format!("Exported to {}", path_str);
                    }
                }
            }

            ui.separator();

            if ui.button("📋 Copy Open Ports").clicked() {
                let text: String = job
                    .results
                    .iter()
                    .map(|r| format!("{}:{}", r.ip, r.port))
                    .collect::<Vec<_>>()
                    .join("\n");
                ui.ctx().copy_text(text);
                self.status_msg = "Copied to clipboard".into();
            }
        });

        ui.add_space(8.0);

        // Results table
        let filter_ip = self.filter_text.to_lowercase();
        let filter_svc = self.filter_service.to_lowercase();

        let filtered: Vec<&ScanResult> = job
            .results
            .iter()
            .filter(|r| {
                (filter_ip.is_empty() || r.ip.to_lowercase().contains(&filter_ip))
                    && (filter_svc.is_empty() || r.service.to_lowercase().contains(&filter_svc))
            })
            .collect();

        ui.label(format!("Showing {} results", filtered.len()));

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("results_table").striped(true).show(ui, |ui| {
                ui.label(egui::RichText::new("IP").strong());
                ui.label(egui::RichText::new("Port").strong());
                ui.label(egui::RichText::new("Protocol").strong());
                ui.label(egui::RichText::new("Service").strong());
                ui.label(egui::RichText::new("State").strong());
                ui.end_row();

                for r in &filtered {
                    ui.monospace(&r.ip);
                    ui.monospace(r.port.to_string());
                    ui.label(&r.protocol);

                    let svc_color = match r.service.as_str() {
                        "SSH" => egui::Color32::from_rgb(100, 200, 255),
                        "HTTP" | "HTTPS" => egui::Color32::from_rgb(80, 200, 80),
                        "MySQL" | "PostgreSQL" | "Redis" | "MongoDB" => {
                            egui::Color32::from_rgb(255, 180, 50)
                        }
                        "SMB" | "RDP" => egui::Color32::from_rgb(255, 100, 100),
                        _ => egui::Color32::WHITE,
                    };
                    ui.label(egui::RichText::new(&r.service).color(svc_color));
                    ui.colored_label(egui::Color32::from_rgb(80, 200, 80), &r.state);
                    ui.end_row();
                }
            });
        });

        // Service breakdown
        ui.add_space(12.0);
        ui.collapsing("Service Breakdown", |ui| {
            let mut stats: Vec<_> = job.results.iter().fold(
                HashMap::<String, usize>::new(),
                |mut acc, r| {
                    *acc.entry(r.service.clone()).or_insert(0) += 1;
                    acc
                },
            )
            .into_iter()
            .collect();
            stats.sort_by(|a, b| b.1.cmp(&a.1));

            egui::Grid::new("service_stats").show(ui, |ui| {
                ui.label(egui::RichText::new("Service").strong());
                ui.label(egui::RichText::new("Count").strong());
                ui.label(egui::RichText::new("Bar").strong());
                ui.end_row();
                let max = stats.first().map(|x| x.1).unwrap_or(1).max(1);
                for (svc, count) in &stats {
                    ui.label(svc.as_str());
                    ui.label(count.to_string());
                    ui.add(egui::ProgressBar::new(*count as f32 / max as f32).show_percentage());
                    ui.end_row();
                }
            });
        });
    }

    fn history_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scan History");
        ui.add_space(8.0);

        if self.history.jobs.is_empty() {
            ui.label("No scan history yet.");
            return;
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
            for job in &self.history.jobs {
                let header = format!(
                    "Job #{} | {} IPs | {} open | {}",
                    job.id,
                    job.total_ips,
                    job.total_open,
                    job.status
                );

                ui.collapsing(header, |ui| {
                    if let Some(ref started) = job.started_at {
                        ui.label(format!("Started: {}", started.format("%Y-%m-%d %H:%M:%S UTC")));
                    }
                    if let Some(ref finished) = job.finished_at {
                        ui.label(format!("Finished: {}", finished.format("%Y-%m-%d %H:%M:%S UTC")));
                    }
                    ui.label(format!("Ports: {}", job.port_range));

                    if !job.results.is_empty() {
                        ui.add_space(4.0);
                        egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                            egui::Grid::new(format!("history_results_{}", job.id))
                                .striped(true)
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("IP").strong());
                                    ui.label(egui::RichText::new("Port").strong());
                                    ui.label(egui::RichText::new("Service").strong());
                                    ui.end_row();
                                    for r in &job.results {
                                        ui.monospace(&r.ip);
                                        ui.monospace(r.port.to_string());
                                        ui.label(&r.service);
                                        ui.end_row();
                                    }
                                });
                        });
                    }

                    if let Some(ref err) = job.error_message {
                        ui.colored_label(egui::Color32::from_rgb(200, 80, 80), err);
                    }
                });
            }
        });
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        ui.add_space(12.0);

        egui::Grid::new("settings_grid").show(ui, |ui| {
            ui.label("Port Range:");
            ui.add(egui::TextEdit::singleline(&mut self.settings.port_range)
                .hint_text("80,443,8080..."));
            ui.end_row();

            ui.label("Rate Limit (pps):");
            ui.add(egui::DragValue::new(&mut self.settings.rate_limit).range(1..=10000));
            ui.end_row();

            ui.label("Threads:");
            ui.add(egui::DragValue::new(&mut self.settings.threads).range(1..=500));
            ui.end_row();

            ui.label("Timeout (ms):");
            ui.add(egui::DragValue::new(&mut self.settings.timeout).range(100..=30000));
            ui.end_row();

            ui.label("Scan Type:");
            egui::ComboBox::from_id_salt("settings_scan_type")
                .selected_text(self.settings.scan_type.to_string())
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.settings.scan_type, ScanType::Connect, "Connect Scan");
                    ui.selectable_value(&mut self.settings.scan_type, ScanType::Syn, "SYN Scan");
                    ui.selectable_value(&mut self.settings.scan_type, ScanType::Auto, "Auto");
                });
            ui.end_row();

            ui.label("Verify Ports:");
            ui.checkbox(&mut self.settings.verify, "Verify open ports");
            ui.end_row();

            ui.label("Use Top Ports:");
            ui.checkbox(&mut self.settings.use_top_ports, "Use top ports");
            ui.end_row();

            if self.settings.use_top_ports {
                ui.label("Top Ports Count:");
                ui.add(egui::DragValue::new(&mut self.settings.top_ports_count).range(10..=10000));
                ui.end_row();
            }

            ui.label("Output Format:");
            egui::ComboBox::from_id_salt("output_format")
                .selected_text(self.settings.output_format.to_string())
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.settings.output_format, OutputFormat::Csv, "CSV");
                    ui.selectable_value(&mut self.settings.output_format, OutputFormat::Json, "JSON");
                    ui.selectable_value(&mut self.settings.output_format, OutputFormat::PlainText, "Plain Text");
                });
            ui.end_row();
        });

        ui.add_space(12.0);

        ui.label("Preset Port Ranges:");
        ui.horizontal(|ui| {
            if ui.button("Web").clicked() {
                self.settings.port_range = "80,443,8080,8443,8000,8888,3000,5000,9090".into();
            }
            if ui.button("Mail").clicked() {
                self.settings.port_range = "25,110,143,465,587,993,995".into();
            }
            if ui.button("Database").clicked() {
                self.settings.port_range = "3306,5432,6379,27017,1433,1521,9042".into();
            }
            if ui.button("Remote").clicked() {
                self.settings.port_range = "22,23,3389,5900,5901,6000".into();
            }
            if ui.button("All Common").clicked() {
                self.settings.port_range = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017".into();
            }
        });

        ui.add_space(16.0);

        ui.collapsing("Log Output", |ui| {
            egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                for msg in &self.log_messages {
                    ui.monospace(msg.as_str());
                }
            });
        });

        ui.add_space(12.0);

        if ui.button("🔄 Reset to Defaults").clicked() {
            self.settings = ScanSettings::default();
            self.status_msg = "Settings reset to defaults".into();
        }
    }
}
