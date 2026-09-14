mod app;
mod ip_generator;
mod models;
mod scanner;

use app::NaabuGuiApp;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 700.0])
            .with_min_inner_size([960.0, 620.0])
            .with_title("Naabu GUI Scanner"),
        ..Default::default()
    };

    eframe::run_native(
        "Naabu GUI Scanner",
        options,
        Box::new(|cc| Ok(Box::new(NaabuGuiApp::new(cc)))),
    )
}
