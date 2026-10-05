use std::path::{Path, PathBuf};

pub fn serve(case_dir: &Path) -> Result<(), eframe::Error> {
    let case_dir = case_dir.to_path_buf();
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_inner_size([900.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "McParser",
        options,
        Box::new(move |_cc| Ok(Box::new(McParserApp::new(case_dir)))),
    )
}

struct McParserApp {
    case_dir: PathBuf,
    sql: String,
    output: String,
}

impl McParserApp {
    fn new(case_dir: PathBuf) -> Self {
        let output = stats_text(&case_dir);
        Self {
            case_dir,
            sql: "SELECT event_id, count(*) FROM events GROUP BY event_id ORDER BY count(*) DESC LIMIT 20".to_string(),
            output,
        }
    }
}

impl eframe::App for McParserApp {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        ui.heading("McParser");
        ui.label(self.case_dir.display().to_string());
        if ui.button("Stats").clicked() {
            self.output = stats_text(&self.case_dir);
        }
        ui.label("Query");
        ui.add(
            eframe::egui::TextEdit::multiline(&mut self.sql)
                .desired_rows(4)
                .desired_width(f32::INFINITY),
        );
        if ui.button("Run").clicked() {
            self.output = query_text(&self.case_dir, &self.sql);
        }
        eframe::egui::ScrollArea::vertical().show(ui, |ui| {
            ui.monospace(&self.output);
        });
    }
}

fn stats_text(case_dir: &Path) -> String {
    let db = case_dir.join("events.duckdb");
    let sections = [
        ("time range", "SELECT min(time_created), max(time_created), count(*) FROM events"),
        ("channels", "SELECT channel, count(*) FROM events GROUP BY channel ORDER BY count(*) DESC"),
        ("providers", "SELECT provider, count(*) FROM events GROUP BY provider ORDER BY count(*) DESC"),
        ("event ids", "SELECT event_id, count(*) FROM events GROUP BY event_id ORDER BY count(*) DESC LIMIT 20"),
    ];
    let mut out = String::new();
    for (title, sql) in sections {
        out.push_str("# ");
        out.push_str(title);
        out.push('\n');
        out.push_str(&table(&db, sql));
        out.push_str("\n\n");
    }
    out
}

fn query_text(case_dir: &Path, sql: &str) -> String {
    if sql.trim().is_empty() {
        return "empty query".to_string();
    }
    table(&case_dir.join("events.duckdb"), sql)
}

fn table(db: &Path, sql: &str) -> String {
    match case::query(db, sql) {
        Ok(rows) => rows
            .iter()
            .map(|row| row.join("\t"))
            .collect::<Vec<_>>()
            .join("\n"),
        Err(err) => err.to_string(),
    }
}
