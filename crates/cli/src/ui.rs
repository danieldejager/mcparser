use case::Table;
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::path::{Path, PathBuf};
use std::time::Instant;

const WINDOW: egui::Color32 = egui::Color32::from_rgb(243, 243, 243);
const PANEL: egui::Color32 = egui::Color32::from_rgb(255, 255, 255);
const INK: egui::Color32 = egui::Color32::from_rgb(32, 32, 32);
const MUTED: egui::Color32 = egui::Color32::from_rgb(96, 96, 96);

pub fn serve(case_dir: &Path) -> Result<(), eframe::Error> {
    let case_dir = case_dir.to_path_buf();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1100.0, 720.0]),
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
    channels: Vec<String>,
    providers: Vec<String>,
    event_ids: Vec<String>,
    result: Table,
    error: String,
    elapsed_ms: u128,
}

impl McParserApp {
    fn new(case_dir: PathBuf) -> Self {
        let mut app = Self {
            case_dir,
            sql: "SELECT event_id, count(*) AS count\nFROM events\nGROUP BY event_id\nORDER BY count DESC\nLIMIT 20".to_string(),
            channels: Vec::new(),
            providers: Vec::new(),
            event_ids: Vec::new(),
            result: Table { columns: Vec::new(), rows: Vec::new() },
            error: String::new(),
            elapsed_ms: 0,
        };
        app.load_sidebar();
        app.run_query();
        app
    }

    fn load_sidebar(&mut self) {
        let db = self.case_dir.join("events.duckdb");
        self.channels = first_column(&db, "SELECT channel FROM events GROUP BY channel ORDER BY count(*) DESC");
        self.providers = first_column(&db, "SELECT provider FROM events GROUP BY provider ORDER BY count(*) DESC");
        self.event_ids = first_column(&db, "SELECT event_id FROM events GROUP BY event_id ORDER BY count(*) DESC LIMIT 20");
    }

    fn run_query(&mut self) {
        let started = Instant::now();
        match case::query_table(&self.case_dir.join("events.duckdb"), &self.sql) {
            Ok(table) => {
                self.result = table;
                self.error.clear();
            }
            Err(err) => {
                self.result = Table { columns: Vec::new(), rows: Vec::new() };
                self.error = err.to_string();
            }
        }
        self.elapsed_ms = started.elapsed().as_millis();
    }

    fn add_filter(&mut self, clause: &str) {
        if self.sql.to_ascii_lowercase().contains("where") {
            self.sql.push_str(" AND ");
        } else {
            self.sql.push_str("\nWHERE ");
        }
        self.sql.push_str(clause);
    }
}

impl eframe::App for McParserApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let mut visuals = egui::Visuals::light();
        visuals.panel_fill = WINDOW;
        visuals.window_fill = WINDOW;
        visuals.extreme_bg_color = PANEL;
        visuals.override_text_color = Some(INK);
        ui.ctx().set_visuals(visuals.clone());
        ui.style_mut().visuals = visuals;

        let height = ui.available_height();
        let width = ui.available_width();
        ui.painter().rect_filled(ui.available_rect_before_wrap(), 0.0, WINDOW);

        ui.horizontal_top(|ui| {
            ui.allocate_ui(egui::vec2(260.0, height), |ui| {
                egui::Frame::new().fill(PANEL).inner_margin(8.0).show(ui, |ui| {
                    ui.set_min_size(egui::vec2(244.0, height - 16.0));
                    ui.heading("Case");
                    ui.label(self.case_dir.display().to_string());
                    ui.separator();
                    ui.colored_label(MUTED, "Channels");
                    for channel in self.channels.clone() {
                        if ui.button(&channel).clicked() {
                            self.add_filter(&format!("channel = '{channel}'"));
                        }
                    }
                    ui.separator();
                    ui.colored_label(MUTED, "Providers");
                    for provider in self.providers.clone() {
                        if ui.button(&provider).clicked() {
                            self.add_filter(&format!("provider = '{provider}'"));
                        }
                    }
                    ui.separator();
                    ui.colored_label(MUTED, "Event IDs");
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        for event_id in self.event_ids.clone() {
                            if ui.button(&event_id).clicked() {
                                self.add_filter(&format!("event_id = {event_id}"));
                            }
                        }
                    });
                });
            });
            ui.allocate_ui(egui::vec2((width - 268.0).max(400.0), height), |ui| {
                egui::Frame::new().fill(PANEL).inner_margin(8.0).show(ui, |ui| {
                    ui.set_min_size(egui::vec2((width - 284.0).max(380.0), height - 16.0));
                    ui.horizontal(|ui| {
                        ui.heading("SQL");
                        if ui.button("Run").clicked() {
                            self.run_query();
                        }
                        if ui.button("Refresh case").clicked() {
                            self.load_sidebar();
                        }
                    });
                    ui.add(
                        egui::TextEdit::multiline(&mut self.sql)
                            .code_editor()
                            .desired_rows(6)
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(8.0);
                    ui.colored_label(MUTED, "Results");
                    if !self.error.is_empty() {
                        ui.colored_label(egui::Color32::from_rgb(180, 40, 40), &self.error);
                    } else {
                        show_grid(ui, &self.result, (height - 220.0).max(160.0));
                    }
                    ui.add_space(8.0);
                    ui.colored_label(
                        MUTED,
                        format!(
                            "rows {} | elapsed {} ms | case {}",
                            self.result.rows.len(),
                            self.elapsed_ms,
                            self.case_dir.display()
                        ),
                    );
                });
            });
        });
    }
}

fn show_grid(ui: &mut egui::Ui, table: &Table, height: f32) {
    if table.columns.is_empty() {
        ui.label("No rows");
        return;
    }
    let mut builder = TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .max_scroll_height(height);
    for _ in &table.columns {
        builder = builder.column(Column::initial(180.0).at_least(100.0).resizable(true));
    }
    builder
        .header(22.0, |mut header| {
            for column in &table.columns {
                header.col(|ui| {
                    ui.strong(column);
                });
            }
        })
        .body(|mut body| {
            for row in &table.rows {
                body.row(22.0, |mut table_row| {
                    for cell in row {
                        table_row.col(|ui| {
                            ui.label(cell);
                        });
                    }
                });
            }
        });
}

fn first_column(db: &Path, sql: &str) -> Vec<String> {
    case::query_table(db, sql)
        .map(|table| table.rows.into_iter().filter_map(|mut row| row.pop()).collect())
        .unwrap_or_default()
}
