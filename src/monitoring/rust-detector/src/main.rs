use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use sysinfo::{ProcessExt, System, SystemExt};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RunningApp {
    pid: u32,
    name: String,
    exe_path: Option<String>,
    is_active: bool,
}

#[derive(Debug, Serialize)]
struct DetectionResult {
    apps: Vec<RunningApp>,
    active_window: Option<RunningApp>,
    total_count: usize,
    target_apps_detected: Vec<String>,
}

struct AppDetector {
    system: System,
    target_apps: HashMap<String, Vec<String>>,
}

impl AppDetector {
    fn new() -> Self {
        let mut target_apps = HashMap::new();
        
        target_apps.insert("burpsuite".to_string(), vec![
            "burpsuite".to_string(),
            "burp suite".to_string(),
            "burp.exe".to_string(),
        ]);
        target_apps.insert("chrome".to_string(), vec![
            "chrome.exe".to_string(),
            "google chrome".to_string(),
        ]);
        target_apps.insert("firefox".to_string(), vec![
            "firefox.exe".to_string(),
        ]);
        target_apps.insert("vscode".to_string(), vec![
            "code.exe".to_string(),
            "visual studio code".to_string(),
        ]);
        target_apps.insert("postman".to_string(), vec![
            "postman.exe".to_string(),
        ]);
        target_apps.insert("wireshark".to_string(), vec![
            "wireshark.exe".to_string(),
        ]);

        AppDetector {
            system: System::new_all(),
            target_apps,
        }
    }

    fn detect(&mut self, targets: Option<Vec<String>>) -> DetectionResult {
        self.system.refresh_all();
        
        let mut apps = Vec::new();
        let mut detected_categories = Vec::new();

        for (pid, process) in self.system.processes() {
            let name = process.name().to_lowercase();
            let exe_path = process.exe().and_then(|p| p.to_str()).map(|s| s.to_string());
            
            let category = self.get_app_category(&name, &exe_path);
            
            if let Some(ref tgts) = targets {
                if !tgts.iter().any(|t| category.as_ref().map_or(false, |c| c == t)) {
                    continue;
                }
            } else if category.is_none() {
                continue;
            }

            if let Some(cat) = &category {
                if !detected_categories.contains(cat) {
                    detected_categories.push(cat.clone());
                }
            }

            apps.push(RunningApp {
                pid: pid.as_u32(),
                name: process.name().to_string(),
                exe_path,
                is_active: false,
            });
        }

        DetectionResult {
            total_count: apps.len(),
            apps,
            active_window: None,
            target_apps_detected: detected_categories,
        }
    }

    fn get_app_category(&self, name: &str, exe_path: &Option<String>) -> Option<String> {
        for (category, patterns) in &self.target_apps {
            for pattern in patterns {
                if name.contains(&pattern.to_lowercase()) {
                    return Some(category.clone());
                }
                if let Some(ref exe) = exe_path {
                    if exe.to_lowercase().contains(&pattern.to_lowercase()) {
                        return Some(category.clone());
                    }
                }
            }
        }
        None
    }

    fn is_running(&mut self, app_name: &str) -> bool {
        let result = self.detect(Some(vec![app_name.to_string()]));
        !result.apps.is_empty()
    }
}

#[derive(Deserialize)]
struct DetectQuery {
    targets: Option<String>,
}

async fn detect_apps(
    detector: web::Data<std::sync::Mutex<AppDetector>>,
    query: web::Query<DetectQuery>,
) -> impl Responder {
    let targets = query.targets.as_ref().map(|t| {
        t.split(',').map(|s| s.trim().to_string()).collect()
    });

    let mut det = detector.lock().unwrap();
    let result = det.detect(targets);
    HttpResponse::Ok().json(result)
}

async fn check_app(
    detector: web::Data<std::sync::Mutex<AppDetector>>,
    app_name: web::Path<String>,
) -> impl Responder {
    let mut det = detector.lock().unwrap();
    let running = det.is_running(&app_name);
    HttpResponse::Ok().json(serde_json::json!({
        "app": app_name.as_str(),
        "running": running
    }))
}

async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "aether-app-detector"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let detector = web::Data::new(std::sync::Mutex::new(AppDetector::new()));
    let port = std::env::var("DETECTOR_PORT").unwrap_or_else(|_| "9002".to_string());

    println!("App Detector Service running on port {}", port);

    HttpServer::new(move || {
        App::new()
            .app_data(detector.clone())
            .route("/detect", web::get().to(detect_apps))
            .route("/check/{app}", web::get().to(check_app))
            .route("/health", web::get().to(health))
    })
    .bind(format!("127.0.0.1:{}", port))?
    .run()
    .await
}
