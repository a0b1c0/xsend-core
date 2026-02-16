#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use tauri::Manager;

struct DaemonState(Mutex<Option<xsend::daemon::DaemonHandle>>);

fn main() {
    let app = tauri::Builder::default()
        .manage(DaemonState(Mutex::new(None)))
        .setup(|app| {
            // Start daemon on the Tauri async runtime so its tasks stay alive.
            let daemon = tauri::async_runtime::block_on(async { xsend::daemon::start().await })
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            let ui_url = daemon.info.ui_url.clone();
            {
                let state = app.state::<DaemonState>();
                *state.0.lock().unwrap() = Some(daemon);
            }

            let url = tauri::Url::parse(&ui_url)?;
            tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::External(url))
                .title("xSend")
                .inner_size(980.0, 740.0)
                .resizable(true)
                .build()?;

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri app");

    app.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::ExitRequested { .. }) {
            let state = app_handle.state::<DaemonState>();
            if let Ok(mut guard) = state.0.lock() {
                if let Some(mut daemon) = guard.take() {
                    daemon.signal_shutdown();
                }
            }
        }
    });
}
