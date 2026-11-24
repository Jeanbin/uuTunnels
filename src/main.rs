#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod autostart;
mod config;
mod forwarder;
mod ssh_engine;
mod tray;
mod uu_window;

use crate::api::AppState;
use crate::forwarder::ForwarderManager;
use crate::ssh_engine::SshEngine;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::info;

struct CliArgs {
    no_open: bool,
    ui_port: Option<u16>,
    config_path: Option<PathBuf>,
}

fn parse_args() -> CliArgs {
    let mut args = std::env::args().skip(1);
    let mut out = CliArgs {
        no_open: false,
        ui_port: None,
        config_path: None,
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "--no-open" => out.no_open = true,
            "--ui-port" => {
                if let Some(v) = args.next() {
                    out.ui_port = v.parse().ok();
                }
            }
            "--config" => {
                if let Some(v) = args.next() {
                    out.config_path = Some(PathBuf::from(v));
                }
            }
            _ => {}
        }
    }
    out
}

fn is_already_running(ui_port: u16) -> bool {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], ui_port));
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(300)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(400)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(400)));
    if s.write_all(b"GET /api/ping HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf.contains("uuTunnels")
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = parse_args();
    let config_path = cli.config_path.unwrap_or_else(config::default_config_path);
    let mut cfg = config::load_or_create(&config_path).expect("加载配置文件失败");
    if let Some(p) = cli.ui_port {
        cfg.ui_port = p;
    }
    let ui_port = cfg.ui_port;

    if is_already_running(ui_port) {
        if !cli.no_open {
            tray::open_ui_window(ui_port);
        }
        return;
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("创建 Tokio 运行时失败");

    let rt_handle = rt.handle().clone();
    let root_cancel = CancellationToken::new();
    let (ssh, forwarder, app_state) = {
        let _guard = rt.enter();
        let ssh = Arc::new(SshEngine::new(root_cancel.clone()));
        let forwarder = Arc::new(ForwarderManager::new(ssh.clone(), root_cancel.clone()));
        let app_state = AppState {
            config_path,
            config: Arc::new(RwLock::new(cfg.clone())),
            ssh: ssh.clone(),
            forwarder: forwarder.clone(),
        };
        (ssh, forwarder, app_state)
    };
    let _ = (&ssh, &forwarder);

    let bg_state = app_state.clone();
    let bg_cancel = root_cancel.clone();

    let bg_thread = std::thread::spawn(move || {
        rt.block_on(async move {
            bg_state.ssh.sync_all(&cfg).await;
            bg_state.forwarder.sync_all(&cfg).await;

            let router = api::build_router(bg_state);
            let bind_addr = format!("127.0.0.1:{ui_port}");
            let listener = tokio::net::TcpListener::bind(&bind_addr)
                .await
                .unwrap_or_else(|e| panic!("绑定管理界面端口 {bind_addr} 失败: {e}"));
            info!("uuTunnels UI listening on http://{bind_addr}/");

            let shutdown_sig = bg_cancel.clone();
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    shutdown_sig.cancelled().await;
                })
                .await;
        });
    });

    if !cli.no_open {
        let open_port = ui_port;
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            tray::open_ui_window(open_port);
        });
    }

    tray::run_tray_loop(ui_port, app_state, rt_handle, root_cancel);
    let _ = bg_thread.join();
}
