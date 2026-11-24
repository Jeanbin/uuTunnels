use crate::api::AppState;
use crate::browser_tab;
use crate::config;
use crate::ssh_engine::BaseStatus;
use crate::uu_window;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, KillTimer,
    PostQuitMessage, RegisterClassW, SetTimer, TranslateMessage, MSG, WM_TIMER, WNDCLASSW,
};

const ID_OPEN: &str = "sys:open";
const ID_HIDE_UU: &str = "sys:hide_uu";
const ID_SHOW_UU: &str = "sys:show_uu";
const ID_ENABLE_ALL: &str = "sys:enable_all";
const ID_DISABLE_ALL: &str = "sys:disable_all";
const ID_QUIT: &str = "sys:quit";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrayHealth {
    Connected,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
struct TrayRuleEntry {
    id: String,
    name: String,
    local_port: u16,
    target_port: u16,
    enabled: bool,
}

#[derive(Debug, Clone)]
struct TrayMachineEntry {
    name: String,
    rules: Vec<TrayRuleEntry>,
}

#[derive(Debug, Clone)]
struct TraySnapshot {
    health: TrayHealth,
    tooltip: String,
    menu_sig: String,
    machines: Vec<TrayMachineEntry>,
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

static OPEN_GATE: Mutex<Option<Instant>> = Mutex::new(None);
static OPEN_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

struct OpenInProgressGuard;

impl Drop for OpenInProgressGuard {
    fn drop(&mut self) {
        OPEN_IN_PROGRESS.store(false, Ordering::SeqCst);
    }
}

/// Focuses an existing browser tab showing the management UI (and bumps `reload_seq`
/// so the page refreshes), or opens a new browser tab if none is found.
/// Debounced and executed on a dedicated worker thread so COM UIA never blocks the tray loop.
pub fn trigger_open_ui(ui_port: u16, reload_seq: Arc<AtomicU64>) {
    {
        let mut gate = OPEN_GATE.lock().unwrap();
        let now = Instant::now();
        if let Some(prev) = *gate {
            if now.duration_since(prev) < Duration::from_millis(500) {
                return;
            }
        }
        if OPEN_IN_PROGRESS
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        *gate = Some(now);
    }

    std::thread::spawn(move || {
        let _guard = OpenInProgressGuard;
        browser_tab::focus_or_open_ui(ui_port, || {
            reload_seq.fetch_add(1, Ordering::SeqCst);
        });
    });
}

fn generate_tray_icon(health: TrayHealth) -> Icon {
    let w = 32usize;
    let h = 32usize;
    let mut rgba = vec![0u8; w * h * 4];
    let (c1, c2) = match health {
        TrayHealth::Connected => ((13.0f32, 148.0f32, 136.0f32), (2.0f32, 132.0f32, 199.0f32)),
        TrayHealth::Warning => ((217.0f32, 119.0f32, 6.0f32), (245.0f32, 158.0f32, 11.0f32)),
        TrayHealth::Error => ((185.0f32, 28.0f32, 28.0f32), (239.0f32, 68.0f32, 68.0f32)),
    };
    for y in 0..h {
        for x in 0..w {
            let idx = (y * w + x) * 4;
            let fx = x as f32 - 15.5;
            let fy = y as f32 - 15.5;
            let dx = (fx.abs() - 10.5).max(0.0);
            let dy = (fy.abs() - 10.5).max(0.0);
            let dist = (dx * dx + dy * dy).sqrt();
            if dist <= 4.5 {
                let t = (x + y) as f32 / 62.0;
                let mut r = (c1.0 + (c2.0 - c1.0) * t) as u8;
                let mut g = (c1.1 + (c2.1 - c1.1) * t) as u8;
                let mut b = (c1.2 + (c2.2 - c1.2) * t) as u8;

                let in_arch = (y >= 9 && y <= 23)
                    && ((x >= 8 && x <= 11)
                        || (x >= 20 && x <= 23)
                        || (y <= 12 && x >= 10 && x <= 21));
                let in_dot = (x >= 14 && x <= 17) && (y >= 17 && y <= 20);
                if in_arch || in_dot {
                    r = 248;
                    g = 250;
                    b = 252;
                }
                rgba[idx] = r;
                rgba[idx + 1] = g;
                rgba[idx + 2] = b;
                rgba[idx + 3] = 255;
            }
        }
    }
    Icon::from_rgba(rgba, w as u32, h as u32).expect("valid 32x32 icon")
}

fn build_tray_menu(machines: &[TrayMachineEntry]) -> Menu {
    let menu = Menu::new();
    let _ = menu.append(&MenuItem::with_id(ID_OPEN, "打开管理面板", true, None));
    let _ = menu.append(&PredefinedMenuItem::separator());

    for m in machines {
        let on_cnt = m.rules.iter().filter(|r| r.enabled).count();
        let label = format!("{} ({}/{})", m.name, on_cnt, m.rules.len());
        let sub = Submenu::new(label, true);
        for r in &m.rules {
            let item_label = format!("{} (:{} → :{})", r.name, r.local_port, r.target_port);
            let item = CheckMenuItem::with_id(
                MenuId::new(format!("toggle:{}", r.id)),
                item_label,
                true,
                r.enabled,
                None,
            );
            let _ = sub.append(&item);
        }
        let _ = menu.append(&sub);
    }

    if !machines.is_empty() {
        let _ = menu.append(&PredefinedMenuItem::separator());
    }

    let _ = menu.append(&MenuItem::with_id(
        ID_HIDE_UU,
        "收纳 UU 端口映射窗口",
        true,
        None,
    ));
    let _ = menu.append(&MenuItem::with_id(
        ID_SHOW_UU,
        "恢复已收纳的 UU 窗口",
        true,
        None,
    ));
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&MenuItem::with_id(ID_ENABLE_ALL, "全部开启映射", true, None));
    let _ = menu.append(&MenuItem::with_id(ID_DISABLE_ALL, "全部关闭映射", true, None));
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&MenuItem::with_id(ID_QUIT, "退出 uuTunnels", true, None));
    menu
}

async fn collect_tray_snapshot(state: &AppState) -> TraySnapshot {
    let cfg = state.config.read().await.clone();
    let base_snaps = state.ssh.snapshot_all().await;
    let rule_snaps = state.forwarder.snapshot_all().await;

    let enabled_bases: Vec<_> = cfg
        .bases
        .iter()
        .filter(|b| b.enabled)
        .filter_map(|b| base_snaps.get(&b.id).map(|s| (b, s)))
        .collect();

    let mut health = TrayHealth::Warning;
    let mut base_desc = "未启用基座".to_string();
    if let Some((b, s)) = enabled_bases.first() {
        match s.status {
            BaseStatus::Connected => {
                let all_ok = enabled_bases
                    .iter()
                    .all(|(_, st)| st.status == BaseStatus::Connected);
                health = if all_ok {
                    TrayHealth::Connected
                } else {
                    TrayHealth::Warning
                };
                let lat = s
                    .latency_ms
                    .map(|ms| format!(" ({ms}ms)"))
                    .unwrap_or_default();
                base_desc = format!("{} 已连接{}", b.name, lat);
            }
            BaseStatus::Connecting | BaseStatus::NeedsCredentials => {
                health = TrayHealth::Warning;
                base_desc = match s.status {
                    BaseStatus::Connecting => format!("{} 连接中...", b.name),
                    _ => format!("{} 待填写凭据", b.name),
                };
            }
            BaseStatus::Error | BaseStatus::Disconnected => {
                health = TrayHealth::Error;
                base_desc = format!("{} 未连接", b.name);
            }
        }
    } else if !cfg.bases.is_empty() {
        health = TrayHealth::Error;
        base_desc = "所有基座已断开".to_string();
    }

    let running = cfg
        .rules
        .iter()
        .filter(|r| {
            r.enabled
                && rule_snaps
                    .get(&r.id)
                    .map(|s| s.status == crate::forwarder::RuleStatus::Running)
                    .unwrap_or(false)
        })
        .count();
    let enabled_total = cfg.rules.iter().filter(|r| r.enabled).count();
    let tooltip = format!(
        "uuTunnels · {base_desc} · 运行 {running}/{enabled_total} (总 {})",
        cfg.rules.len()
    );

    let mut sig = String::new();
    let mut machines = Vec::with_capacity(cfg.machines.len());
    for m in &cfg.machines {
        sig.push_str(&m.id);
        sig.push(':');
        sig.push_str(&m.name);
        sig.push(';');
        let mut r_list = Vec::new();
        for r in cfg.rules.iter().filter(|r| r.machine_id == m.id) {
            sig.push_str(&format!(
                "{}={}:{}:{}:{};",
                r.id, r.name, r.local_port, r.target_port, r.enabled
            ));
            r_list.push(TrayRuleEntry {
                id: r.id.clone(),
                name: r.name.clone(),
                local_port: r.local_port,
                target_port: r.target_port,
                enabled: r.enabled,
            });
        }
        machines.push(TrayMachineEntry {
            name: m.name.clone(),
            rules: r_list,
        });
    }

    TraySnapshot {
        health,
        tooltip,
        menu_sig: sig,
        machines,
    }
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

pub fn run_tray_loop(
    ui_port: u16,
    app_state: AppState,
    rt_handle: tokio::runtime::Handle,
    shutdown: CancellationToken,
) {
    let icon_ok = generate_tray_icon(TrayHealth::Connected);
    let icon_warn = generate_tray_icon(TrayHealth::Warning);
    let icon_err = generate_tray_icon(TrayHealth::Error);

    let initial_snap = rt_handle.block_on(collect_tray_snapshot(&app_state));
    let mut current_health = initial_snap.health;
    let mut current_tooltip = initial_snap.tooltip.clone();
    let mut current_sig = initial_snap.menu_sig.clone();

    let initial_icon = match current_health {
        TrayHealth::Connected => icon_ok.clone(),
        TrayHealth::Warning => icon_warn.clone(),
        TrayHealth::Error => icon_err.clone(),
    };
    let initial_menu = build_tray_menu(&initial_snap.machines);

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(initial_menu))
        .with_tooltip(&current_tooltip)
        .with_icon(initial_icon)
        .build()
        .expect("Failed to create Windows tray icon");

    let (tx_snap, rx_snap) = mpsc::channel::<TraySnapshot>();
    let snap_state = app_state.clone();
    let snap_cancel = shutdown.clone();
    let trigger_refresh = std::sync::Arc::new(tokio::sync::Notify::new());
    let trigger_rx = trigger_refresh.clone();
    rt_handle.spawn(async move {
        loop {
            tokio::select! {
                _ = snap_cancel.cancelled() => break,
                _ = trigger_rx.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_millis(1200)) => {}
            }
            let s = collect_tray_snapshot(&snap_state).await;
            if tx_snap.send(s).is_err() {
                break;
            }
        }
    });

    let class_name = to_wide("uuTunnelsTrayMsgClass");
    let wc = WNDCLASSW {
        style: 0,
        lpfnWndProc: Some(wnd_proc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: std::ptr::null_mut(),
        hIcon: std::ptr::null_mut(),
        hCursor: std::ptr::null_mut(),
        hbrBackground: std::ptr::null_mut(),
        lpszMenuName: std::ptr::null(),
        lpszClassName: class_name.as_ptr(),
    };
    unsafe {
        RegisterClassW(&wc);
    }
    let title = to_wide("uuTunnelsHiddenMsgWin");
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    unsafe {
        SetTimer(hwnd, 1, 50, None);
    }

    let menu_rx = MenuEvent::receiver();
    let tray_rx = TrayIconEvent::receiver();
    let mut msg: MSG = unsafe { std::mem::zeroed() };

    while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } > 0 {
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if msg.message == WM_TIMER {
            // Apply latest snapshot updates non-blockingly
            let mut latest: Option<TraySnapshot> = None;
            while let Ok(s) = rx_snap.try_recv() {
                latest = Some(s);
            }
            if let Some(s) = latest {
                if s.health != current_health {
                    current_health = s.health;
                    let ic = match current_health {
                        TrayHealth::Connected => icon_ok.clone(),
                        TrayHealth::Warning => icon_warn.clone(),
                        TrayHealth::Error => icon_err.clone(),
                    };
                    let _ = tray.set_icon(Some(ic));
                }
                if s.tooltip != current_tooltip {
                    current_tooltip = s.tooltip;
                    let _ = tray.set_tooltip(Some(&current_tooltip));
                }
                if s.menu_sig != current_sig {
                    current_sig = s.menu_sig;
                    let m = build_tray_menu(&s.machines);
                    tray.set_menu(Some(Box::new(m)));
                }
            }

            while let Ok(ev) = tray_rx.try_recv() {
                match ev {
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
                    | TrayIconEvent::DoubleClick {
                        button: MouseButton::Left,
                        ..
                    } => {
                        trigger_open_ui(ui_port, app_state.ui_reload_seq.clone());
                    }
                    _ => {}
                }
            }

            while let Ok(ev) = menu_rx.try_recv() {
                let id_str = ev.id.0.as_str();
                if id_str == ID_OPEN {
                    trigger_open_ui(ui_port, app_state.ui_reload_seq.clone());
                } else if id_str == ID_HIDE_UU {
                    let _ = uu_window::hide_portmap_windows();
                } else if id_str == ID_SHOW_UU {
                    let _ = uu_window::restore_all_hidden();
                } else if id_str == ID_ENABLE_ALL {
                    let st = app_state.clone();
                    let trig = trigger_refresh.clone();
                    rt_handle.spawn(async move {
                        let cfg_clone = {
                            let mut cfg = st.config.write().await;
                            cfg.rules.iter_mut().for_each(|r| r.enabled = true);
                            let _ = config::save(&st.config_path, &cfg);
                            cfg.clone()
                        };
                        st.forwarder.sync_all(&cfg_clone).await;
                        trig.notify_one();
                    });
                } else if id_str == ID_DISABLE_ALL {
                    let st = app_state.clone();
                    let trig = trigger_refresh.clone();
                    rt_handle.spawn(async move {
                        let cfg_clone = {
                            let mut cfg = st.config.write().await;
                            cfg.rules.iter_mut().for_each(|r| r.enabled = false);
                            let _ = config::save(&st.config_path, &cfg);
                            cfg.clone()
                        };
                        st.forwarder.sync_all(&cfg_clone).await;
                        trig.notify_one();
                    });
                } else if let Some(rule_id) = id_str.strip_prefix("toggle:") {
                    let rule_id = rule_id.to_string();
                    let st = app_state.clone();
                    let trig = trigger_refresh.clone();
                    rt_handle.spawn(async move {
                        let cfg_clone = {
                            let mut cfg = st.config.write().await;
                            if let Some(r) = cfg.rules.iter_mut().find(|r| r.id == rule_id) {
                                r.enabled = !r.enabled;
                                let _ = config::save(&st.config_path, &cfg);
                            }
                            cfg.clone()
                        };
                        st.forwarder.sync_all(&cfg_clone).await;
                        trig.notify_one();
                    });
                } else if id_str == ID_QUIT {
                    let _ = uu_window::restore_all_hidden();
                    shutdown.cancel();
                    unsafe {
                        KillTimer(hwnd, 1);
                        DestroyWindow(hwnd);
                        PostQuitMessage(0);
                    }
                    return;
                }
            }
        }
    }

    let _ = uu_window::restore_all_hidden();
    shutdown.cancel();
}
