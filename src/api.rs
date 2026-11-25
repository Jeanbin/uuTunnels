use crate::autostart;
use crate::config::{self, AppConfig, AuthType, BaseKind, ForwardRule, Machine, TunnelBase};
use crate::forwarder::{ForwarderManager, RuleRuntimeSnapshot};
use crate::ssh_engine::{BaseRuntimeSnapshot, SshEngine};
use crate::ssh_terminal::{self, AskpassStore};
use crate::uu_window::{self, UuWindowInfo};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post, put};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

const INDEX_HTML: &str = include_str!("../ui/index.html");

#[derive(Clone)]
pub struct AppState {
    pub config_path: PathBuf,
    pub config: Arc<RwLock<AppConfig>>,
    pub ssh: Arc<SshEngine>,
    pub forwarder: Arc<ForwarderManager>,
    pub askpass: Arc<AskpassStore>,
    pub ui_boot_id: String,
    pub ui_reload_seq: Arc<AtomicU64>,
}

#[derive(Serialize)]
struct BaseView {
    id: String,
    name: String,
    kind: BaseKind,
    host: String,
    port: u16,
    username: String,
    auth_type: AuthType,
    has_password: bool,
    key_path: Option<String>,
    has_key_passphrase: bool,
    enabled: bool,
    runtime: BaseRuntimeSnapshot,
}

#[derive(Serialize)]
struct RuleView {
    id: String,
    machine_id: String,
    name: String,
    protocol: String,
    local_host: String,
    local_port: u16,
    target_host: String,
    target_port: u16,
    url_path: String,
    ssh_username: Option<String>,
    ssh_auth_type: Option<AuthType>,
    ssh_has_password: bool,
    ssh_key_path: Option<String>,
    ssh_has_key_passphrase: bool,
    effective_ssh_username: Option<String>,
    enabled: bool,
    pinned: bool,
    runtime: RuleRuntimeSnapshot,
}

#[derive(Serialize)]
struct StateResponse {
    bases: Vec<BaseView>,
    machines: Vec<Machine>,
    rules: Vec<RuleView>,
    uu_windows: Vec<UuWindowInfo>,
    autostart: bool,
    auto_hide_uu: bool,
    ssh_terminal: config::SshTerminalConfig,
    config_path: String,
    ui_port: u16,
    ui_boot_id: String,
    ui_reload_seq: u64,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/api/ping", get(|| async { "uuTunnels" }))
        .route("/api/state", get(get_state))
        .route("/api/ui/signal", get(get_ui_signal))
        .route("/api/ui/open", post(open_ui_handler))
        .route("/api/bases", post(create_base))
        .route("/api/bases/{id}", put(update_base).delete(delete_base))
        .route("/api/bases/{id}/reconnect", post(reconnect_base))
        .route("/api/bases/{id}/disconnect", post(disconnect_base))
        .route("/api/machines", post(create_machine))
        .route(
            "/api/machines/{id}",
            put(update_machine).delete(delete_machine),
        )
        .route("/api/rules", post(create_rule))
        .route("/api/rules/{id}", put(update_rule).delete(delete_rule))
        .route("/api/rules/{id}/toggle", post(toggle_rule))
        .route("/api/rules/{id}/pin", post(pin_rule))
        .route("/api/rules/{id}/probe", post(probe_rule_handler))
        .route("/api/rules/{id}/open-ssh", post(open_ssh_terminal))
        .route("/api/rules/batch", post(batch_rules))
        .route("/api/uu/windows", get(list_uu_windows))
        .route("/api/uu/hide/{hwnd}", post(hide_uu_window))
        .route("/api/uu/show/{hwnd}", post(show_uu_window))
        .route("/api/uu/hide-portmap", post(hide_uu_portmap))
        .route("/api/uu/show-all", post(show_all_uu))
        .route("/api/settings/autostart", post(set_autostart))
        .route("/api/settings/auto-hide-uu", post(set_auto_hide_uu))
        .route("/api/ssh-terminals", get(list_ssh_terminals))
        .route("/api/settings/ssh-terminal", post(set_ssh_terminal))
        .route("/api/internal/askpass/{token}", post(consume_askpass))
        .route("/api/app/open-config-dir", post(open_config_dir))
        .with_state(state)
}

async fn index_handler() -> Html<&'static str> {
    Html(INDEX_HTML)
}

fn err_resp(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": msg.into() })))
}

async fn save_and_sync(state: &AppState) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let cfg = state.config.read().await.clone();
    config::save(&state.config_path, &cfg)
        .map_err(|e| err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state.ssh.sync_all(&cfg).await;
    state.forwarder.sync_all(&cfg).await;
    Ok(())
}

async fn build_state_payload(state: &AppState) -> StateResponse {
    let cfg = state.config.read().await.clone();
    let base_snaps = state.ssh.snapshot_all().await;
    let rule_snaps = state.forwarder.snapshot_all().await;

    let effective_ssh_users: std::collections::HashMap<String, Option<String>> = cfg
        .rules
        .iter()
        .filter(|r| r.protocol.eq_ignore_ascii_case("ssh"))
        .map(|r| (r.id.clone(), ssh_terminal::resolve_effective_ssh_username(&cfg, r)))
        .collect();

    let ssh_terminal_cfg = cfg.ssh_terminal.clone();

    let bases = cfg
        .bases
        .into_iter()
        .map(|b| {
            let rt = base_snaps.get(&b.id).cloned().unwrap_or(BaseRuntimeSnapshot {
                status: crate::ssh_engine::BaseStatus::Disconnected,
                latency_ms: None,
                last_error: None,
            });
            BaseView {
                id: b.id,
                name: b.name,
                kind: b.kind,
                host: b.host,
                port: b.port,
                username: b.username,
                auth_type: b.auth_type,
                has_password: b.password.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
                key_path: b.key_path,
                has_key_passphrase: b
                    .key_passphrase
                    .as_deref()
                    .map(|s| !s.is_empty())
                    .unwrap_or(false),
                enabled: b.enabled,
                runtime: rt,
            }
        })
        .collect();

    let rules = cfg
        .rules
        .into_iter()
        .map(|r| {
            let rt = rule_snaps.get(&r.id).cloned().unwrap_or(RuleRuntimeSnapshot {
                status: crate::forwarder::RuleStatus::Stopped,
                active_conns: 0,
                total_conns: 0,
                rx_bytes: 0,
                tx_bytes: 0,
                rx_bps: 0,
                tx_bps: 0,
                last_error: None,
            });
            let ssh_has_password = r.ssh_password.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
            let ssh_has_key_passphrase = r
                .ssh_key_passphrase
                .as_deref()
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            let effective_ssh_username = effective_ssh_users.get(&r.id).cloned().flatten();
            RuleView {
                id: r.id,
                machine_id: r.machine_id,
                name: r.name,
                protocol: r.protocol,
                local_host: r.local_host,
                local_port: r.local_port,
                target_host: r.target_host,
                target_port: r.target_port,
                url_path: config::normalize_url_path(&r.url_path),
                ssh_username: r.ssh_username,
                ssh_auth_type: r.ssh_auth_type,
                ssh_has_password,
                ssh_key_path: r.ssh_key_path,
                ssh_has_key_passphrase,
                effective_ssh_username,
                enabled: r.enabled,
                pinned: r.pinned,
                runtime: rt,
            }
        })
        .collect();

    let uu_windows = tokio::task::spawn_blocking(uu_window::list_uu_windows)
        .await
        .unwrap_or_default();
    let auto = tokio::task::spawn_blocking(autostart::is_enabled)
        .await
        .unwrap_or(false);

    StateResponse {
        bases,
        machines: cfg.machines,
        rules,
        uu_windows,
        autostart: auto,
        auto_hide_uu: cfg.auto_hide_uu,
        ssh_terminal: ssh_terminal_cfg,
        config_path: state.config_path.display().to_string(),
        ui_port: cfg.ui_port,
        ui_boot_id: state.ui_boot_id.clone(),
        ui_reload_seq: state.ui_reload_seq.load(Ordering::SeqCst),
    }
}

async fn get_state(State(state): State<AppState>) -> impl IntoResponse {
    Json(build_state_payload(&state).await)
}

async fn get_ui_signal(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "boot_id": state.ui_boot_id,
        "reload_seq": state.ui_reload_seq.load(Ordering::SeqCst),
    }))
}

async fn open_ui_handler(State(state): State<AppState>) -> impl IntoResponse {
    let ui_port = state.config.read().await.ui_port;
    crate::tray::trigger_open_ui(ui_port, state.ui_reload_seq.clone());
    Json(serde_json::json!({ "ok": true }))
}

#[derive(Deserialize)]
struct BaseInput {
    name: String,
    kind: BaseKind,
    host: String,
    port: u16,
    #[serde(default)]
    username: String,
    #[serde(default = "default_auth")]
    auth_type: AuthType,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    clear_password: bool,
    #[serde(default)]
    key_path: Option<String>,
    #[serde(default)]
    key_passphrase: Option<String>,
    #[serde(default)]
    clear_key_passphrase: bool,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_auth() -> AuthType {
    AuthType::Password
}

fn default_true() -> bool {
    true
}

async fn create_base(
    State(state): State<AppState>,
    Json(input): Json<BaseInput>,
) -> impl IntoResponse {
    if input.name.trim().is_empty() {
        return err_resp(StatusCode::BAD_REQUEST, "基座名称不能为空").into_response();
    }
    let id = format!("base-{}", &Uuid::new_v4().to_string()[..8]);
    let base = TunnelBase {
        id,
        name: input.name.trim().to_string(),
        kind: input.kind,
        host: input.host.trim().to_string(),
        port: input.port,
        username: input.username.trim().to_string(),
        auth_type: input.auth_type,
        password: input.password.filter(|s| !s.is_empty()),
        key_path: input.key_path.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        key_passphrase: input.key_passphrase.filter(|s| !s.is_empty()),
        enabled: input.enabled,
    };
    state.config.write().await.bases.push(base);
    if let Err(e) = save_and_sync(&state).await {
        return e.into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

async fn update_base(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<BaseInput>,
) -> impl IntoResponse {
    {
        let mut cfg = state.config.write().await;
        let Some(b) = cfg.bases.iter_mut().find(|b| b.id == id) else {
            return err_resp(StatusCode::NOT_FOUND, "未找到该基座").into_response();
        };
        b.name = input.name.trim().to_string();
        b.kind = input.kind;
        b.host = input.host.trim().to_string();
        b.port = input.port;
        b.username = input.username.trim().to_string();
        b.auth_type = input.auth_type;
        b.enabled = input.enabled;

        if input.clear_password {
            b.password = None;
        } else if let Some(pwd) = input.password {
            if !pwd.is_empty() {
                b.password = Some(pwd);
            }
        }

        b.key_path = input
            .key_path
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        if input.clear_key_passphrase {
            b.key_passphrase = None;
        } else if let Some(pp) = input.key_passphrase {
            if !pp.is_empty() {
                b.key_passphrase = Some(pp);
            }
        }
    }

    if let Err(e) = save_and_sync(&state).await {
        return e.into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

async fn delete_base(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    {
        let mut cfg = state.config.write().await;
        if cfg.machines.iter().any(|m| m.base_id == id) {
            return err_resp(StatusCode::BAD_REQUEST, "仍有机器绑定到此基座，请先修改或删除对应机器").into_response();
        }
        let before = cfg.bases.len();
        cfg.bases.retain(|b| b.id != id);
        if cfg.bases.len() == before {
            return err_resp(StatusCode::NOT_FOUND, "未找到该基座").into_response();
        }
    }
    if let Err(e) = save_and_sync(&state).await {
        return e.into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

async fn reconnect_base(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    {
        let mut cfg = state.config.write().await;
        if let Some(b) = cfg.bases.iter_mut().find(|b| b.id == id) {
            b.enabled = true;
        }
    }
    if let Err(e) = state.ssh.reconnect_base(&id).await {
        return err_resp(StatusCode::NOT_FOUND, e.to_string()).into_response();
    }
    let cfg = state.config.read().await.clone();
    let _ = config::save(&state.config_path, &cfg);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    Json(build_state_payload(&state).await).into_response()
}

async fn disconnect_base(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    {
        let mut cfg = state.config.write().await;
        if let Some(b) = cfg.bases.iter_mut().find(|b| b.id == id) {
            b.enabled = false;
        }
    }
    if let Err(e) = state.ssh.disconnect_base(&id).await {
        return err_resp(StatusCode::NOT_FOUND, e.to_string()).into_response();
    }
    let cfg = state.config.read().await.clone();
    let _ = config::save(&state.config_path, &cfg);
    Json(build_state_payload(&state).await).into_response()
}

#[derive(Deserialize)]
struct MachineInput {
    name: String,
    #[serde(default)]
    note: String,
    base_id: String,
    default_target_host: String,
}

async fn create_machine(
    State(state): State<AppState>,
    Json(input): Json<MachineInput>,
) -> impl IntoResponse {
    if input.name.trim().is_empty() {
        return err_resp(StatusCode::BAD_REQUEST, "机器名称不能为空").into_response();
    }
    {
        let mut cfg = state.config.write().await;
        if !cfg.bases.iter().any(|b| b.id == input.base_id) {
            return err_resp(StatusCode::BAD_REQUEST, "选择的隧道基座不存在").into_response();
        }
        let id = format!("mach-{}", &Uuid::new_v4().to_string()[..8]);
        cfg.machines.push(Machine {
            id,
            name: input.name.trim().to_string(),
            note: input.note.trim().to_string(),
            base_id: input.base_id,
            default_target_host: input.default_target_host.trim().to_string(),
        });
    }
    if let Err(e) = save_and_sync(&state).await {
        return e.into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

async fn update_machine(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<MachineInput>,
) -> impl IntoResponse {
    {
        let mut cfg = state.config.write().await;
        if !cfg.bases.iter().any(|b| b.id == input.base_id) {
            return err_resp(StatusCode::BAD_REQUEST, "选择的隧道基座不存在").into_response();
        }
        let Some(m) = cfg.machines.iter_mut().find(|m| m.id == id) else {
            return err_resp(StatusCode::NOT_FOUND, "未找到该机器").into_response();
        };
        m.name = input.name.trim().to_string();
        m.note = input.note.trim().to_string();
        m.base_id = input.base_id;
        m.default_target_host = input.default_target_host.trim().to_string();
    }
    if let Err(e) = save_and_sync(&state).await {
        return e.into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

async fn delete_machine(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    {
        let mut cfg = state.config.write().await;
        let before = cfg.machines.len();
        cfg.machines.retain(|m| m.id != id);
        if cfg.machines.len() == before {
            return err_resp(StatusCode::NOT_FOUND, "未找到该机器").into_response();
        }
        cfg.rules.retain(|r| r.machine_id != id);
    }
    if let Err(e) = save_and_sync(&state).await {
        return e.into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

#[derive(Deserialize)]
struct RuleInput {
    machine_id: String,
    name: String,
    #[serde(default = "default_proto")]
    protocol: String,
    #[serde(default = "default_lh")]
    local_host: String,
    local_port: u16,
    target_host: String,
    target_port: u16,
    #[serde(default)]
    url_path: String,
    #[serde(default)]
    ssh_username: Option<String>,
    #[serde(default)]
    ssh_auth_type: Option<AuthType>,
    #[serde(default)]
    ssh_password: Option<String>,
    #[serde(default)]
    clear_ssh_password: bool,
    #[serde(default)]
    ssh_key_path: Option<String>,
    #[serde(default)]
    ssh_key_passphrase: Option<String>,
    #[serde(default)]
    clear_ssh_key_passphrase: bool,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    pinned: bool,
}

fn default_proto() -> String {
    "tcp".to_string()
}

fn default_lh() -> String {
    "127.0.0.1".to_string()
}

async fn create_rule(
    State(state): State<AppState>,
    Json(input): Json<RuleInput>,
) -> impl IntoResponse {
    if input.name.trim().is_empty() || input.target_host.trim().is_empty() || input.target_port == 0
    {
        return err_resp(StatusCode::BAD_REQUEST, "请填写完整的服务名称和目标地址/端口")
            .into_response();
    }
    let local_host = if input.local_host.trim().is_empty() {
        "127.0.0.1".to_string()
    } else {
        input.local_host.trim().to_string()
    };

    let protocol = input.protocol.trim().to_lowercase();
    let url_path = if protocol == "http" || protocol == "https" {
        config::normalize_url_path(&input.url_path)
    } else {
        String::new()
    };

    let (ssh_username, ssh_auth_type, ssh_password, ssh_key_path, ssh_key_passphrase) =
        if protocol == "ssh" {
            (
                input
                    .ssh_username
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                input.ssh_auth_type,
                input.ssh_password.filter(|s| !s.is_empty()),
                input
                    .ssh_key_path
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                input.ssh_key_passphrase.filter(|s| !s.is_empty()),
            )
        } else {
            (None, None, None, None, None)
        };

    {
        let mut cfg = state.config.write().await;
        if !cfg.machines.iter().any(|m| m.id == input.machine_id) {
            return err_resp(StatusCode::BAD_REQUEST, "所属机器不存在").into_response();
        }
        if let Err(e) = cfg.validate_no_port_conflict(&local_host, input.local_port, None) {
            return err_resp(StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
        let id = format!("rule-{}", &Uuid::new_v4().to_string()[..8]);
        cfg.rules.push(ForwardRule {
            id,
            machine_id: input.machine_id,
            name: input.name.trim().to_string(),
            protocol,
            local_host,
            local_port: input.local_port,
            target_host: input.target_host.trim().to_string(),
            target_port: input.target_port,
            url_path,
            ssh_username,
            ssh_auth_type,
            ssh_password,
            ssh_key_path,
            ssh_key_passphrase,
            enabled: input.enabled,
            pinned: input.pinned,
        });
    }
    if let Err(e) = save_and_sync(&state).await {
        return e.into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<RuleInput>,
) -> impl IntoResponse {
    let local_host = if input.local_host.trim().is_empty() {
        "127.0.0.1".to_string()
    } else {
        input.local_host.trim().to_string()
    };
    let protocol = input.protocol.trim().to_lowercase();
    let url_path = if protocol == "http" || protocol == "https" {
        config::normalize_url_path(&input.url_path)
    } else {
        String::new()
    };

    {
        let mut cfg = state.config.write().await;
        if !cfg.machines.iter().any(|m| m.id == input.machine_id) {
            return err_resp(StatusCode::BAD_REQUEST, "所属机器不存在").into_response();
        }
        if let Err(e) = cfg.validate_no_port_conflict(&local_host, input.local_port, Some(&id)) {
            return err_resp(StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
        let Some(r) = cfg.rules.iter_mut().find(|r| r.id == id) else {
            return err_resp(StatusCode::NOT_FOUND, "未找到该映射规则").into_response();
        };
        r.machine_id = input.machine_id;
        r.name = input.name.trim().to_string();
        r.protocol = protocol.clone();
        r.local_host = local_host;
        r.local_port = input.local_port;
        r.target_host = input.target_host.trim().to_string();
        r.target_port = input.target_port;
        r.url_path = url_path;
        r.enabled = input.enabled;
        r.pinned = input.pinned;

        if protocol == "ssh" {
            r.ssh_username = input
                .ssh_username
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            if input.ssh_auth_type.is_some() {
                r.ssh_auth_type = input.ssh_auth_type;
            }
            if input.clear_ssh_password {
                r.ssh_password = None;
            } else if let Some(pwd) = input.ssh_password {
                if !pwd.is_empty() {
                    r.ssh_password = Some(pwd);
                }
            }
            r.ssh_key_path = input
                .ssh_key_path
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            if input.clear_ssh_key_passphrase {
                r.ssh_key_passphrase = None;
            } else if let Some(pp) = input.ssh_key_passphrase {
                if !pp.is_empty() {
                    r.ssh_key_passphrase = Some(pp);
                }
            }
        } else {
            r.ssh_username = None;
            r.ssh_auth_type = None;
            r.ssh_password = None;
            r.ssh_key_path = None;
            r.ssh_key_passphrase = None;
        }
    }

    if let Err(e) = save_and_sync(&state).await {
        return e.into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

async fn delete_rule(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    {
        let mut cfg = state.config.write().await;
        let before = cfg.rules.len();
        cfg.rules.retain(|r| r.id != id);
        if cfg.rules.len() == before {
            return err_resp(StatusCode::NOT_FOUND, "未找到该映射规则").into_response();
        }
    }
    if let Err(e) = save_and_sync(&state).await {
        return e.into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

#[derive(Deserialize)]
struct ToggleBody {
    enabled: Option<bool>,
}

async fn toggle_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<ToggleBody>>,
) -> impl IntoResponse {
    {
        let mut cfg = state.config.write().await;
        let Some(r) = cfg.rules.iter_mut().find(|r| r.id == id) else {
            return err_resp(StatusCode::NOT_FOUND, "未找到该映射规则").into_response();
        };
        r.enabled = body
            .and_then(|b| b.enabled)
            .unwrap_or(!r.enabled);
    }
    if let Err(e) = save_and_sync(&state).await {
        return e.into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

async fn pin_rule(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    {
        let mut cfg = state.config.write().await;
        let Some(r) = cfg.rules.iter_mut().find(|r| r.id == id) else {
            return err_resp(StatusCode::NOT_FOUND, "未找到该映射规则").into_response();
        };
        r.pinned = !r.pinned;
    }
    if let Err(e) = save_and_sync(&state).await {
        return e.into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

async fn probe_rule_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let (rule, base_id) = {
        let cfg = state.config.read().await;
        let Some(r) = cfg.rules.iter().find(|r| r.id == id).cloned() else {
            return err_resp(StatusCode::NOT_FOUND, "未找到该映射规则").into_response();
        };
        let base_id = cfg
            .machines
            .iter()
            .find(|m| m.id == r.machine_id)
            .map(|m| m.base_id.clone())
            .unwrap_or_default();
        (r, base_id)
    };
    let res = state.forwarder.probe_rule(&base_id, &rule).await;
    Json(res).into_response()
}

#[derive(Deserialize, Default)]
struct OpenSshBody {
    #[serde(default)]
    terminal_kind: Option<String>,
}

async fn open_ssh_terminal(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<OpenSshBody>>,
) -> impl IntoResponse {
    let req_kind = body
        .and_then(|b| b.0.terminal_kind)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if let Some(ref k) = req_kind {
        if !ssh_terminal::is_valid_terminal_kind(k) {
            return err_resp(StatusCode::BAD_REQUEST, format!("不支持的 SSH 终端类型: {k}"))
                .into_response();
        }
    }

    let (spec, mut term_cfg, ui_port) = {
        let cfg = state.config.read().await;
        let Some(r) = cfg.rules.iter().find(|r| r.id == id) else {
            return err_resp(StatusCode::NOT_FOUND, "未找到该映射规则").into_response();
        };
        let spec = ssh_terminal::build_connection_spec(&cfg, r);
        (spec, cfg.ssh_terminal.clone(), cfg.ui_port)
    };

    if let Some(k) = req_kind {
        if k != term_cfg.kind {
            term_cfg.kind = k;
            term_cfg.custom_path.clear();
            term_cfg.custom_args.clear();
        }
    }

    let askpass = state.askpass.clone();
    let res = tokio::task::spawn_blocking(move || {
        ssh_terminal::launch_ssh_terminal(&spec, &term_cfg, Some((&askpass, ui_port)))
    })
    .await;

    match res {
        Ok(Ok(info)) => Json(serde_json::json!({
            "ok": true,
            "terminal_id": info.terminal_id,
            "terminal_name": info.terminal_name,
            "command": info.display_command,
        }))
        .into_response(),
        Ok(Err(e)) => err_resp(StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct BatchBody {
    action: String,
    #[serde(default)]
    machine_id: Option<String>,
}

async fn batch_rules(
    State(state): State<AppState>,
    Json(body): Json<BatchBody>,
) -> impl IntoResponse {
    {
        let mut cfg = state.config.write().await;
        match body.action.as_str() {
            "enable_all" => cfg.rules.iter_mut().for_each(|r| r.enabled = true),
            "disable_all" => cfg.rules.iter_mut().for_each(|r| r.enabled = false),
            "enable_machine" => {
                let mid = body.machine_id.as_deref().unwrap_or("");
                cfg.rules
                    .iter_mut()
                    .filter(|r| r.machine_id == mid)
                    .for_each(|r| r.enabled = true);
            }
            "disable_machine" => {
                let mid = body.machine_id.as_deref().unwrap_or("");
                cfg.rules
                    .iter_mut()
                    .filter(|r| r.machine_id == mid)
                    .for_each(|r| r.enabled = false);
            }
            _ => return err_resp(StatusCode::BAD_REQUEST, "未知批量操作").into_response(),
        }
    }
    if let Err(e) = save_and_sync(&state).await {
        return e.into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

async fn list_uu_windows() -> impl IntoResponse {
    let wins = tokio::task::spawn_blocking(uu_window::list_uu_windows)
        .await
        .unwrap_or_default();
    Json(wins)
}

async fn hide_uu_window(Path(hwnd): Path<isize>) -> impl IntoResponse {
    let ok = tokio::task::spawn_blocking(move || uu_window::hide_window(hwnd))
        .await
        .unwrap_or(false);
    let wins = tokio::task::spawn_blocking(uu_window::list_uu_windows)
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "ok": ok, "windows": wins }))
}

async fn show_uu_window(Path(hwnd): Path<isize>) -> impl IntoResponse {
    let ok = tokio::task::spawn_blocking(move || uu_window::show_window(hwnd))
        .await
        .unwrap_or(false);
    let wins = tokio::task::spawn_blocking(uu_window::list_uu_windows)
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "ok": ok, "windows": wins }))
}

async fn hide_uu_portmap() -> impl IntoResponse {
    let count = tokio::task::spawn_blocking(uu_window::hide_portmap_windows)
        .await
        .unwrap_or(0);
    let wins = tokio::task::spawn_blocking(uu_window::list_uu_windows)
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "hidden_count": count, "windows": wins }))
}

async fn show_all_uu() -> impl IntoResponse {
    let count = tokio::task::spawn_blocking(uu_window::restore_all_hidden)
        .await
        .unwrap_or(0);
    let wins = tokio::task::spawn_blocking(uu_window::list_uu_windows)
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "restored_count": count, "windows": wins }))
}

#[derive(Deserialize)]
struct AutostartBody {
    enabled: bool,
}

async fn set_autostart(
    State(state): State<AppState>,
    Json(body): Json<AutostartBody>,
) -> impl IntoResponse {
    let res = tokio::task::spawn_blocking(move || autostart::set_enabled(body.enabled)).await;
    match res {
        Ok(Ok(())) => Json(build_state_payload(&state).await).into_response(),
        Ok(Err(e)) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn set_auto_hide_uu(
    State(state): State<AppState>,
    Json(body): Json<AutostartBody>,
) -> impl IntoResponse {
    {
        let mut cfg = state.config.write().await;
        cfg.auto_hide_uu = body.enabled;
    }
    state.ssh.set_auto_hide_uu(body.enabled);
    if body.enabled {
        let ready_any = {
            let snaps = state.ssh.snapshot_all().await;
            snaps
                .values()
                .any(|s| s.status == crate::ssh_engine::BaseStatus::Connected)
        };
        if ready_any {
            let _ = tokio::task::spawn_blocking(uu_window::hide_portmap_windows).await;
        }
    }
    if let Err(e) = save_and_sync(&state).await {
        return e.into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

#[derive(Deserialize)]
struct SshTerminalBody {
    kind: String,
    #[serde(default)]
    custom_path: String,
    #[serde(default)]
    custom_args: String,
}

async fn list_ssh_terminals(State(state): State<AppState>) -> impl IntoResponse {
    let selected = state.config.read().await.ssh_terminal.clone();
    let terminals = tokio::task::spawn_blocking(ssh_terminal::detect_terminals)
        .await
        .unwrap_or_default();
    Json(serde_json::json!({
        "selected": selected,
        "terminals": terminals,
    }))
}

async fn set_ssh_terminal(
    State(state): State<AppState>,
    Json(body): Json<SshTerminalBody>,
) -> impl IntoResponse {
    let kind = body.kind.trim().to_string();
    if !ssh_terminal::is_valid_terminal_kind(&kind) {
        return err_resp(StatusCode::BAD_REQUEST, format!("不支持的 SSH 终端类型: {kind}"))
            .into_response();
    }
    let custom_path = body.custom_path.trim().to_string();
    let custom_args = body.custom_args.trim().to_string();
    if kind == "custom" && custom_path.is_empty() {
        return err_resp(StatusCode::BAD_REQUEST, "自定义 SSH 终端路径不能为空")
            .into_response();
    }

    let cfg_snapshot = {
        let mut cfg = state.config.write().await;
        cfg.ssh_terminal = config::SshTerminalConfig {
            kind,
            custom_path,
            custom_args,
        };
        cfg.clone()
    };
    if let Err(e) = config::save(&state.config_path, &cfg_snapshot) {
        return err_resp(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    Json(build_state_payload(&state).await).into_response()
}

async fn consume_askpass(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> impl IntoResponse {
    match state.askpass.consume(&token) {
        Some(secret) => (StatusCode::OK, secret).into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn open_config_dir(State(state): State<AppState>) -> impl IntoResponse {
    let p = state.config_path.clone();
    let _ = std::process::Command::new("explorer.exe")
        .arg(format!("/select,{}", p.display()))
        .spawn();
    Json(serde_json::json!({ "ok": true }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    async fn make_test_state() -> (PathBuf, CancellationToken, Arc<AskpassStore>, u16) {
        let tmp = std::env::temp_dir().join(format!("uutunnels_test_{}.json", Uuid::new_v4()));
        let cfg = AppConfig::preset();
        config::save(&tmp, &cfg).unwrap();

        let root = CancellationToken::new();
        let ssh = Arc::new(SshEngine::new(root.clone()));
        let fwd = Arc::new(ForwarderManager::new(ssh.clone(), root.clone()));
        let askpass = Arc::new(AskpassStore::new());
        let state = AppState {
            config_path: tmp.clone(),
            config: Arc::new(RwLock::new(cfg)),
            ssh,
            forwarder: fwd,
            askpass: askpass.clone(),
            ui_boot_id: "boot-test-1".to_string(),
            ui_reload_seq: Arc::new(AtomicU64::new(0)),
        };
        let app = build_router(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (tmp, root, askpass, port)
    }

    #[tokio::test]
    async fn api_state_and_toggle_smoke() {
        let (tmp, root, _askpass, port) = make_test_state().await;

        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        s.write_all(b"GET /api/state HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).await.unwrap();
        assert!(buf.contains("200 OK"));
        assert!(buf.contains("linux-host"));
        assert!(buf.contains("lan-nas"));
        assert!(buf.contains("auto_hide_uu"));
        assert!(buf.contains("ssh_terminal"));
        assert!(buf.contains("effective_ssh_username"));
        assert!(buf.contains("rx_bps"));
        assert!(buf.contains("pinned"));
        assert!(buf.contains("url_path"));

        root.cancel();
        let _ = std::fs::remove_file(&tmp);
    }

    async fn send_http_json(
        port: u16,
        method: &str,
        path: &str,
        body: &str,
    ) -> String {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let req = format!(
            "{method} {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).await.unwrap();
        buf
    }

    #[tokio::test]
    async fn api_rule_url_path_create_and_update() {
        let (tmp, root, _askpass, port) = make_test_state().await;

        let update_body = serde_json::json!({
            "machine_id": "linux-host",
            "name": "管理面板示例 (HTTPS)",
            "protocol": "https",
            "local_host": "127.0.0.1",
            "local_port": 8443,
            "target_host": "127.0.0.1",
            "target_port": 8443,
            "url_path": "43235a23",
            "enabled": false,
            "pinned": false
        })
        .to_string();
        let resp = send_http_json(port, "PUT", "/api/rules/lh-8443", &update_body).await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"url_path\":\"/43235a23\""));

        let saved = config::load_or_create(&tmp).unwrap();
        let bt = saved.rules.iter().find(|r| r.id == "lh-8443").unwrap();
        assert_eq!(bt.url_path, "/43235a23");

        let clear_body = serde_json::json!({
            "machine_id": "linux-host",
            "name": "管理面板示例 (HTTPS)",
            "protocol": "https",
            "local_host": "127.0.0.1",
            "local_port": 8443,
            "target_host": "127.0.0.1",
            "target_port": 8443,
            "url_path": "",
            "enabled": false,
            "pinned": false
        })
        .to_string();
        let resp_clear = send_http_json(port, "PUT", "/api/rules/lh-8443", &clear_body).await;
        assert!(resp_clear.contains("200 OK"));
        let saved2 = config::load_or_create(&tmp).unwrap();
        let bt2 = saved2.rules.iter().find(|r| r.id == "lh-8443").unwrap();
        assert_eq!(bt2.url_path, "");

        let ssh_body = serde_json::json!({
            "machine_id": "linux-host",
            "name": "Extra SSH",
            "protocol": "ssh",
            "local_host": "127.0.0.1",
            "local_port": 2299,
            "target_host": "127.0.0.1",
            "target_port": 22,
            "url_path": "ignored",
            "enabled": false,
            "pinned": false
        })
        .to_string();
        let resp_ssh = send_http_json(port, "POST", "/api/rules", &ssh_body).await;
        assert!(resp_ssh.contains("200 OK"));
        let saved3 = config::load_or_create(&tmp).unwrap();
        let extra = saved3.rules.iter().find(|r| r.name == "Extra SSH").unwrap();
        assert_eq!(extra.url_path, "");

        root.cancel();
        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn api_ssh_rule_credentials_and_masking() {
        let (tmp, root, _askpass, port) = make_test_state().await;

        let create_body = serde_json::json!({
            "machine_id": "lan-nas",
            "name": "NAS Admin SSH",
            "protocol": "ssh",
            "local_host": "127.0.0.1",
            "local_port": 2298,
            "target_host": "192.168.1.100",
            "target_port": 22,
            "ssh_username": "nasadmin",
            "ssh_auth_type": "password",
            "ssh_password": "secret-nas-password",
            "enabled": false,
            "pinned": false
        })
        .to_string();
        let resp = send_http_json(port, "POST", "/api/rules", &create_body).await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"ssh_username\":\"nasadmin\""));
        assert!(resp.contains("\"ssh_has_password\":true"));
        assert!(resp.contains("\"effective_ssh_username\":\"nasadmin\""));
        assert!(!resp.contains("secret-nas-password"));

        let saved = config::load_or_create(&tmp).unwrap();
        let created = saved.rules.iter().find(|r| r.name == "NAS Admin SSH").unwrap();
        assert_eq!(created.ssh_password.as_deref(), Some("secret-nas-password"));
        let rule_id = created.id.clone();

        // Empty password on PUT preserves existing password
        let preserve_body = serde_json::json!({
            "machine_id": "lan-nas",
            "name": "NAS Admin SSH",
            "protocol": "ssh",
            "local_host": "127.0.0.1",
            "local_port": 2298,
            "target_host": "192.168.1.100",
            "target_port": 22,
            "ssh_username": "nasadmin2",
            "ssh_auth_type": "password",
            "ssh_password": "",
            "enabled": false,
            "pinned": false
        })
        .to_string();
        let resp2 = send_http_json(port, "PUT", &format!("/api/rules/{rule_id}"), &preserve_body).await;
        assert!(resp2.contains("200 OK"));
        assert!(resp2.contains("\"ssh_has_password\":true"));
        let saved2 = config::load_or_create(&tmp).unwrap();
        let r2 = saved2.rules.iter().find(|r| r.id == rule_id).unwrap();
        assert_eq!(r2.ssh_username.as_deref(), Some("nasadmin2"));
        assert_eq!(r2.ssh_password.as_deref(), Some("secret-nas-password"));

        // Explicit clear removes password
        let clear_body = serde_json::json!({
            "machine_id": "lan-nas",
            "name": "NAS Admin SSH",
            "protocol": "ssh",
            "local_host": "127.0.0.1",
            "local_port": 2298,
            "target_host": "192.168.1.100",
            "target_port": 22,
            "ssh_username": "nasadmin2",
            "ssh_auth_type": "private_key",
            "clear_ssh_password": true,
            "ssh_key_path": "~/.ssh/id_ed25519",
            "ssh_key_passphrase": "key-pp",
            "enabled": false,
            "pinned": false
        })
        .to_string();
        let resp3 = send_http_json(port, "PUT", &format!("/api/rules/{rule_id}"), &clear_body).await;
        assert!(resp3.contains("200 OK"));
        assert!(resp3.contains("\"ssh_has_password\":false"));
        assert!(resp3.contains("\"ssh_has_key_passphrase\":true"));
        assert!(!resp3.contains("key-pp"));

        // Switching protocol away from ssh clears all ssh_* fields
        let tcp_body = serde_json::json!({
            "machine_id": "lan-nas",
            "name": "NAS TCP",
            "protocol": "tcp",
            "local_host": "127.0.0.1",
            "local_port": 2298,
            "target_host": "192.168.1.100",
            "target_port": 22,
            "enabled": false,
            "pinned": false
        })
        .to_string();
        let resp4 = send_http_json(port, "PUT", &format!("/api/rules/{rule_id}"), &tcp_body).await;
        assert!(resp4.contains("200 OK"));
        let saved4 = config::load_or_create(&tmp).unwrap();
        let r4 = saved4.rules.iter().find(|r| r.id == rule_id).unwrap();
        assert!(r4.ssh_username.is_none());
        assert!(r4.ssh_auth_type.is_none());
        assert!(r4.ssh_password.is_none());
        assert!(r4.ssh_key_path.is_none());
        assert!(r4.ssh_key_passphrase.is_none());

        root.cancel();
        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn api_ssh_terminals_and_askpass_endpoints() {
        let (tmp, root, askpass, port) = make_test_state().await;

        let list_resp = send_http_json(port, "GET", "/api/ssh-terminals", "").await;
        assert!(list_resp.contains("200 OK"));
        assert!(list_resp.contains("\"powershell\""));
        assert!(list_resp.contains("\"xshell\""));

        let bad_kind = send_http_json(
            port,
            "POST",
            "/api/settings/ssh-terminal",
            r#"{"kind":"unknown_term"}"#,
        )
        .await;
        assert!(bad_kind.contains("400 Bad Request"));

        let missing_custom = send_http_json(
            port,
            "POST",
            "/api/settings/ssh-terminal",
            r#"{"kind":"custom","custom_path":"","custom_args":"{host}"}"#,
        )
        .await;
        assert!(missing_custom.contains("400 Bad Request"));

        let ok_save = send_http_json(
            port,
            "POST",
            "/api/settings/ssh-terminal",
            r#"{"kind":"pwsh","custom_path":"","custom_args":""}"#,
        )
        .await;
        assert!(ok_save.contains("200 OK"));
        assert!(ok_save.contains("\"kind\":\"pwsh\""));
        let saved = config::load_or_create(&tmp).unwrap();
        assert_eq!(saved.ssh_terminal.kind, "pwsh");

        let tok = askpass.mint("my-pass-123".to_string());
        let first = send_http_json(port, "POST", &format!("/api/internal/askpass/{tok}"), "").await;
        assert!(first.contains("200 OK"));
        assert!(first.ends_with("my-pass-123"));

        let second = send_http_json(port, "POST", &format!("/api/internal/askpass/{tok}"), "").await;
        assert!(second.contains("404 Not Found"));

        root.cancel();
        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn api_ui_signal_tracks_reload_seq() {
        let tmp = std::env::temp_dir().join(format!("uutunnels_test_{}.json", Uuid::new_v4()));
        let cfg = AppConfig::preset();
        config::save(&tmp, &cfg).unwrap();

        let root = CancellationToken::new();
        let ssh = Arc::new(SshEngine::new(root.clone()));
        let fwd = Arc::new(ForwarderManager::new(ssh.clone(), root.clone()));
        let reload_seq = Arc::new(AtomicU64::new(0));
        let state = AppState {
            config_path: tmp.clone(),
            config: Arc::new(RwLock::new(cfg)),
            ssh,
            forwarder: fwd,
            askpass: Arc::new(AskpassStore::new()),
            ui_boot_id: "boot-xyz".to_string(),
            ui_reload_seq: reload_seq.clone(),
        };
        let app = build_router(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        s.write_all(b"GET /api/ui/signal HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).await.unwrap();
        assert!(buf.contains("200 OK"));
        assert!(buf.contains("\"boot_id\":\"boot-xyz\""));
        assert!(buf.contains("\"reload_seq\":0"));

        reload_seq.fetch_add(1, Ordering::SeqCst);

        let mut s2 = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        s2.write_all(b"GET /api/ui/signal HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut buf2 = String::new();
        s2.read_to_string(&mut buf2).await.unwrap();
        assert!(buf2.contains("\"reload_seq\":1"));

        let mut s3 = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        s3.write_all(b"GET /api/state HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut buf3 = String::new();
        s3.read_to_string(&mut buf3).await.unwrap();
        assert!(buf3.contains("\"ui_boot_id\":\"boot-xyz\""));
        assert!(buf3.contains("\"ui_reload_seq\":1"));

        root.cancel();
        let _ = std::fs::remove_file(&tmp);
    }
}
