use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BaseKind {
    Ssh,
    Socks5,
    Direct,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    Password,
    PrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelBase {
    pub id: String,
    pub name: String,
    pub kind: BaseKind,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_type: AuthType,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub key_passphrase: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Machine {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub note: String,
    pub base_id: String,
    pub default_target_host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardRule {
    pub id: String,
    pub machine_id: String,
    pub name: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_local_host")]
    pub local_host: String,
    pub local_port: u16,
    pub target_host: String,
    pub target_port: u16,
    #[serde(default)]
    pub url_path: String,
    #[serde(default)]
    pub ssh_username: Option<String>,
    #[serde(default)]
    pub ssh_auth_type: Option<AuthType>,
    #[serde(default)]
    pub ssh_password: Option<String>,
    #[serde(default)]
    pub ssh_key_path: Option<String>,
    #[serde(default)]
    pub ssh_key_passphrase: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub pinned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshTerminalConfig {
    #[serde(default = "default_ssh_terminal_kind")]
    pub kind: String,
    #[serde(default)]
    pub custom_path: String,
    #[serde(default)]
    pub custom_args: String,
}

fn default_ssh_terminal_kind() -> String {
    "auto".to_string()
}

impl Default for SshTerminalConfig {
    fn default() -> Self {
        Self {
            kind: default_ssh_terminal_kind(),
            custom_path: String::new(),
            custom_args: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default = "default_ui_port")]
    pub ui_port: u16,
    #[serde(default)]
    pub auto_hide_uu: bool,
    #[serde(default)]
    pub ssh_terminal: SshTerminalConfig,
    #[serde(default)]
    pub bases: Vec<TunnelBase>,
    #[serde(default)]
    pub machines: Vec<Machine>,
    #[serde(default)]
    pub rules: Vec<ForwardRule>,
}

fn default_true() -> bool {
    true
}

fn default_protocol() -> String {
    "tcp".to_string()
}

fn default_local_host() -> String {
    "127.0.0.1".to_string()
}

fn default_ui_port() -> u16 {
    17890
}

impl Default for AppConfig {
    fn default() -> Self {
        Self::preset()
    }
}

impl AppConfig {
    /// Pre-configured workspace preset for a Linux host and LAN NAS behind a single UU SSH base.
    pub fn preset() -> Self {
        let base_id = "base-linux".to_string();
        let linux_id = "linux-host".to_string();
        let nas_id = "lan-nas".to_string();

        let bases = vec![TunnelBase {
            id: base_id.clone(),
            name: "UU-Linux 基座".to_string(),
            kind: BaseKind::Ssh,
            host: "127.0.0.1".to_string(),
            port: 2201,
            username: "ubuntu".to_string(),
            auth_type: AuthType::Password,
            password: None,
            key_path: None,
            key_passphrase: None,
            enabled: true,
        }];

        let machines = vec![
            Machine {
                id: linux_id.clone(),
                name: "linux-host".to_string(),
                note: "Linux 被控端 (uu-remote-linux)".to_string(),
                base_id: base_id.clone(),
                default_target_host: "127.0.0.1".to_string(),
            },
            Machine {
                id: nas_id.clone(),
                name: "lan-nas".to_string(),
                note: "192.168.1.100 · 同局域网设备示例".to_string(),
                base_id,
                default_target_host: "192.168.1.100".to_string(),
            },
        ];

        let rules = vec![
            rule("lh-8080", &linux_id, "Web 服务示例 (HTTP)", "http", 8080, "127.0.0.1", 8080),
            rule("lh-8443", &linux_id, "管理面板示例 (HTTPS)", "https", 8443, "127.0.0.1", 8443),
            rule("lh-2202", &linux_id, "Linux SSH", "ssh", 2202, "127.0.0.1", 22),
            rule("nas-5000", &nas_id, "NAS 管理后台 (HTTP)", "http", 5000, "192.168.1.100", 5000),
            rule("nas-5001", &nas_id, "NAS 管理后台 (HTTPS)", "https", 5001, "192.168.1.100", 5001),
            rule("nas-3000", &nas_id, "内网 Git / Web 服务", "http", 3000, "192.168.1.100", 3000),
            rule("nas-2203", &nas_id, "NAS SSH", "ssh", 2203, "192.168.1.100", 22),
        ];

        Self {
            ui_port: default_ui_port(),
            auto_hide_uu: false,
            ssh_terminal: SshTerminalConfig::default(),
            bases,
            machines,
            rules,
        }
    }

    pub fn validate_no_port_conflict(
        &self,
        local_host: &str,
        local_port: u16,
        ignore_rule_id: Option<&str>,
    ) -> Result<()> {
        if local_port == 0 {
            anyhow::bail!("本地端口不能为 0");
        }
        for r in &self.rules {
            if Some(r.id.as_str()) == ignore_rule_id {
                continue;
            }
            if r.local_port == local_port && r.local_host == local_host {
                anyhow::bail!("本地端口 {local_host}:{local_port} 已被规则「{}」使用", r.name);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn unique_local_ports(&self) -> bool {
        let mut seen = HashSet::new();
        self.rules
            .iter()
            .all(|r| seen.insert((r.local_host.clone(), r.local_port)))
    }
}

/// Normalizes an optional HTTP/HTTPS URL path/query/fragment suffix.
pub fn normalize_url_path(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|&c| c != '\r' && c != '\n')
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with('/') || trimmed.starts_with('?') || trimmed.starts_with('#') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn rule(
    id: &str,
    machine_id: &str,
    name: &str,
    protocol: &str,
    local_port: u16,
    target_host: &str,
    target_port: u16,
) -> ForwardRule {
    ForwardRule {
        id: id.to_string(),
        machine_id: machine_id.to_string(),
        name: name.to_string(),
        protocol: protocol.to_string(),
        local_host: "127.0.0.1".to_string(),
        local_port,
        target_host: target_host.to_string(),
        target_port,
        url_path: String::new(),
        ssh_username: None,
        ssh_auth_type: None,
        ssh_password: None,
        ssh_key_path: None,
        ssh_key_passphrase: None,
        enabled: false,
        pinned: false,
    }
}

pub fn default_config_path() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("uuTunnels").join("config.json")
}

pub fn load_or_create(path: &Path) -> Result<AppConfig> {
    if path.exists() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置文件失败: {}", path.display()))?;
        let cfg: AppConfig = serde_json::from_str(&raw)
            .with_context(|| format!("解析配置文件失败: {}", path.display()))?;
        return Ok(cfg);
    }
    let cfg = AppConfig::preset();
    save(path, &cfg)?;
    Ok(cfg)
}

pub fn save(path: &Path, cfg: &AppConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("创建配置目录失败: {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(cfg)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)
        .with_context(|| format!("写入临时配置文件失败: {}", tmp.display()))?;
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("保存配置文件失败: {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_contains_all_expected_services_without_port_conflicts() {
        let cfg = AppConfig::preset();
        assert_eq!(cfg.bases.len(), 1);
        assert_eq!(cfg.machines.len(), 2);
        assert_eq!(cfg.rules.len(), 7);

        let linux_ports: Vec<u16> = cfg
            .rules
            .iter()
            .filter(|r| r.machine_id == "linux-host")
            .map(|r| r.target_port)
            .collect();
        assert_eq!(linux_ports, vec![8080, 8443, 22]);

        let nas_ports: Vec<u16> = cfg
            .rules
            .iter()
            .filter(|r| r.machine_id == "lan-nas")
            .map(|r| r.target_port)
            .collect();
        assert_eq!(nas_ports, vec![5000, 5001, 3000, 22]);

        assert!(cfg.unique_local_ports());
        assert!(cfg.rules.iter().all(|r| !r.enabled));
    }

    #[test]
    fn legacy_config_without_new_fields_deserializes() {
        let legacy_json = r#"{
            "ui_port": 17890,
            "bases": [],
            "machines": [],
            "rules": [{
                "id": "r1",
                "machine_id": "m1",
                "name": "Web App",
                "protocol": "http",
                "local_host": "127.0.0.1",
                "local_port": 8081,
                "target_host": "127.0.0.1",
                "target_port": 8081,
                "enabled": true
            }]
        }"#;
        let cfg: AppConfig = serde_json::from_str(legacy_json).unwrap();
        assert!(!cfg.auto_hide_uu);
        assert_eq!(cfg.ssh_terminal, SshTerminalConfig::default());
        assert!(!cfg.rules[0].pinned);
        assert!(cfg.rules[0].enabled);
        assert!(cfg.rules[0].url_path.is_empty());
        assert!(cfg.rules[0].ssh_username.is_none());
        assert!(cfg.rules[0].ssh_auth_type.is_none());
        assert!(cfg.rules[0].ssh_password.is_none());
        assert!(cfg.rules[0].ssh_key_path.is_none());
        assert!(cfg.rules[0].ssh_key_passphrase.is_none());
    }

    #[test]
    fn ssh_terminal_and_rule_credentials_roundtrip() {
        let mut cfg = AppConfig::preset();
        cfg.ssh_terminal = SshTerminalConfig {
            kind: "xshell".to_string(),
            custom_path: r"D:\Portable\Xshell.exe".to_string(),
            custom_args: "-p {port} {target}".to_string(),
        };
        let ssh_rule = cfg.rules.iter_mut().find(|r| r.protocol == "ssh").unwrap();
        ssh_rule.ssh_username = Some("admin".to_string());
        ssh_rule.ssh_auth_type = Some(AuthType::PrivateKey);
        ssh_rule.ssh_password = None;
        ssh_rule.ssh_key_path = Some("~/.ssh/id_ed25519".to_string());
        ssh_rule.ssh_key_passphrase = Some("pass123".to_string());

        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.ssh_terminal, cfg.ssh_terminal);
        let decoded_rule = decoded.rules.iter().find(|r| r.protocol == "ssh").unwrap();
        assert_eq!(decoded_rule.ssh_username.as_deref(), Some("admin"));
        assert_eq!(decoded_rule.ssh_auth_type, Some(AuthType::PrivateKey));
        assert!(decoded_rule.ssh_password.is_none());
        assert_eq!(
            decoded_rule.ssh_key_path.as_deref(),
            Some("~/.ssh/id_ed25519")
        );
        assert_eq!(decoded_rule.ssh_key_passphrase.as_deref(), Some("pass123"));
    }

    #[test]
    fn normalize_url_path_handles_variants() {
        assert_eq!(normalize_url_path(""), "");
        assert_eq!(normalize_url_path("   "), "");
        assert_eq!(normalize_url_path("43235a23"), "/43235a23");
        assert_eq!(normalize_url_path("/43235a23"), "/43235a23");
        assert_eq!(normalize_url_path("/43235a23/"), "/43235a23/");
        assert_eq!(normalize_url_path("admin/login?a=1"), "/admin/login?a=1");
        assert_eq!(normalize_url_path("?token=abc"), "?token=abc");
        assert_eq!(normalize_url_path("#/dashboard"), "#/dashboard");
        assert_eq!(
            normalize_url_path("43235a23\r\nX-Inject: 1"),
            "/43235a23X-Inject: 1"
        );
    }
}
