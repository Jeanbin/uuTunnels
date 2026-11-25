use crate::config::{AppConfig, AuthType, BaseKind, ForwardRule, SshTerminalConfig};
use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CLASSES_ROOT,
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    REG_EXPAND_SZ, REG_SZ,
};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
const ASKPASS_TTL: Duration = Duration::from_secs(30);

const VALID_TERMINAL_KINDS: &[&str] = &[
    "auto",
    "xshell",
    "mobaxterm",
    "putty",
    "kitty",
    "securecrt",
    "electerm",
    "wt",
    "pwsh",
    "powershell",
    "cmd",
    "git_bash",
    "ssh_uri",
    "custom",
];

#[derive(Debug, Clone, Serialize)]
pub struct SshTerminalInfo {
    pub id: String,
    pub name: String,
    pub category: String,
    pub detected: bool,
    pub executable: Option<String>,
    pub supports_password: bool,
    pub supports_key: bool,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct SshConnectionSpec {
    pub title: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub auth_type: AuthType,
    pub password: Option<String>,
    pub key_path: Option<String>,
    pub key_passphrase: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LaunchResult {
    pub terminal_id: String,
    pub terminal_name: String,
    pub display_command: String,
}

struct AskpassEntry {
    secret: String,
    expires_at: Instant,
}

pub struct AskpassStore {
    entries: Mutex<HashMap<String, AskpassEntry>>,
}

impl Default for AskpassStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AskpassStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn mint(&self, secret: String) -> String {
        let now = Instant::now();
        let token = Uuid::new_v4().simple().to_string();
        let mut map = self.entries.lock().unwrap();
        map.retain(|_, v| v.expires_at > now);
        map.insert(
            token.clone(),
            AskpassEntry {
                secret,
                expires_at: now + ASKPASS_TTL,
            },
        );
        token
    }

    pub fn consume(&self, token: &str) -> Option<String> {
        let now = Instant::now();
        let mut map = self.entries.lock().unwrap();
        map.retain(|_, v| v.expires_at > now);
        map.remove(token).map(|entry| entry.secret)
    }
}

/// Handles `SSH_ASKPASS` invocation when `uuTunnels.exe` is launched by OpenSSH
/// with `UUTUNNELS_ASKPASS_TOKEN` and `UUTUNNELS_ASKPASS_PORT` set.
/// Must run before tracing/config/Tokio/tray initialization so stdout stays clean.
pub fn try_run_askpass_mode() -> Option<i32> {
    let token = std::env::var("UUTUNNELS_ASKPASS_TOKEN").ok()?;
    let port_raw = std::env::var("UUTUNNELS_ASKPASS_PORT").ok()?;
    let token = token.trim();
    let port_raw = port_raw.trim();
    if token.is_empty() || port_raw.is_empty() {
        return None;
    }

    let Ok(port) = port_raw.parse::<u16>() else {
        return Some(1);
    };

    if let Some(prompt) = std::env::args().nth(1) {
        let lower = prompt.to_lowercase();
        if lower.contains("continue connecting")
            || lower.contains("(yes/no")
            || lower.contains("fingerprint")
        {
            return Some(1);
        }
    }

    if !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Some(1);
    }

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return Some(1);
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    let req = format!(
        "POST /api/internal/askpass/{token} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return Some(1);
    }

    let mut resp = Vec::new();
    if stream.read_to_end(&mut resp).is_err() {
        return Some(1);
    }

    let Some(sep_idx) = resp.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Some(1);
    };
    let head = std::str::from_utf8(&resp[..sep_idx]).ok()?;
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") {
        return Some(1);
    }

    let body = &resp[sep_idx + 4..];
    let mut stdout = std::io::stdout().lock();
    if stdout.write_all(body).is_err() {
        return Some(1);
    }
    if !body.ends_with(b"\n") && stdout.write_all(b"\n").is_err() {
        return Some(1);
    }
    if stdout.flush().is_err() {
        return Some(1);
    }
    Some(0)
}

pub fn is_valid_terminal_kind(kind: &str) -> bool {
    VALID_TERMINAL_KINDS.contains(&kind)
}

pub fn resolve_effective_ssh_username(cfg: &AppConfig, rule: &ForwardRule) -> Option<String> {
    if let Some(u) = rule.ssh_username.as_deref() {
        let trimmed = u.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    if rule.target_host == "127.0.0.1" || rule.target_host.eq_ignore_ascii_case("localhost") {
        let machine = cfg.machines.iter().find(|m| m.id == rule.machine_id)?;
        let base = cfg.bases.iter().find(|b| b.id == machine.base_id)?;
        if base.kind == BaseKind::Ssh {
            let u = base.username.trim();
            if !u.is_empty() {
                return Some(u.to_string());
            }
        }
    }

    None
}

pub fn build_connection_spec(cfg: &AppConfig, rule: &ForwardRule) -> SshConnectionSpec {
    let username = resolve_effective_ssh_username(cfg, rule);
    let auth_type = rule.ssh_auth_type.clone().unwrap_or_else(|| {
        if rule
            .ssh_key_path
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
        {
            AuthType::PrivateKey
        } else {
            AuthType::Password
        }
    });

    let (password, key_path, key_passphrase) = match auth_type {
        AuthType::Password => (
            rule.ssh_password
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(ToString::to_string),
            None,
            None,
        ),
        AuthType::PrivateKey => (
            None,
            rule.ssh_key_path
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(expand_tilde_path),
            rule.ssh_key_passphrase
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(ToString::to_string),
        ),
    };

    let host = {
        let h = rule.local_host.trim();
        if h.is_empty() {
            "127.0.0.1".to_string()
        } else {
            h.to_string()
        }
    };
    let title = {
        let t = rule.name.trim();
        if t.is_empty() {
            format!("{}:{}", host, rule.local_port)
        } else {
            t.to_string()
        }
    };

    SshConnectionSpec {
        title,
        host,
        port: rule.local_port,
        username,
        auth_type,
        password,
        key_path,
        key_passphrase,
    }
}

pub fn expand_tilde_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed == "~" {
        return dirs::home_dir()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|| "~".to_string());
    }
    if let Some(rest) = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix("~\\"))
    {
        if let Some(home) = dirs::home_dir() {
            let mut pb = home;
            for part in rest.split(['/', '\\']) {
                if !part.is_empty() {
                    pb.push(part);
                }
            }
            return pb.to_string_lossy().into_owned();
        }
    }
    trimmed.to_string()
}

pub fn percent_encode_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn win_to_mobaxterm_path(path: &str) -> String {
    let trimmed = path.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let rest = trimmed[2..].replace('\\', "/");
        if rest.starts_with('/') {
            format!("/drives/{drive}{rest}")
        } else if rest.is_empty() {
            format!("/drives/{drive}")
        } else {
            format!("/drives/{drive}/{rest}")
        }
    } else {
        trimmed.replace('\\', "/")
    }
}

pub fn win_to_git_bash_path(path: &str) -> String {
    let trimmed = path.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        let rest = trimmed[2..].replace('\\', "/");
        if rest.starts_with('/') {
            format!("/{drive}{rest}")
        } else if rest.is_empty() {
            format!("/{drive}")
        } else {
            format!("/{drive}/{rest}")
        }
    } else {
        trimmed.replace('\\', "/")
    }
}

pub fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

pub fn encode_powershell_command(script: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn wt_escape_arg(s: &str) -> String {
    s.replace(';', r"\;")
}

pub fn build_wt_launch_args(
    title: &str,
    ssh_args: &[String],
    askpass: Option<(&str, &str, u16)>,
) -> Vec<String> {
    if let Some((askpass_exe, token, ui_port)) = askpass {
        let ps_args = ssh_args
            .iter()
            .map(|a| ps_single_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        let ps_cmd = format!(
            "$env:SSH_ASKPASS = {}; $env:SSH_ASKPASS_REQUIRE = 'force'; $env:DISPLAY = ':0'; $env:UUTUNNELS_ASKPASS_TOKEN = {}; $env:UUTUNNELS_ASKPASS_PORT = {}; & ssh {}; $code = $LASTEXITCODE; Remove-Item Env:SSH_ASKPASS,Env:SSH_ASKPASS_REQUIRE,Env:DISPLAY,Env:UUTUNNELS_ASKPASS_TOKEN,Env:UUTUNNELS_ASKPASS_PORT -ErrorAction SilentlyContinue; if ($code -ne 0) {{ Read-Host 'SSH 已退出 (按回车关闭)' }}",
            ps_single_quote(askpass_exe),
            ps_single_quote(token),
            ps_single_quote(&ui_port.to_string()),
            ps_args,
        );
        let encoded = encode_powershell_command(&ps_cmd);
        vec![
            "new-tab".to_string(),
            "--title".to_string(),
            wt_escape_arg(title),
            "powershell.exe".to_string(),
            "-NoLogo".to_string(),
            "-NoProfile".to_string(),
            "-EncodedCommand".to_string(),
            encoded,
        ]
    } else {
        let mut args = vec![
            "new-tab".to_string(),
            "--title".to_string(),
            wt_escape_arg(title),
            "ssh".to_string(),
        ];
        args.extend(ssh_args.iter().map(|a| wt_escape_arg(a)));
        args
    }
}

pub fn posix_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub fn short_path_if_spaces(path: &Path) -> String {
    let s = path.to_string_lossy().into_owned();
    if !s.chars().any(char::is_whitespace) {
        return s;
    }
    let wide = to_wide(&s);
    let required = unsafe { GetShortPathNameW(wide.as_ptr(), std::ptr::null_mut(), 0) };
    if required == 0 {
        return s;
    }
    let mut buf = vec![0u16; required as usize];
    let written = unsafe { GetShortPathNameW(wide.as_ptr(), buf.as_mut_ptr(), required) };
    if written == 0 || written >= required {
        return s;
    }
    String::from_utf16_lossy(&buf[..written as usize])
}

/// Splits a custom CLI argument template by whitespace, respecting single and double quotes
/// without modifying backslashes in Windows paths.
pub fn split_arg_template(template: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut in_double = false;
    let mut in_single = false;
    let mut has_token = false;

    for ch in template.chars() {
        if in_double {
            if ch == '"' {
                in_double = false;
            } else {
                cur.push(ch);
            }
        } else if in_single {
            if ch == '\'' {
                in_single = false;
            } else {
                cur.push(ch);
            }
        } else if ch == '"' {
            in_double = true;
            has_token = true;
        } else if ch == '\'' {
            in_single = true;
            has_token = true;
        } else if ch.is_whitespace() {
            if has_token {
                args.push(std::mem::take(&mut cur));
                has_token = false;
            }
        } else {
            cur.push(ch);
            has_token = true;
        }
    }
    if has_token {
        args.push(cur);
    }
    args
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

struct RegKey(HKEY);

impl Drop for RegKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
}

impl RegKey {
    fn open(root: HKEY, subkey: &str, sam: u32) -> Option<Self> {
        let wide = to_wide(subkey);
        let mut hkey: HKEY = std::ptr::null_mut();
        let status = unsafe { RegOpenKeyExW(root, wide.as_ptr(), 0, sam, &mut hkey) };
        if status == ERROR_SUCCESS && !hkey.is_null() {
            Some(Self(hkey))
        } else {
            None
        }
    }

    fn read_string(&self, value_name: Option<&str>) -> Option<String> {
        let name_wide = value_name.map(to_wide);
        let ptr = name_wide
            .as_ref()
            .map(|v| v.as_ptr())
            .unwrap_or(std::ptr::null());
        let mut reg_type: u32 = 0;
        let mut bytes: u32 = 0;
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                ptr,
                std::ptr::null_mut(),
                &mut reg_type,
                std::ptr::null_mut(),
                &mut bytes,
            )
        };
        if status != ERROR_SUCCESS || bytes == 0 {
            return None;
        }
        if reg_type != REG_SZ && reg_type != REG_EXPAND_SZ {
            return None;
        }
        let u16_len = (bytes as usize).div_ceil(2);
        let mut buf = vec![0u16; u16_len];
        let status2 = unsafe {
            RegQueryValueExW(
                self.0,
                ptr,
                std::ptr::null_mut(),
                &mut reg_type,
                buf.as_mut_ptr() as *mut u8,
                &mut bytes,
            )
        };
        if status2 != ERROR_SUCCESS {
            return None;
        }
        let actual_u16 = (bytes as usize) / 2;
        let slice = &buf[..actual_u16.min(buf.len())];
        let trimmed_end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        let raw = String::from_utf16_lossy(&slice[..trimmed_end]);
        let expanded = expand_env_vars(&raw);
        let s = expanded.trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    fn enum_subkeys(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut idx: u32 = 0;
        loop {
            let mut buf = [0u16; 256];
            let mut len = buf.len() as u32;
            let status = unsafe {
                RegEnumKeyExW(
                    self.0,
                    idx,
                    buf.as_mut_ptr(),
                    &mut len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if status != ERROR_SUCCESS {
                break;
            }
            out.push(String::from_utf16_lossy(&buf[..len as usize]));
            idx += 1;
        }
        out
    }
}

fn expand_env_vars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' {
            if let Some(rel_end) = chars[i + 1..].iter().position(|&c| c == '%') {
                let end = i + 1 + rel_end;
                let var_name: String = chars[i + 1..end].iter().collect();
                if !var_name.is_empty() {
                    if let Ok(val) = std::env::var(&var_name) {
                        out.push_str(&val);
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn extract_exe_path_from_reg(raw: &str) -> Option<PathBuf> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let candidate = if let Some(rest) = s.strip_prefix('"') {
        rest.split('"').next().unwrap_or("")
    } else if let Some(idx) = s.to_ascii_lowercase().find(".exe") {
        &s[..idx + 4]
    } else {
        s.split(',').next().unwrap_or(s).trim()
    };
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn find_in_path(exe_name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join(exe_name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn find_in_app_paths(exe_names: &[&str]) -> Option<PathBuf> {
    let roots = [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE];
    let sams = [KEY_READ | KEY_WOW64_64KEY, KEY_READ | KEY_WOW64_32KEY];
    for exe in exe_names {
        let subkey = format!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{exe}");
        for &root in &roots {
            for &sam in &sams {
                if let Some(key) = RegKey::open(root, &subkey, sam) {
                    if let Some(val) = key.read_string(None) {
                        if let Some(p) = extract_exe_path_from_reg(&val) {
                            if p.is_file() {
                                return Some(p);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn find_in_uninstall(name_patterns: &[&str], exe_candidates: &[&str]) -> Option<PathBuf> {
    let roots = [
        (HKEY_CURRENT_USER, KEY_READ),
        (HKEY_LOCAL_MACHINE, KEY_READ | KEY_WOW64_64KEY),
        (HKEY_LOCAL_MACHINE, KEY_READ | KEY_WOW64_32KEY),
    ];
    let base_subkey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    for (root, sam) in roots {
        let Some(parent) = RegKey::open(root, base_subkey, sam) else {
            continue;
        };
        for sub in parent.enum_subkeys() {
            let full = format!("{base_subkey}\\{sub}");
            let Some(entry) = RegKey::open(root, &full, sam) else {
                continue;
            };
            let display_name = entry.read_string(Some("DisplayName")).unwrap_or_default();
            let hay = format!("{sub} {display_name}").to_ascii_lowercase();
            if !name_patterns
                .iter()
                .any(|pat| hay.contains(&pat.to_ascii_lowercase()))
            {
                continue;
            }
            if let Some(loc) = entry.read_string(Some("InstallLocation")) {
                let dir = PathBuf::from(loc.trim_matches('"'));
                for exe in exe_candidates {
                    let p = dir.join(exe);
                    if p.is_file() {
                        return Some(p);
                    }
                }
            }
            if let Some(icon) = entry.read_string(Some("DisplayIcon")) {
                if let Some(p) = extract_exe_path_from_reg(&icon) {
                    if p.is_file()
                        && p.extension()
                            .and_then(|e| e.to_str())
                            .map(|e| e.eq_ignore_ascii_case("exe"))
                            .unwrap_or(false)
                    {
                        if let Some(dir) = p.parent() {
                            for exe in exe_candidates {
                                let cand = dir.join(exe);
                                if cand.is_file() {
                                    return Some(cand);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn program_roots() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        if let Ok(v) = std::env::var(var) {
            let p = PathBuf::from(v);
            if !dirs.contains(&p) {
                dirs.push(p);
            }
        }
    }
    dirs
}

fn find_first_file(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.into_iter().find(|p| p.is_file()).cloned()
}

fn detect_xshell() -> Option<PathBuf> {
    if let Some(p) = find_in_app_paths(&["Xshell.exe"]) {
        return Some(p);
    }
    for exe in ["Xshell.exe", "xshell.exe"] {
        if let Some(p) = find_in_path(exe) {
            return Some(p);
        }
    }
    if let Some(p) = find_in_uninstall(&["xshell"], &["Xshell.exe"]) {
        return Some(p);
    }
    let mut cands = Vec::new();
    for root in program_roots() {
        for ver in ["9", "8", "7", "6", "5"] {
            cands.push(
                root.join("NetSarang")
                    .join(format!("Xshell {ver}"))
                    .join("Xshell.exe"),
            );
        }
        cands.push(root.join("NetSarang").join("Xshell").join("Xshell.exe"));
    }
    find_first_file(&cands)
}

fn detect_mobaxterm() -> Option<PathBuf> {
    if let Some(p) = find_in_app_paths(&["MobaXterm.exe", "MobaXterm_Personal.exe"]) {
        return Some(p);
    }
    for exe in [
        "MobaXterm.exe",
        "MobaXterm_Personal.exe",
        "MobaXterm_Professional.exe",
    ] {
        if let Some(p) = find_in_path(exe) {
            return Some(p);
        }
    }
    if let Some(p) = find_in_uninstall(
        &["mobaxterm"],
        &[
            "MobaXterm.exe",
            "MobaXterm_Personal.exe",
            "MobaXterm_Professional.exe",
        ],
    ) {
        return Some(p);
    }
    let mut cands = Vec::new();
    for root in program_roots() {
        for exe in [
            "MobaXterm.exe",
            "MobaXterm_Personal.exe",
            "MobaXterm_Professional.exe",
        ] {
            cands.push(root.join("Mobatek").join("MobaXterm").join(exe));
        }
    }
    find_first_file(&cands)
}

fn detect_putty() -> Option<PathBuf> {
    if let Some(p) = find_in_app_paths(&["putty.exe"]) {
        return Some(p);
    }
    if let Some(p) = find_in_path("putty.exe") {
        return Some(p);
    }
    if let Some(p) = find_in_uninstall(&["putty"], &["putty.exe"]) {
        return Some(p);
    }
    let mut cands = Vec::new();
    for root in program_roots() {
        cands.push(root.join("PuTTY").join("putty.exe"));
    }
    find_first_file(&cands)
}

fn detect_kitty() -> Option<PathBuf> {
    if let Some(p) = find_in_app_paths(&["kitty.exe", "kitty_portable.exe"]) {
        return Some(p);
    }
    for exe in ["kitty_portable.exe", "kitty.exe"] {
        if let Some(p) = find_in_path(exe) {
            return Some(p);
        }
    }
    let mut cands = Vec::new();
    for root in program_roots() {
        cands.push(root.join("KiTTY").join("kitty.exe"));
        cands.push(root.join("KiTTY").join("kitty_portable.exe"));
    }
    find_first_file(&cands)
}

fn detect_securecrt() -> Option<PathBuf> {
    if let Some(p) = find_in_app_paths(&["SecureCRT.exe"]) {
        return Some(p);
    }
    if let Some(p) = find_in_path("SecureCRT.exe") {
        return Some(p);
    }
    if let Some(p) = find_in_uninstall(&["securecrt"], &["SecureCRT.exe"]) {
        return Some(p);
    }
    let mut cands = Vec::new();
    for root in program_roots() {
        cands.push(root.join("VanDyke Software").join("SecureCRT").join("SecureCRT.exe"));
        cands.push(root.join("VanDyke Software").join("Clients").join("SecureCRT.exe"));
    }
    find_first_file(&cands)
}

fn detect_electerm() -> Option<PathBuf> {
    if let Some(p) = find_in_app_paths(&["electerm.exe"]) {
        return Some(p);
    }
    if let Some(p) = find_in_path("electerm.exe") {
        return Some(p);
    }
    if let Some(p) = find_in_uninstall(&["electerm"], &["electerm.exe"]) {
        return Some(p);
    }
    let mut cands = Vec::new();
    for root in program_roots() {
        cands.push(root.join("Programs").join("electerm").join("electerm.exe"));
        cands.push(root.join("electerm").join("electerm.exe"));
    }
    find_first_file(&cands)
}

fn detect_wt() -> Option<PathBuf> {
    if let Some(p) = find_in_app_paths(&["wt.exe"]) {
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let p = PathBuf::from(local)
            .join("Microsoft")
            .join("WindowsApps")
            .join("wt.exe");
        if p.is_file() {
            return Some(p);
        }
    }
    find_in_path("wt.exe")
}

fn detect_pwsh() -> Option<PathBuf> {
    if let Some(p) = find_in_app_paths(&["pwsh.exe"]) {
        return Some(p);
    }
    if let Some(p) = find_in_path("pwsh.exe") {
        return Some(p);
    }
    let mut cands = Vec::new();
    for root in program_roots() {
        cands.push(root.join("PowerShell").join("7").join("pwsh.exe"));
    }
    find_first_file(&cands)
}

fn detect_powershell() -> Option<PathBuf> {
    if let Ok(sysroot) = std::env::var("SystemRoot") {
        let p = PathBuf::from(sysroot)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if p.is_file() {
            return Some(p);
        }
    }
    find_in_path("powershell.exe")
}

fn detect_cmd() -> Option<PathBuf> {
    if let Ok(sysroot) = std::env::var("SystemRoot") {
        let p = PathBuf::from(sysroot).join("System32").join("cmd.exe");
        if p.is_file() {
            return Some(p);
        }
    }
    find_in_path("cmd.exe")
}

fn detect_git_bash() -> Option<PathBuf> {
    for (root, sam) in [
        (HKEY_LOCAL_MACHINE, KEY_READ | KEY_WOW64_64KEY),
        (HKEY_LOCAL_MACHINE, KEY_READ | KEY_WOW64_32KEY),
        (HKEY_CURRENT_USER, KEY_READ),
    ] {
        if let Some(key) = RegKey::open(root, "SOFTWARE\\GitForWindows", sam) {
            if let Some(dir) = key.read_string(Some("InstallPath")) {
                let p = PathBuf::from(dir).join("git-bash.exe");
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    if let Some(p) = find_in_uninstall(&["git"], &["git-bash.exe"]) {
        return Some(p);
    }
    if let Some(git_exe) = find_in_path("git.exe") {
        if let Some(parent) = git_exe.parent().and_then(|p| p.parent()) {
            let p = parent.join("git-bash.exe");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    let mut cands = Vec::new();
    for root in program_roots() {
        cands.push(root.join("Git").join("git-bash.exe"));
    }
    find_first_file(&cands)
}

fn read_ssh_uri_handler() -> Option<String> {
    RegKey::open(HKEY_CLASSES_ROOT, "ssh\\shell\\open\\command", KEY_READ)
        .and_then(|k| k.read_string(None))
}

fn detect_executable_for_kind(kind: &str) -> Option<PathBuf> {
    match kind {
        "xshell" => detect_xshell(),
        "mobaxterm" => detect_mobaxterm(),
        "putty" => detect_putty(),
        "kitty" => detect_kitty(),
        "securecrt" => detect_securecrt(),
        "electerm" => detect_electerm(),
        "wt" => detect_wt(),
        "pwsh" => detect_pwsh(),
        "powershell" => detect_powershell(),
        "cmd" => detect_cmd(),
        "git_bash" => detect_git_bash(),
        _ => None,
    }
}

pub fn detect_terminals() -> Vec<SshTerminalInfo> {
    let wt_exe = detect_wt();
    let ps_exe = detect_powershell();
    let auto_exe = wt_exe
        .as_ref()
        .or(ps_exe.as_ref())
        .map(|p| p.display().to_string());

    let xshell_exe = detect_xshell();
    let moba_exe = detect_mobaxterm();
    let putty_exe = detect_putty();
    let kitty_exe = detect_kitty();
    let scrt_exe = detect_securecrt();
    let electerm_exe = detect_electerm();
    let pwsh_exe = detect_pwsh();
    let cmd_exe = detect_cmd();
    let git_bash_exe = detect_git_bash();
    let ssh_uri_handler = read_ssh_uri_handler();

    vec![
        SshTerminalInfo {
            id: "auto".to_string(),
            name: "自动选择 (推荐)".to_string(),
            category: "builtin".to_string(),
            detected: auto_exe.is_some(),
            executable: auto_exe,
            supports_password: true,
            supports_key: true,
            note: "优先 Windows Terminal，回退 PowerShell；支持自动填充密码与私钥".to_string(),
        },
        SshTerminalInfo {
            id: "xshell".to_string(),
            name: "Xshell".to_string(),
            category: "ssh_client".to_string(),
            detected: xshell_exe.is_some(),
            executable: xshell_exe.map(|p| p.display().to_string()),
            supports_password: true,
            supports_key: true,
            note: "新建标签页连接；支持用户名、密码与私钥参数".to_string(),
        },
        SshTerminalInfo {
            id: "mobaxterm".to_string(),
            name: "MobaXterm".to_string(),
            category: "ssh_client".to_string(),
            detected: moba_exe.is_some(),
            executable: moba_exe.map(|p| p.display().to_string()),
            supports_password: false,
            supports_key: true,
            note: "新建标签页执行 ssh；支持用户名与私钥（密码需交互或由 MobaXterm 托管）".to_string(),
        },
        SshTerminalInfo {
            id: "putty".to_string(),
            name: "PuTTY".to_string(),
            category: "ssh_client".to_string(),
            detected: putty_exe.is_some(),
            executable: putty_exe.map(|p| p.display().to_string()),
            supports_password: true,
            supports_key: true,
            note: "支持用户名、密码 (-pw) 与 .ppk 私钥 (-i)".to_string(),
        },
        SshTerminalInfo {
            id: "kitty".to_string(),
            name: "KiTTY".to_string(),
            category: "ssh_client".to_string(),
            detected: kitty_exe.is_some(),
            executable: kitty_exe.map(|p| p.display().to_string()),
            supports_password: true,
            supports_key: true,
            note: "PuTTY 增强分支，支持用户名、密码 (-pw) 与私钥 (-i)".to_string(),
        },
        SshTerminalInfo {
            id: "securecrt".to_string(),
            name: "SecureCRT".to_string(),
            category: "ssh_client".to_string(),
            detected: scrt_exe.is_some(),
            executable: scrt_exe.map(|p| p.display().to_string()),
            supports_password: true,
            supports_key: true,
            note: "新建标签页 /T /SSH2；支持用户名、密码与私钥".to_string(),
        },
        SshTerminalInfo {
            id: "electerm".to_string(),
            name: "Electerm".to_string(),
            category: "ssh_client".to_string(),
            detected: electerm_exe.is_some(),
            executable: electerm_exe.map(|p| p.display().to_string()),
            supports_password: true,
            supports_key: true,
            note: "支持用户名、密码、私钥及口令直连".to_string(),
        },
        SshTerminalInfo {
            id: "wt".to_string(),
            name: "Windows Terminal (wt)".to_string(),
            category: "console".to_string(),
            detected: wt_exe.is_some(),
            executable: wt_exe.map(|p| p.display().to_string()),
            supports_password: true,
            supports_key: true,
            note: "调用系统 OpenSSH；支持通过内置 Askpass 自动填充密码/口令".to_string(),
        },
        SshTerminalInfo {
            id: "pwsh".to_string(),
            name: "PowerShell 7 (pwsh)".to_string(),
            category: "console".to_string(),
            detected: pwsh_exe.is_some(),
            executable: pwsh_exe.map(|p| p.display().to_string()),
            supports_password: true,
            supports_key: true,
            note: "调用系统 OpenSSH；支持通过内置 Askpass 自动填充密码/口令".to_string(),
        },
        SshTerminalInfo {
            id: "powershell".to_string(),
            name: "Windows PowerShell".to_string(),
            category: "console".to_string(),
            detected: ps_exe.is_some(),
            executable: ps_exe.map(|p| p.display().to_string()),
            supports_password: true,
            supports_key: true,
            note: "系统内置；调用 OpenSSH 并支持自动填充密码/口令".to_string(),
        },
        SshTerminalInfo {
            id: "cmd".to_string(),
            name: "CMD 命令提示符".to_string(),
            category: "console".to_string(),
            detected: cmd_exe.is_some(),
            executable: cmd_exe.map(|p| p.display().to_string()),
            supports_password: true,
            supports_key: true,
            note: "系统内置；调用 OpenSSH 并支持自动填充密码/口令".to_string(),
        },
        SshTerminalInfo {
            id: "git_bash".to_string(),
            name: "Git Bash".to_string(),
            category: "console".to_string(),
            detected: git_bash_exe.is_some(),
            executable: git_bash_exe.map(|p| p.display().to_string()),
            supports_password: true,
            supports_key: true,
            note: "MinTTY + Bash 环境；支持私钥路径自动转换与密码填充".to_string(),
        },
        SshTerminalInfo {
            id: "ssh_uri".to_string(),
            name: "系统默认 ssh:// 协议".to_string(),
            category: "uri".to_string(),
            detected: true,
            executable: None,
            supports_password: false,
            supports_key: false,
            note: match ssh_uri_handler {
                Some(h) => format!("系统关联程序: {h}（仅传递用户名/主机/端口）"),
                None => "调用系统默认 ssh:// 处理程序（仅传递用户名/主机/端口）".to_string(),
            },
        },
        SshTerminalInfo {
            id: "custom".to_string(),
            name: "自定义 SSH 工具 / 命令模板".to_string(),
            category: "custom".to_string(),
            detected: true,
            executable: None,
            supports_password: true,
            supports_key: true,
            note: "指定任意终端 .exe 路径及参数模板（支持 {host} {port} {user} {password} {key_path} 等占位符）".to_string(),
        },
    ]
}

fn spec_target(spec: &SshConnectionSpec) -> String {
    match spec.username.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(u) => format!("{u}@{}", spec.host),
        None => spec.host.clone(),
    }
}

fn spec_askpass_secret(spec: &SshConnectionSpec) -> Option<&str> {
    match spec.auth_type {
        AuthType::Password => spec.password.as_deref().filter(|s| !s.is_empty()),
        AuthType::PrivateKey => {
            if spec.key_path.is_some() {
                spec.key_passphrase.as_deref().filter(|s| !s.is_empty())
            } else {
                None
            }
        }
    }
}

pub fn build_openssh_args(spec: &SshConnectionSpec, has_askpass_secret: bool) -> Vec<String> {
    let mut args = vec![
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-p".to_string(),
        spec.port.to_string(),
    ];
    match spec.auth_type {
        AuthType::Password => {
            if has_askpass_secret {
                args.push("-o".to_string());
                args.push("PubkeyAuthentication=no".to_string());
                args.push("-o".to_string());
                args.push("PreferredAuthentications=password,keyboard-interactive".to_string());
            }
        }
        AuthType::PrivateKey => {
            if let Some(kp) = spec.key_path.as_deref().filter(|s| !s.trim().is_empty()) {
                args.push("-i".to_string());
                args.push(kp.to_string());
                args.push("-o".to_string());
                args.push("IdentitiesOnly=yes".to_string());
            }
        }
    }
    args.push(spec_target(spec));
    args
}

fn build_ssh_url(spec: &SshConnectionSpec, include_password: bool, mask_password: bool) -> String {
    let user_part = match spec.username.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(u) => {
            let enc_u = percent_encode_userinfo(u);
            if include_password && spec.auth_type == AuthType::Password {
                if let Some(p) = spec.password.as_deref().filter(|s| !s.is_empty()) {
                    let pass_part = if mask_password {
                        "******".to_string()
                    } else {
                        percent_encode_userinfo(p)
                    };
                    format!("{enc_u}:{pass_part}@")
                } else {
                    format!("{enc_u}@")
                }
            } else {
                format!("{enc_u}@")
            }
        }
        None => String::new(),
    };
    format!("ssh://{user_part}{}:{}", spec.host, spec.port)
}

pub fn build_xshell_args(spec: &SshConnectionSpec) -> (Vec<String>, String) {
    let real_url = build_ssh_url(spec, true, false);
    let masked_url = build_ssh_url(spec, true, true);
    let mut args = vec![
        "-newtab".to_string(),
        spec.title.clone(),
        "-url".to_string(),
        real_url,
    ];
    let mut disp = vec![
        "-newtab".to_string(),
        quote_for_display(&spec.title),
        "-url".to_string(),
        masked_url,
    ];
    if spec.auth_type == AuthType::PrivateKey {
        if let Some(kp) = spec.key_path.as_deref().filter(|s| !s.trim().is_empty()) {
            args.push("-i".to_string());
            args.push(kp.to_string());
            disp.push("-i".to_string());
            disp.push(quote_for_display(kp));
        }
    }
    (args, format!("xshell {}", disp.join(" ")))
}

pub fn build_putty_family_args(
    tool_label: &str,
    spec: &SshConnectionSpec,
) -> (Vec<String>, String) {
    let port_str = spec.port.to_string();
    let mut args = vec!["-ssh".to_string(), "-P".to_string(), port_str.clone()];
    let mut disp = vec!["-ssh".to_string(), "-P".to_string(), port_str];
    if let Some(u) = spec.username.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        args.push("-l".to_string());
        args.push(u.to_string());
        disp.push("-l".to_string());
        disp.push(quote_for_display(u));
    }
    match spec.auth_type {
        AuthType::Password => {
            if let Some(p) = spec.password.as_deref().filter(|s| !s.is_empty()) {
                args.push("-pw".to_string());
                args.push(p.to_string());
                disp.push("-pw".to_string());
                disp.push("******".to_string());
            }
        }
        AuthType::PrivateKey => {
            if let Some(kp) = spec.key_path.as_deref().filter(|s| !s.trim().is_empty()) {
                args.push("-i".to_string());
                args.push(kp.to_string());
                disp.push("-i".to_string());
                disp.push(quote_for_display(kp));
            }
        }
    }
    args.push(spec.host.clone());
    disp.push(spec.host.clone());
    (args, format!("{tool_label} {}", disp.join(" ")))
}

pub fn build_securecrt_args(spec: &SshConnectionSpec) -> (Vec<String>, String) {
    let port_str = spec.port.to_string();
    let mut args = vec![
        "/T".to_string(),
        "/SSH2".to_string(),
        "/P".to_string(),
        port_str.clone(),
    ];
    let mut disp = vec!["/T".to_string(), "/SSH2".to_string(), "/P".to_string(), port_str];
    if let Some(u) = spec.username.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        args.push("/L".to_string());
        args.push(u.to_string());
        disp.push("/L".to_string());
        disp.push(quote_for_display(u));
    }
    match spec.auth_type {
        AuthType::Password => {
            if let Some(p) = spec.password.as_deref().filter(|s| !s.is_empty()) {
                args.push("/PASSWORD".to_string());
                args.push(p.to_string());
                disp.push("/PASSWORD".to_string());
                disp.push("******".to_string());
            }
        }
        AuthType::PrivateKey => {
            if let Some(kp) = spec.key_path.as_deref().filter(|s| !s.trim().is_empty()) {
                args.push("/I".to_string());
                args.push(kp.to_string());
                disp.push("/I".to_string());
                disp.push(quote_for_display(kp));
            }
        }
    }
    args.push(spec.host.clone());
    disp.push(spec.host.clone());
    (args, format!("SecureCRT {}", disp.join(" ")))
}

pub fn build_electerm_args(spec: &SshConnectionSpec) -> (Vec<String>, String) {
    let port_str = spec.port.to_string();
    let mut args = vec![
        "-P".to_string(),
        port_str.clone(),
        "-t".to_string(),
        spec.title.clone(),
    ];
    let mut disp = vec![
        "-P".to_string(),
        port_str,
        "-t".to_string(),
        quote_for_display(&spec.title),
    ];
    if let Some(u) = spec.username.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        args.push("-l".to_string());
        args.push(u.to_string());
        disp.push("-l".to_string());
        disp.push(quote_for_display(u));
    }
    match spec.auth_type {
        AuthType::Password => {
            if let Some(p) = spec.password.as_deref().filter(|s| !s.is_empty()) {
                args.push("-pw".to_string());
                args.push(p.to_string());
                disp.push("-pw".to_string());
                disp.push("******".to_string());
            }
        }
        AuthType::PrivateKey => {
            if let Some(kp) = spec.key_path.as_deref().filter(|s| !s.trim().is_empty()) {
                args.push("-i".to_string());
                args.push(kp.to_string());
                disp.push("-i".to_string());
                disp.push(quote_for_display(kp));
                if let Some(pp) = spec.key_passphrase.as_deref().filter(|s| !s.is_empty()) {
                    args.push("-pw".to_string());
                    args.push(pp.to_string());
                    disp.push("-pw".to_string());
                    disp.push("******".to_string());
                }
            }
        }
    }
    args.push(spec.host.clone());
    disp.push(spec.host.clone());
    (args, format!("electerm {}", disp.join(" ")))
}

pub fn build_mobaxterm_args(spec: &SshConnectionSpec) -> (Vec<String>, String) {
    let mut cmd_parts = vec![
        "ssh".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-p".to_string(),
        spec.port.to_string(),
    ];
    if spec.auth_type == AuthType::PrivateKey {
        if let Some(kp) = spec.key_path.as_deref().filter(|s| !s.trim().is_empty()) {
            let moba_path = win_to_mobaxterm_path(kp);
            cmd_parts.push("-i".to_string());
            cmd_parts.push(posix_single_quote(&moba_path));
        }
    }
    cmd_parts.push(spec_target(spec));
    let inner = cmd_parts.join(" ");
    let args = vec!["-newtab".to_string(), inner.clone()];
    (args, format!("MobaXterm -newtab {}", quote_for_display(&inner)))
}

pub fn build_custom_args(
    template: &str,
    spec: &SshConnectionSpec,
) -> (Vec<String>, String) {
    let raw_tpl = if template.trim().is_empty() {
        "-p {port} {target}"
    } else {
        template
    };
    let tokens = split_arg_template(raw_tpl);
    let port_str = spec.port.to_string();
    let user_str = spec.username.as_deref().unwrap_or("");
    let target_str = spec_target(spec);
    let pwd_str = if spec.auth_type == AuthType::Password {
        spec.password.as_deref().unwrap_or("")
    } else {
        ""
    };
    let key_str = if spec.auth_type == AuthType::PrivateKey {
        spec.key_path.as_deref().unwrap_or("")
    } else {
        ""
    };
    let pp_str = if spec.auth_type == AuthType::PrivateKey {
        spec.key_passphrase.as_deref().unwrap_or("")
    } else {
        ""
    };
    let ssh_url = build_ssh_url(spec, false, false);
    let ssh_url_auth = build_ssh_url(spec, true, false);
    let ssh_url_auth_masked = build_ssh_url(spec, true, true);
    let pwd_masked = if pwd_str.is_empty() { "" } else { "******" };
    let pp_masked = if pp_str.is_empty() { "" } else { "******" };

    let apply = |tok: &str, masked: bool| -> String {
        tok.replace("{host}", &spec.host)
            .replace("{port}", &port_str)
            .replace("{user}", user_str)
            .replace("{target}", &target_str)
            .replace("{password}", if masked { pwd_masked } else { pwd_str })
            .replace("{key_path}", key_str)
            .replace("{key_passphrase}", if masked { pp_masked } else { pp_str })
            .replace("{name}", &spec.title)
            .replace("{ssh_url}", &ssh_url)
            .replace(
                "{ssh_url_auth}",
                if masked {
                    &ssh_url_auth_masked
                } else {
                    &ssh_url_auth
                },
            )
    };

    let real_args: Vec<String> = tokens.iter().map(|t| apply(t, false)).collect();
    let disp_args: Vec<String> = tokens
        .iter()
        .map(|t| quote_for_display(&apply(t, true)))
        .collect();
    (real_args, disp_args.join(" "))
}

fn quote_for_display(s: &str) -> String {
    if s.is_empty() || s.chars().any(|c| c.is_whitespace() || c == '"' || c == '&') {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

fn resolve_custom_or_detected_exe(kind: &str, term_cfg: &SshTerminalConfig) -> Result<PathBuf> {
    let custom = term_cfg.custom_path.trim();
    if !custom.is_empty() {
        let p = PathBuf::from(expand_env_vars(custom).trim_matches('"'));
        if p.is_file() {
            return Ok(p);
        }
        if let Some(found) = find_in_path(custom.trim_matches('"')) {
            return Ok(found);
        }
        bail!("未找到配置的终端程序: {}", p.display());
    }
    detect_executable_for_kind(kind).ok_or_else(|| anyhow!("未在系统中检测到 {kind}，请在 SSH 终端设置中检查或填写自定义路径"))
}

fn format_ssh_display(args: &[String], has_askpass: bool) -> String {
    let rendered = args
        .iter()
        .map(|a| quote_for_display(a))
        .collect::<Vec<_>>()
        .join(" ");
    if has_askpass {
        format!("ssh {rendered} (已注入自动认证)")
    } else {
        format!("ssh {rendered}")
    }
}

fn cmd_quote_inner(s: &str) -> String {
    let sanitized = s.replace('"', "");
    if sanitized.is_empty()
        || sanitized
            .chars()
            .any(|c| c.is_whitespace() || "&|<>()^;,".contains(c))
    {
        format!("\"{sanitized}\"")
    } else {
        sanitized
    }
}

pub fn launch_ssh_terminal(
    spec: &SshConnectionSpec,
    term_cfg: &SshTerminalConfig,
    askpass_ctx: Option<(&AskpassStore, u16)>,
) -> Result<LaunchResult> {
    let kind = term_cfg.kind.trim();
    let effective_kind = if kind.is_empty() || kind == "auto" {
        if detect_wt().is_some() {
            "wt"
        } else if detect_powershell().is_some() {
            "powershell"
        } else if detect_pwsh().is_some() {
            "pwsh"
        } else {
            "cmd"
        }
    } else {
        kind
    };

    if !is_valid_terminal_kind(effective_kind) {
        bail!("不支持的 SSH 终端类型: {effective_kind}");
    }

    match effective_kind {
        "xshell" => {
            let exe = resolve_custom_or_detected_exe("xshell", term_cfg)?;
            let (args, display) = build_xshell_args(spec);
            Command::new(&exe)
                .args(&args)
                .spawn()
                .with_context(|| format!("启动 Xshell 失败: {}", exe.display()))?;
            Ok(LaunchResult {
                terminal_id: "xshell".to_string(),
                terminal_name: "Xshell".to_string(),
                display_command: display,
            })
        }
        "putty" => {
            let exe = resolve_custom_or_detected_exe("putty", term_cfg)?;
            let (args, display) = build_putty_family_args("putty", spec);
            Command::new(&exe)
                .args(&args)
                .spawn()
                .with_context(|| format!("启动 PuTTY 失败: {}", exe.display()))?;
            Ok(LaunchResult {
                terminal_id: "putty".to_string(),
                terminal_name: "PuTTY".to_string(),
                display_command: display,
            })
        }
        "kitty" => {
            let exe = resolve_custom_or_detected_exe("kitty", term_cfg)?;
            let (args, display) = build_putty_family_args("kitty", spec);
            Command::new(&exe)
                .args(&args)
                .spawn()
                .with_context(|| format!("启动 KiTTY 失败: {}", exe.display()))?;
            Ok(LaunchResult {
                terminal_id: "kitty".to_string(),
                terminal_name: "KiTTY".to_string(),
                display_command: display,
            })
        }
        "securecrt" => {
            let exe = resolve_custom_or_detected_exe("securecrt", term_cfg)?;
            let (args, display) = build_securecrt_args(spec);
            Command::new(&exe)
                .args(&args)
                .spawn()
                .with_context(|| format!("启动 SecureCRT 失败: {}", exe.display()))?;
            Ok(LaunchResult {
                terminal_id: "securecrt".to_string(),
                terminal_name: "SecureCRT".to_string(),
                display_command: display,
            })
        }
        "electerm" => {
            let exe = resolve_custom_or_detected_exe("electerm", term_cfg)?;
            let (args, display) = build_electerm_args(spec);
            Command::new(&exe)
                .args(&args)
                .spawn()
                .with_context(|| format!("启动 Electerm 失败: {}", exe.display()))?;
            Ok(LaunchResult {
                terminal_id: "electerm".to_string(),
                terminal_name: "Electerm".to_string(),
                display_command: display,
            })
        }
        "mobaxterm" => {
            let exe = resolve_custom_or_detected_exe("mobaxterm", term_cfg)?;
            let (args, display) = build_mobaxterm_args(spec);
            Command::new(&exe)
                .args(&args)
                .spawn()
                .with_context(|| format!("启动 MobaXterm 失败: {}", exe.display()))?;
            Ok(LaunchResult {
                terminal_id: "mobaxterm".to_string(),
                terminal_name: "MobaXterm".to_string(),
                display_command: display,
            })
        }
        "ssh_uri" => {
            let uri = build_ssh_url(spec, false, false);
            let op_wide = to_wide("open");
            let uri_wide = to_wide(&uri);
            let ret = unsafe {
                ShellExecuteW(
                    std::ptr::null_mut(),
                    op_wide.as_ptr(),
                    uri_wide.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    SW_SHOWNORMAL,
                )
            };
            if (ret as isize) <= 32 {
                bail!("调用系统 ssh:// 协议失败 (code={})", ret as isize);
            }
            Ok(LaunchResult {
                terminal_id: "ssh_uri".to_string(),
                terminal_name: "系统默认 ssh://".to_string(),
                display_command: uri,
            })
        }
        "custom" => {
            let custom_path = term_cfg.custom_path.trim();
            if custom_path.is_empty() {
                bail!("请先在 SSH 终端设置中填写自定义终端程序路径");
            }
            let exe = resolve_custom_or_detected_exe("custom", term_cfg)?;
            let (args, disp_args) = build_custom_args(&term_cfg.custom_args, spec);
            Command::new(&exe)
                .args(&args)
                .spawn()
                .with_context(|| format!("启动自定义终端失败: {}", exe.display()))?;
            let exe_name = exe
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("custom");
            Ok(LaunchResult {
                terminal_id: "custom".to_string(),
                terminal_name: format!("自定义 ({exe_name})"),
                display_command: if disp_args.is_empty() {
                    exe_name.to_string()
                } else {
                    format!("{exe_name} {disp_args}")
                },
            })
        }
        "wt" | "pwsh" | "powershell" | "cmd" | "git_bash" => {
            launch_openssh_console(effective_kind, spec, term_cfg, askpass_ctx)
        }
        _ => unreachable!(),
    }
}

fn prepare_askpass_env(
    spec: &SshConnectionSpec,
    askpass_ctx: Option<(&AskpassStore, u16)>,
) -> Result<Option<(String, String, u16)>> {
    let Some(secret) = spec_askpass_secret(spec) else {
        return Ok(None);
    };
    let Some((store, ui_port)) = askpass_ctx else {
        return Ok(None);
    };
    let exe = std::env::current_exe().context("获取当前程序路径失败")?;
    let askpass_exe = short_path_if_spaces(&exe);
    let token = store.mint(secret.to_string());
    Ok(Some((askpass_exe, token, ui_port)))
}

fn launch_openssh_console(
    kind: &str,
    spec: &SshConnectionSpec,
    term_cfg: &SshTerminalConfig,
    askpass_ctx: Option<(&AskpassStore, u16)>,
) -> Result<LaunchResult> {
    let askpass = prepare_askpass_env(spec, askpass_ctx)?;
    let has_askpass = askpass.is_some();
    let ssh_args = build_openssh_args(spec, has_askpass);
    let display = format_ssh_display(&ssh_args, has_askpass);

    match kind {
        "wt" => {
            let exe = resolve_custom_or_detected_exe("wt", term_cfg)?;
            let askpass_ref = askpass
                .as_ref()
                .map(|(p, t, port)| (p.as_str(), t.as_str(), *port));
            let wt_args = build_wt_launch_args(&spec.title, &ssh_args, askpass_ref);
            Command::new(&exe)
                .args(&wt_args)
                .spawn()
                .with_context(|| format!("启动 Windows Terminal 失败: {}", exe.display()))?;
            Ok(LaunchResult {
                terminal_id: "wt".to_string(),
                terminal_name: "Windows Terminal".to_string(),
                display_command: display,
            })
        }
        "pwsh" | "powershell" => {
            let exe = resolve_custom_or_detected_exe(kind, term_cfg)?;
            let ps_args = ssh_args
                .iter()
                .map(|a| ps_single_quote(a))
                .collect::<Vec<_>>()
                .join(" ");
            let ps_cmd = format!("& ssh {ps_args}");
            let mut cmd = Command::new(&exe);
            cmd.creation_flags(CREATE_NEW_CONSOLE);
            cmd.args(["-NoLogo", "-NoExit", "-Command", &ps_cmd]);
            if let Some((askpass_exe, token, ui_port)) = askpass {
                cmd.env("SSH_ASKPASS", askpass_exe)
                    .env("SSH_ASKPASS_REQUIRE", "force")
                    .env("DISPLAY", ":0")
                    .env("UUTUNNELS_ASKPASS_TOKEN", token)
                    .env("UUTUNNELS_ASKPASS_PORT", ui_port.to_string());
            }
            let name = if kind == "pwsh" {
                "PowerShell 7"
            } else {
                "Windows PowerShell"
            };
            cmd.spawn()
                .with_context(|| format!("启动 {name} 失败: {}", exe.display()))?;
            Ok(LaunchResult {
                terminal_id: kind.to_string(),
                terminal_name: name.to_string(),
                display_command: display,
            })
        }
        "cmd" => {
            let exe = resolve_custom_or_detected_exe("cmd", term_cfg)?;
            let inner_args = ssh_args
                .iter()
                .map(|a| cmd_quote_inner(a))
                .collect::<Vec<_>>()
                .join(" ");
            let raw_cmd = format!("/K \"\"ssh\" {inner_args}\"");
            let mut cmd = Command::new(&exe);
            cmd.creation_flags(CREATE_NEW_CONSOLE);
            cmd.raw_arg(&raw_cmd);
            if let Some((askpass_exe, token, ui_port)) = askpass {
                cmd.env("SSH_ASKPASS", askpass_exe)
                    .env("SSH_ASKPASS_REQUIRE", "force")
                    .env("DISPLAY", ":0")
                    .env("UUTUNNELS_ASKPASS_TOKEN", token)
                    .env("UUTUNNELS_ASKPASS_PORT", ui_port.to_string());
            }
            cmd.spawn()
                .with_context(|| format!("启动 CMD 失败: {}", exe.display()))?;
            Ok(LaunchResult {
                terminal_id: "cmd".to_string(),
                terminal_name: "CMD 命令提示符".to_string(),
                display_command: display,
            })
        }
        "git_bash" => {
            let exe = resolve_custom_or_detected_exe("git_bash", term_cfg)?;
            let mut bash_args = Vec::with_capacity(ssh_args.len());
            let mut i = 0;
            while i < ssh_args.len() {
                if ssh_args[i] == "-i" && i + 1 < ssh_args.len() {
                    bash_args.push(posix_single_quote("-i"));
                    bash_args.push(posix_single_quote(&win_to_git_bash_path(&ssh_args[i + 1])));
                    i += 2;
                } else {
                    bash_args.push(posix_single_quote(&ssh_args[i]));
                    i += 1;
                }
            }
            let bash_script = format!(
                "ssh {}; code=$?; if [ $code -ne 0 ]; then read -rp 'SSH exited, press Enter...'; fi",
                bash_args.join(" ")
            );
            let mintty = exe
                .parent()
                .map(|p| p.join("usr").join("bin").join("mintty.exe"))
                .filter(|p| p.is_file());

            let mut cmd = if let Some(mintty_exe) = mintty {
                let mut c = Command::new(&mintty_exe);
                c.args([
                    "--title",
                    &spec.title,
                    "-e",
                    "/usr/bin/bash",
                    "--login",
                    "-i",
                    "-c",
                    &bash_script,
                ]);
                c
            } else {
                let mut c = Command::new(&exe);
                c.args(["-c", &bash_script]);
                c
            };

            if let Some((askpass_exe, token, ui_port)) = askpass {
                cmd.env("SSH_ASKPASS", askpass_exe.replace('\\', "/"))
                    .env("SSH_ASKPASS_REQUIRE", "force")
                    .env("DISPLAY", ":0")
                    .env("UUTUNNELS_ASKPASS_TOKEN", token)
                    .env("UUTUNNELS_ASKPASS_PORT", ui_port.to_string());
            }
            cmd.spawn()
                .with_context(|| format!("启动 Git Bash 失败: {}", exe.display()))?;
            Ok(LaunchResult {
                terminal_id: "git_bash".to_string(),
                terminal_name: "Git Bash".to_string(),
                display_command: display,
            })
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_spec() -> SshConnectionSpec {
        SshConnectionSpec {
            title: "NAS SSH".to_string(),
            host: "127.0.0.1".to_string(),
            port: 2203,
            username: Some("admin".to_string()),
            auth_type: AuthType::Password,
            password: Some("p@ss:w#rd 1".to_string()),
            key_path: None,
            key_passphrase: None,
        }
    }

    #[test]
    fn xshell_builder_encodes_and_masks_password() {
        let spec = sample_spec();
        let (args, display) = build_xshell_args(&spec);
        assert_eq!(args[0], "-newtab");
        assert_eq!(args[1], "NAS SSH");
        assert_eq!(args[2], "-url");
        assert_eq!(args[3], "ssh://admin:p%40ss%3Aw%23rd%201@127.0.0.1:2203");
        assert!(display.contains("ssh://admin:******@127.0.0.1:2203"));
        assert!(!display.contains("p%40ss"));
        assert!(!display.contains("p@ss"));
    }

    #[test]
    fn xshell_builder_includes_key_for_private_key_auth() {
        let spec = SshConnectionSpec {
            auth_type: AuthType::PrivateKey,
            password: None,
            key_path: Some(r"C:\Users\me\.ssh\id_ed25519".to_string()),
            ..sample_spec()
        };
        let (args, display) = build_xshell_args(&spec);
        assert_eq!(
            args,
            vec![
                "-newtab",
                "NAS SSH",
                "-url",
                "ssh://admin@127.0.0.1:2203",
                "-i",
                r"C:\Users\me\.ssh\id_ed25519"
            ]
        );
        assert!(display.contains(r"-i C:\Users\me\.ssh\id_ed25519"));
    }

    #[test]
    fn putty_securecrt_electerm_mobaxterm_builders_mask_secrets() {
        let spec = sample_spec();
        let (putty_args, putty_disp) = build_putty_family_args("putty", &spec);
        assert_eq!(
            putty_args,
            vec!["-ssh", "-P", "2203", "-l", "admin", "-pw", "p@ss:w#rd 1", "127.0.0.1"]
        );
        assert!(putty_disp.contains("-pw ******"));
        assert!(!putty_disp.contains("p@ss"));

        let (scrt_args, scrt_disp) = build_securecrt_args(&spec);
        assert_eq!(
            scrt_args,
            vec![
                "/T",
                "/SSH2",
                "/P",
                "2203",
                "/L",
                "admin",
                "/PASSWORD",
                "p@ss:w#rd 1",
                "127.0.0.1"
            ]
        );
        assert!(scrt_disp.contains("/PASSWORD ******"));
        assert!(!scrt_disp.contains("p@ss"));

        let (el_args, el_disp) = build_electerm_args(&spec);
        assert_eq!(
            el_args,
            vec![
                "-P",
                "2203",
                "-t",
                "NAS SSH",
                "-l",
                "admin",
                "-pw",
                "p@ss:w#rd 1",
                "127.0.0.1"
            ]
        );
        assert!(el_disp.contains("-pw ******"));

        let key_spec = SshConnectionSpec {
            auth_type: AuthType::PrivateKey,
            password: None,
            key_path: Some(r"D:\My Keys\id_rsa".to_string()),
            ..sample_spec()
        };
        let (moba_args, _) = build_mobaxterm_args(&key_spec);
        assert_eq!(moba_args[0], "-newtab");
        assert!(moba_args[1].contains("'/drives/d/My Keys/id_rsa'"));
        assert!(moba_args[1].contains("admin@127.0.0.1"));
    }

    #[test]
    fn openssh_args_switch_between_password_key_and_interactive() {
        let spec = sample_spec();
        let pw_args = build_openssh_args(&spec, true);
        assert!(pw_args.contains(&"PubkeyAuthentication=no".to_string()));
        assert!(pw_args.contains(&"PreferredAuthentications=password,keyboard-interactive".to_string()));
        assert_eq!(pw_args.last().unwrap(), "admin@127.0.0.1");

        let interactive_args = build_openssh_args(&spec, false);
        assert!(!interactive_args.contains(&"PubkeyAuthentication=no".to_string()));

        let key_spec = SshConnectionSpec {
            auth_type: AuthType::PrivateKey,
            password: None,
            key_path: Some(r"C:\keys\id_ed25519".to_string()),
            ..sample_spec()
        };
        let key_args = build_openssh_args(&key_spec, false);
        assert!(key_args.windows(2).any(|w| w == ["-i", r"C:\keys\id_ed25519"]));
        assert!(key_args.contains(&"IdentitiesOnly=yes".to_string()));
    }

    #[test]
    fn custom_template_splits_respects_quotes_and_masks_passwords() {
        let spec = sample_spec();
        let (args, disp) = build_custom_args(r#"-title "{name}" -l {user} -pw {password} -P {port} {host}"#, &spec);
        assert_eq!(
            args,
            vec!["-title", "NAS SSH", "-l", "admin", "-pw", "p@ss:w#rd 1", "-P", "2203", "127.0.0.1"]
        );
        assert!(disp.contains("-pw ******"));
        assert!(!disp.contains("p@ss"));
    }

    #[test]
    fn askpass_store_is_single_use_and_expires() {
        let store = AskpassStore::new();
        let token = store.mint("top-secret".to_string());
        assert_eq!(store.consume(&token).as_deref(), Some("top-secret"));
        assert!(store.consume(&token).is_none());

        let expired_tok = "expired-tok".to_string();
        {
            let mut map = store.entries.lock().unwrap();
            map.insert(
                expired_tok.clone(),
                AskpassEntry {
                    secret: "old".to_string(),
                    expires_at: Instant::now() - Duration::from_secs(1),
                },
            );
        }
        assert!(store.consume(&expired_tok).is_none());
    }

    #[test]
    fn resolve_effective_username_prefers_rule_over_base_fallback() {
        let mut cfg = AppConfig::preset();
        let r_idx = cfg.rules.iter().position(|r| r.id == "lh-2202").unwrap();
        assert_eq!(
            resolve_effective_ssh_username(&cfg, &cfg.rules[r_idx]).as_deref(),
            Some("ubuntu")
        );

        cfg.rules[r_idx].ssh_username = Some("root".to_string());
        assert_eq!(
            resolve_effective_ssh_username(&cfg, &cfg.rules[r_idx]).as_deref(),
            Some("root")
        );

        let nas_rule = cfg.rules.iter().find(|r| r.id == "nas-2203").unwrap();
        assert_eq!(resolve_effective_ssh_username(&cfg, nas_rule), None);
    }

    #[test]
    fn detect_terminals_includes_system_consoles() {
        let list = detect_terminals();
        assert!(list.iter().any(|t| t.id == "auto" && t.detected));
        assert!(list.iter().any(|t| t.id == "powershell" && t.detected));
        assert!(list.iter().any(|t| t.id == "cmd" && t.detected));
        assert!(list.iter().any(|t| t.id == "ssh_uri" && t.detected));
        assert!(list.iter().any(|t| t.id == "custom" && t.detected));
    }

    #[test]
    fn path_helpers_expand_and_convert() {
        assert_eq!(win_to_mobaxterm_path(r"C:\Users\a\id_rsa"), "/drives/c/Users/a/id_rsa");
        assert_eq!(win_to_git_bash_path(r"D:\keys\my key\id_ed25519"), "/d/keys/my key/id_ed25519");
        let expanded = expand_tilde_path("~/.ssh/id_ed25519");
        if let Some(home) = dirs::home_dir() {
            assert_eq!(PathBuf::from(expanded), home.join(".ssh").join("id_ed25519"));
        }
        assert_eq!(ps_single_quote("a'b"), "'a''b'");
        assert_eq!(posix_single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn encode_powershell_command_matches_utf16le_base64() {
        assert_eq!(encode_powershell_command("hi"), "aABpAA==");
        let cn = encode_powershell_command("echo '测试;ok'");
        assert!(!cn.contains(';'));
        assert!(!cn.chars().any(char::is_whitespace));
        assert!(!cn.contains('"'));
        assert!(!cn.contains('\''));
    }

    #[test]
    fn wt_launch_args_contain_no_unescaped_semicolons() {
        let has_unescaped_semi = |s: &str| {
            let bytes = s.as_bytes();
            bytes.iter().enumerate().any(|(i, &b)| {
                b == b';' && (i == 0 || bytes[i - 1] != b'\\')
            })
        };

        let spec = sample_spec();
        let ssh_args = build_openssh_args(&spec, true);
        let wt_askpass = build_wt_launch_args(
            "Title;Test",
            &ssh_args,
            Some((r"C:\tools\uuTunnels.exe", "tok123", 17890)),
        );
        assert_eq!(wt_askpass[0], "new-tab");
        assert_eq!(wt_askpass[1], "--title");
        assert_eq!(wt_askpass[2], r"Title\;Test");
        assert_eq!(wt_askpass[3], "powershell.exe");
        assert_eq!(wt_askpass[6], "-EncodedCommand");
        assert!(wt_askpass.iter().all(|a| !has_unescaped_semi(a)));

        let direct_args = build_openssh_args(&spec, false);
        let wt_direct = build_wt_launch_args("Direct;Tab", &direct_args, None);
        assert_eq!(wt_direct[2], r"Direct\;Tab");
        assert_eq!(wt_direct[3], "ssh");
        assert!(wt_direct.iter().all(|a| !has_unescaped_semi(a)));
    }
}
