use crate::config::{AppConfig, AuthType, BaseKind, TunnelBase};
use anyhow::{anyhow, Context, Result};
use russh::client;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Notify, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type BoxedStream = Box<dyn AsyncStream>;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BaseStatus {
    Connected,
    Connecting,
    NeedsCredentials,
    Disconnected,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct BaseRuntimeSnapshot {
    pub status: BaseStatus,
    pub latency_ms: Option<u64>,
    pub last_error: Option<String>,
}

struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }
}

struct BaseRuntime {
    config: TunnelBase,
    status: BaseStatus,
    latency_ms: Option<u64>,
    last_error: Option<String>,
    handle: Option<Arc<client::Handle<ClientHandler>>>,
    cancel: CancellationToken,
    wake: Arc<Notify>,
}

pub struct SshEngine {
    inner: Arc<RwLock<HashMap<String, BaseRuntime>>>,
    root_cancel: CancellationToken,
    auto_hide_uu: Arc<AtomicBool>,
}

impl SshEngine {
    pub fn new(root_cancel: CancellationToken) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            root_cancel,
            auto_hide_uu: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_auto_hide_uu(&self, enabled: bool) {
        self.auto_hide_uu.store(enabled, Ordering::Relaxed);
    }

    pub async fn sync_all(&self, cfg: &AppConfig) {
        self.set_auto_hide_uu(cfg.auto_hide_uu);
        let existing_ids: Vec<String> = {
            let map = self.inner.read().await;
            map.keys().cloned().collect()
        };
        let desired_ids: std::collections::HashSet<&str> =
            cfg.bases.iter().map(|b| b.id.as_str()).collect();

        for id in existing_ids {
            if !desired_ids.contains(id.as_str()) {
                self.remove_base(&id).await;
            }
        }

        for base in &cfg.bases {
            self.upsert_base(base.clone()).await;
        }
    }

    pub async fn remove_base(&self, base_id: &str) {
        let mut map = self.inner.write().await;
        if let Some(rt) = map.remove(base_id) {
            rt.cancel.cancel();
        }
    }

    pub async fn upsert_base(&self, base: TunnelBase) {
        let mut map = self.inner.write().await;
        if let Some(existing) = map.get(&base.id) {
            if base_config_equal(&existing.config, &base) {
                return;
            }
            existing.cancel.cancel();
        }

        let cancel = self.root_cancel.child_token();
        let wake = Arc::new(Notify::new());
        let initial_status = if !base.enabled {
            BaseStatus::Disconnected
        } else if needs_credentials(&base) {
            BaseStatus::NeedsCredentials
        } else {
            BaseStatus::Connecting
        };

        let rt = BaseRuntime {
            config: base.clone(),
            status: initial_status,
            latency_ms: None,
            last_error: None,
            handle: None,
            cancel: cancel.clone(),
            wake: wake.clone(),
        };
        map.insert(base.id.clone(), rt);
        drop(map);

        let inner = self.inner.clone();
        let auto_hide_uu = self.auto_hide_uu.clone();
        tokio::spawn(async move {
            base_worker(inner, base, cancel, wake, auto_hide_uu).await;
        });
    }

    pub async fn reconnect_base(&self, base_id: &str) -> Result<()> {
        let base_opt = {
            let mut map = self.inner.write().await;
            let rt = map
                .get_mut(base_id)
                .ok_or_else(|| anyhow!("未找到基座: {base_id}"))?;
            rt.cancel.cancel();
            rt.handle = None;
            rt.config.enabled = true;
            rt.last_error = None;
            rt.status = if needs_credentials(&rt.config) {
                BaseStatus::NeedsCredentials
            } else {
                BaseStatus::Connecting
            };
            rt.cancel = self.root_cancel.child_token();
            rt.wake = Arc::new(Notify::new());
            (rt.config.clone(), rt.cancel.clone(), rt.wake.clone())
        };

        let inner = self.inner.clone();
        let auto_hide_uu = self.auto_hide_uu.clone();
        tokio::spawn(async move {
            base_worker(inner, base_opt.0, base_opt.1, base_opt.2, auto_hide_uu).await;
        });
        Ok(())
    }

    pub async fn disconnect_base(&self, base_id: &str) -> Result<()> {
        let mut map = self.inner.write().await;
        let rt = map
            .get_mut(base_id)
            .ok_or_else(|| anyhow!("未找到基座: {base_id}"))?;
        rt.cancel.cancel();
        rt.handle = None;
        rt.config.enabled = false;
        rt.status = BaseStatus::Disconnected;
        rt.latency_ms = None;
        Ok(())
    }

    pub async fn snapshot_all(&self) -> HashMap<String, BaseRuntimeSnapshot> {
        let map = self.inner.read().await;
        map.iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    BaseRuntimeSnapshot {
                        status: v.status.clone(),
                        latency_ms: v.latency_ms,
                        last_error: v.last_error.clone(),
                    },
                )
            })
            .collect()
    }

    pub async fn is_base_ready(&self, base_id: &str) -> bool {
        let map = self.inner.read().await;
        matches!(
            map.get(base_id).map(|b| &b.status),
            Some(BaseStatus::Connected)
        )
    }

    pub async fn open_stream(
        &self,
        base_id: &str,
        target_host: &str,
        target_port: u16,
        peer_addr: SocketAddr,
    ) -> Result<BoxedStream> {
        let (kind, host, port, handle, wake) = {
            let map = self.inner.read().await;
            let rt = map
                .get(base_id)
                .ok_or_else(|| anyhow!("关联的隧道基座不存在: {base_id}"))?;
            if !rt.config.enabled {
                anyhow::bail!("基座「{}」已停用", rt.config.name);
            }
            (
                rt.config.kind.clone(),
                rt.config.host.clone(),
                rt.config.port,
                rt.handle.clone(),
                rt.wake.clone(),
            )
        };

        match kind {
            BaseKind::Direct => {
                let s = tokio::time::timeout(
                    Duration::from_secs(8),
                    TcpStream::connect((target_host, target_port)),
                )
                .await
                .context("直连目标超时")??;
                let _ = s.set_nodelay(true);
                Ok(Box::new(s))
            }
            BaseKind::Socks5 => {
                let s = socks5_connect(&host, port, target_host, target_port).await?;
                Ok(Box::new(s))
            }
            BaseKind::Ssh => {
                let Some(handle) = handle else {
                    wake.notify_one();
                    anyhow::bail!("SSH 基座尚未连接");
                };
                if handle.is_closed() {
                    wake.notify_one();
                    anyhow::bail!("SSH 会话已断开，正在重连");
                }
                let orig_ip = peer_addr.ip().to_string();
                let orig_port = peer_addr.port() as u32;
                match tokio::time::timeout(
                    Duration::from_secs(10),
                    handle.channel_open_direct_tcpip(
                        target_host,
                        target_port as u32,
                        orig_ip,
                        orig_port,
                    ),
                )
                .await
                {
                    Ok(Ok(ch)) => Ok(Box::new(ch.into_stream())),
                    Ok(Err(e)) => {
                        if handle.is_closed() {
                            wake.notify_one();
                        }
                        Err(anyhow!("SSH 通道打开失败 ({target_host}:{target_port}): {e}"))
                    }
                    Err(_) => {
                        wake.notify_one();
                        Err(anyhow!("SSH 通道打开超时 ({target_host}:{target_port})"))
                    }
                }
            }
        }
    }
}

fn needs_credentials(base: &TunnelBase) -> bool {
    if base.kind != BaseKind::Ssh {
        return false;
    }
    if base.username.trim().is_empty() {
        return true;
    }
    match base.auth_type {
        AuthType::Password => base.password.as_deref().unwrap_or("").is_empty(),
        AuthType::PrivateKey => base
            .key_path
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty(),
    }
}

fn base_config_equal(a: &TunnelBase, b: &TunnelBase) -> bool {
    a.id == b.id
        && a.name == b.name
        && a.kind == b.kind
        && a.host == b.host
        && a.port == b.port
        && a.username == b.username
        && a.auth_type == b.auth_type
        && a.password == b.password
        && a.key_path == b.key_path
        && a.key_passphrase == b.key_passphrase
        && a.enabled == b.enabled
}

async fn set_base_state(
    inner: &Arc<RwLock<HashMap<String, BaseRuntime>>>,
    base_id: &str,
    status: BaseStatus,
    latency_ms: Option<u64>,
    last_error: Option<String>,
    handle: Option<Arc<client::Handle<ClientHandler>>>,
) {
    let mut map = inner.write().await;
    if let Some(rt) = map.get_mut(base_id) {
        rt.status = status;
        rt.latency_ms = latency_ms;
        rt.last_error = last_error;
        rt.handle = handle;
    }
}

async fn base_worker(
    inner: Arc<RwLock<HashMap<String, BaseRuntime>>>,
    base: TunnelBase,
    cancel: CancellationToken,
    wake: Arc<Notify>,
    auto_hide_uu: Arc<AtomicBool>,
) {
    if !base.enabled {
        set_base_state(&inner, &base.id, BaseStatus::Disconnected, None, None, None).await;
        return;
    }

    if needs_credentials(&base) {
        set_base_state(
            &inner,
            &base.id,
            BaseStatus::NeedsCredentials,
            None,
            Some("请先填写 SSH 用户名与密码/私钥路径".to_string()),
            None,
        )
        .await;
        return;
    }

    match base.kind {
        BaseKind::Direct => {
            set_base_state(&inner, &base.id, BaseStatus::Connected, Some(0), None, None).await;
            cancel.cancelled().await;
        }
        BaseKind::Socks5 => {
            let mut backoff = 2u64;
            loop {
                if cancel.is_cancelled() {
                    break;
                }
                let t0 = Instant::now();
                match tokio::time::timeout(
                    Duration::from_secs(4),
                    TcpStream::connect((base.host.as_str(), base.port)),
                )
                .await
                {
                    Ok(Ok(_)) => {
                        let ms = t0.elapsed().as_millis() as u64;
                        set_base_state(
                            &inner,
                            &base.id,
                            BaseStatus::Connected,
                            Some(ms),
                            None,
                            None,
                        )
                        .await;
                        backoff = 2;
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                            _ = wake.notified() => {}
                        }
                    }
                    Ok(Err(e)) => {
                        set_base_state(
                            &inner,
                            &base.id,
                            BaseStatus::Error,
                            None,
                            Some(format!("SOCKS5 基座不可达: {e}")),
                            None,
                        )
                        .await;
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
                            _ = wake.notified() => {}
                        }
                        backoff = (backoff * 2).min(10);
                    }
                    Err(_) => {
                        set_base_state(
                            &inner,
                            &base.id,
                            BaseStatus::Error,
                            None,
                            Some("SOCKS5 基座连接超时".to_string()),
                            None,
                        )
                        .await;
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
                            _ = wake.notified() => {}
                        }
                        backoff = (backoff * 2).min(10);
                    }
                }
            }
        }
        BaseKind::Ssh => {
            let mut backoff = 2u64;
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                set_base_state(
                    &inner,
                    &base.id,
                    BaseStatus::Connecting,
                    None,
                    None,
                    None,
                )
                .await;

                match connect_ssh(&base).await {
                    Ok((handle, initial_lat)) => {
                        let handle = Arc::new(handle);
                        let lat = probe_ssh_ping(&handle).await.unwrap_or(initial_lat);
                        info!(base_id = %base.id, host = %base.host, port = base.port, lat_ms = lat, "SSH base connected");
                        set_base_state(
                            &inner,
                            &base.id,
                            BaseStatus::Connected,
                            Some(lat),
                            None,
                            Some(handle.clone()),
                        )
                        .await;
                        backoff = 2;

                        if auto_hide_uu.load(Ordering::Relaxed) {
                            tokio::task::spawn_blocking(|| {
                                let _ = crate::uu_window::hide_portmap_windows();
                            });
                        }

                        // Monitor connection health and update real end-to-end SSH RTT periodically
                        loop {
                            tokio::select! {
                                _ = cancel.cancelled() => {
                                    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
                                    return;
                                }
                                _ = wake.notified() => {
                                    if handle.is_closed() {
                                        break;
                                    }
                                }
                                _ = tokio::time::sleep(Duration::from_secs(12)) => {
                                    if handle.is_closed() {
                                        warn!(base_id = %base.id, "SSH session closed");
                                        break;
                                    }
                                    match probe_ssh_ping(&handle).await {
                                        Ok(rtt) => {
                                            let mut map = inner.write().await;
                                            if let Some(rt) = map.get_mut(&base.id) {
                                                rt.latency_ms = Some(rtt);
                                            }
                                        }
                                        Err(e) => {
                                            warn!(base_id = %base.id, err = %e, "SSH ping failed, reconnecting");
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        set_base_state(
                            &inner,
                            &base.id,
                            BaseStatus::Error,
                            None,
                            Some("SSH 会话已断开，正在尝试重连".to_string()),
                            None,
                        )
                        .await;
                    }
                    Err(e) => {
                        debug!(base_id = %base.id, err = %e, "SSH base connect failed");
                        set_base_state(
                            &inner,
                            &base.id,
                            BaseStatus::Error,
                            None,
                            Some(e.to_string()),
                            None,
                        )
                        .await;
                    }
                }

                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = wake.notified() => { backoff = 2; }
                    _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
                }
                backoff = (backoff * 2).min(10);
            }
        }
    }
}

async fn probe_ssh_ping(handle: &client::Handle<ClientHandler>) -> Result<u64> {
    let t0 = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), handle.send_ping())
        .await
        .map_err(|_| anyhow!("SSH ping 超时"))?
        .map_err(|e| anyhow!("SSH ping 失败: {e}"))?;
    Ok(t0.elapsed().as_millis() as u64)
}

async fn connect_ssh(base: &TunnelBase) -> Result<(client::Handle<ClientHandler>, u64)> {
    let t0 = Instant::now();
    let tcp = tokio::time::timeout(
        Duration::from_secs(8),
        TcpStream::connect((base.host.as_str(), base.port)),
    )
    .await
    .map_err(|_| anyhow!("连接 SSH 基座 {}:{} 超时（请确认 UU 端口映射已开启）", base.host, base.port))?
    .map_err(|e| anyhow!("无法连接 {}:{} ({e})，请确认 UU 端口映射已开启", base.host, base.port))?;
    let _ = tcp.set_nodelay(true);

    let config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        inactivity_timeout: None,
        ..Default::default()
    });

    let mut handle = tokio::time::timeout(
        Duration::from_secs(10),
        client::connect_stream(config, tcp, ClientHandler),
    )
    .await
    .map_err(|_| anyhow!("SSH 握手超时"))?
    .map_err(|e| anyhow!("SSH 握手失败: {e}"))?;

    match base.auth_type {
        AuthType::Password => {
            let pwd = base.password.as_deref().unwrap_or("");
            let res = handle
                .authenticate_password(&base.username, pwd)
                .await
                .map_err(|e| anyhow!("SSH 密码认证异常: {e}"))?;
            if !res.success() {
                anyhow::bail!("SSH 密码认证被拒绝（用户名或密码错误）");
            }
        }
        AuthType::PrivateKey => {
            let key_path = base.key_path.as_deref().unwrap_or("").trim();
            let passphrase = base
                .key_passphrase
                .as_deref()
                .filter(|p| !p.is_empty());
            let key = load_secret_key(key_path, passphrase)
                .with_context(|| format!("读取 SSH 私钥失败: {key_path}"))?;
            let hash_alg = handle.best_supported_rsa_hash().await.ok().flatten().flatten();
            let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
            let res = handle
                .authenticate_publickey(&base.username, key_with_alg)
                .await
                .map_err(|e| anyhow!("SSH 私钥认证异常: {e}"))?;
            if !res.success() {
                anyhow::bail!("SSH 私钥认证被拒绝");
            }
        }
    }

    let lat = t0.elapsed().as_millis() as u64;
    Ok((handle, lat))
}

async fn socks5_connect(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    let mut s = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect((proxy_host, proxy_port)),
    )
    .await
    .context("连接 SOCKS5 基座超时")??;
    let _ = s.set_nodelay(true);

    // Greeting: VER=5, NMETHODS=1, NOAUTH=0
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greet = [0u8; 2];
    s.read_exact(&mut greet).await?;
    if greet != [0x05, 0x00] {
        anyhow::bail!("SOCKS5 认证协商失败: {greet:?}");
    }

    let mut req = Vec::with_capacity(64);
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(ipv4) = target_host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ipv4.octets());
    } else {
        let host_bytes = target_host.as_bytes();
        if host_bytes.len() > 255 {
            anyhow::bail!("目标域名过长");
        }
        req.push(0x03);
        req.push(host_bytes.len() as u8);
        req.extend_from_slice(host_bytes);
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        anyhow::bail!("SOCKS5 连接目标 {target_host}:{target_port} 失败 (rep={})", head[1]);
    }
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            s.read_exact(&mut rest).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut rest).await?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            s.read_exact(&mut rest).await?;
        }
        _ => anyhow::bail!("未知 SOCKS5 ATYP: {}", head[3]),
    }

    Ok(s)
}
