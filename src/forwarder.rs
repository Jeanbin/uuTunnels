use crate::config::{AppConfig, ForwardRule};
use crate::ssh_engine::SshEngine;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleStatus {
    Stopped,
    Running,
    WaitingBase,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleRuntimeSnapshot {
    pub status: RuleStatus,
    pub active_conns: u64,
    pub total_conns: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub ok: bool,
    pub latency_ms: u64,
    pub detail: String,
}

struct RuleCounters {
    active_conns: AtomicU64,
    total_conns: AtomicU64,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bps: AtomicU64,
    tx_bps: AtomicU64,
    status: RwLock<RuleStatus>,
    last_error: RwLock<Option<String>>,
}

impl RuleCounters {
    fn new(status: RuleStatus) -> Self {
        Self {
            active_conns: AtomicU64::new(0),
            total_conns: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bps: AtomicU64::new(0),
            tx_bps: AtomicU64::new(0),
            status: RwLock::new(status),
            last_error: RwLock::new(None),
        }
    }
}

struct RuleHandle {
    rule: ForwardRule,
    base_id: String,
    cancel: CancellationToken,
    counters: Arc<RuleCounters>,
}

pub struct ForwarderManager {
    rules: Arc<RwLock<HashMap<String, RuleHandle>>>,
    ssh: Arc<SshEngine>,
    root_cancel: CancellationToken,
}

impl ForwarderManager {
    pub fn new(ssh: Arc<SshEngine>, root_cancel: CancellationToken) -> Self {
        let rules: Arc<RwLock<HashMap<String, RuleHandle>>> = Arc::new(RwLock::new(HashMap::new()));
        let sampler_rules = rules.clone();
        let sampler_cancel = root_cancel.clone();
        tokio::spawn(async move {
            let mut prev: HashMap<String, (u64, u64)> = HashMap::new();
            loop {
                tokio::select! {
                    _ = sampler_cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {
                        let items: Vec<(String, Arc<RuleCounters>)> = {
                            let map = sampler_rules.read().await;
                            map.iter().map(|(id, h)| (id.clone(), h.counters.clone())).collect()
                        };
                        let mut next_prev = HashMap::with_capacity(items.len());
                        for (id, c) in items {
                            let rx = c.rx_bytes.load(Ordering::Relaxed);
                            let tx = c.tx_bytes.load(Ordering::Relaxed);
                            let (prx, ptx) = prev.get(&id).copied().unwrap_or((rx, tx));
                            c.rx_bps.store(rx.saturating_sub(prx), Ordering::Relaxed);
                            c.tx_bps.store(tx.saturating_sub(ptx), Ordering::Relaxed);
                            next_prev.insert(id, (rx, tx));
                        }
                        prev = next_prev;
                    }
                }
            }
        });
        Self {
            rules,
            ssh,
            root_cancel,
        }
    }

    pub async fn sync_all(&self, cfg: &AppConfig) {
        let machine_base: HashMap<&str, &str> = cfg
            .machines
            .iter()
            .map(|m| (m.id.as_str(), m.base_id.as_str()))
            .collect();

        let existing_ids: Vec<String> = {
            let map = self.rules.read().await;
            map.keys().cloned().collect()
        };
        let desired_ids: HashSet<&str> = cfg.rules.iter().map(|r| r.id.as_str()).collect();
        for id in existing_ids {
            if !desired_ids.contains(id.as_str()) {
                self.stop_and_remove(&id).await;
            }
        }

        for rule in &cfg.rules {
            let base_id = machine_base
                .get(rule.machine_id.as_str())
                .copied()
                .unwrap_or("")
                .to_string();
            self.sync_rule(rule.clone(), base_id).await;
        }
    }

    pub async fn stop_and_remove(&self, rule_id: &str) {
        let mut map = self.rules.write().await;
        if let Some(h) = map.remove(rule_id) {
            h.cancel.cancel();
        }
    }

    pub async fn sync_rule(&self, rule: ForwardRule, base_id: String) {
        {
            let mut map = self.rules.write().await;
            if let Some(existing) = map.get(&rule.id) {
                if rule_equal(&existing.rule, &rule) && existing.base_id == base_id {
                    return;
                }
                existing.cancel.cancel();
            }
            if !rule.enabled {
                let cancel = self.root_cancel.child_token();
                let counters = Arc::new(RuleCounters::new(RuleStatus::Stopped));
                map.insert(
                    rule.id.clone(),
                    RuleHandle {
                        rule,
                        base_id,
                        cancel,
                        counters,
                    },
                );
                return;
            }
        }

        let cancel = self.root_cancel.child_token();
        let counters = Arc::new(RuleCounters::new(RuleStatus::WaitingBase));
        {
            let mut map = self.rules.write().await;
            map.insert(
                rule.id.clone(),
                RuleHandle {
                    rule: rule.clone(),
                    base_id: base_id.clone(),
                    cancel: cancel.clone(),
                    counters: counters.clone(),
                },
            );
        }

        let bind_addr = format!("{}:{}", rule.local_host, rule.local_port);
        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                warn!(rule = %rule.name, addr = %bind_addr, err = %e, "Failed to bind local port");
                *counters.status.write().await = RuleStatus::Error;
                *counters.last_error.write().await = Some(format!("监听 {bind_addr} 失败: {e}"));
                return;
            }
        };

        info!(rule = %rule.name, addr = %bind_addr, target = %format!("{}:{}", rule.target_host, rule.target_port), "Forwarder rule listening");
        *counters.status.write().await = RuleStatus::Running;

        let ssh = self.ssh.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        debug!(rule = %rule.name, "Forwarder listener stopped");
                        break;
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((local_stream, peer_addr)) => {
                                let _ = local_stream.set_nodelay(true);
                                let ssh = ssh.clone();
                                let counters = counters.clone();
                                let rule_cancel = cancel.clone();
                                let target_host = rule.target_host.clone();
                                let target_port = rule.target_port;
                                let base_id = base_id.clone();

                                tokio::spawn(async move {
                                    counters.active_conns.fetch_add(1, Ordering::Relaxed);
                                    counters.total_conns.fetch_add(1, Ordering::Relaxed);

                                    let res = handle_conn(
                                        local_stream,
                                        peer_addr,
                                        ssh,
                                        base_id,
                                        target_host,
                                        target_port,
                                        counters.clone(),
                                        rule_cancel,
                                    ).await;

                                    if let Err(e) = res {
                                        *counters.last_error.write().await = Some(e.to_string());
                                    } else {
                                        *counters.last_error.write().await = None;
                                    }

                                    counters.active_conns.fetch_sub(1, Ordering::Relaxed);
                                });
                            }
                            Err(e) => {
                                warn!(rule = %rule.name, err = %e, "Accept error");
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            }
        });
    }

    pub async fn snapshot_all(&self) -> HashMap<String, RuleRuntimeSnapshot> {
        let entries: Vec<(String, String, bool, Arc<RuleCounters>)> = {
            let map = self.rules.read().await;
            map.iter()
                .map(|(id, h)| (id.clone(), h.base_id.clone(), h.rule.enabled, h.counters.clone()))
                .collect()
        };

        let mut out = HashMap::with_capacity(entries.len());
        for (id, base_id, enabled, counters) in entries {
            let mut status = counters.status.read().await.clone();
            if enabled && status == RuleStatus::Running && !self.ssh.is_base_ready(&base_id).await {
                status = RuleStatus::WaitingBase;
            }
            let last_error = counters.last_error.read().await.clone();
            out.insert(
                id,
                RuleRuntimeSnapshot {
                    status,
                    active_conns: counters.active_conns.load(Ordering::Relaxed),
                    total_conns: counters.total_conns.load(Ordering::Relaxed),
                    rx_bytes: counters.rx_bytes.load(Ordering::Relaxed),
                    tx_bytes: counters.tx_bytes.load(Ordering::Relaxed),
                    rx_bps: counters.rx_bps.load(Ordering::Relaxed),
                    tx_bps: counters.tx_bps.load(Ordering::Relaxed),
                    last_error,
                },
            );
        }
        out
    }

    pub async fn probe_rule(&self, base_id: &str, rule: &ForwardRule) -> ProbeResult {
        let t0 = Instant::now();
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], rule.local_port));
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(6),
            self.ssh
                .open_stream(base_id, &rule.target_host, rule.target_port, peer_addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return ProbeResult {
                    ok: false,
                    latency_ms: t0.elapsed().as_millis() as u64,
                    detail: e.to_string(),
                };
            }
            Err(_) => {
                return ProbeResult {
                    ok: false,
                    latency_ms: t0.elapsed().as_millis() as u64,
                    detail: "探测超时 (6s)".to_string(),
                };
            }
        };

        let connect_ms = t0.elapsed().as_millis() as u64;
        let detail = match rule.protocol.as_str() {
            "ssh" => {
                let mut buf = [0u8; 128];
                match tokio::time::timeout(Duration::from_millis(1500), stream.read(&mut buf)).await
                {
                    Ok(Ok(n)) if n > 0 => {
                        let line = String::from_utf8_lossy(&buf[..n])
                            .lines()
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if line.is_empty() {
                            "TCP 通道连通".to_string()
                        } else {
                            line
                        }
                    }
                    _ => "TCP 通道连通 (无 banner)".to_string(),
                }
            }
            "http" => {
                let norm = crate::config::normalize_url_path(&rule.url_path);
                let without_frag = norm.split('#').next().unwrap_or("");
                let probe_target = if without_frag.is_empty() {
                    "/".to_string()
                } else if without_frag.starts_with('/') {
                    without_frag.to_string()
                } else {
                    format!("/{without_frag}")
                };
                let req = format!(
                    "HEAD {probe_target} HTTP/1.0\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
                    rule.target_host, rule.target_port
                );
                if stream.write_all(req.as_bytes()).await.is_ok() {
                    let mut buf = [0u8; 256];
                    match tokio::time::timeout(Duration::from_millis(1500), stream.read(&mut buf))
                        .await
                    {
                        Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n])
                            .lines()
                            .next()
                            .unwrap_or("HTTP 已响应")
                            .trim()
                            .to_string(),
                        _ => "TCP 通道连通".to_string(),
                    }
                } else {
                    "TCP 通道连通".to_string()
                }
            }
            _ => "TCP 通道连通".to_string(),
        };
        let total_ms = t0.elapsed().as_millis() as u64;
        let _ = stream.shutdown().await;

        ProbeResult {
            ok: true,
            latency_ms: total_ms.max(connect_ms),
            detail,
        }
    }
}

fn is_benign_disconnect(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    ) || matches!(err.raw_os_error(), Some(10053) | Some(10054))
}

async fn handle_conn(
    local_stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    ssh: Arc<SshEngine>,
    base_id: String,
    target_host: String,
    target_port: u16,
    counters: Arc<RuleCounters>,
    rule_cancel: CancellationToken,
) -> anyhow::Result<()> {
    let remote_stream = ssh
        .open_stream(&base_id, &target_host, target_port, peer_addr)
        .await?;

    // Clear any previous transient error as soon as a new connection opens cleanly
    *counters.last_error.write().await = None;

    let mut local_counted = CountingStream {
        inner: local_stream,
        counters,
    };
    let mut remote_stream = remote_stream;

    tokio::select! {
        _ = rule_cancel.cancelled() => Ok(()),
        res = tokio::io::copy_bidirectional(&mut local_counted, &mut remote_stream) => {
            match res {
                Ok(_) => Ok(()),
                Err(e) if is_benign_disconnect(&e) => {
                    debug!(peer = %peer_addr, target = %format!("{target_host}:{target_port}"), err = %e, "Client/remote closed forwarded connection");
                    Ok(())
                }
                Err(e) => Err(e.into()),
            }
        }
    }
}

struct CountingStream {
    inner: TcpStream,
    counters: Arc<RuleCounters>,
}

impl AsyncRead for CountingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let n = buf.filled().len().saturating_sub(before) as u64;
            if n > 0 {
                self.counters.tx_bytes.fetch_add(n, Ordering::Relaxed);
            }
        }
        res
    }
}

impl AsyncWrite for CountingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                self.counters.rx_bytes.fetch_add(*n as u64, Ordering::Relaxed);
            }
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn rule_equal(a: &ForwardRule, b: &ForwardRule) -> bool {
    a.id == b.id
        && a.machine_id == b.machine_id
        && a.name == b.name
        && a.protocol == b.protocol
        && a.local_host == b.local_host
        && a.local_port == b.local_port
        && a.target_host == b.target_host
        && a.target_port == b.target_port
        && a.enabled == b.enabled
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthType, BaseKind, TunnelBase};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn forwarder_direct_toggle_lifecycle() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    if let Ok(n) = s.read(&mut buf).await {
                        let _ = s.write_all(&buf[..n]).await;
                    }
                });
            }
        });

        // Reserve a free port for the forwarder
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fwd_port = probe.local_addr().unwrap().port();
        drop(probe);

        let root = CancellationToken::new();
        let ssh = Arc::new(SshEngine::new(root.clone()));
        let fwd = ForwarderManager::new(ssh.clone(), root.clone());

        let base = TunnelBase {
            id: "direct".into(),
            name: "Direct".into(),
            kind: BaseKind::Direct,
            host: "127.0.0.1".into(),
            port: 0,
            username: "".into(),
            auth_type: AuthType::Password,
            password: None,
            key_path: None,
            key_passphrase: None,
            enabled: true,
        };
        ssh.upsert_base(base).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut rule = ForwardRule {
            id: "r1".into(),
            machine_id: "m1".into(),
            name: "Echo".into(),
            protocol: "tcp".into(),
            local_host: "127.0.0.1".into(),
            local_port: fwd_port,
            target_host: "127.0.0.1".into(),
            target_port: echo_port,
            url_path: String::new(),
            enabled: true,
            pinned: false,
        };
        fwd.sync_rule(rule.clone(), "direct".into()).await;

        let probe_res = fwd.probe_rule("direct", &rule).await;
        assert!(probe_res.ok);

        // Send and receive payload
        let mut client = TcpStream::connect(("127.0.0.1", fwd_port)).await.unwrap();
        client.write_all(b"hello-uutunnels").await.unwrap();
        let mut resp = [0u8; 15];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"hello-uutunnels");
        drop(client);

        let snap = fwd.snapshot_all().await;
        let r1 = snap.get("r1").unwrap();
        assert_eq!(r1.status, RuleStatus::Running);
        assert!(r1.rx_bytes >= 15 && r1.tx_bytes >= 15);

        // Toggle OFF -> port must close
        rule.enabled = false;
        fwd.sync_rule(rule.clone(), "direct".into()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(TcpStream::connect(("127.0.0.1", fwd_port)).await.is_err());

        // Toggle ON again -> port works again
        rule.enabled = true;
        fwd.sync_rule(rule, "direct".into()).await;
        let mut client2 = TcpStream::connect(("127.0.0.1", fwd_port)).await.unwrap();
        client2.write_all(b"ok").await.unwrap();
        let mut resp2 = [0u8; 2];
        client2.read_exact(&mut resp2).await.unwrap();
        assert_eq!(&resp2, b"ok");

        root.cancel();
    }

    #[test]
    fn benign_disconnect_errors_are_ignored() {
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::NotConnected,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(is_benign_disconnect(&io::Error::new(kind, "closed")));
        }
        assert!(is_benign_disconnect(&io::Error::from_raw_os_error(10054)));
        assert!(is_benign_disconnect(&io::Error::from_raw_os_error(10053)));

        assert!(!is_benign_disconnect(&io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "refused"
        )));
        assert!(!is_benign_disconnect(&io::Error::new(
            io::ErrorKind::TimedOut,
            "timeout"
        )));
    }
}
