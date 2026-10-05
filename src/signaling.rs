//! 信令：房间协调与候选交换。
//!
//! 对应 `docs/设计.md` §5。核心约定：
//!
//! - **无鉴权**：连接即可用，不校验账号、不校验 token。
//! - **匿名身份**：`peer_id` 由客户端自己生成，服务端不校验、不持久化、重启即忘。
//! - **信令内容不落盘**：这里只有内存状态。
//! - 当前只支持**一对一**会话（这是产品定位决定的，多人时再评估）。

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// 信令协议版本。客户端 `hello` 里上报的版本若高于此值会被拒绝。
pub const PROTOCOL_VERSION: u32 = 1;

/// 一个会话最多容纳的连接数（一对一）。
const MAX_MEMBERS: usize = 2;

/// 客户端 → 服务端 消息。
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// 声明匿名身份。必须最先发送。
    Hello {
        peer_id: String,
        #[serde(default)]
        protocol_version: u32,
    },
    /// 创建一个会话，返回短码 `session_id`。
    Create,
    /// 用短码加入会话。
    Join { session_id: String },
    /// 透传 SDP offer。
    Offer { payload: serde_json::Value },
    /// 透传 SDP answer。
    Answer { payload: serde_json::Value },
    /// 透传单个 ICE 候选。
    Candidate { payload: serde_json::Value },
    /// 主动离开。
    Bye,
}

/// 服务端 → 客户端 消息。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    Hello {
        protocol_version: u32,
    },
    Created {
        session_id: String,
    },
    Joined {
        session_id: String,
    },
    PeerJoined {
        peer_id: String,
    },
    PeerLeft {
        peer_id: String,
    },
    Offer {
        from: String,
        payload: serde_json::Value,
    },
    Answer {
        from: String,
        payload: serde_json::Value,
    },
    Candidate {
        from: String,
        payload: serde_json::Value,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug)]
struct Peer {
    /// 匿名身份，由客户端声明；空字符串表示还没发 `hello`。
    peer_id: String,
    session_id: Option<String>,
    tx: mpsc::UnboundedSender<ServerMsg>,
    last_active: Instant,
}

#[derive(Debug, Default)]
struct Inner {
    peers: HashMap<u64, Peer>,
    sessions: HashMap<String, Vec<u64>>,
    next_conn_id: u64,
}

/// 信令中心。所有状态都在内存里，进程重启即清空。
#[derive(Debug)]
pub struct SignalingHub {
    idle_timeout: Duration,
    inner: Mutex<Inner>,
}

impl SignalingHub {
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            idle_timeout,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// 注册一条新连接，返回连接 ID。
    pub fn register(&self, tx: mpsc::UnboundedSender<ServerMsg>) -> u64 {
        let mut inner = self.lock();
        inner.next_conn_id += 1;
        let conn = inner.next_conn_id;
        inner.peers.insert(
            conn,
            Peer {
                peer_id: String::new(),
                session_id: None,
                tx,
                last_active: Instant::now(),
            },
        );
        conn
    }

    /// 注销连接，并通知会话内的其他人。
    pub fn unregister(&self, conn: u64) {
        let mut inner = self.lock();

        let Some(peer) = inner.peers.remove(&conn) else {
            return;
        };

        let Some(session_id) = peer.session_id else {
            return;
        };

        let mut notify: Vec<mpsc::UnboundedSender<ServerMsg>> = Vec::new();
        if let Some(members) = inner.sessions.get_mut(&session_id) {
            members.retain(|id| *id != conn);
        }
        // 分成两次不可变借用，避免同时持有 sessions 与 peers 的可变借用。
        if let Some(members) = inner.sessions.get(&session_id) {
            for id in members.iter() {
                if let Some(p) = inner.peers.get(id) {
                    notify.push(p.tx.clone());
                }
            }
        }

        let empty = inner
            .sessions
            .get(&session_id)
            .map(|m| m.is_empty())
            .unwrap_or(true);
        if empty {
            inner.sessions.remove(&session_id);
        }
        drop(inner);

        for tx in notify {
            let _ = tx.send(ServerMsg::PeerLeft {
                peer_id: peer.peer_id.clone(),
            });
        }
    }

    /// 记录匿名身份。
    pub fn set_peer_id(&self, conn: u64, peer_id: String) {
        let mut inner = self.lock();
        if let Some(peer) = inner.peers.get_mut(&conn) {
            peer.peer_id = peer_id;
            peer.last_active = Instant::now();
        }
    }

    /// 读取匿名身份（未 `hello` 时为空字符串）。
    pub fn peer_id(&self, conn: u64) -> Option<String> {
        self.lock().peers.get(&conn).map(|p| p.peer_id.clone())
    }

    /// 刷新活跃时间。
    pub fn touch(&self, conn: u64) {
        let mut inner = self.lock();
        if let Some(peer) = inner.peers.get_mut(&conn) {
            peer.last_active = Instant::now();
        }
    }

    /// 创建会话，返回短码。
    pub fn create_session(&self, conn: u64) -> Result<String, String> {
        let mut inner = self.lock();

        let peer_id = inner
            .peers
            .get(&conn)
            .map(|p| p.peer_id.clone())
            .ok_or_else(|| "连接未注册".to_string())?;
        if peer_id.is_empty() {
            return Err("请先发送 hello 声明匿名身份".to_string());
        }

        let session_id = loop {
            let candidate = new_session_id();
            if !inner.sessions.contains_key(&candidate) {
                break candidate;
            }
        };

        inner.sessions.insert(session_id.clone(), vec![conn]);
        if let Some(peer) = inner.peers.get_mut(&conn) {
            peer.session_id = Some(session_id.clone());
            peer.last_active = Instant::now();
        }
        Ok(session_id)
    }

    /// 加入会话。
    pub fn join_session(&self, conn: u64, session_id: &str) -> Result<(), String> {
        let mut inner = self.lock();

        let peer_id = inner
            .peers
            .get(&conn)
            .map(|p| p.peer_id.clone())
            .ok_or_else(|| "连接未注册".to_string())?;
        if peer_id.is_empty() {
            return Err("请先发送 hello 声明匿名身份".to_string());
        }

        let members = inner
            .sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| "会话不存在或已失效".to_string())?;

        if members.contains(&conn) {
            return Ok(()); // 幂等
        }
        if members.len() >= MAX_MEMBERS {
            return Err("会话已满（当前仅支持一对一）".to_string());
        }

        if let Some(list) = inner.sessions.get_mut(session_id) {
            list.push(conn);
        }
        if let Some(peer) = inner.peers.get_mut(&conn) {
            peer.session_id = Some(session_id.to_string());
            peer.last_active = Instant::now();
        }

        // 通知已在会话里的其他人（此时只有对端）。
        let notify: Vec<mpsc::UnboundedSender<ServerMsg>> = members
            .iter()
            .filter_map(|id| inner.peers.get(id).map(|p| p.tx.clone()))
            .collect();
        drop(inner);

        for tx in notify {
            let _ = tx.send(ServerMsg::PeerJoined {
                peer_id: peer_id.clone(),
            });
        }
        Ok(())
    }

    /// 把消息转发给同会话的对端。
    pub fn relay(&self, conn: u64, msg: ServerMsg) -> Result<(), String> {
        let inner = self.lock();

        let session_id = inner
            .peers
            .get(&conn)
            .and_then(|p| p.session_id.clone())
            .ok_or_else(|| "尚未加入任何会话".to_string())?;

        let members = inner.sessions.get(&session_id).cloned().unwrap_or_default();
        let targets: Vec<mpsc::UnboundedSender<ServerMsg>> = members
            .iter()
            .filter(|id| **id != conn)
            .filter_map(|id| inner.peers.get(id).map(|p| p.tx.clone()))
            .collect();
        drop(inner);

        if targets.is_empty() {
            return Err("对端尚未加入会话".to_string());
        }
        for tx in targets {
            let _ = tx.send(msg.clone());
        }
        Ok(())
    }

    /// 给指定连接发消息。
    pub fn send_to(&self, conn: u64, msg: ServerMsg) -> bool {
        let tx = self
            .lock()
            .peers
            .get(&conn)
            .map(|p| p.tx.clone());
        match tx {
            Some(tx) => tx.send(msg).is_ok(),
            None => false,
        }
    }

    /// 回收空闲连接，返回回收数量。
    pub fn gc(&self) -> usize {
        let stale: Vec<u64> = {
            let inner = self.lock();
            let now = Instant::now();
            inner
                .peers
                .iter()
                .filter(|(_, p)| now.duration_since(p.last_active) >= self.idle_timeout)
                .map(|(id, _)| *id)
                .collect()
        };

        for conn in &stale {
            self.unregister(*conn);
        }
        stale.len()
    }

    /// 当前连接数。
    pub fn active_connections(&self) -> usize {
        self.lock().peers.len()
    }

    /// 当前会话数。
    pub fn active_sessions(&self) -> usize {
        self.lock().sessions.len()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // 互斥锁中毒不应让服务停摆。
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// 生成 8 位十六进制短码。注意：这是**防碰撞**而非防猜测，安全性由 E2EE 负责。
fn new_session_id() -> String {
    let raw = uuid::Uuid::new_v4().simple().to_string();
    raw[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hub_with_peer() -> (SignalingHub, u64, mpsc::UnboundedReceiver<ServerMsg>) {
        let hub = SignalingHub::new(Duration::from_secs(120));
        let (tx, rx) = mpsc::unbounded_channel();
        let conn = hub.register(tx);
        hub.set_peer_id(conn, "peer-a".to_string());
        (hub, conn, rx)
    }

    #[test]
    fn 创建会话返回短码() {
        let (hub, conn, mut rx) = hub_with_peer();
        let session_id = hub.create_session(conn).expect("创建应当成功");
        assert_eq!(session_id.len(), 8);
        assert_eq!(hub.active_sessions(), 1);
        // 不应给创建者回消息（由上层发送 Created）
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn 未声明身份不能创建会话() {
        let hub = SignalingHub::new(Duration::from_secs(120));
        let (tx, _rx) = mpsc::unbounded_channel();
        let conn = hub.register(tx);
        assert!(hub.create_session(conn).is_err());
    }

    #[test]
    fn 对端加入后收到通知且能转发() {
        let hub = SignalingHub::new(Duration::from_secs(120));

        let (tx_a, mut rx_a) = mpsc::unbounded_channel();
        let a = hub.register(tx_a);
        hub.set_peer_id(a, "peer-a".to_string());
        let session_id = hub.create_session(a).unwrap();

        let (tx_b, mut rx_b) = mpsc::unbounded_channel();
        let b = hub.register(tx_b);
        hub.set_peer_id(b, "peer-b".to_string());
        hub.join_session(b, &session_id).unwrap();

        // A 应收到 PeerJoined
        match rx_a.try_recv().expect("A 应收到 PeerJoined") {
            ServerMsg::PeerJoined { peer_id } => assert_eq!(peer_id, "peer-b"),
            other => panic!("收到意外消息: {other:?}"),
        }

        // B 的 offer 应转给 A
        hub.relay(
            b,
            ServerMsg::Offer {
                from: "peer-b".to_string(),
                payload: serde_json::json!({"sdp": "x"}),
            },
        )
        .unwrap();

        match rx_a.try_recv().expect("A 应收到 Offer") {
            ServerMsg::Offer { from, .. } => assert_eq!(from, "peer-b"),
            other => panic!("收到意外消息: {other:?}"),
        }
        // B 自己不应收到自己的消息
        assert!(rx_b.try_recv().is_err());
    }

    #[test]
    fn 会话满员后拒绝第三人() {
        let hub = SignalingHub::new(Duration::from_secs(120));

        let (tx_a, _rx_a) = mpsc::unbounded_channel();
        let a = hub.register(tx_a);
        hub.set_peer_id(a, "peer-a".into());
        let session_id = hub.create_session(a).unwrap();

        let (tx_b, _rx_b) = mpsc::unbounded_channel();
        let b = hub.register(tx_b);
        hub.set_peer_id(b, "peer-b".into());
        hub.join_session(b, &session_id).unwrap();

        let (tx_c, _rx_c) = mpsc::unbounded_channel();
        let c = hub.register(tx_c);
        hub.set_peer_id(c, "peer-c".into());
        assert!(hub.join_session(c, &session_id).is_err());
    }

    #[test]
    fn 断开后对端收到_peer_left_且会话被回收() {
        let hub = SignalingHub::new(Duration::from_secs(120));

        let (tx_a, mut rx_a) = mpsc::unbounded_channel();
        let a = hub.register(tx_a);
        hub.set_peer_id(a, "peer-a".into());
        let session_id = hub.create_session(a).unwrap();

        let (tx_b, _rx_b) = mpsc::unbounded_channel();
        let b = hub.register(tx_b);
        hub.set_peer_id(b, "peer-b".into());
        hub.join_session(b, &session_id).unwrap();
        let _ = rx_a.try_recv(); // 丢掉 PeerJoined

        hub.unregister(b);

        match rx_a.try_recv().expect("A 应收到 PeerLeft") {
            ServerMsg::PeerLeft { peer_id } => assert_eq!(peer_id, "peer-b"),
            other => panic!("收到意外消息: {other:?}"),
        }
        assert_eq!(hub.active_connections(), 1);
        assert_eq!(hub.active_sessions(), 1, "会话里还有 A");
    }

    #[test]
    fn 加入不存在的会话报错() {
        let (hub, conn, _rx) = hub_with_peer();
        assert!(hub.join_session(conn, "deadbeef").is_err());
    }

    #[test]
    fn 未加入会话不能转发() {
        let (hub, conn, _rx) = hub_with_peer();
        let err = hub.relay(
            conn,
            ServerMsg::Error {
                code: "x".into(),
                message: "y".into(),
            },
        );
        assert!(err.is_err());
    }

    #[test]
    fn 空闲连接会被回收() {
        let hub = SignalingHub::new(Duration::from_millis(0));
        let (tx, _rx) = mpsc::unbounded_channel();
        let conn = hub.register(tx);
        hub.set_peer_id(conn, "peer-a".into());
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(hub.gc(), 1);
        assert_eq!(hub.active_connections(), 0);
    }

    #[test]
    fn 短码长度稳定() {
        for _ in 0..64 {
            assert_eq!(new_session_id().len(), 8);
        }
    }
}
