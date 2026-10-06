//! HTTP 与 WebSocket 接口。
//!
//! | 路由 | 说明 |
//! |---|---|
//! | `GET /healthz` | 健康检查与配置自检 |
//! | `GET /metrics` | Prometheus 文本指标 |
//! | `GET|POST /api/v1/ice` | 下发 STUN/TURN 配置（含短期凭据） |
//! | `GET /api/v1/relay` | 中继发现：信令地址 + ICE 列表 + 短期凭据 |
//! | `GET /ws/signal` | 信令 WebSocket |
//!
//! **没有任何鉴权。** 这是产品决策（见 `docs/设计.md` §1），
//! 配套的滥用防护是每 IP 配额与短期凭据（§4）。

use std::net::{IpAddr, SocketAddr};
use std::ops::ControlFlow;

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::config::CredentialMode;
use crate::metrics::Metrics;
use crate::signaling::{ClientMsg, ServerMsg, PROTOCOL_VERSION};
use crate::turn::ephemeral_credential;
use crate::SharedState;

/// 服务端版本，取自 Cargo。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/api/v1/ice", get(ice_get).post(ice_post))
        .route("/api/v1/relay", get(relay))
        .route("/ws/signal", get(ws_handler))
        .with_state(state)
}

// ---------------------------------------------------------------- 健康检查

#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    protocol_version: u32,
    /// TURN 是否真正配置好了（未配置时中继路径不可用）。
    turn_configured: bool,
    credential_mode: &'static str,
    active_signaling_connections: usize,
    active_sessions: usize,
    peers_over_quota: usize,
}

async fn healthz(State(state): State<SharedState>) -> impl IntoResponse {
    let body = Health {
        status: if state.config.turn_configured() {
            "ok"
        } else {
            "degraded"
        },
        version: VERSION,
        protocol_version: PROTOCOL_VERSION,
        turn_configured: state.config.turn_configured(),
        credential_mode: state.config.credential_mode.as_str(),
        active_signaling_connections: state.hub.active_connections(),
        active_sessions: state.hub.active_sessions(),
        peers_over_quota: state.quota.active_ips(),
    };
    Json(body)
}

// ---------------------------------------------------------------- 指标

async fn metrics(State(state): State<SharedState>) -> impl IntoResponse {
    state.metrics.render()
}

// ---------------------------------------------------------------- ICE 配置

/// `/api/v1/ice` 的可选请求体。
///
/// `subject` 是**为将来预留**的匿名主体标识：现在服务端只把它当配额分组键，
/// **不校验真实性、不调用任何账号系统**。将来若要给配额绑定账号，
/// 只需把这个字段从"信任"改为"验证"，**客户端协议不变**。见设计文档 §8。
#[derive(Debug, Default, Deserialize)]
struct IceRequest {
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    client_version: Option<String>,
    #[serde(default)]
    platform: Option<String>,
}

/// ICE 服务器：STUN 无凭据，TURN 带短期凭据。
#[derive(Debug, Serialize)]
struct IceServer {
    urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<String>,
}

/// `/api/v1/ice` 的响应。
#[derive(Debug, Serialize)]
struct IceResponse {
    stun: Vec<String>,
    turn: Vec<IceServer>,
    /// 短期凭据有效期（秒）。
    ttl: u64,
}

/// 一次下发的 ICE 配置：一个 TURN 条目（可能含多个 URL）+ 若干 STUN URL。
struct IcePlan {
    turn_urls: Vec<String>,
    turn_username: Option<String>,
    turn_credential: Option<String>,
    stun_urls: Vec<String>,
    /// 该 IP 今日中继流量超额，未签发 TURN 凭据。
    budget_exhausted: bool,
}

impl IcePlan {
    /// TURN 条目；未配置或超额时为 `None`。
    fn turn_server(&self) -> Option<IceServer> {
        if self.turn_urls.is_empty() || self.budget_exhausted {
            return None;
        }
        Some(IceServer {
            urls: self.turn_urls.clone(),
            username: self.turn_username.clone(),
            credential: self.turn_credential.clone(),
        })
    }

    /// 拼成客户端要的完整列表（TURN 在前，STUN 在后）。
    fn into_servers(self) -> Vec<IceServer> {
        let mut servers: Vec<IceServer> = self.turn_server().into_iter().collect();
        servers.extend(self.stun_urls.into_iter().map(|url| IceServer {
            urls: vec![url],
            username: None,
            credential: None,
        }));
        servers
    }
}

/// 按配额与配置决定这次能下发什么。
fn plan_ice(state: &SharedState, ip: IpAddr) -> IcePlan {
    let mut plan = IcePlan {
        turn_urls: state.config.turn_urls.clone(),
        turn_username: None,
        turn_credential: None,
        stun_urls: state.config.stun_urls.clone(),
        budget_exhausted: false,
    };

    if state.config.turn_urls.is_empty() {
        return plan;
    }

    if state.quota.relay_budget_exhausted(ip) {
        // 超额：仍给 STUN（不花钱），但不给中继凭据。
        plan.budget_exhausted = true;
        Metrics::inc(&state.metrics.relay_budget_rejections_total);
        tracing::info!(%ip, "该 IP 今日中继流量已超额，不下发 TURN 凭据");
        return plan;
    }

    if state.config.credential_mode == CredentialMode::Ephemeral {
        Metrics::inc(&state.metrics.ice_credentials_issued_total);
        let (username, credential) =
            ephemeral_credential(&state.config.turn_secret, state.config.turn_credential_ttl);
        plan.turn_username = Some(username);
        plan.turn_credential = Some(credential);
    }
    // open 模式下 coturn 侧不做校验，凭据字段留空。

    plan
}

async fn ice_get(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    build_ice(&state, addr.ip(), IceRequest::default())
}

async fn ice_post(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> Response {
    // 空 body 或解析失败都退回默认值：这个接口不该因为格式问题把人挡在门外。
    let req = if body.is_empty() {
        IceRequest::default()
    } else {
        serde_json::from_slice(&body).unwrap_or_default()
    };
    build_ice(&state, addr.ip(), req)
}

fn build_ice(state: &SharedState, ip: IpAddr, req: IceRequest) -> Response {
    let plan = plan_ice(state, ip);

    if let Some(subject) = req.subject.as_deref() {
        tracing::debug!(
            %ip,
            %subject,
            client_version = req.client_version.as_deref().unwrap_or("-"),
            platform = req.platform.as_deref().unwrap_or("-"),
            "ICE 请求（subject 仅作配额分组键，不做校验）"
        );
    }

    let body = IceResponse {
        stun: plan.stun_urls.clone(),
        turn: plan.turn_server().into_iter().collect(),
        ttl: state.config.turn_credential_ttl,
    };
    Json(body).into_response()
}

// ---------------------------------------------------------------- 中继发现

/// `/api/v1/relay` 的响应：客户端凭这个接口拿齐接入信息。
#[derive(Debug, Serialize)]
struct RelayResponse {
    /// 由对外 origin 推导的短 ID，客户端用同一规则自行核算后比对。
    id: String,
    /// 本服务版本。
    version: &'static str,
    /// 信令协议版本，客户端据此判断兼容性。
    protocol_version: u32,
    /// 信令 WebSocket 完整地址（由 `PUBLIC_BASE_URL` 拼出）。
    signaling: String,
    /// ICE 服务器列表（STUN + TURN，TURN 带新签发的短期凭据）。
    ice: Vec<IceServer>,
    /// 凭据有效期（秒），过期后要重新调用本接口。
    credential_ttl: u64,
    /// TURN 域，与 coturn 的 `realm` 必须一致。
    realm: String,
    /// TURN 是否可用；false 时 `ice` 里只有 STUN。
    turn_configured: bool,
}

fn relay_payload(state: &SharedState, ip: IpAddr) -> RelayResponse {
    RelayResponse {
        version: VERSION,
        protocol_version: PROTOCOL_VERSION,
        id: crate::identity::relay_id(&state.config.public_base_url),
        signaling: state.config.signaling_url(),
        ice: plan_ice(state, ip).into_servers(),
        credential_ttl: state.config.turn_credential_ttl,
        realm: state.config.turn_realm.clone(),
        turn_configured: state.config.turn_configured(),
    }
}

async fn relay(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    let payload = relay_payload(&state, addr.ip());
    tracing::debug!(ip = %addr.ip(), "下发中继配置");
    Json(payload).into_response()
}

// ---------------------------------------------------------------- 信令 WebSocket

async fn ws_handler(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state, addr.ip()))
}

async fn handle_socket(socket: WebSocket, state: SharedState, ip: IpAddr) {
    // 每 IP 并发配额（设计文档 §4 L2）。租约在函数结束时自动归还。
    let guard = match state.quota.try_acquire(ip) {
        Ok(guard) => guard,
        Err(err) => {
            Metrics::inc(&state.metrics.connections_rejected_quota);
            tracing::warn!(%ip, "拒绝信令连接：{err}");
            let (mut sink, _stream) = socket.split();
            let payload = json(&ServerMsg::Error {
                code: "quota_exceeded".to_string(),
                message: err.to_string(),
            });
            let _ = sink.send(Message::Text(payload.into())).await;
            let _ = sink.send(Message::Close(None)).await;
            return;
        }
    };

    Metrics::inc(&state.metrics.connections_total);
    tracing::debug!(%ip, "信令连接建立");

    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<ServerMsg>();
    let conn = state.hub.register(tx);

    // 出站任务：把 hub 推来的消息写进 socket。
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sink.send(Message::Text(json(&msg).into())).await.is_err() {
                break;
            }
        }
    });

    state.hub.send_to(
        conn,
        ServerMsg::Hello {
            protocol_version: PROTOCOL_VERSION,
        },
    );

    while let Some(incoming) = stream.next().await {
        let msg = match incoming {
            Ok(msg) => msg,
            Err(err) => {
                tracing::debug!(%ip, "WebSocket 读取出错：{err}");
                break;
            }
        };

        match msg {
            Message::Text(text) => {
                state.hub.touch(conn);
                Metrics::inc(&state.metrics.signaling_messages_total);

                match serde_json::from_str::<ClientMsg>(text.as_str()) {
                    Ok(client_msg) => {
                        if handle_client_msg(&state, conn, client_msg).is_break() {
                            break;
                        }
                    }
                    Err(err) => {
                        state.hub.send_to(
                            conn,
                            ServerMsg::Error {
                                code: "bad_message".to_string(),
                                message: format!("无法解析信令消息：{err}"),
                            },
                        );
                    }
                }
            }
            // 协议只接受 JSON 文本；二进制按无效消息忽略。
            Message::Binary(_) => {}
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => break,
        }
    }

    state.hub.unregister(conn);
    send_task.abort();
    drop(guard);
    tracing::debug!(%ip, "信令连接结束");
}

fn handle_client_msg(state: &SharedState, conn: u64, msg: ClientMsg) -> ControlFlow<()> {
    match msg {
        ClientMsg::Hello {
            peer_id,
            protocol_version,
        } => {
            if protocol_version > PROTOCOL_VERSION {
                state.hub.send_to(
                    conn,
                    ServerMsg::Error {
                        code: "unsupported_version".to_string(),
                        message: format!(
                            "客户端协议版本 {protocol_version} 高于服务端 {PROTOCOL_VERSION}"
                        ),
                    },
                );
            } else {
                tracing::debug!(%peer_id, "匿名身份声明（不校验、不持久化）");
                state.hub.set_peer_id(conn, peer_id);
            }
        }

        ClientMsg::Create => match state.hub.create_session(conn) {
            Ok(session_id) => {
                tracing::debug!(%session_id, "会话已创建");
                state.hub.send_to(conn, ServerMsg::Created { session_id });
            }
            Err(message) => {
                state.hub.send_to(
                    conn,
                    ServerMsg::Error {
                        code: "create_failed".to_string(),
                        message,
                    },
                );
            }
        },

        ClientMsg::Join { session_id } => match state.hub.join_session(conn, &session_id) {
            Ok(()) => {
                tracing::debug!(%session_id, "已加入会话");
                state.hub.send_to(conn, ServerMsg::Joined { session_id });
            }
            Err(message) => {
                state.hub.send_to(
                    conn,
                    ServerMsg::Error {
                        code: "join_failed".to_string(),
                        message,
                    },
                );
            }
        },

        ClientMsg::Offer { payload } => {
            relay_from(state, conn, move |from| ServerMsg::Offer { from, payload });
        }
        ClientMsg::Answer { payload } => {
            relay_from(state, conn, move |from| ServerMsg::Answer { from, payload });
        }
        ClientMsg::Candidate { payload } => {
            relay_from(state, conn, move |from| ServerMsg::Candidate { from, payload });
        }

        ClientMsg::Bye => {
            state.hub.unregister(conn);
            return ControlFlow::Break(());
        }
    }

    ControlFlow::Continue(())
}

/// 把消息打上发送者身份后转给对端。
fn relay_from<F>(state: &SharedState, conn: u64, build: F)
where
    F: FnOnce(String) -> ServerMsg,
{
    let Some(from) = state.hub.peer_id(conn) else {
        return;
    };
    if from.is_empty() {
        state.hub.send_to(
            conn,
            ServerMsg::Error {
                code: "no_identity".to_string(),
                message: "请先发送 hello 声明匿名身份".to_string(),
            },
        );
        return;
    }

    if let Err(message) = state.hub.relay(conn, build(from)) {
        state.hub.send_to(
            conn,
            ServerMsg::Error {
                code: "relay_failed".to_string(),
                message,
            },
        );
    }
}

fn json(msg: &ServerMsg) -> String {
    serde_json::to_string(msg).unwrap_or_else(|_| {
        r#"{"type":"error","code":"serialize_failed","message":"服务端序列化失败"}"#.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::net::Ipv4Addr;

    fn state_with(turn_urls: Vec<String>) -> SharedState {
        let config = Config::test_config(turn_urls);
        std::sync::Arc::new(crate::AppState {
            quota: crate::quota::Quota::new(config.max_conns_per_ip, config.daily_bytes_per_ip),
            hub: crate::signaling::SignalingHub::new(std::time::Duration::from_secs(
                config.session_idle_timeout,
            )),
            metrics: Metrics::default(),
            config,
        })
    }

    fn client_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
    }

    fn turn_urls() -> Vec<String> {
        vec![
            "turn:relay.example.com:3478?transport=udp".to_string(),
            "turns:relay.example.com:5349".to_string(),
        ]
    }

    #[test]
    fn relay_未配置_turn_时只给_stun() {
        let state = state_with(Vec::new());
        let payload = relay_payload(&state, client_ip());

        assert!(!payload.turn_configured);
        assert_eq!(payload.ice.len(), 1, "只剩一条 STUN");
        assert_eq!(payload.ice[0].urls, vec!["stun:stun.example.com:3478"]);
        assert!(payload.ice[0].username.is_none());
        assert!(payload.ice[0].credential.is_none());
        // 信令地址与 TTL 不依赖 TURN，仍要给。
        assert_eq!(payload.signaling, "wss://relay.example.com/ws/signal");
        assert_eq!(payload.credential_ttl, 600);
        assert_eq!(payload.version, VERSION);
        assert_eq!(payload.protocol_version, PROTOCOL_VERSION);
    }

    #[test]
    fn relay_配置_turn_后带新签发凭据() {
        let state = state_with(turn_urls());
        let before = crate::turn::unix_now();

        let payload = relay_payload(&state, client_ip());
        assert!(payload.turn_configured);
        assert_eq!(payload.realm, "secrelay.relay");
        assert_eq!(payload.ice.len(), 2, "TURN + STUN");

        let turn = &payload.ice[0];
        assert_eq!(turn.urls, turn_urls());
        let username = turn.username.as_deref().expect("应当带用户名");
        let credential = turn.credential.as_deref().expect("应当带密码");

        // 用户名格式与凭据必须能被同一个密钥验回来。
        let (expiry, tag) = username.split_once(':').expect("用户名是 时间戳:标识");
        assert_eq!(tag, "secrelay");
        let expiry: u64 = expiry.parse().expect("前半段是 Unix 秒");
        assert!(
            (before + payload.credential_ttl..=crate::turn::unix_now() + payload.credential_ttl)
                .contains(&expiry),
            "过期时间应当落在 TTL 窗口内，实际 {expiry}"
        );
        assert!(crate::turn::verify_credential(
            &state.config.turn_secret,
            username,
            credential
        ));

        let stun = &payload.ice[1];
        assert_eq!(stun.urls, vec!["stun:stun.example.com:3478"]);
        assert!(stun.username.is_none());
    }

    #[test]
    fn relay_响应里不含密钥本身() {
        let state = state_with(turn_urls());
        let text = serde_json::to_string(&relay_payload(&state, client_ip())).unwrap();
        assert!(
            !text.contains(&state.config.turn_secret),
            "响应里不能出现 static-auth-secret：{text}"
        );
    }

    #[test]
    fn relay_流量超额后退化为只给_stun() {
        let state = state_with(turn_urls());
        state.quota.record_bytes(client_ip(), state.config.daily_bytes_per_ip);

        let payload = relay_payload(&state, client_ip());
        assert!(payload.turn_configured, "配置仍在，只是这次不发凭据");
        assert!(payload.ice.iter().all(|s| s.username.is_none()));
        assert!(payload.ice.iter().all(|s| !s.urls[0].starts_with("turn")));
        assert_eq!(payload.ice.len(), 1);
    }

    #[test]
    fn relay_响应_json_字段齐全() {
        let state = state_with(turn_urls());
        let text = serde_json::to_string(&relay_payload(&state, client_ip())).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        for key in [
            "version",
            "protocol_version",
            "signaling",
            "ice",
            "credential_ttl",
            "realm",
            "turn_configured",
        ] {
            assert!(value.get(key).is_some(), "响应缺少字段 {key}：{text}");
        }
        assert_eq!(value["ice"][0]["urls"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn ice_接口在未配置_turn_时只给_stun() {
        let state = state_with(Vec::new());
        let plan = plan_ice(&state, client_ip());
        assert!(plan.turn_urls.is_empty());
        assert_eq!(plan.into_servers().len(), 1);
    }
}
