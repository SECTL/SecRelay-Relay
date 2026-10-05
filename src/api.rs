//! HTTP 与 WebSocket 接口。
//!
//! | 路由 | 说明 |
//! |---|---|
//! | `GET /healthz` | 健康检查与配置自检 |
//! | `GET /metrics` | Prometheus 文本指标 |
//! | `GET|POST /api/v1/ice` | 下发 STUN/TURN 配置（含短期凭据） |
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
use crate::turn::{ephemeral_credential, IceServer};
use crate::SharedState;

/// 服务端版本，取自 Cargo。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/api/v1/ice", get(ice_get).post(ice_post))
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

#[derive(Debug, Serialize)]
struct IceResponse {
    stun: Vec<String>,
    turn: Vec<IceServer>,
    /// 短期凭据有效期（秒）。
    ttl: u64,
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
    let mut turn_servers = Vec::new();

    if state.quota.relay_budget_exhausted(ip) {
        // 超额：仍给 STUN（不花钱），但不给中继凭据。
        Metrics::inc(&state.metrics.relay_budget_rejections_total);
        tracing::info!(%ip, "该 IP 今日中继流量已超额，不下发 TURN 凭据");
    } else if !state.config.turn_urls.is_empty() {
        let (username, credential) = match state.config.credential_mode {
            CredentialMode::Ephemeral => {
                Metrics::inc(&state.metrics.ice_credentials_issued_total);
                let (u, c) =
                    ephemeral_credential(&state.config.turn_secret, state.config.turn_credential_ttl);
                (Some(u), Some(c))
            }
            CredentialMode::Open => (None, None),
        };
        turn_servers.push(IceServer {
            urls: state.config.turn_urls.clone(),
            username,
            credential,
        });
    }

    if let Some(subject) = req.subject.as_deref() {
        tracing::debug!(
            %ip,
            %subject,
            client_version = req.client_version.as_deref().unwrap_or("-"),
            platform = req.platform.as_deref().unwrap_or("-"),
            "ICE 请求（subject 仅作配额分组键，不做校验）"
        );
    }

    Json(IceResponse {
        stun: state.config.stun_urls.clone(),
        turn: turn_servers,
        ttl: state.config.turn_credential_ttl,
    })
    .into_response()
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
