//! SecRelay-Relay：SecRelay 的信令与中继服务。
//!
//! # 两条硬约束
//!
//! 1. **不做账号验证** —— 中继不校验 token，任何人可以连。
//! 2. **零知识** —— 只转发密文，服务器读不到画面、文件与消息内容。
//!
//! # 但"无鉴权"不等于"无保护"
//!
//! 中继唯一的显著成本是带宽（1080p 约 1.8 GB/小时·单向），一个完全开放的 TURN
//! 会迅速被白嫖。所以本服务用**短期凭据 + 每 IP 配额 + 观测**来提高滥用成本。
//! 这些措施不是鉴权，挡不住有决心的攻击者 —— 详见 `docs/设计.md` §4。

mod api;
mod config;
mod metrics;
mod quota;
mod signaling;
mod turn;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use crate::config::{Config, CredentialMode};
use crate::metrics::Metrics;
use crate::quota::Quota;
use crate::signaling::SignalingHub;

/// 全局共享状态。
pub struct AppState {
    pub config: Config,
    pub quota: Quota,
    pub hub: SignalingHub,
    pub metrics: Metrics,
}

pub type SharedState = Arc<AppState>;

/// 空闲连接回收间隔。
const GC_INTERVAL: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let config = Config::from_env()?;
    let bind_addr = config.bind_addr;

    if !config.turn_configured() {
        tracing::warn!(
            "TURN 未配置（需要同时设置 TURN_URLS 与 TURN_SECRET）：\
             中继路径不可用，目前只有信令与 STUN 生效"
        );
    }
    if config.credential_mode == CredentialMode::Open {
        tracing::warn!("TURN_CREDENTIAL_MODE=open：中继完全开放，极易被白嫖，生产环境不要这么配");
    }

    let state: SharedState = Arc::new(AppState {
        quota: Quota::new(config.max_conns_per_ip, config.daily_bytes_per_ip),
        hub: SignalingHub::new(Duration::from_secs(config.session_idle_timeout)),
        metrics: Metrics::default(),
        config,
    });

    // 后台回收空闲信令连接，避免内存里的 peer 表无限增长。
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(GC_INTERVAL);
            loop {
                ticker.tick().await;
                let reaped = state.hub.gc();
                if reaped > 0 {
                    tracing::debug!(reaped, "回收空闲信令连接");
                }
            }
        });
    }

    let app = api::router(Arc::clone(&state));
    let listener = TcpListener::bind(bind_addr).await?;

    tracing::info!(
        %bind_addr,
        version = api::VERSION,
        credential_mode = %config_mode(&state),
        turn_configured = state.config.turn_configured(),
        "SecRelay-Relay 已启动（无账号验证 / 零知识）"
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("已退出");
    Ok(())
}

fn config_mode(state: &SharedState) -> &'static str {
    state.config.credential_mode.as_str()
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!("收到退出信号，正在关闭"),
        Err(err) => tracing::warn!("无法监听退出信号：{err}"),
    }
}
