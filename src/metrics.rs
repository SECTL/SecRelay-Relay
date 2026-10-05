//! 极简指标导出（Prometheus 文本格式）。
//!
//! 只埋"量"的指标，不碰内容 —— 这是零知识的前提。
//! KPI 口径见 `docs/设计.md` §9。

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Metrics {
    /// 累计接受的 WebSocket 信令连接数。
    pub connections_total: AtomicU64,
    /// 因每 IP 并发配额被拒的连接数。
    pub connections_rejected_quota: AtomicU64,
    /// 累计处理的信令消息数。
    pub signaling_messages_total: AtomicU64,
    /// 累计签发的短期 TURN 凭据数。
    pub ice_credentials_issued_total: AtomicU64,
    /// 因中继流量超额而未下发 TURN 凭据的次数。
    pub relay_budget_rejections_total: AtomicU64,
}

impl Metrics {
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// 渲染成 Prometheus 文本格式。
    pub fn render(&self) -> String {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        format!(
            "# HELP secrelay_relay_connections_total 累计接受的 WebSocket 信令连接数\n\
             # TYPE secrelay_relay_connections_total counter\n\
             secrelay_relay_connections_total {}\n\
             # HELP secrelay_relay_connections_rejected_quota_total 因每 IP 并发配额被拒的连接数\n\
             # TYPE secrelay_relay_connections_rejected_quota_total counter\n\
             secrelay_relay_connections_rejected_quota_total {}\n\
             # HELP secrelay_relay_signaling_messages_total 累计处理的信令消息数\n\
             # TYPE secrelay_relay_signaling_messages_total counter\n\
             secrelay_relay_signaling_messages_total {}\n\
             # HELP secrelay_relay_ice_credentials_issued_total 累计签发的短期 TURN 凭据数\n\
             # TYPE secrelay_relay_ice_credentials_issued_total counter\n\
             secrelay_relay_ice_credentials_issued_total {}\n\
             # HELP secrelay_relay_relay_budget_rejections_total 因流量超额未下发 TURN 凭据的次数\n\
             # TYPE secrelay_relay_relay_budget_rejections_total counter\n\
             secrelay_relay_relay_budget_rejections_total {}\n",
            get(&self.connections_total),
            get(&self.connections_rejected_quota),
            get(&self.signaling_messages_total),
            get(&self.ice_credentials_issued_total),
            get(&self.relay_budget_rejections_total),
        )
    }
}
