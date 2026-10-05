//! 每 IP 配额：并发会话数 + 每日中继流量。
//!
//! 对应 `docs/设计.md` §4 的 L2 / L3 层。
//!
//! ⚠️ **这不是鉴权。** 本服务按产品决策不做账号验证，配额只是提高"顺手白嫖"的成本，
//! 挡不住有决心的攻击者。若要根治，必须把凭据与账号体系绑定（与"不做账号验证"冲突）。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const DAY: Duration = Duration::from_secs(86_400);

#[derive(Debug, thiserror::Error)]
pub enum QuotaError {
    #[error("该 IP 的并发会话数已达上限（{limit}）")]
    TooManyConnections { limit: usize },
}

#[derive(Debug)]
struct IpState {
    conns: usize,
    bytes_today: u64,
    window_start: Instant,
}

impl IpState {
    fn new(now: Instant) -> Self {
        Self {
            conns: 0,
            bytes_today: 0,
            window_start: now,
        }
    }

    /// 跨天则重置流量窗口。
    fn roll_window(&mut self, now: Instant) {
        if now.duration_since(self.window_start) >= DAY {
            self.window_start = now;
            self.bytes_today = 0;
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    ips: HashMap<IpAddr, IpState>,
}

/// 每 IP 配额表。
///
/// 内部用 `Arc<Mutex<_>>` 而不是把 `Quota` 本身放进 `Arc`，这样 `AppState` 里
/// 直接持有一个 `Quota` 就能申请租约（租约需要独立持有内部状态的所有权）。
#[derive(Debug)]
pub struct Quota {
    max_conns_per_ip: usize,
    daily_bytes_per_ip: u64,
    inner: Arc<Mutex<Inner>>,
}

/// 会话配额租约。**Drop 时自动归还**，这样提前 return 或 panic 都不会泄漏计数。
#[derive(Debug)]
pub struct IpGuard {
    ip: IpAddr,
    inner: Arc<Mutex<Inner>>,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut inner = lock_inner(&self.inner);
        release(&mut inner, self.ip);
    }
}

impl Quota {
    pub fn new(max_conns_per_ip: usize, daily_bytes_per_ip: u64) -> Self {
        Self {
            max_conns_per_ip: max_conns_per_ip.max(1),
            daily_bytes_per_ip,
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    /// 尝试占用一个会话名额。超出上限返回 [`QuotaError`]。
    pub fn try_acquire(&self, ip: IpAddr) -> Result<IpGuard, QuotaError> {
        let mut inner = self.lock();
        let now = Instant::now();
        let state = inner.ips.entry(ip).or_insert_with(|| IpState::new(now));
        state.roll_window(now);

        if state.conns >= self.max_conns_per_ip {
            return Err(QuotaError::TooManyConnections {
                limit: self.max_conns_per_ip,
            });
        }
        state.conns += 1;

        Ok(IpGuard {
            ip,
            inner: Arc::clone(&self.inner),
        })
    }

    /// 记录该 IP 的中继转发字节数（只统计"量"，不检查内容 —— 否则破坏零知识）。
    pub fn record_bytes(&self, ip: IpAddr, bytes: u64) {
        let mut inner = self.lock();
        let now = Instant::now();
        let state = inner.ips.entry(ip).or_insert_with(|| IpState::new(now));
        state.roll_window(now);
        state.bytes_today = state.bytes_today.saturating_add(bytes);
    }

    /// 该 IP 今日的中继流量是否已超额。超额后仍可建立信令连接，但不下发 TURN 凭据。
    pub fn relay_budget_exhausted(&self, ip: IpAddr) -> bool {
        if self.daily_bytes_per_ip == 0 {
            return false;
        }
        let mut inner = self.lock();
        let now = Instant::now();
        match inner.ips.get_mut(&ip) {
            None => false,
            Some(state) => {
                state.roll_window(now);
                state.bytes_today >= self.daily_bytes_per_ip
            }
        }
    }

    /// 当前占用过会话名额的 IP 数量（用于观测）。
    pub fn active_ips(&self) -> usize {
        self.lock().ips.values().filter(|s| s.conns > 0).count()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        lock_inner(&self.inner)
    }
}

/// 归还一个名额，并顺手回收完全空闲的条目，避免长期运行时 IP 表无限增长。
fn release(inner: &mut Inner, ip: IpAddr) {
    if let Some(state) = inner.ips.get_mut(&ip) {
        state.conns = state.conns.saturating_sub(1);
    }
    let now = Instant::now();
    inner
        .ips
        .retain(|_, s| s.conns > 0 || now.duration_since(s.window_start) < DAY);
}

/// 互斥锁中毒不应让服务停摆：直接取回内部数据。
fn lock_inner(inner: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    inner.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last))
    }

    #[test]
    fn 并发上限生效且归还后可再占用() {
        let quota = Arc::new(Quota::new(2, 1024));

        let a = quota.try_acquire(ip(1)).expect("第 1 个名额");
        let b = quota.try_acquire(ip(1)).expect("第 2 个名额");
        assert!(quota.try_acquire(ip(1)).is_err(), "第 3 个应当被拒");

        drop(a);
        let _c = quota.try_acquire(ip(1)).expect("归还后应当可以再占用");

        drop(b);
        assert_eq!(quota.active_ips(), 1);
    }

    #[test]
    fn 不同_ip_互不影响() {
        let quota = Arc::new(Quota::new(1, 1024));
        let _a = quota.try_acquire(ip(1)).expect("A 占满");
        let _b = quota.try_acquire(ip(2)).expect("B 不受 A 影响");
    }

    #[test]
    fn 流量超额后判定为耗尽() {
        let quota = Arc::new(Quota::new(1, 1000));
        let guard = quota.try_acquire(ip(9)).expect("占位以建表");
        assert!(!quota.relay_budget_exhausted(ip(9)));
        quota.record_bytes(ip(9), 1000);
        assert!(quota.relay_budget_exhausted(ip(9)));
        drop(guard);
    }
}
