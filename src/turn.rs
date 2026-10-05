//! TURN 短期凭据签发（TURN REST API 风格）。
//!
//! 这是 `docs/设计.md` §4 的 L1 层：**不是鉴权**，只是让"直接拿公开 TURN 配置白嫖"
//! 变得没那么顺手。任何人调用 `/api/v1/ice` 都能拿到凭据。
//!
//! 凭据格式（coturn `use-auth-secret` / `static-auth-secret` 标准做法）：
//!
//! ```text
//! username   = "<过期 Unix 时间戳>:<任意标识>"
//! credential = base64(HMAC-SHA1(secret, username))
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// 凭据用户名里的标识后缀（仅为可读性，coturn 不关心）。
const USERNAME_TAG: &str = "secrelay";

/// 一条 ICE 服务器配置（可直接喂给 WebRTC 客户端）。
#[derive(Debug, Clone, Serialize)]
pub struct IceServer {
    pub urls: Vec<String>,
    /// 短期凭据的用户名；`open` 模式下为 `None`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// 短期凭据的密码；`open` 模式下为 `None`。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// 当前 Unix 时间戳（秒）。
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 生成一对短期凭据，有效期 `ttl_secs`。
pub fn ephemeral_credential(secret: &str, ttl_secs: u64) -> (String, String) {
    credential_at(secret, unix_now().saturating_add(ttl_secs))
}

/// 针对指定过期时间生成凭据。**确定性函数**，便于测试。
pub fn credential_at(secret: &str, expiry: u64) -> (String, String) {
    let username = format!("{expiry}:{USERNAME_TAG}");

    // HMAC 接受任意长度密钥，这里不会失败。
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC-SHA1 接受任意长度密钥");
    mac.update(username.as_bytes());
    let credential = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    (username, credential)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 用户名带过期时间戳() {
        let (username, credential) = credential_at("test-secret", 1_700_000_000);
        assert_eq!(username, "1700000000:secrelay");
        assert!(!credential.is_empty());
    }

    #[test]
    fn 确定性_同输入同输出() {
        // HMAC 必须确定性，否则 coturn 无法校验客户端提交的凭据。
        let (u1, c1) = credential_at("s", 42);
        let (u2, c2) = credential_at("s", 42);
        assert_eq!(u1, u2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn 不同密钥产生不同凭据() {
        let (u1, c1) = credential_at("secret-a", 42);
        let (u2, c2) = credential_at("secret-b", 42);
        assert_eq!(u1, u2, "过期时间相同则用户名相同");
        assert_ne!(c1, c2, "密钥不同则凭据必须不同");
    }

    #[test]
    fn 不同过期时间产生不同凭据() {
        let (_, c1) = credential_at("secret", 42);
        let (_, c2) = credential_at("secret", 43);
        assert_ne!(c1, c2);
    }

    #[test]
    fn 有效期落在预期窗口内() {
        let before = unix_now();
        let (username, _) = ephemeral_credential("s", 600);
        let expiry: u64 = username.split_once(':').unwrap().0.parse().unwrap();
        assert!(expiry >= before + 600);
        assert!(expiry <= unix_now() + 600);
    }
}
