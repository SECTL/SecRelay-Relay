//! TURN 短期凭据签发（coturn `use-auth-secret` 约定）。
//!
//! **不是鉴权**，只是让"直接拿公开 TURN 配置白嫖"变得没那么顺手：
//! 任何人调用 `/api/v1/ice` 或 `/api/v1/relay` 都能拿到凭据。
//!
//! ```text
//! username   = "<过期 Unix 时间戳>:<标识>"
//! credential = base64(HMAC-SHA1(static-auth-secret, username))
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// 凭据用户名里的标识后缀（仅为可读性，coturn 不关心）。
const USERNAME_TAG: &str = "secrelay";

/// 用户名标识的字符白名单：只保留 `[A-Za-z0-9]`，其余换成 `-`。
///
/// 用户名里带 `:` 会被 TURN 消息的明文编码截断，控制字符在日志里也很难看。
fn sanitize_tag(tag: &str) -> String {
    let cleaned: String = tag
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let cleaned = cleaned.trim_matches('-');
    if cleaned.is_empty() {
        USERNAME_TAG.to_string()
    } else {
        cleaned.to_string()
    }
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
    credential_with_tag(secret, unix_now().saturating_add(ttl_secs), USERNAME_TAG)
}

/// 针对指定过期时间与标识生成凭据。`expiry` 是**过期时刻**的 Unix 秒，不是有效期。
///
/// 密码按 coturn 的约定算：
///
/// ```text
/// password = base64( HMAC-SHA1( key = static-auth-secret, data = username ) )
/// ```
///
/// 几处容易算错的地方：
/// - HMAC 的**密钥是 secret、数据是完整的 username 字符串**（含冒号与标识），不是反过来；
///   用户名里任何一个字符变了，密码就完全不同。
/// - 摘要按 **base64 标准表**编码（含 `=` 填充），不是 hex、也不是 base64url。
/// - HMAC-SHA1 输出固定 20 字节，所以密码恒定 28 个字符、以 `=` 结尾。
fn credential_with_tag(secret: &str, expiry: u64, tag: &str) -> (String, String) {
    let username = format!("{expiry}:{}", sanitize_tag(tag));

    // HMAC 接受任意长度密钥，这里不会失败。
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC-SHA1 接受任意长度密钥");
    mac.update(username.as_bytes());
    let credential = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    (username, credential)
}

/// 校验客户端提交的凭据；在线校验由 coturn 完成，这里只用于自检与测试。
#[cfg(test)]
pub(crate) fn verify_credential(secret: &str, username: &str, credential: &str) -> bool {
    let Some((expiry, tag)) = username.split_once(':') else {
        return false;
    };
    let Ok(expiry) = expiry.parse::<u64>() else {
        return false;
    };

    let (expected_user, expected_credential) = credential_with_tag(secret, expiry, tag);
    expected_user == username && expected_credential == credential
}

/// 固定过期时间的凭据，供测试钉住算法。
#[cfg(test)]
fn credential_at(secret: &str, expiry: u64) -> (String, String) {
    credential_with_tag(secret, expiry, USERNAME_TAG)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 用户名带过期时间戳() {
        let (username, credential) = credential_at("test-secret", 1_700_000_000);
        assert_eq!(username, "1700000000:secrelay");
        assert_eq!(credential.len(), 28, "HMAC-SHA1 是 20 字节，base64 后 28 字符");
    }

    /// 固定输入下的逐字符断言。期望值用 .NET `HMACSHA1` 与 node `crypto.createHmac`
    /// 各算一遍，两者一致后才写进来——用来钉死"冒号顺序、SHA1、标准 base64"三件事。
    #[test]
    fn 固定向量逐字符正确() {
        let (username, credential) = credential_at("north-star-turn-secret", 1_700_000_000);
        assert_eq!(username, "1700000000:secrelay");
        assert_eq!(credential, "Nwgu8hoFc2X6ovaVEEGO5R4G2XU=");

        // 同一个密钥、换标识：用户名变了，密码必须跟着变。
        let (username, credential) =
            credential_with_tag("north-star-turn-secret", 1_700_000_000, "peer-a");
        assert_eq!(username, "1700000000:peer-a");
        assert_ne!(credential, "Nwgu8hoFc2X6ovaVEEGO5R4G2XU=");
        assert_eq!(credential.len(), 28);
    }

    #[test]
    fn 标识被清洗到只留字母数字() {
        let (username, _) = credential_with_tag("s", 42, "a:b c");
        assert_eq!(username, "42:a-b-c");
        // 全是非法字符时退回默认标识，不会得到一个只有时间戳的空用户名。
        let (username, _) = credential_with_tag("s", 42, "::");
        assert_eq!(username, "42:secrelay");
    }

    #[test]
    fn 自检函数认得自己签发的凭据() {
        let (username, credential) = credential_at("check-me", 1_700_000_000);
        assert!(verify_credential("check-me", &username, &credential));
        assert!(!verify_credential("other-secret", &username, &credential));
        assert!(!verify_credential("check-me", "1700000000:secrelay", "wrong"));
        assert!(!verify_credential("check-me", "not-a-timestamp:secrelay", &credential));
        assert!(!verify_credential("check-me", "1700000000", &credential));
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
