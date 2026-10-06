//! 中继身份：由对外 origin 推导出来的短 ID。
//!
//! 不让中继自行声明 ID：中继是开放且没有注册表的，自行声明就能冒用别人的 ID。
//! 把 ID 绑到 origin 上之后，冒用某个 ID 就必须真正拥有那个 origin。
//!
//! 客户端用同一套规则自己算一次，与服务端上报的值比对；对不上就不认。

use sha1::{Digest, Sha1};

/// ID 长度（字符）。
const ID_LEN: usize = 10;

/// 由中继的对外基址算出短 ID。
pub fn relay_id(base: &str) -> String {
    let canonical = canonical_origin(base);
    let digest = Sha1::digest(canonical.as_bytes());
    base32_upper(&digest)[..ID_LEN].to_string()
}

/// 把基址规范成 `scheme://host[:port]`：小写、去掉路径、省略默认端口。
///
/// 客户端必须做同样的规范化，否则同一台中继在两边会算出不同的 ID。
/// 例如 `HTTPS://Relay.Example.com/` 与 `https://relay.example.com` 必须等价。
pub fn canonical_origin(base: &str) -> String {
    let trimmed = base.trim().trim_end_matches('/');
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        // 没写 scheme 时按 https 处理
        None => ("https".to_string(), trimmed),
    };

    let host_port = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .to_ascii_lowercase();

    let default_port = if scheme == "http" { ":80" } else { ":443" };
    let host_port = match host_port.strip_suffix(default_port) {
        Some(stripped) => stripped.to_string(),
        None => host_port,
    };

    format!("{scheme}://{host_port}")
}

/// RFC 4648 base32：大写字母表，不带填充。
fn base32_upper(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for byte in data {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 固定向量逐字符正确() {
        // 期望值用 .NET SHA1 + 手写 base32 独立算过一遍（不是本实现算完自己抄回来）
        assert_eq!(relay_id("https://relay.example.com"), "AF4KR6IMPE");
        assert_eq!(relay_id("http://127.0.0.1:8080"), "6AYTZEVUQP");
        assert_eq!(relay_id("https://relay.secrelay.dev"), "VQPG6YZOS3");
    }

    #[test]
    fn 长度固定为十个字符() {
        for base in ["https://a.example", "http://192.168.1.1:9000", "relay.local"] {
            assert_eq!(relay_id(base).len(), ID_LEN, "{base}");
        }
    }

    #[test]
    fn 规范化后等价的写法算出同一个_id() {
        let expected = relay_id("https://relay.example.com");
        for variant in [
            "HTTPS://Relay.Example.com",
            "https://relay.example.com/",
            "https://relay.example.com/api/v1/relay",
            "https://relay.example.com:443",
            "  https://Relay.Example.COM//  ",
        ] {
            assert_eq!(relay_id(variant), expected, "{variant} 应当等价");
        }
    }

    #[test]
    fn http_的默认端口也省略() {
        assert_eq!(relay_id("http://relay.example.com:80"), relay_id("http://relay.example.com"));
    }

    #[test]
    fn 非默认端口参与计算() {
        assert_ne!(relay_id("https://relay.example.com"), relay_id("https://relay.example.com:8443"));
        assert_ne!(relay_id("http://127.0.0.1:8080"), relay_id("http://127.0.0.1:9090"));
    }

    #[test]
    fn 不同_origin_算出不同_id() {
        let ids: Vec<String> = [
            "https://a.example",
            "https://b.example",
            "http://a.example",
            "https://a.example:8443",
        ]
        .iter()
        .map(|base| relay_id(base))
        .collect();

        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), ids.len(), "出现碰撞：{ids:?}");
    }

    #[test]
    fn 只有_host_不同时也要区分() {
        assert_ne!(
            relay_id("https://relay.example.com"),
            relay_id("https://relay.example.org")
        );
    }

    #[test]
    fn 没写_scheme_时按_https_处理() {
        assert_eq!(relay_id("relay.example.com"), relay_id("https://relay.example.com"));
    }

    #[test]
    fn base32_符合_rfc4648_大写无填充() {
        // RFC 4648 的示例：字符串 "foobar" 的 base32 是 MZXW6YTBOI======
        assert_eq!(base32_upper(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_upper(b"f"), "MY");
        assert_eq!(base32_upper(b"fo"), "MZXQ");
    }
}
