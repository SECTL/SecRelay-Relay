//! 配置加载。
//!
//! 全部通过环境变量注入；`.env` 已在 `.gitignore` 中排除。
//! 变量清单见 `docs/设计.md` §10。

use std::env;
use std::fmt;
use std::net::SocketAddr;

/// TURN 凭据模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialMode {
    /// 签发短期凭据（默认）。见 `docs/设计.md` §4 L1。
    Ephemeral,
    /// 完全开放，不做任何门槛。**极易被白嫖，生产环境不要用。**
    Open,
}

impl CredentialMode {
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialMode::Ephemeral => "ephemeral",
            CredentialMode::Open => "open",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    /// 对外可访问的 HTTP(S) 基址，用于拼信令地址与 ICE 地址。
    pub public_base_url: String,
    pub turn_secret: String,
    /// TURN_SECRET 是否来自环境变量（未配置时用的是进程内随机密钥，与 coturn 不匹配）。
    turn_secret_from_env: bool,
    pub turn_urls: Vec<String>,
    pub turn_realm: String,
    pub stun_urls: Vec<String>,
    pub turn_credential_ttl: u64,
    pub credential_mode: CredentialMode,
    pub max_conns_per_ip: usize,
    pub daily_bytes_per_ip: u64,
    pub session_idle_timeout: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = env_str("BIND_ADDR", "0.0.0.0:8080")
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::Invalid("BIND_ADDR", e.to_string()))?;

        // TURN_SECRET 未配置时生成一个进程内随机密钥：服务能起来（方便本地跑通），
        // 但这份密钥与真实 coturn 不匹配，中继路径实际不可用 —— 启动时会告警。
        let (turn_secret, turn_secret_from_env) = match env_opt("TURN_SECRET") {
            Some(secret) => (secret, true),
            None => (random_secret(), false),
        };

        let credential_mode = match env_str("TURN_CREDENTIAL_MODE", "ephemeral").as_str() {
            "ephemeral" => CredentialMode::Ephemeral,
            "open" => CredentialMode::Open,
            other => {
                return Err(ConfigError::Invalid(
                    "TURN_CREDENTIAL_MODE",
                    format!("只支持 ephemeral / open，收到 {other}"),
                ))
            }
        };

        Ok(Self {
            bind_addr,
            public_base_url: env_str("PUBLIC_BASE_URL", "http://127.0.0.1:8080"),
            turn_secret,
            turn_secret_from_env,
            turn_urls: env_list("TURN_URLS"),
            turn_realm: env_str("TURN_REALM", "secrelay.relay"),
            stun_urls: env_list("STUN_URLS"),
            turn_credential_ttl: env_parse("TURN_CREDENTIAL_TTL", 600)?,
            credential_mode,
            max_conns_per_ip: env_parse("MAX_CONNS_PER_IP", 16)?,
            daily_bytes_per_ip: env_parse("DAILY_BYTES_PER_IP", 21_474_836_480)?,
            session_idle_timeout: env_parse("SESSION_IDLE_TIMEOUT", 120)?,
        })
    }

    /// TURN 是否真正可用（需要地址与密钥都配置）。
    pub fn turn_configured(&self) -> bool {
        !self.turn_urls.is_empty() && self.turn_secret_from_env
    }

    /// 信令 WebSocket 的对外完整地址，由 `PUBLIC_BASE_URL` 换 scheme 得到。
    pub fn signaling_url(&self) -> String {
        signaling_url(&self.public_base_url)
    }
}

/// 把对外基址换成对应的 WebSocket 地址：`https` → `wss`、其余 → `ws`。
/// 找不到 host 时按原样转发（由运维保证 `PUBLIC_BASE_URL` 是合法 URL）。
pub fn signaling_url(base: &str) -> String {
    // 先按 "://" 拆，再修剪斜杠：否则空的 "https://" 会被修剪成 "https:" 而不再可拆。
    let trimmed = base.trim();
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => return trimmed.to_string(),
    };
    let rest = rest.trim_end_matches('/');
    if rest.is_empty() {
        return trimmed.to_string();
    }

    let ws_scheme = if scheme == "https" { "wss" } else { "ws" };
    format!("{ws_scheme}://{rest}/ws/signal")
}

/// 测试用配置：不读环境变量，避免测试之间互相干扰。
#[cfg(test)]
impl Config {
    pub(crate) fn test_config(turn_urls: Vec<String>) -> Self {
        Self {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            public_base_url: "https://relay.example.com".to_string(),
            turn_secret: "north-star-turn-secret".to_string(),
            turn_secret_from_env: !turn_urls.is_empty(),
            turn_urls,
            turn_realm: "secrelay.relay".to_string(),
            stun_urls: vec!["stun:stun.example.com:3478".to_string()],
            turn_credential_ttl: 600,
            credential_mode: CredentialMode::Ephemeral,
            max_conns_per_ip: 16,
            daily_bytes_per_ip: 21_474_836_480,
            session_idle_timeout: 120,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("环境变量 {0} 的值无效：{1}")]
    Invalid(&'static str, String),
}

impl fmt::Display for CredentialMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn env_opt(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.trim().is_empty())
}

fn env_str(key: &str, default: &str) -> String {
    env_opt(key).unwrap_or_else(|| default.to_string())
}

fn env_list(key: &str) -> Vec<String> {
    env_opt(key)
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn env_parse<T>(key: &'static str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    match env_opt(key) {
        None => Ok(default),
        Some(raw) => raw
            .parse::<T>()
            .map_err(|e| ConfigError::Invalid(key, e.to_string())),
    }
}

/// 生成进程内随机密钥（仅用于本地开发占位）。
fn random_secret() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 默认配置可以加载() {
        // 不依赖具体环境变量，只验证解析路径不 panic 且默认值合理。
        let cfg = Config::from_env().expect("默认配置应当可用");
        assert_eq!(cfg.credential_mode, CredentialMode::Ephemeral);
        assert_eq!(cfg.turn_credential_ttl, 600);
        assert!(cfg.max_conns_per_ip > 0);
        assert!(cfg.session_idle_timeout > 0);
        assert_eq!(cfg.turn_realm, "secrelay.relay");
    }

    #[test]
    fn 未配置密钥时报告_turn_不可用() {
        // test_config 用空地址列表构造，等价于"没配 TURN"。
        let cfg = Config::test_config(Vec::new());
        assert!(!cfg.turn_configured());
    }

    #[test]
    fn 信令地址按对外基址拼出() {
        assert_eq!(
            signaling_url("https://relay.example.com"),
            "wss://relay.example.com/ws/signal"
        );
        assert_eq!(
            signaling_url("http://relay.example.com:8080"),
            "ws://relay.example.com:8080/ws/signal"
        );
        assert_eq!(
            signaling_url("HTTP://Relay.Example.com/"),
            "ws://Relay.Example.com/ws/signal"
        );
        // 反代挂在子路径下时保留该前缀。
        assert_eq!(
            signaling_url("https://example.com/relay"),
            "wss://example.com/relay/ws/signal"
        );
        assert_eq!(signaling_url("没有 scheme"), "没有 scheme");
        assert_eq!(signaling_url("https://"), "https://");
    }
}
