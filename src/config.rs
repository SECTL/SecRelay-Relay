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
    pub turn_secret: String,
    pub turn_urls: Vec<String>,
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
        let turn_secret = match env_opt("TURN_SECRET") {
            Some(secret) => secret,
            None => random_secret(),
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
            turn_secret,
            turn_urls: env_list("TURN_URLS"),
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
        !self.turn_urls.is_empty() && env_opt("TURN_SECRET").is_some()
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
    }
}
