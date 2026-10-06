# SecRelay-Relay

SecRelay 的信令与中继服务。

> 定位：让两台设备在无法直连时也能连上，同时**不成为任何人的免费带宽**。

## 这个仓库负责什么

| 负责 | 不负责 |
|---|---|
| 信令协调（交换候选、协调打洞） | 账号与登录（那是 SECTL-auth 的事） |
| 短期 ICE 凭据签发 | 解密任何内容（**零知识**） |
| 打洞失败时的密文中继（基于 coturn） | 离线消息暂存（独立组件） |
| 配额、限速与滥用防护 | 用户数据的持久化 |
| 直连成功率 / 中继占比等 KPI 埋点 | 客户端 UI |

## 两条硬约束

1. **不做账号验证。** 任何人都可以连接，中继不校验 token、不关心你有没有登录。
2. **零知识。** 中继只转发密文。即使服务器被完全控制，也读不到画面、文件与消息内容。

> ⚠️ **但"无鉴权"不等于"无保护"。** 中继唯一的显著成本是带宽（1080p 约 **1.8 GB/小时**，单向），
> 一个完全开放的 TURN 服务器会迅速被白嫖。本仓库的做法是：**不要账号，但要短期凭据 + 配额 + 观测**，
> 详见 [docs/设计.md](docs/设计.md) §4。

## 状态

🚧 **骨架 + 中继接入**。已有配置、健康检查、信令 WebSocket、配额中间件、TURN 短期凭据签发、
中继发现接口 `/api/v1/relay`，以及 `deploy/` 下的 coturn 配置模板与验证脚本。
**尚未在真实 coturn 上跑过端到端验证**（本机没有 coturn），也还没做压测。

## 快速开始

```bash
cargo run
# 默认监听 0.0.0.0:8080
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/api/v1/relay
```

配置全部走环境变量，见 [docs/设计.md](docs/设计.md) §10。

## 接上 coturn

数据面交给 [coturn](https://github.com/coturn/coturn)，本服务只做控制面：

1. 按 [docs/部署-coturn.md](docs/部署-coturn.md) 起 coturn，用 `deploy/turnserver.conf` 当模板；
2. 把同一个随机密钥填进 coturn 的 `static-auth-secret` 和本服务的 `TURN_SECRET`，
   `realm` 两边也要一致；
3. 设好 `PUBLIC_BASE_URL`（对外域名）与 `TURN_URLS`；
4. 用验证脚本确认凭据能被 coturn 接受：

   ```powershell
   .\deploy\verify-relay.ps1 -RelayBase https://relay.example.com `
     -Secret $env:TURN_SECRET -TurnHost relay.example.com -TurnPort 3478
   ```

> **coturn 只转发密文。** 它按 RFC 8656 转发 DTLS-SRTP / 端到端加密后的数据，
> 没有密钥，读不到画面、文件与消息内容；能看到的只有 IP、端口、流量大小这些元数据。

## 相关仓库

- `SecRelay` —— 客户端与核心（Rust 核心 + 可替换 UI）
- `SECTL-auth` —— 组织账号系统（OAuth 2.0 + 云存储 + 通知），中继**不依赖**它

## 许可证

**AGPL-3.0-or-later**，全文见 [LICENSE](LICENSE)。

为什么是中继用 AGPL 而不是跟着主仓库的 GPLv3：GPLv3 的源码义务**不覆盖"仅通过网络提供服务"**
这一情形，而中继恰好是一个网络服务 —— 别人改了这个实现拿去对外提供中继，我们希望对等地拿到他的改动。
AGPL §13 正是为此存在。

> 官方部署的那台不受此约束：著作权在我们手里，官方仓库是著作权人自己的作品，保持专有。
> 公开仓库的 AGPL 用来约束**第三方**，不是约束我们自己。