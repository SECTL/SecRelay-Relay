# coturn 部署

本服务只做控制面：签发短期凭据、协调打洞、计数。真正的数据转发由 **coturn** 完成，
所以"中继不可用"这件事，十有八九是 coturn 这边没配好，而不是 Rust 服务。

## 数据面是零知识的

coturn 按 RFC 8656 转发的是 **DTLS-SRTP / 端到端加密后的密文**，它没有密钥，读不到画面、
文件与消息内容。服务端能看到的只有连接的元数据（IP、端口、流量大小与时刻）。
配置文件里没有任何解密钩子，coturn 也不存在这种插件能力。

## 1. 装

```bash
# Debian / Ubuntu
sudo apt-get install -y coturn
# 让 coturn 以服务方式运行
sudo sed -i 's/^#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn
```

## 2. 配置

把 `deploy/turnserver.conf` 拷到 `/etc/turnserver.conf`，改掉这几处：

| 字段 | 要点 |
|---|---|
| `external-ip` | 有公网 IP 的机器必须写，写 IP 不写域名；机器在 NAT 后面时写 `公网IP/内网IP` |
| `static-auth-secret` | 必须与 Rust 服务的 `TURN_SECRET` **完全一致** |
| `realm` | 必须与 `TURN_REALM` **完全一致**（默认 `secrelay.relay`） |
| `cert` / `pkey` | 真实证书；不配证书就只能用明文 `turn:`，`turns:` 起不来 |

凭据算法是 coturn 的 `use-auth-secret` 约定，Rust 侧实现见 `src/turn.rs`：

```text
username   = "<过期 Unix 秒>:<标识>"
password   = base64( HMAC-SHA1( static-auth-secret, username ) )
```

两边不一致时的表现是客户端 `Allocate` 收到 **401**，日志里会写
`wrong password` / `cannot find user`。**换密钥必须同时改两边并重启。**

`MIN_PORT` / `MAX_PORT`（模板里是 `min-port` / `max-port`）决定的是一段 UDP 端口池，
端口数约等于**可并发中继会话的上限**。模板用 `49152-65535`（约 1.6 万个，也是 RFC 5766
建议的区间）。省着用可以缩，但不要缩到几百——那是几百路并发就满了。

## 3. 放行端口

| 端口 | 协议 | 用途 |
|---|---|---|
| 3478 | UDP + TCP | 标准 TURN 监听 |
| 5349 | TCP | TURN over TLS（`turns:`），企业防火墙的兜底 |
| 5350 | TCP | `alt-tls-listening-port`，模板里开了 |
| 49152–65535 | **UDP** | 中继分配用；这段不放行，信令能通但媒体过不去 |

```bash
sudo ufw allow 3478/udp; sudo ufw allow 3478/tcp
sudo ufw allow 5349/tcp; sudo ufw allow 5350/tcp
sudo ufw allow 49152:65535/udp
```

> 最容易踩的坑：只放行了 3478，忘了端口池。客户端能拿到候选、能连上中继地址，
> 但媒体一个包都过不去。

## 4. 与本服务共用同一个 secret

```bash
# 生成一次，两处都用它，不要分别生成
openssl rand -hex 32
```

`/etc/turnserver.conf` 里写 `static-auth-secret=<它>`，本服务的环境变量里写
`TURN_SECRET=<它>`。secret 不要进仓库（`.gitignore` 已排除 `.env`）。

`TURN_URLS` 要和 coturn 实际监听的地址端口对得上，例如：

```bash
TURN_URLS="turn:relay.example.com:3478?transport=udp,turn:relay.example.com:3478?transport=tcp,turns:relay.example.com:5349"
```

## 5. TLS

`turns:` 用真实证书（Let's Encrypt 即可）。coturn 需要**读得到**私钥，
常见做法是给它一份拷贝并设好权限，或者把 coturn 加进证书目录的组：

```bash
sudo install -o turnserver -g turnserver -m 640 \
  /etc/letsencrypt/live/relay.example.com/privkey.pem /etc/turnserver/privkey.pem
sudo install -o turnserver -g turnserver -m 644 \
  /etc/letsencrypt/live/relay.example.com/fullchain.pem /etc/turnserver/fullchain.pem
```

配置里指到 `/etc/turnserver/...`，重启 coturn，然后确认：

```bash
sudo journalctl -u coturn -n 50 | grep -i "tls\|cert"
```

## 6. 起服务

```bash
sudo systemctl enable --now coturn
sudo systemctl status coturn
```

## 7. 怎么验证它真的在转发

用 `deploy/verify-relay.ps1`（Windows / PowerShell）：

```powershell
.\deploy\verify-relay.ps1 -RelayBase https://relay.example.com `
  -Secret $env:TURN_SECRET -TurnHost relay.example.com -TurnPort 3478
```

它做两件事：

1. 拉 `/api/v1/relay`，用独立实现重算 `base64(HMAC-SHA1(secret, username))`，
   确认逐字符一致；
2. 拿这份凭据向 coturn 发一条真正的 TURN `Allocate`（先收 401 挑战拿 REALM/NONCE，
   带 `MESSAGE-INTEGRITY` 重发），确认 **coturn 接受该凭据并分配了中继地址**。

Linux 上也可以用 coturn 自带的客户端做等价验证：

```bash
turnutils_uclient -v -u "$(curl -s https://relay.example.com/api/v1/relay | jq -r '.ice[0].username')" \
  -w "$(curl -s https://relay.example.com/api/v1/relay | jq -r '.ice[0].credential')" \
  -p 3478 relay.example.com
```

（两次 `curl` 会拿到不同的过期时间戳，凭据要取同一次响应。）

真正验证"打洞失败会回退到中继"还需要两台客户端：在两端都禁用 UDP（或用一个只放行
TCP/443 的网络）后发起连接，然后在 coturn 侧观察 `Allocate` 与中继流量：

```bash
# coturn 日志里应当出现 Allocate 与中继会话
sudo journalctl -u coturn -f | grep -i "allocate\|relay"
# 同时看本服务的指标：中继占比、每 IP 流量
curl -s http://127.0.0.1:8080/metrics
```

## 8. 本仓库内的验证状态（如实说明）

- **本机实测过的**：`/api/v1/relay` 的响应、凭据与 `TURN_SECRET` 的一致性、
  `deploy/verify-relay.ps1` 里那个 TURN 客户端（401 挑战 → 带凭据 Allocate → 成功响应）。
  客户端是对着一个**本机回环上的模拟 coturn** 跑的，由模拟端独立按 coturn 的算法校验了
  `MESSAGE-INTEGRITY`（key = `MD5(username:realm:password)`）、`REQUESTED-TRANSPORT`、
  `REALM`、`NONCE` 与过期时间。也就是说：**客户端发的 Allocate 格式是对的**，
  但"真实 coturn 会不会接受"这一步没有在本机验证过。
- **本机没有实测的**：真实 coturn 二进制、真实 TLS 握手、真实媒体转发、
  两台客户端之间的打洞失败回退。本机没有 coturn / Docker / WSL 发行版，
  也没有可用的公网 STUN，这几项只能部署到服务器上再跑。
