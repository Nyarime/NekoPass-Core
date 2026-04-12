# NekoPass Lite

[![Go Reference](https://pkg.go.dev/badge/github.com/nyarime/nekopass-lite.svg)](https://pkg.go.dev/github.com/nyarime/nekopass-lite)

基于 [NRUP](https://github.com/Nyarime/NRUP) 的轻量加密代理，伪装为 Cisco AnyConnect SSL VPN。社区版，开箱即用。

[English](#english)

## 特性

- **Cisco AnyConnect 伪装** — 完整模拟 ASA SSL VPN Portal 登录页、tunnel-group-list.xml、DTLS 指纹
- **高校 SSL VPN 伪装** — DPI 无法区分真实 VPN 和 NekoPass
- **NRUP 传输** — FEC 纠错 + ARQ 重传，弱网 30% 丢包仍可用
- **0-RTT 重连** — 首次握手后秒连
- **SOCKS5 代理** — 兼容所有客户端
- **密码认证** — 简单安全
- **单文件部署** — 零依赖

## 快速开始

### 服务端

```bash
nekopass-lite-server -listen :443 -password "your-password"
```

### 客户端

```bash
nekopass-lite-client -c config.yaml
```

```yaml
# config.yaml
server: "your-server.com:443"
password: "your-password"
disgrise: "anyconnect"

proxy:
  http: "127.0.0.1:7890"     # HTTP/HTTPS 代理
  socks5: "127.0.0.1:7891"   # SOCKS5 代理

rules:
  - "DOMAIN-KEYWORD,baidu,DIRECT"
  - "DOMAIN-KEYWORD,bilibili,DIRECT"
  - "GEOIP,CN,DIRECT"
  - "MATCH,PROXY"
```

默认配置绕过 CN 流量，其余全走代理。规则语法与 Clash 一致。

## 参数

### Server

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-listen` | `:443` | 监听地址 |
| `-password` | (必填) | 连接密码 |
| `-disguise` | `anyconnect` | 伪装模式 (`anyconnect` / `quic`) |
| `-portal` | `:8443` | AnyConnect Portal HTTPS 监听 (留空禁用) |
| `-portal-title` | `SSL VPN Service` | Portal 页面标题 |

### Portal 伪装

服务端自动提供 Cisco ASA 风格的 SSL VPN Portal 登录页：

- `/` — SSL VPN 登录页（模拟高校/企业 VPN Portal）
- `/+CSCOE+/logon.html` — AnyConnect 客户端探测端点
- `/+CSCOT+/tunnel-group-list.xml` — Tunnel Group XML
- `/CSCOSSLC/tunnel` — CONNECT 端点

浏览器直接访问看到的是标准的 Cisco ASA 登录界面，DPI 检测结果也是标准 SSL VPN 服务。

### Client

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-server` | (必填) | 服务端地址 |
| `-password` | (必填) | 连接密码 |
| `-listen` | `127.0.0.1:1080` | 本地 SOCKS5 监听 |
| `-disguise` | `anyconnect` | 伪装模式 |

## 编译

```bash
# 全平台
make all

# 或手动
go build -o nekopass-lite-server ./cmd/server
go build -o nekopass-lite-client ./cmd/client
```

## 与 NekoPass Pro 的区别

| 功能 | Lite (社区版) | Pro (专业版) |
|------|:---:|:---:|
| NRUP 传输 | ✅ | ✅ |
| AnyConnect/QUIC 伪装 | ✅ | ✅ |
| Cisco ASA Portal | ✅ | ✅ |
| 0-RTT 重连 | ✅ | ✅ |
| HTTP/HTTPS 代理 | ✅ | ✅ |
| SOCKS5 代理 | ✅ | ✅ |
| 分流规则 (Clash 语法) | ✅ | ✅ |
| GEOIP CN 直连 | ✅ | ✅ |
| YAML 配置 | ✅ | ✅ |
| 密码认证 | ✅ | ✅ |
| TLS 伪装 | ❌ | ✅ |
| TUN 全局代理 | ❌ | ✅ |
| 多节点切换 | ❌ | ✅ |
| Master 管控 | ❌ | ✅ |
| 用户/流量管理 | ❌ | ✅ |
| 订阅分发 | ❌ | ✅ |

## 许可证

Apache License 2.0

---

<a name="english"></a>
## English

Lightweight encrypted proxy based on [NRUP](https://github.com/Nyarime/NRUP). Community edition.

### Features

- **NRUP transport** — FEC + ARQ, works at 30% packet loss
- **Traffic disguise** — Cisco AnyConnect SSL VPN portal + DTLS fingerprint
- **University VPN camouflage** — Indistinguishable from real campus SSL VPN
- **0-RTT reconnect** — instant after first handshake
- **SOCKS5 proxy** — universal compatibility
- **Password auth** — simple and secure

### Quick Start

```bash
# Server
nekopass-lite-server -listen :443 -password "your-password"

# Client
nekopass-lite-client -server your-server:443 -password "your-password"
```

Set system proxy to `socks5://127.0.0.1:1080`.
