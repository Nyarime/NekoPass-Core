# NekoPass Lite

[![Go Reference](https://pkg.go.dev/badge/github.com/nyarime/nekopass-lite.svg)](https://pkg.go.dev/github.com/nyarime/nekopass-lite)

基于 [NRUP](https://github.com/Nyarime/NRUP) 的轻量加密代理。社区版，开箱即用。

[English](#english)

## 特性

- **NRUP 传输** — FEC 纠错 + ARQ 重传，弱网 30% 丢包仍可用
- **流量伪装** — AnyConnect DTLS / QUIC，DPI 不可区分
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
nekopass-lite-client -server your-server:443 -password "your-password" -listen 127.0.0.1:1080
```

然后设置系统代理为 `socks5://127.0.0.1:1080`。

## 参数

### Server

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-listen` | `:443` | 监听地址 |
| `-password` | (必填) | 连接密码 |
| `-disguise` | `anyconnect` | 伪装模式 (`anyconnect` / `quic`) |
| `-sni` | | QUIC 模式的 SNI |

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
| 0-RTT 重连 | ✅ | ✅ |
| SOCKS5 代理 | ✅ | ✅ |
| 密码认证 | ✅ | ✅ |
| TLS 伪装 | ❌ | ✅ |
| 智能分流规则 | ❌ | ✅ |
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
- **Traffic disguise** — AnyConnect DTLS / QUIC
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
