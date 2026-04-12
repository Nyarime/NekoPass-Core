# NekoPass Lite

**看起来像 VPN 的加密代理。**

NekoPass Lite 是免费开源的加密代理，基于 [NRUP](https://github.com/Nyarime/NRUP) 协议。流量伪装为 Cisco AnyConnect SSL VPN，与真实高校/企业 VPN 不可区分。

[English](#english)

---

## 快速开始

从 [Releases](https://github.com/Nyarime/NekoPass-Lite/releases) 下载，或编译：

```bash
# 服务端
nekopass-lite-server -listen :443 -password "密码"

# 客户端
nekopass-lite-client -c config.yaml
```

系统代理设为 `127.0.0.1:1080`（HTTP/HTTPS/SOCKS5 自动识别）。

## 核心能力

### DPI？不存在的

NekoPass Lite 不只是加密流量——它让流量*看起来*就是 Cisco AnyConnect SSL VPN 会话。服务端还提供一个逼真的 VPN Portal 登录页。DPI 看到的是标准企业 VPN，仅此而已。

### 别人连不上的时候你能连

基于 NRUP 协议，专为最恶劣的网络设计。FEC 前向纠错即时恢复丢包，ARQ 重传兜底。30% 丢包？照常用。70% 丢包？照样连。

### 零延迟重连

首次连接后缓存会话，0-RTT 秒连——无需完整握手，无需等待。

### 智能分流，简单配置

Clash 兼容规则语法。CN 流量默认直连，其余走代理。一个 YAML 搞定。

```yaml
server: "your-server.com:443"
password: "your-password"

proxy:
  listen: "127.0.0.1:1080"

rules:
  - "GEOIP,CN,DIRECT"
  - "MATCH,PROXY"
```

## NekoPass Lite vs NekoPass Pro

Lite 给你所有开始需要的东西。准备好了再升级 [NekoPass Pro](https://github.com/Nyarime/NekoPass)。

| | Lite | Pro |
|---|:---:|:---:|
| NRUP 传输 (FEC + ARQ + BBR) | ✅ | ✅ |
| AnyConnect / QUIC 伪装 | ✅ | ✅ |
| Cisco ASA Portal 回落页 | ✅ | ✅ |
| 0-RTT 秒连 | ✅ | ✅ |
| HTTP / HTTPS / SOCKS5 代理 | ✅ | ✅ |
| Clash 分流规则 | ✅ | ✅ |
| GEOIP CN 直连 | ✅ | ✅ |
| YAML 配置 | ✅ | ✅ |
| 密码认证 | ✅ | ✅ |
| TLS 伪装 (Reality) | | ✅ |
| TUN 全局代理 | | ✅ |
| 多节点切换 | | ✅ |
| 中心化管理 | | ✅ |
| 用户/流量管理 | | ✅ |
| 订阅分发 | | ✅ |
| 自动测速切换 | | ✅ |

## 工作原理

```
你 → [HTTP/SOCKS5 :1080] → NekoPass Client
        ↓ (看起来像 AnyConnect VPN)
    NekoPass Server [:443]
        ↓ (Portal 页面伪装)
    互联网
```

底层 NRUP 协议提供：
- **FEC**：Reed-Solomon 纠删码，无需重传即时恢复
- **ARQ**：选择性重传，FEC 兜不住的它来
- **BBR**：Google 拥塞控制算法
- **nDTLS**：AES-256-GCM / ChaCha20 加密，X25519 密钥交换

## 许可证

Apache License 2.0

---

<a name="english"></a>
## English

**The encrypted proxy that looks like a VPN.**

NekoPass Lite is a free, open-source encrypted proxy built on the [NRUP](https://github.com/Nyarime/NRUP) protocol. It disguises your traffic as Cisco AnyConnect SSL VPN — indistinguishable from a real campus or enterprise VPN connection.

### Get Started

Download from [Releases](https://github.com/Nyarime/NekoPass-Lite/releases), or build:

```bash
# Server
nekopass-lite-server -listen :443 -password "your-password"

# Client
nekopass-lite-client -c config.yaml
```

Set system proxy to `127.0.0.1:1080` (HTTP/HTTPS/SOCKS5 auto-detected).

### Key Features

- **DPI bypass** — Full Cisco ASA SSL VPN portal + DTLS fingerprint disguise
- **Works on bad networks** — 30% packet loss? Works. 70%? Still connects.
- **0-RTT reconnect** — Instant after first handshake
- **Smart routing** — Clash-compatible rules, CN traffic bypassed by default
- **Single port** — HTTP/HTTPS/SOCKS5 on :1080
- **Single binary** — Zero dependencies, download and run
