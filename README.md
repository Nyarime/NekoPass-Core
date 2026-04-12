# NekoPass Lite

**The encrypted proxy that looks like a VPN.**

NekoPass Lite is a free, open-source encrypted proxy built on the [NRUP](https://github.com/Nyarime/NRUP) protocol. It disguises your traffic as Cisco AnyConnect SSL VPN — indistinguishable from a real campus or enterprise VPN connection.

[中文](#中文)

---

## Get Started

Download the latest binaries from [Releases](https://github.com/Nyarime/NekoPass-Lite/releases), or build from source:

```bash
go install github.com/nyarime/nekopass-lite/cmd/server@latest
go install github.com/nyarime/nekopass-lite/cmd/client@latest
```

**Server:**
```bash
nekopass-lite-server -listen :443 -password "your-password"
```

**Client:**
```bash
nekopass-lite-client -c config.yaml
```

Set your system proxy to `127.0.0.1:1080` — HTTP, HTTPS, and SOCKS5 auto-detected on the same port.

## Key Features

### Deep Packet Inspection? What's that?

NekoPass Lite doesn't just encrypt your traffic — it makes it *look like* a legitimate Cisco AnyConnect SSL VPN session. The server even serves a real-looking VPN portal page. DPI systems see a standard enterprise VPN. Nothing more.

### Works when nothing else does

Built on NRUP, a protocol designed for the worst networks imaginable. FEC forward error correction recovers lost packets instantly. ARQ retransmission catches what FEC misses. 30% packet loss? Still works. 70% packet loss? Still connects.

### Zero to connected in zero round trips

After your first connection, NekoPass Lite caches your session. Reconnect instantly with 0-RTT — no full handshake, no waiting.

### Smart routing, simple config

Clash-compatible rule syntax. CN traffic goes direct by default. Everything else goes through the tunnel. One YAML file, done.

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

NekoPass Lite gives you everything you need to get started. When you're ready for more, [NekoPass Pro](https://github.com/Nyarime/NekoPass) is there.

| | Lite | Pro |
|---|:---:|:---:|
| NRUP transport (FEC + ARQ + BBR) | ✅ | ✅ |
| AnyConnect / QUIC disguise | ✅ | ✅ |
| Cisco ASA portal page | ✅ | ✅ |
| 0-RTT reconnect | ✅ | ✅ |
| HTTP / HTTPS / SOCKS5 proxy | ✅ | ✅ |
| Clash-style routing rules | ✅ | ✅ |
| GEOIP CN bypass | ✅ | ✅ |
| YAML config | ✅ | ✅ |
| Password auth | ✅ | ✅ |
| TLS disguise (Reality) | | ✅ |
| TUN system proxy | | ✅ |
| Multi-node switching | | ✅ |
| Centralized management | | ✅ |
| User & traffic management | | ✅ |
| Subscription feeds | | ✅ |
| Auto speed test & failover | | ✅ |

## How It Works

```
You → [SOCKS5/HTTP :1080] → NekoPass Client
        ↓ (looks like AnyConnect VPN)
    NekoPass Server [:443]
        ↓ (portal page for camouflage)
    Internet
```

The NRUP protocol underneath provides:
- **FEC**: Reed-Solomon erasure coding recovers packets without retransmission
- **ARQ**: Selective retransmission for what FEC can't fix
- **BBR**: Google's congestion control algorithm
- **nDTLS**: AES-256-GCM / ChaCha20-Poly1305 encryption with X25519 key exchange

## License

Apache License 2.0. The underlying [NRUP](https://github.com/Nyarime/NRUP) protocol is also Apache 2.0.

---

<a name="中文"></a>
## 中文

**看起来像 VPN 的加密代理。**

NekoPass Lite 是免费开源的加密代理，基于 [NRUP](https://github.com/Nyarime/NRUP) 协议。流量伪装为 Cisco AnyConnect SSL VPN，与真实高校/企业 VPN 不可区分。

### 快速开始

从 [Releases](https://github.com/Nyarime/NekoPass-Lite/releases) 下载，或编译：

```bash
# 服务端
nekopass-lite-server -listen :443 -password "密码"

# 客户端
nekopass-lite-client -c config.yaml
```

系统代理设为 `127.0.0.1:1080`（HTTP/HTTPS/SOCKS5 自动识别）。

### 核心能力

- **DPI 绕过** — 完整模拟 Cisco ASA SSL VPN Portal + DTLS 指纹
- **弱网可用** — 30% 丢包仍传输，70% 丢包仍连接
- **0-RTT 秒连** — 首次握手后免重连
- **智能分流** — Clash 规则语法，默认绕过 CN
- **单端口** — HTTP/HTTPS/SOCKS5 共用 :1080
- **单文件** — 零依赖，下载即用
