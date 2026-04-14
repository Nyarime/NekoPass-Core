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

NekoPass Lite 不只是加密流量——它让流量*看起来*就是 Cisco AnyConnect SSL VPN 会话。TLS 证书从真实 VPN 服务器镜像（fake-tls 模式），Portal 页面完整模拟 Cisco ASA。DPI 看到的是标准企业 VPN，仅此而已。

### 别人连不上的时候你能连

基于 NRUP 协议，专为最恶劣的网络设计。FEC 前向纠错即时恢复丢包，ARQ 重传兜底。30% 丢包？照常用。70% 丢包？照样连。UDP 被封？自动降级 TCP TLS。

### 零延迟重连

首次连接后缓存会话，0-RTT 秒连——无需完整握手，无需等待。

### 智能分流，简单配置

Clash 兼容规则语法。CN 流量默认直连，其余走代理。一个 YAML 搞定。

```yaml
server: "your-server.com:443"
password: "your-password"
sni: "vpn2fa.hku.hk"

proxy:
  listen: "127.0.0.1:1080"

rules:
  - "GEOIP,CN,DIRECT"
  - "MATCH,PROXY"
```

## NekoPass Lite vs NekoPass Pro

Lite 提供完整的单机代理能力。Pro 在此基础上增加集群管理和商业运营功能。

| | Lite | Pro |
|---|:---:|:---:|
| NRUP 传输 (FEC + ARQ + BBR) | ✅ | ✅ |
| AnyConnect DTLS 伪装 | ✅ | ✅ |
| fake-tls 伪装 | ✅ | ✅ |
| Cisco ASA Portal 模拟 | ✅ | ✅ |
| TCP TLS 降级 | ✅ | ✅ |
| 0-RTT 秒连 | ✅ | ✅ |
| HTTP / HTTPS / SOCKS5 | ✅ | ✅ |
| SOCKS5 UDP | ✅ | ✅ |
| Clash 分流规则 | ✅ | ✅ |
| GEOIP CN 直连 | ✅ | ✅ |
| 多节点集群 | | ✅ |
| 用户 / 流量管理 | | ✅ |
| 订阅分发 | | ✅ |
| Web 管理面板 | | ✅ |
| 节点智能调度 | | ✅ |
| 内置 TUN | | ✅ |

## 工作原理

```
你 → [HTTP/SOCKS5 :1080] → NekoPass Client
        ↓ (看起来像 AnyConnect VPN)
    NekoPass Server [:443]
        ↓ (Cisco ASA Portal 伪装)
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

- **fake-tls-style TLS** — Certificate mirrored from real VPN server
- **Cisco ASA portal** — Full AnyConnect portal simulation
- **Works on bad networks** — 30% loss? Works. 70%? Still connects. UDP blocked? Auto TCP fallback.
- **0-RTT reconnect** — Instant after first handshake
- **Smart routing** — Clash-compatible rules, CN bypassed by default
- **Single port** — HTTP/HTTPS/SOCKS5 + UDP on :1080
- **Single binary** — Zero dependencies

## NRUP↔NRTP Bridge

NRUP(UDP)和NRTP(TCP)共享状态：
- 证书共享：NRTP获取→NRUP nDTLS也用
- UDP状态同步：SmartTransport读取
- 共用PSK密钥
- 零开销（同进程指针共享）
- 事件驱动 (状态变化<1ms通知)
- 优雅退出: bridge.Close()
- Bridge 负责 NRUP 与 NRTP 之间的状态同步与证书共享，启动时自动初始化，退出时自动清理

## 智能传输

UDP (NRUP) 和 TCP (NRTP) 自动切换：

```
UDP 正常 → 用 NRUP (FEC 抗丢包)
UDP 连续3次失败 → 自动降级 TCP (NRTP)
每5分钟探测 UDP → 恢复了自动切回
```

无需手动配置，全自动。

## TUI 终端界面

```bash
nekopass-lite-client -c config.yaml --tui
```

快捷键: `T` TUN / `S` 系统代理 / `M` 模式 / `1-3` 切换页面 / `Q` 退出

## 弱网优化 (v1.4.1)
- SACK选择性重传（只重传真正丢失的包）
- FEC有效性反馈（动态调整冗余率）
- SmartTransport+FEC协同（FEC效果差→提前降级TCP）
