# NekoPass Core

轻量级加密代理，流量伪装为 Cisco AnyConnect SSL VPN。

## 特性

- **Fake-TLS模式**: 镜像真实VPN服务器证书和内容，与目标不可区分
- **TLS模式**: 自签证书 + 本地Cisco ASA Portal模板
- **GoFEC纠删码**: RS / RaptorQ / LDPC，AVX2/NEON SIMD加速
- **AnyConnect伪装**: 完整Portal登录页、XML认证接口、9个cookies
- **JA3S对齐**: ServerHello字节级匹配真实Cisco ASA
- **SmartTransport**: UDP/TCP自动切换，指数退避探测
- **动态Session**: 6-12个并行mux连接，按存活率调整
- **统一端口**: VPN + Portal同端口

## 安装

从 [Releases](https://github.com/Nyarime/NekoPass-Core/releases) 下载对应平台的二进制。

## 使用

### 服务端

```bash
# Fake-TLS模式 (推荐)
nekopass-server -listen :443 -password <密码> -sni vpn.example.edu

# TLS模式
nekopass-server -listen :443 -password <密码> -sni ""

# 停止
nekopass-server stop
```

### 客户端

```bash
nekopass-client -c config.yaml
nekopass-client -c config.yaml -tui    # TUI界面
```

### 配置文件

```yaml
server: "your-server.com:443"
password: "your-password"
sni: "vpn.example.edu"
transport: "auto"      # auto / udp / tcp
fec_type: "rs"         # rs / raptorq / ldpc
mode: "rule"           # rule / global / direct

proxy:
  listen: "127.0.0.1:1080"
```

## 架构

```
客户端                          服务端 (:443)
  │                                │
  ├─ SOCKS5/HTTP ← 本地代理        │
  │                                │
  ├─ NRTP (TCP)                    ├─ Fake-TLS: 偷证书 + proxyToReal
  │   └─ smux多路复用              │   └─ 失败→本地Portal (熔断)
  │   └─ uTLS Chrome指纹          │
  │                                ├─ TLS: 自签证书 + 本地Portal
  ├─ NRUP (UDP, 可选)              │
  │   └─ nDTLS + GoFEC            ├─ Portal: Cisco ASA登录页
  │                                │   └─ 9个cookies + CSP + HSTS
  └─ SmartTransport               │
      └─ UDP优先, TCP降级          └─ JA3S: ECDHE-AES-GCM (无ChaCha20)
```

## 依赖

- [NRTP](https://github.com/Nyarime/NRTP) — TCP传输层
- [NRUP](https://github.com/Nyarime/NRUP) — UDP传输层
- [GoFEC](https://github.com/Nyarime/GoFEC) — FEC纠删码

## 许可证

Apache License 2.0
