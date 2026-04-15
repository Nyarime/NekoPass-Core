# NekoPass-Lite v1.5.3 预规划

## 一、统一端口 (优先级: 最高)

**现状:** 39443(VPN隧道) + 39444(Portal) 双端口
**目标:** 单端口39443，基于握手特征分流

### 分流逻辑

```
ClientHello到达 :39443
  │
  ├─ TLS握手 → 检查SessionID HMAC
  │   ├─ HMAC合法 → 读MUX\n → 代理通道
  │   └─ HMAC非法 → 回落
  │       ├─ HTTP请求 → serve Portal页面 (高仿ASA)
  │       └─ 其他 → 代理到vpn.sjsu.edu
  │
  └─ 非TLS → 直接关闭
```

### 实现方案
- server handleConn已有前4字节判断
- HMAC验证失败时，不转发到39444，直接在当前conn上serve HTTP
- 需要TLS层先完成握手，再判断HTTP路径
- 关键: `net/http`的`Server.Serve()`可以传入自定义listener

### 验证点
- [ ] Portal从独立listener改为handleConn内回落
- [ ] 非法TLS连接能看到Portal登录页
- [ ] 合法连接正常代理
- [ ] 去掉39444端口

---

## 二、Server JA3S对齐 (优先级: 高)

**现状:** Go crypto/tls默认JA3S (ChaCha20优先, Go特征明显)
**目标:** JA3S接近Cisco ASA硬件设备

### Cisco ASA ServerHello特征
- CipherSuite偏好: AES-256-GCM-SHA384 > AES-128-GCM > AES-CBC (FIPS合规)
- 不优先ChaCha20-Poly1305
- 扩展字段精简 (无GREASE)
- Session Ticket/Resumption行为

### 实现方案
**方案A: crypto/tls配置调整 (低成本)**
```go
tlsCfg := &tls.Config{
    CipherSuites: []uint16{
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
        // 故意不放ChaCha20
    },
    MinVersion: tls.VersionTLS12,
    MaxVersion: tls.VersionTLS12, // ASA通常TLS1.2
}
```
限制: Go 1.17+强制接管TLS1.3的CipherSuite排序，无法自定义

**方案B: server-side uTLS (高成本)**
- fork utls支持Server端
- 完全控制ServerHello生成
- 工程量大

**方案C: 限制TLS1.2 (中等成本)**
- MaxVersion=TLS1.2时Go允许自定义CipherSuites
- 真实Cisco ASA大部分还在TLS1.2
- 这是最合理的方案

### 验证点
- [ ] 抓包对比: 当前JA3S vs 修改后JA3S
- [ ] 对比真实Cisco ASA的JA3S
- [ ] 不影响uTLS客户端连接

---

## 三、DTLS Session-ID关联 (优先级: 中)

**现状:** NRUP(UDP)和NRTP(TCP)独立握手
**目标:** 模拟AnyConnect的TLS→DTLS session关联

### 真实AnyConnect流程
1. 客户端通过TLS(TCP)建立控制通道
2. TLS通道下发DTLS参数 (session-id, master-secret, port)
3. 客户端用下发的参数建立DTLS(UDP)数据通道
4. DTLS使用TLS协商的密钥材料

### 实现方案
- NRTP连接成功后，server下发session token
- 客户端用token建立NRUP连接
- server验证NRUP的token与NRTP session匹配
- 复用已有的Bridge机制

### 验证点
- [ ] token通过NRTP下发
- [ ] NRUP握手包含token
- [ ] server验证关联

---

## 四、XML认证接口 (优先级: 低)

**现状:** Portal只有HTML登录页
**目标:** 添加AnyConnect XML认证接口

### 需要的端点
```
POST /                          → XML config (初始握手)
POST /+CSCOE+/tunnel_group.html → tunnel group选择
GET  /+webvpn+/index.html      → 认证后跳转
POST /+CSCOE+/sdesktop/scan.xml → host scan
```

### 关键XML响应
```xml
<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request">
  <version who="sg">9.12(4)53</version>
  <auth-group-select>
    <group-select>Employee-SSO</group-select>
  </auth-group-select>
  <form>
    <input type="text" name="username"/>
    <input type="password" name="password"/>
  </form>
</config-auth>
```

### 验证点
- [ ] OpenConnect客户端能识别XML响应
- [ ] GFW探测器看到标准ASA认证流程

---

## 五、证书动态刷新 (优先级: 低)

**现状:** 启动时一次性获取vpn.sjsu.edu证书
**目标:** 定期刷新，跟随真实证书更新

### 实现方案
- 每24小时重新dial vpn.sjsu.edu:443获取证书
- 证书变化时热更新TLS config
- 不影响已有连接

### 验证点
- [ ] 证书自动更新
- [ ] 已有连接不中断

---

## 优先级排序

| 阶段 | 任务 | 难度 | 收益 |
|------|------|------|------|
| P0 | 统一端口 | 中 | 消除双端口特征 |
| P1 | JA3S对齐(方案C) | 低 | 消除Go TLS指纹 |
| P2 | DTLS Session关联 | 中 | 模拟真实AnyConnect |
| P3 | XML认证接口 | 低 | 完善探测回落 |
| P4 | 证书动态刷新 | 低 | 长期可靠性 |

## 验证标准

v1.5.3发版前必须通过:
- [ ] 单端口: curl https://server:39443/ 看到Portal
- [ ] 单端口: 客户端正常代理
- [ ] JA3S: 抓包确认非Go默认指纹
- [ ] 三平台编译通过
- [ ] HK/TW/US三节点代理测试通过
- [ ] Google/YouTube可正常访问

---

## 发版前验证 (补充)

### JA3S指纹交叉比对
- 用`ja3-server`或`tshark`抓取:
  1. 真实Cisco ASA的ServerHello
  2. NekoPass v1.5.3的ServerHello
- 逐字段比对: 扩展ID+顺序, CipherSuite选择, Session Ticket行为
- 工具: `tshark -r capture.pcap -Y "tls.handshake.type==2" -T fields -e tls.handshake.ciphersuite -e tls.handshake.extensions.supported_version`

### 重放探测压力测试
- 模拟GFW多源高频重放:
  ```bash
  # 抓一个合法ClientHello
  # 从不同IP重放100次
  for i in $(seq 100); do
    openssl s_client -connect server:39443 < captured_hello &
  done
  ```
- 验证: Portal回落在高并发下Server/Date头一致性
- 验证: HMAC时间窗外的重放全部回落Portal
- 验证: 无内存泄漏/goroutine泄漏
