# 豆包萌宠 (com.localfirst.mb) v1.1.4 逆向分析报告

> 分析日期: 2026-11-16 · APK SHA-256: 0bde192dc5e7b18a808da71f4a0e051f55af919f0a90488c914ab006b4b9a515

## 1. 基本信息

| 项目 | 值 |
|---|---|
| 包名 | `com.localfirst.mb` |
| 版本 | 1.1.4 (versionCode 8) |
| minSdk / targetSdk | 24 / 36 |
| 权限 | 仅 `INTERNET` |
| 组件 | 1 Activity (`MainActivity`), 无 Service/Receiver/Provider |
| 大小 | 88 KB, 29 个 zip 条目, 纯 r8 编译, 无壳无加固 |
| 架构 | WebView 壳 + H5 游戏 (Cocos) |
| 清单特点 | `usesCleartextTraffic=false`, 自定义 `networkSecurityConfig` |

## 2. 业务代码结构（仅两个业务类）

- `MbApplication` — 预热 WebView 启动任务（无业务逻辑）
- `MainActivity` — 核心逻辑：线路选择、签名自校验、设备指纹派生、bootstrap 握手、WebView 加载

### 2.1 线路配置（DEX 内 Base64 硬编码）

```
https://mcbtc.cn:20310/launch
https://nalanquede.top:20310/launch
https://nalanquede.cn:20310/launch
```

三个域名当前解析到同一台服务器（nginx/1.24.0 Ubuntu），TLS 叶子证书相同：
`CN=mcbtc.cn, SAN=[mcbtc.cn, nalanquede.cn, nalanquede.top]`,
签发者 `CN=MB Game Private Root CA`（与 APK 内置 CA 一致，已验证签名链）。

### 2.2 内置私有 CA

- 文件: `res/yo.der`（资源名 `@raw/game_tls_certificate`）
- Subject/Issuer: `CN=MB Game Private Root CA`, 自签, CA:TRUE
- 有效期: 2026-10-27 ~ 2036-10-24
- 证书 SHA-256: `9113112d2afe162ba56592564101d04c5b6dff9f01d68feac33e5745cf346c4c`
- `network_security_config`: base-config 仅信任该 CA（系统 CA 全部不信任）
- 含义: 客户端只信任该 CA 签发的证书 → 私服需替换此 CA

### 2.3 签名自校验

`MainActivity.d()` 读取自身签名证书，SHA-256 与资源字符串比较：

```
apk_signer_sha256 = 89290d81c7abe96a090ba4323811068e227d5b68e20e91f5c60b21c342ac37a0
```

不匹配则显示「安装包签名校验失败，请安装官方原版」并退出。
**关键结论: 运行时只读取签名块中的证书，不重新验签 → 保持原签名块、原地改文件即可绕过。**

### 2.4 设备指纹与令牌派生

```
install_salt  = UUID 随机生成一次, 存 SharedPreferences(apk_access)/install_salt, 格式校验 [A-Za-z0-9_-]{32,128}
deviceId      = base64url(SHA256("v1\n" + packageName + "\n" + android_id + "\n" + install_salt))
registration  = base64url(SHA256("mb-registration-v1\n" + packageName + "\n" + lower(android_id)))
               (android_id 需匹配 [0-9a-fA-F]{1,16} 且非全 0 / 非 9774d56d682e549c)
```

### 2.5 bootstrap 握手协议（POST /apk/bootstrap）

请求 JSON:

```json
{"packageName": "com.localfirst.mb", "deviceId": "<b64url>", "registrationDeviceId": "<b64url>",
 "timestamp": <unix秒>, "nonce": "<b64url(18随机字节)>", "proof": "<b64url>"}
```

proof 计算（HMAC-SHA256，密钥内嵌 DEX）:

```
有 registrationDeviceId 时: msg = "v2\n<pkg>\n<deviceId>\n<registration>\n<ts>\n<nonce>"
无时:                      msg = "v1\n<pkg>\n<deviceId>\n<ts>\n<nonce>"
proof = base64url(HMAC_SHA256(secret, msg))
```

**内置 HMAC 密钥（Base64, DEX 硬编码）:**

```
Sang_rIvZNZf1bJkOwkLsC0bOKMll7oY-Juw81rzhZK_h1rgBx5cgl-jZ5GTSKdv
```

请求头: `Content-Type: application/json; charset=utf-8`, `User-Agent: MBGameApp/1.0`

响应分支:

| HTTP | status | 含义 | 客户端行为 |
|---|---|---|---|
| 200 | `ok:true` + `launchToken` | 通过 | token 须匹配 `[A-Za-z0-9_.-]{80,512}` |
| 202 | `pending` + `deviceCode` | 待审批 | 显示机器码 `XXXX-XXXX-XXXX`（格式 `[A-F0-9]{4}-...`） |
| 403 | `revoked` + `deviceCode` | 已吊销 | 显示吊销提示 |
| 其他 | - | 拒绝 | 报错重试 |

**协议已复现: 使用内置密钥向真实服务器模拟握手，成功获得 200 + launchToken。**

### 2.6 launch 流程

1. `GET /launch?apkToken=<token>` → `302` → `Location: /launch` + `Set-Cookie: mb_apk_session=...`(HttpOnly, SameSite=Strict, 24h)
2. 带 cookie `GET /launch` → `302` → `/pet05f/index.html?scid=11&sdkcname=H5_quikSDK&_platform_=304&channel_id=100304&game_channel_id=100304&protocal=ws&serverIp=mcbtc.cn%3A20311&vvv=1&vv=20260327&...`
3. 游戏页加载 `res/start.js?v=5391&mbpatch=...` → Cocos 引擎 → WebSocket 连 `serverIp`

### 2.7 WebView 安全配置

- JS/DOM storage 开启, 文件访问全部关闭, geolocation 关, 多窗口关
- UA 追加 ` MBGameApp/1.0`
- `shouldInterceptRequest`/`shouldOverrideUrlLoading`: 仅放行与所选线路 scheme/host/port 完全一致的 URL，其余一律阻断（拦截返回空响应）
- WS (ws/wss scheme) 不走该拦截 → 游戏可连任意 host 的 WebSocket
- `onReceivedSslError` 直接 cancel（配合 NSC，TLS 必须严格有效）
- 页面注入了服务端变速外挂钩子（`Date.now`/`performance.now` 缩放、`game.BattleAction.prototype.start` 最高 3 倍速）

## 3. 私服改造方案（本仓库实现）

### 3.1 架构

```
┌─ 手机 (root) ────────────────────────────────────────┐
│  改装 APK (原地改 base.apk, 保留原签名块)              │
│   ├ res/yo.der → 换成本地自建 CA 公钥证书              │
│   └ dex 线路 Base64 → https://127.0.0.1:4430/launch   │
│  本地服务 (127.0.0.1)                                 │
│   ├ :4430 HTTPS  /apk/bootstrap  自签发 launchToken    │
│   │              /launch → 本地游戏页(重写 serverIp)   │
│   │              /pet05f/* → 本地镜像或反代源站         │
│   └ :20311 WSS   WebSocket 代理/录制 → 源站 :20311     │
└──────────────────────────────────────────────────────┘
```

### 3.2 为什么保留原签名块

- 签名自校验只比对证书公钥指纹（PackageInfo.signatures）→ 原地改 zip 内容不影响
- 无需重签 → 不需要 Java/apksigner 工具链
- zip 重写后 v2 签名摘要失效，但运行时无人复验（仅重装时校验）

### 3.3 dex 补丁原理

线路 URL 在 DEX 中是 Base64 常量。构造**等长**的 Base64 串（明文用无意义 query 参数填充到精确字节数），
原地字节替换，所有 DEX 偏移不变。


### 3.4 APK 原地补丁流程（tools/patch_apk.py）

```
1. 复制设备上已安装的 base.apk（保持 zip 原始布局，不重打包）
2. 替换 res/yo.der          → 本地 CA 公钥证书 (DER, 原地等长/或用 zip 局部重写)
3. 替换 DEX 中线路 Base64    → https://127.0.0.1:4430/launch (等长填充)
4. push 回设备原路径 + 修复权限/SELinux 上下文
   (不改 AndroidManifest, 不动签名块, 不触发重装校验)
```

注: zip 条目替换需保持压缩方式与 CRC 一致性 —— 本实现直接重写该条目的
local header + central directory 记录，其余字节不动；大小变化通过
中央目录偏移修正处理。

### 3.5 本地服务端（server/）

| 端点 | 行为 |
|---|---|
| `POST /apk/bootstrap` | 校验 proof（同一 HMAC 密钥）→ 200 + launchToken |
| `GET /launch?apkToken=` | 种 `mb_apk_session` cookie → 302 /launch |
| `GET /launch` (带 cookie) | 302 → `/pet05f/index.html?...&serverIp=127.0.0.1:20311&vvv=1&...` |
| `GET /pet05f/*` | 本地静态镜像；缺失文件实时反代源站并缓存 |
| `WSS :20311` | WebSocket 反代 → `mcbtc.cn:20311`（保留游戏联机功能） |
| `:4430` TLS | 本地 CA 签发的证书, SAN=[127.0.0.1, localhost, mcbtc.cn, nalanquede.top, nalanquede.cn] |

### 3.6 改装 APK 的 WebView 拦截兼容性

MainActivity.e() 只放行与线路 origin 完全一致的 URL：

```
scheme = https, host = 127.0.0.1, port = 4430  → 与 dex 内新线路一致 ✓
```

WebView 直连 `https://127.0.0.1:4430` 要求证书对 `127.0.0.1` 有效 →
本地 CA 的 SAN 必须包含 `127.0.0.1` 与 `localhost`（Android WebView 对 IP 直接连
按 IP 校验 SAN，需要 iPAddress:127.0.0.1 条目）。

## 4. 完整时间线

| 日期 | 事件 |
|---|---|
| 2026-10-27 | 私有根 CA 创建（30 天前） |
| 2026-11-04 | 服务器叶子证书签发（12 天前） |
| 2026-11-16 (今天) | APK v1.1.4 样本获取, 完成逆向 |
| 版本标记 | `mbpatch=20261116-island-capacity-league-reward-v513`（服务端热更标记, 与本地分析同日） |

## 5. 法律与边界声明

- 本项目仅用于对**用户自己拥有并已付费/运营授权**的 H5 游戏服务进行本地化部署、
  网络调试、存档研究与学术分析。
- 逆向产物（报告、补丁工具、服务端）**不得**用于：
  - 运营面向第三方的盗版服务器
  - 破坏原服务（DoS、账号盗取、数据篡改）
  - 任何商业用途
- 原游戏的美术资源、代码、商标属于原作者；反代/镜像仅限个人本地缓存用途。
- WebSocket 代理保留原服务器联机功能时，遵守原服务的用户协议。

## 6. 仓库结构

```
docs/RE-analysis.md   ← 本报告
tools/patch_apk.py    ← APK 原地补丁工具（dex 线路 + CA 替换）
tools/gen_certs.sh    ← 本地 CA / 服务器证书生成
server/mbserver.py    ← 本地私服 (HTTPS + WS 代理)
server/pem/           ← 证书目录 (生成产物)
```
