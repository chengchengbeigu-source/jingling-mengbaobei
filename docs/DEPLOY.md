# MB 豆包萌宠 · 本地私服与共存包部署

> 架构：**共存版 APK**（与官方原版可同机安装）→ **本地私服**（127.0.0.1:4430 / :20311）→ 官方源站（资源回源缓存 + WS 透传）。
> 私服对所有 `bootstrap` 请求直接放行发 `launchToken`，因此**无需机器码人工授权**。

```
共存包(com.localfirst.Mb)                本地私服(mbserver.py)                 官方
┌──────────────────────┐   HTTPS 4430   ┌────────────────────┐   回源(带会话)  ┌──────────┐
│ 线路URL→127.0.0.1:4430│ ─────────────→ │ /apk/bootstrap 放行 │ ─────────────→ │ mcbtc.cn │
│ 内置CA→本地CA         │                │ /launch 会话流      │                │ :20310   │
│ 签名指纹→本地签名证书  │                │ /pet05f/* 镜像+回源 │                └──────────┘
└──────────────────────┘   WSS  20311   │ /client-* 埋点吸收  │   TLS-bump 透传
                                        │ WS 隧道(可抓包)     │ ─────────────→ :20311
                                        └────────────────────┘
```

## 一、本地构建共存包

```bash
# 0) 依赖：python3 + cryptography
pip install cryptography

# 1) 生成证书三件套（CA / server / coexist，幂等；已有则跳过）
python3 tools/gen_certs.py            # --force 强制重生成

# 2) 构建共存包（官方原版 APK → 共存 APK）
python3 tools/build_coexist.py apk/mb-1.1.4.apk out/mb-coexist.apk

# 3) 复核（zip对齐 / 补丁点 / v2签名 / 指纹一致性，全过才装）
python3 tools/verify_apk.py out/mb-coexist.apk
```

共存包相对原版只改四处：

| 位置 | 改动 | 目的 |
|---|---|---|
| `classes.dex` | 线路常量（Base64 三行 URL）→ `https://127.0.0.1:4430/launch` ×3（字符串表重定位，修 SHA-1/Adler32） | 流量指向本地私服 |
| `AndroidManifest.xml` | 仅 applicationId `com.localfirst.mb`→`com.localfirst.Mb`（边界锚定；组件类名 `com.localfirst.mb.*` 不动） | 与原版共存 |
| `resources.arsc` | 包名字符串 + 内置预期签名指纹 → 新签名证书指纹 | 通过 App 自校验 |
| `res/yo.der` | 内置私有 CA → 本地私有 CA | 信任本地 server 证书 |

签名：仅 v2（APK Signing Block, RSA-SHA256, 0x0103），全条目 STORED + 4 字节对齐（targetSdk 36 要求）。

## 二、启动私服

```bash
cd server
python3 mbserver.py            # 前台；MB_RECORD=1 python3 mbserver.py 可抓 WS 帧
```

- `https://127.0.0.1:4430`：bootstrap / launch / 游戏资源（先镜像后回源，官方更新自动跟进）
- `wss://127.0.0.1:20311`：游戏 WS 隧道（TLS-bump 透传到官方 :20311）
- 证书在 `server/pem/`；`*.key` 不入库（CI 用 secrets 注入）

## 三、CI 自动构建（GitHub Actions）

推送到 `main`（或手动 workflow_dispatch）自动构建并上传 artifact `mb-coexist-apk`。

签名密钥通过 repo secrets 注入（`MB_CA_KEY` / `MB_SERVER_KEY` / `MB_COEXIST_KEY`，均为 base64(PEM 私钥)）：

```bash
gh secret set MB_CA_KEY      < server/pem/ca.key      # 先 base64：base64 -w0 ca.key
gh secret set MB_SERVER_KEY  < server/pem/server.key
gh secret set MB_COEXIST_KEY < server/pem/coexist.key
```

（写入时用 `base64 -w0 文件 | gh secret set 名称`。）

## 四、安装与验收清单

1. `adb install -r out/mb-coexist.apk`（或手机上直接点装；与官方原版包名不同，可共存）
2. 启动**共存版**图标 → 应直接进游戏（无机器码授权页）
3. 打开**官方原版** → 应一切照旧（互不影响）
4. 私服日志应出现：`bootstrap APPROVED` → `GET /launch` 302 → `/pet05f/index.html?...serverIp=127.0.0.1:20311`
5. 游戏内跑一圈（进战斗、看状态栏），`server/mirror/` 应持续新增缓存文件
6. 断网官方再启动：资源走镜像缓存；**WS 仍需官方在线**（离线仿真见"已知边界"）

## 五、已知边界 / 后续路线

- **官方关服时**：HTTP 资源走本地镜像缓存可玩，但 WS 游戏服仍透传到官方 → 官方宕机则战斗不可用。
  路线：`MB_RECORD=1` 抓 WS 帧 → 分析二进制协议（长度前缀+packetStamp）→ 本地协议仿真/回放。
- 源站会话失效会自动用模拟客户端重新 bootstrap（协议见 `docs/RE-analysis.md`）。
- 共存包若与官方更新后的新版本 APK 不兼容，需对新版重跑 `build_coexist.py`（补丁点按 `docs/RE-analysis.md` 复核）。
