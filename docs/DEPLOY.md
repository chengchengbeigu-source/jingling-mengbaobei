# 部署指南（手机本地私服）

## 前置条件

- Android 手机已 root（Magisk/KernelSU 均可）
- Python 3.8+（手机本地或 Termux 容器内运行 server/mbserver.py）
- 本仓库已克隆/同步到手机

## 第 1 步：生成证书

```bash
bash tools/gen_certs.sh        # 生成 server/pem/{ca.key, ca.crt, server.crt, server.key}
```

## 第 2 步：启动本地服务

```bash
python3 server/mbserver.py     # 监听 20311 需要 root；4430 普通用户即可
```

成功标志（日志）：

```
[..] WS tunnel listening on 127.0.0.1:20311
[..] origin session acquired (171 bytes)
[..] HTTPS listening on 127.0.0.1:4430
```

## 第 3 步：补丁已安装的 APK

```bash
# 3.1 找到设备上的安装包（root shell）
PM_PATH=$(pm path com.localfirst.mb | sed 's/package://;s/base://' | head -1)
cp "$PM_PATH" /sdcard/Download/DSHA/游戏/精灵萌宝贝/installed.apk

# 3.2 在仓库目录执行补丁（PC/容器/Termux 均可）
python3 tools/patch_apk.py installed.apk patched_installed.apk

# 3.3 回写设备（root shell）
cp patched_installed.apk "$PM_PATH"
chmod 644 "$PM_PATH"
restorecon "$PM_PATH" 2>/dev/null || true

# 3.4 杀进程后重启应用
am force-stop com.localfirst.mb
```

原地替换 base.apk 不触发 PackageManager 重装校验（仅 pm install 会验签）。
应用自身的签名自校验只比对证书公钥指纹，zip 内签名块对应条目未动，补丁后校验仍然通过。

## 第 4 步：验证

打开「豆包萌宠」→ 应直接进入游戏（本地 bootstrap 立即通过，无设备审批）。

服务端日志预期：

```
[..] bootstrap APPROVED deviceId=...
[..] mirror /pet05f/index.html (208967 B)
[..] WS tunnel established
```

## 工作原理速查

| 组件 | 说明 |
|---|---|
| dex 线路 | mcbtc.cn:20310 等长 Base64 替换为 127.0.0.1:4430（query 填充保持长度） |
| TLS | WebView 只信任 res/yo.der CA，换成本地 CA（SAN 含 IP:127.0.0.1） |
| bootstrap | 同一 HMAC 密钥校验 proof，本地直接签发 launchToken |
| /launch | 模拟源站双跳 302 进游戏页（serverIp=127.0.0.1:20311） |
| 静态资源 | 本地镜像（server/mirror/）优先，缺失实时反代源站并缓存 |
| WebSocket | :20311 TLS-bump 透传隧道到 mcbtc.cn:20311（保留联机） |

## 已知边界

- 源站资源 URL 带版本参数（?v=...）变化时会重新拉取并覆盖镜像。
- 若源站更换 WS 地址/协议（serverIp 参数），需同步更新 mbserver.py 的 ORIGIN_WS。
- 仓库中的样例补丁基于随包样本；线上安装包请用第 3 步从设备提取的 APK 重新补丁。
