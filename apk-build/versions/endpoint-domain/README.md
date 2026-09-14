# endpoint-domain：域名直改最终版本

这个版本在 APK 内把游戏业务请求的两个原始 HTTPS authority：

- `227.hand.co.jp`
- `prd-asset.227.hand.co.jp`

在 `UnityWebRequest` 构造阶段精确改写为私服域名。默认目标是
`nanaon.0000227.xyz`，默认包名为 `com.aniplex.nananiji.ps227`，应用名为
`ナナオン 227`。同包名的旧测试包可以覆盖安装；其它包名通过参数独立生成。

## 目标与边界

最终发布版本，面向无 root 设备：

- 不需要 DNS 重写、VPN、LSPosed 或 TrustMeAlready；
- 不在 APK 内置任何私服证书或 CA 文件；
- 默认只信任 Android 系统 CA，适配公开 CA 签发的域名证书；
- `--allow-user-ca` 仅作为明确的诊断/兼容选项，默认关闭；
- 继承已验证的 AppGuard/watchdog/Unity bridge 修复，使重签包能够完成游戏流程。

已发布产物与哈希见 `../../README.md`；设备侧验收按 `docs/TESTING.md` 执行。

## 快速构建

```powershell
. .\tools\apk-mod\keys\local-signing.local.ps1
python .\tools\Nanaon-Private-Server\apk-build\versions\endpoint-domain\scripts\build.py --force
```

默认读取本目录未跟踪的 `.env`，输出：

```text
tools/apk-mod/out/nanaon-2.4.0-com.aniplex.nananiji.ps227.endpoint-domain.signed.apk
```

脚本从官方 APK 重建已验证基线，应用版本守卫的 AppGuard patch、bridge、域名
改写 helper 和 NSC，随后执行 zip 对齐、v1/v2/v3 签名及静态校验。所有中间文件
只写 `tools/_tmp/`，不会写入 APK 证书或操作设备。

## 自定义域名或包名

命令行参数优先于 `.env`：

```powershell
python .\tools\Nanaon-Private-Server\apk-build\versions\endpoint-domain\scripts\build.py `
  --api-host nanaon.0000227.xyz `
  --asset-host nanaon.0000227.xyz `
  --target-package com.aniplex.nananiji.ps227 `
  --app-name 'ナナオン 227' `
  --system-only --force
```

域名证书必须覆盖 API/CDN 两个目标 Host（同一域名时只需一个 SAN），并且服务端
必须能处理 `/api/*`、资源和音频路径。若使用自签证书，不要把证书偷偷放进 APK；
应在测试时显式使用 `--allow-user-ca` 并记录这不是零设置验收。

## 目录导航

- `AGENTS.md`：agent 快速入口和安全门禁。
- `config.example.env`：不含本机路径/口令的配置模板。
- `scripts/build.py`：唯一构建入口。
- `scripts/patch_unity_web_request.py`：2.4.0 DEX 锚点 patch。
- `docs/ANALYSIS.md`：为什么选择该消费点以及已排除的路线。
- `docs/BUILD.md`：依赖、命令、静态校验和复现记录。
- `docs/CONFIGURATION.md`：环境变量、CLI 参数和 CA 策略。
- `docs/PATCHES.md`：基线、AppGuard、NSC、helper 和端点改写细节。
- `docs/TESTING.md`：root/无 root 分层验收、截图和失败归因。
