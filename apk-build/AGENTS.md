# APK 构建目录指南

本目录是 Nanaon 私服目标 APK 的构建知识库。当前唯一维护版本是
`versions/endpoint-domain/`（ps227 域名版），历史方案在 `archive/`（只读参考）。
先读本文件和 `README.md`，再进入版本目录阅读其 `AGENTS.md`/`docs/`。

## 快速入口

```powershell
. <仓库>\apk-mod\keys\local-signing.local.ps1
python .\versions\endpoint-domain\scripts\build.py --force
```

默认生成包名 `com.aniplex.nananiji.ps227`、应用名 `ナナオン 227` 的目标包，
输出到 `tools/apk-mod/out/`；中间文件只写 `tools/_tmp/`。

## 依赖与输入

- 官方 APK：`../../apk-mod/work/original.apk`，必须匹配 `PLAN.md` 中的 SHA-256。
- 工具链路径全部可配置、不硬编码：`NANAON_APKTOOL_JAR`（缺省在 PATH 找
  `apktool`）、`NANAON_BUILD_TOOLS` 与 `NANAON_ANDROID_JAR`（缺省在
  `NANAON_SDK_ROOT`/`ANDROID_HOME`/`ANDROID_SDK_ROOT` 的标准 SDK 布局下解析）。
- 签名 keystore：默认 `../../apk-mod/keys/test.keystore`；口令只来自 `NANAON_KS_PASS` 或本地未跟踪 helper。
- 共享补丁基座：`../apktool/`（`build_patched_apk.py` 的 `build_nsc()` 等被
  endpoint-domain 直接依赖）。

## 边界

- 不把 keystore、私钥、口令、`.env`、APK 输出、日志或临时解包目录提交到 Git。
- 不复制私服 `var/certs/game_key.pem`；CA 公钥仅作为设备安装材料，可从 `var/certs/gateway_trust_cert.pem` 外部引用。
- 此目录的脚本不自动连接或操作真机；设备安装和 OBB 部署按 `docs/TESTING.md` 手动执行，并严格遵守 `PLAN.md` 白名单。
- 代码补丁是 2.4.0 版本特定的，修改后必须重新做静态校验和设备真实画面验收。

## 导航

- `versions/endpoint-domain/`：唯一维护版本（域名直改 + system-only CA），先读其 `AGENTS.md` 和 `docs/`。
- `archive/`：已退役方案（dns-user-ca、endpoint-direct、endpoint-rewrite×2、endpoint-embedded-ca），保持原结构。
- `xapk/`：XAPK 分发打包工具（APK+OBB → 下载页用的 XAPK）。
- `PLAN.md`：设备白名单、全局状态和最终验收边界。
