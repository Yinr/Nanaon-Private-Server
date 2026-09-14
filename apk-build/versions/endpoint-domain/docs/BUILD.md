# 域名版构建说明

## 固定输入

- 官方 APK：`tools/apk-mod/work/original.apk`
- 官方 APK SHA-256：`692247DE9DAEC19FCC7BB28559215069B5093197326170F75CC5A3DC6A199C89`
- Apktool：`NANAON_APKTOOL_JAR`，缺省在 PATH 找 `apktool`（独立 JAR 或
  惯例的"启动器旁放 apktool.jar"布局）
- Android build-tools：`NANAON_BUILD_TOOLS`，缺省在
  `NANAON_SDK_ROOT`/`ANDROID_HOME`/`ANDROID_SDK_ROOT` 下取
  `build-tools/37.0.0`（否则最新版）
- Android API jar：`NANAON_ANDROID_JAR`，缺省在 SDK 的
  `platforms/android-34`（否则最新平台）找 `android.jar`
- 签名材料：`tools/apk-mod/keys/test.keystore`；口令只从本地 helper 设置的
  `NANAON_KS_PASS` 读取。

## 默认构建

```powershell
. .\tools\apk-mod\keys\local-signing.local.ps1
python .\tools\Nanaon-Private-Server\apk-build\versions\endpoint-domain\scripts\build.py --force
```

构建器按以下顺序工作：

1. 从官方 APK 重建目标包名和已验证的 AppGuard/watchdog/bridge 基线；
2. 重新生成目标域名的 NSC（默认 system-only）；
3. 对 `UnityWebRequest` 做严格锚点 patch；
4. 编译 `EndpointRewrite` helper 为新增 `classes3.dex`；
5. 保留已验证的 `classes2.dex` bridge，移除旧签名；
6. `zipalign`、v1/v2/v3 签名；
7. 执行 ZIP/CRC、包名/版本/应用名、helper、NSC、对齐和签名检查。

临时解包、Java 编译和中间 APK 全部写在 `tools/_tmp/endpoint-domain-build-*`，
成功后自动删除；调试时可加 `--keep-work`，但不要把该目录提交。

## 用户 CA 变体

默认构建必须保持 system-only：

```powershell
python .\tools\Nanaon-Private-Server\apk-build\versions\endpoint-domain\scripts\build.py --system-only --force
```

仅在自签证书诊断时显式开启：

```powershell
python .\tools\Nanaon-Private-Server\apk-build\versions\endpoint-domain\scripts\build.py --allow-user-ca --force
```

脚本最终 manifest 会输出 `allow_user_ca`，静态 verifier 会拒绝开关与 NSC 实际
内容不一致。两种产物应使用不同输出文件名，避免误把诊断包当作最终包。

## 自定义参数

路径参数在 CLI 中按当前工作目录解析，在 `.env` 中相对本目录解析；主机名只接受
合法 DNS 名称或 IPv4 地址，不接受 URL、端口或路径。常用覆盖：

```powershell
python .\scripts\build.py `
  --api-host nanaon.example.invalid `
  --asset-host nanaon.example.invalid `
  --output-apk .\tools\apk-mod\out\custom-domain.signed.apk `
  --target-package com.example.nanaon.ps `
  --app-name 'Nanaon Private' --system-only --force
```

不要把 `--ks-pass` 写入脚本、历史命令或 CI 日志；优先使用
`tools/apk-mod/keys/local-signing.local.ps1`。

## 静态验收清单

- 官方输入哈希匹配；
- `aapt2 dump badging` 显示目标包、`2.4.0/5465` 和应用名；
- ZIP 无重复条目且 `testzip()` 通过；
- `classes.dex` 含受版本守卫的 patch，`classes2.dex`/`classes3.dex` 存在；
- 默认包名为 `com.aniplex.nananiji.ps227`，应用名为 `ナナオン 227`；
- NSC 含目标域名和 `system`，默认不含 `A: src="user"`；
- 没有新增私服证书/CA 文件；
- `zipalign -c -P 16 4` 和 `apksigner verify --verbose --print-certs` 通过。

静态通过不等于设备通过；真实 TLS、AES API、CDN 和画面流程必须按
`TESTING.md` 验证。
