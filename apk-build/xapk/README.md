# XAPK 打包工具

这个工具把一个已经构建并签名的 APK 与对应 OBB 封装为 XAPK。它只写新的 XAPK 文件，
不会改动输入 APK/OBB，也不会重新签名、安装或操作真机。

## 支持的输入

- `--apk` 接受单体 APK。脚本会优先使用 `aapt2 dump badging` 读取包名、版本、应用名、
  SDK 和权限。
- `--obb` 接受独立 `.obb` 文件，也接受现有 `.xapk`。传入 `.xapk` 时，如果其中只有
  一个 `Android/obb/**.obb` 条目会自动选择；有多个时用 `--obb-entry` 指定。若该
  XAPK 含 `icon.png`，脚本默认同时复制它；可用 `--icon-entry` 选择其它条目，或用
  `--no-icon` 关闭自动复制。
- `--package-name` 用于显式校验 APK 内包名，或在没有 aapt2 时提供包名。它不会修改
  APK 内的 AndroidManifest.xml。

当前项目的 OBB 仍保存在官方 XAPK 容器内，因此可以直接把官方 `.xapk` 作为 `--obb`
输入，不需要先手动解压。

## 快速使用

从仓库根目录执行，下面示例只演示参数，不会自动安装：

```powershell
$apk = Resolve-Path '.\tools\apk-mod\out\nanaon-2.4.0-com.aniplex.nananiji.ps227.endpoint-domain.signed.apk'
$obb = Resolve-Path '.\tools\APK\22_7+音楽の時間_2.4.0_apkcombo.com.xapk'
$aapt2 = '<ANDROID_SDK>\build-tools\37.0.0\aapt2.exe'

python .\tools\Nanaon-Private-Server\apk-build\xapk\scripts\pack_xapk.py `
  --apk $apk `
  --obb $obb `
  --aapt2 $aapt2 `
  --package-name com.aniplex.nananiji.ps227 `
  --output '.\tools\apk-mod\out\nanaon-2.4.0-com.aniplex.nananiji.ps227.xapk'
```

如果使用独立 OBB，只需把 `--obb` 改为该文件路径：

```powershell
python .\tools\Nanaon-Private-Server\apk-build\xapk\scripts\pack_xapk.py `
  --apk '.\path\client.apk' `
  --obb '.\path\main.5465.client.obb' `
  --output '.\path\client.xapk'
```

输出已存在时必须显式加 `--force`。在真正写文件前可用 `--dry-run` 检查输入和最终
归档布局：

```powershell
python .\tools\Nanaon-Private-Server\apk-build\xapk\scripts\pack_xapk.py `
  --apk '.\path\client.apk' `
  --obb '.\path\main.5465.client.obb' `
  --aapt2 '<ANDROID_SDK>\build-tools\37.0.0\aapt2.exe' `
  --dry-run
```

## 输出布局

默认输出的 XAPK 使用 APKPure/APKCombo 常见的单 APK + 扩展包布局：

```text
<package>.apk
icon.png                         # 源 XAPK 含图标时默认包含；可用 --no-icon 关闭
Android/obb/<package>/
└── main.<versionCode>.<package>.obb
manifest.json
```

`manifest.json` 包含 `xapk_version=2`、包名、版本、权限、APK 条目、OBB 条目和
`total_size`（APK + OBB 字节数）。如果包含图标，还会写入 `icon: "icon.png"`。
OBB 和图标在容器内使用 `ZIP_STORED` 原样复制，避免对已经压缩的 Unity 资源再次压缩。

## 重要限制

- XAPK 是第三方安装器使用的 ZIP 容器，不是 Android 系统包管理器的原生扩展名。
  安装器可能要求用户允许“安装未知应用”；也可以手动解压后安装 APK，再把 OBB 放到
  `/sdcard/Android/obb/<package>/`。
- `--app-name` 只设置 XAPK `manifest.json` 的显示名，不会改变 APK 内应用名称。
  应用名称或包名需要改变时，应先使用对应 APK 构建版本重新构建 APK。
- 脚本不验证服务器、TLS、TrustMeAlready、AppGuard 或游戏画面流程；这些仍按
  `PLAN.md` 和各版本 `docs/TESTING.md` 执行。
