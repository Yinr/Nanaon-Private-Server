# XAPK 打包工具指南

本目录只负责把已有 APK 与 OBB 封装为 XAPK ZIP 容器。先阅读 `README.md`，再运行
`scripts/pack_xapk.py --help`。

## 边界

- 脚本不会修改 APK、OBB、签名、证书、设备或网络配置。
- `--package-name` 是对 APK 内包名的校验值，不会把 APK 重命名为另一个包名。
- OBB 内容按原字节流复制；输出路径会按目标包名生成
  `Android/obb/<package>/main.<versionCode>.<package>.obb`。
- 输出 XAPK、日志和临时文件不要提交到 Git；脚本默认拒绝覆盖已有输出，覆盖必须显式
  传入 `--force`。

## 输入

- `--apk`：单体 APK 文件。
- `--obb`：独立 OBB，或包含一个 OBB 的现有 `.xapk`；可用 `--obb-entry` 指定 ZIP
  内部条目。
- 当 `--obb` 是 XAPK 时，脚本默认从其中复制 `icon.png`；可用 `--icon-entry` 或
  `--no-icon` 调整。
- `--aapt2`：可选，自动读取包名、版本、应用名、SDK 和权限。若无法找到 aapt2，
  必须显式提供包名、版本号和版本名。

## 验证

脚本只做归档级检查：输入 APK 必须是可读 ZIP，输出必须无重复条目且 `testzip()` 通过，
`manifest.json`、APK 条目和 OBB 条目必须互相一致。它不负责安装或设备验收。
