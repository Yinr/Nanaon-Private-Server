# 配置参考

配置优先级：命令行参数 > 本目录 `.env` > 脚本默认值。`.env` 应保持本机未跟踪，
示例文件不得包含口令、私钥或绝对机器路径。

| 变量/参数 | 默认值 | 作用 |
|---|---|---|
| `NANAON_ENDPOINT_API_HOST` / `--api-host` | `nanaon.0000227.xyz` | 原 API Host 的替换目标 |
| `NANAON_ENDPOINT_ASSET_HOST` / `--asset-host` | `nanaon.0000227.xyz` | 原 CDN/资源 Host 的替换目标 |
| `NANAON_PRIVATE_DOMAINS` / `--private-domain` | 两个目标 Host | NSC 的窄域名列表；不代表 DNS |
| `NANAON_ALLOW_USER_CA` / `--allow-user-ca` | `false` | 目标域名是否允许 Android 用户 CA |
| `--system-only` | 开关 | 强制关闭用户 CA，优先用于发布构建 |
| `NANAON_USE_ORIGINAL_HOST_VERIFIER` | `false` | 仅旧 IP/自签诊断使用，域名版应保持 false |
| `NANAON_TARGET_PACKAGE` | `com.aniplex.nananiji.ps227` | APK 包名；同包可覆盖安装 |
| `NANAON_APP_NAME` | `ナナオン 227` | 启动器显示名 |
| `NANAON_OUTPUT_APK` | `tools/apk-mod/out/...endpoint-domain.signed.apk` | 输出路径 |
| `NANAON_STOCK_APK` | `tools/apk-mod/work/original.apk` | 固定官方输入 |
| `NANAON_KEYSTORE` / `NANAON_KS_ALIAS` | `test.keystore` / `test` | 本地签名材料 |
| `NANAON_KS_PASS` | 无默认值 | 签名口令，仅环境变量/本地 helper |
| `NANAON_BUILD_TOOLS` | 可选，缺省自动解析（SDK 布局） | `aapt2`、`d8`、`zipalign`、`apksigner` |
| `NANAON_APKTOOL_JAR` | 可选，缺省在 PATH 找 apktool | DEX 解码/重建 |
| `NANAON_ANDROID_JAR` | 可选，缺省自动解析（SDK 布局） | helper 编译 classpath |
| `NANAON_TMP_ROOT` | `tools/_tmp` | 中间文件目录 |

## 信任策略

`allow_user_ca=false` 时生成的 NSC 结构为：

- `base-config`: cleartext false，`system`；
- 目标域名 block: cleartext false，`system`；
- 官方 APK 原有的旧明文 IP block: 保留为 `system`，不接受用户 CA。

开启用户 CA 后，仅目标域名 block 变为 `system + user`。不会向 base-config 添加
`user`，因此其它 HTTPS 服务仍保持系统 CA-only。脚本会把实际状态写进
`final-manifest` 并作反向校验。

## 域名变更检查

更换目标域名时必须同时确认：

1. DNS 能从目标设备解析到私服或反向代理；
2. 证书 SAN 覆盖 API/CDN 目标域名，且链由系统 CA 信任；
3. `/api/environment/server` 返回的 API/asset URL 仍能被构造期 patch 捕获；
4. Caddy/网关不会缓存或改写加密 API 响应；
5. 使用新输出文件名保存静态哈希和设备证据。

不要把域名的私钥、Cloudflare token、Origin CA 文件或用户证书复制到本目录。
