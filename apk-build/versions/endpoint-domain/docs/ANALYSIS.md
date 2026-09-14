# 域名直改技术分析

## 问题

官方 2.4.0 APK 的业务 Host 不存在于普通 ZIP 资源和明文 IL2CPP metadata 中。
`global-metadata.dat` 是受保护格式，静态字符串替换既不能覆盖运行期 URL，也可能
破坏资源完整性。运行期取证确认 `SERVER` 响应会提供 `api_url`/`asset_url`，随后
由 Java 层 `com.unity3d.player.UnityWebRequest` 统一创建网络请求。

## 选定消费点

`UnityWebRequest.<init>(JLjava/lang/String;Ljava/util/Map;Ljava/lang/String;ZI)V`
把 URL 保存到字段 `b`；`runSafe()` 随后在 `new java.net.URL(this.b)` 处消费。因而
在构造函数做精确 authority 改写可以覆盖：

1. 首次 bootstrap `/api/environment/server`；
2. `SERVER` 返回后生成的 API URL；
3. Manifest、AssetBundle 和音频 CDN URL；
4. 后续同一 Java 网络栈请求。

patch 只匹配完整 authority，不会修改查询参数、路径、用户信息或其它第三方 URL。

## 目标域名链路

默认把两个原始 Host 都改为 `nanaon.0000227.xyz`。原始 Host 会暂存在私有字段，
并作为 `X-Nanaon-Original-Host` 请求头发送，便于网关在需要时继续区分 API/CDN。
TLS 连接的 SNI、URL hostname 和默认 HostnameVerifier 使用目标域名，而不是原始
Host。

## 证书与信任模型

- 默认 NSC：`base-config` 和目标域名 block 都只含 `src="system"`。
- `NANAON_ALLOW_USER_CA=true`/`--allow-user-ca`：只在目标域名 block 增加
  `src="user"`，用于自签证书诊断；不改变其它 HTTPS 主机。
- 构建脚本不读取、复制或打包 `var/certs/*`。
- 默认不启用原始 Host verifier；只有显式
  `NANAON_USE_ORIGINAL_HOST_VERIFIER=true` 才启用兼容路径。
