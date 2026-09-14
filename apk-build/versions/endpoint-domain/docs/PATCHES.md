# 补丁说明

## 基线

输入是官方 Nanaon 2.4.0 APK（SHA-256 见 `BUILD.md`）。内嵌的
`scripts/base_build.py` 生成目标包名和 AppGuard/watchdog/bridge 基线，随后本版本
重写自己的 NSC。

## AppGuard/watchdog/bridge

包含四项：

- `AppGuardProxyApplication.attachBaseContext` 的 native loader 调用短路；
- `AppGuardProxyApplication.onCreate` 的 native 初始化调用短路；
- `libcompatible.so` watchdog 入口返回 0；
- basic `AppGuardClientUnityBridge` 注入为 `classes2.dex`。

该组合让重签包保持 Unity/bridge 可见性并跨过约 190 秒终止窗口；它不是网络
信任绕过，也不包含 TMA/LSPosed 代码。

## UnityWebRequest patch

`scripts/patch_unity_web_request.py` 只处理一个版本守卫类：

1. 在 `UnityWebRequest` 增加原始 Host 私有字段；
2. 构造函数调用 `EndpointRewrite.originalHost()` 保存两个业务 Host；
3. 调用 `EndpointRewrite.rewrite()` 精确替换 authority；
4. `runSafe()` 在请求上增加 `X-Nanaon-Original-Host`；
5. 只有显式启用 `NANAON_USE_ORIGINAL_HOST_VERIFIER` 才安装兼容 verifier，默认
   使用目标域名的 Android 默认 verifier。

锚点数量、类描述符、方法签名或 DEX 布局变化时脚本必须失败，不允许使用全局
字符串替换硬凑。

## EndpointRewrite helper

helper 由构建时生成 Java 源码并用 `javac` + `d8` 编译为 `classes3.dex`。目标主机
经过 DNS/IP 格式校验并使用 Java 字符串安全转义后嵌入；不读取证书或私钥。原始
Host 常量只用于精确匹配和路由标记，所有其它 URL 原样返回。

## Network Security Config

共享 `apktool/build_patched_apk.py` 的 `build_nsc()` 生成 NSC：默认传入
`allow_user_ca=False`，得到目标域名 system-only 配置；传入 `--allow-user-ca`
才生成 system+user。最终由 `aapt2 dump xmltree` 检查确认。
