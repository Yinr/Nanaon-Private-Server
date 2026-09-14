# endpoint-domain 版本指南

本目录维护“把私服域名直接写入 APK”的独立版本。默认把官方客户端在
`UnityWebRequest` 构造阶段使用的两个业务 Host 改写为
`nanaon.0000227.xyz`，并使用 Android 系统 CA 校验证书。默认不允许用户 CA；
只有显式设置 `NANAON_ALLOW_USER_CA=true` 或传入 `--allow-user-ca` 才会在目标
域名的窄域名配置中加入用户证书存储。

## 快速入口

从仓库根目录执行：

```powershell
. .\tools\apk-mod\keys\local-signing.local.ps1
python .\tools\Nanaon-Private-Server\apk-build\versions\endpoint-domain\scripts\build.py --force
```

本机默认配置在未跟踪的 `.env`。换机器时复制 `config.example.env`，只填写本机
路径和签名别名；不要把口令写进配置或提交记录。

## 安全边界

- 构建脚本不安装 APK、不启动/停止进程、不修改 DNS、证书、TMA、Magisk 或
  SELinux。
- 默认 NSC 对嵌入目标域名只列 `system` CA；不向 APK 添加私服证书、公钥文件
  或 CA bundle。`--allow-user-ca` 只影响目标域名，绝不改变全局 `base-config`。
- 默认关闭“按原始 Host 校验证书”的 IP 兼容 verifier；域名版使用目标域名的
  标准 TLS/SNI/HostnameVerifier。只有排查旧证书时才显式打开该诊断选项。
- 原始 Host 仅作为精确匹配键和 `X-Nanaon-Original-Host` 路由标记保留，不是
  DNS 配置，也不是信任放宽。

## 设备规则

安装或测试必须先读取根目录 `PLAN.md`，只对白名单 serial 操作。出现其它设备、
白名单设备 `offline`、身份或网络变化时停止设备动作并更新 `PLAN.md`。完整流程
必须查看截图，不能以 PID 存活或单个 HTTP 200 代替真实渲染。

## 文档顺序

1. `README.md`：版本边界和快速使用。
2. `docs/ANALYSIS.md`：端点定位和运行期证据。
3. `docs/CONFIGURATION.md`：所有参数与信任策略。
4. `docs/BUILD.md`：可复现构建和静态检查。
5. `docs/PATCHES.md`：每个修改点及其输入/输出。
6. `docs/TESTING.md`：分层设备验收和失败归因。
