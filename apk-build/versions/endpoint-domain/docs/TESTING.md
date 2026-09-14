# 域名版测试说明

## 测试变量

发布候选的目标变量：

- 包：`com.aniplex.nananiji.ps227`；应用名 `ナナオン 227`；
- endpoint：`nanaon.0000227.xyz`（API/CDN 同域）；
- 用户 CA：关闭（发布默认）；
- TMA/LSPosed：关闭或目标包不在作用域；
- DNS 重写：关闭；
- 私服：443 反向代理、API/资源路径和加密密钥配置正常。

诊断候选可以把 `NANAON_ALLOW_USER_CA=true` 作为单独变量，但不能把它的结果
当作零设置发布证据。

## 构建前主机检查

```powershell
Resolve-DnsName nanaon.0000227.xyz -Type A
curl.exe -I --max-time 15 https://nanaon.0000227.xyz/health
curl.exe -I --max-time 15 https://nanaon.0000227.xyz/api/environment/server
```

确认返回 200、证书 SAN 覆盖域名、响应头来自 NanaOn 私服。状态异常时先修复
服务端，不要用 APK patch 掩盖 DNS/TLS 问题。

## root 对照机

只使用 `PLAN.md` 白名单 `8022cd7`，每次先核对 serial、model、Android/SDK、
Wi-Fi、root、SELinux。安装前：

```powershell
$adb='<ANDROID_SDK>\platform-tools\adb.exe'
$apk='<仓库>\apk-mod\out\nanaon-2.4.0-com.aniplex.nananiji.ps227.endpoint-domain.signed.apk'
& $adb -s 8022cd7 install -r $apk
```

保留对应 OBB 路径。启动后必须保存截图并按真实顺序点击：通信错误（私服当前
可能正常弹一次）→ 标题 → 引继“後で” → 资源补充/下载 → 主界面 → `Live!` →
`ソロ` → 曲目 → 队伍确认 → `ライブスタート`。黑屏、只有 PID 或单一日志不算通过。

## 无 root 最终验收

在无 root 白名单机上关闭 DNS 重写、TMA、VPN 和用户 CA（除非正在做诊断变体），
手动安装同一 APK 并完成上述点击流程。至少确认：

1. 首次 bootstrap TLS 成功；
2. AES API 请求/响应成功；
3. 至少一个 AssetBundle 和音频 CDN 返回 200；
4. 主界面和真实 Live 画面可见；
5. 运行超过历史约 190 秒 watchdog 窗口。

首屏出现一次通信错误不必立即归因失败；应点击继续并观察最终流程。截图要实际
查看，8 秒左右的字幕/加载黑帧不能代替最终渲染判断。

## 证据与退出

每轮材料放在 `tools/_tmp/<candidate>-<date>/`：设备身份、安装输出、截图、
logcat、私服网关请求摘要、PID/线程和退出信息。结束 root 长测后主动：

```powershell
& $adb -s 8022cd7 shell am force-stop --user 0 com.aniplex.nananiji.ps227
```

记录 `USER REQUESTED/FORCE STOP`，不要把用户手动停止、SwipeUpClean、TMA 作用域
变化或网络切换当作自然 AppGuard 终止。

## 失败归因

| 现象 | 优先检查 |
|---|---|
| `UnknownHostException` | DNS/网络路由/目标域名配置 |
| `CertPathValidatorException` | 系统 CA 链、证书 SAN、是否误启用自签诊断 |
| API 200 但资源失败 | `SERVER` 返回的 asset URL、Caddy 路径和 CDN 请求 |
| 画面黑屏 | OBB、Unity 初始化、AppGuard bridge；先截图和 logcat |
| 约 190 秒退出 | native watchdog/完整性链；区分自然 signal 与主动 force-stop |
| 只出现通信错误框但后续可玩 | 私服设计的正常启动提示，不单独判定失败 |
