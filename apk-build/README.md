# Nanaon 私服 APK 构建

本目录是私服目标 APK 的构建知识库。**唯一维护的版本是 `versions/endpoint-domain/`**
（ps227 域名版）；已退役的其他方案归档在 `archive/`（未跟踪，仅磁盘参考）。

## 最终版本：`versions/endpoint-domain/`（ps227 域名版）

- 包名 `com.aniplex.nananiji.ps227`，应用名 `ナナオン 227`，版本 2.4.0/5465；
- 在 `UnityWebRequest` 构造期把两个原始业务 Host 改写为 `nanaon.0000227.xyz`；
- NSC 为窄域名 system-only CA——**用户零设置**：不装用户 CA、不改 DNS、
  不依赖 TrustMeAlready/LSPosed/root；
- 需要配合官方 OBB（`main.5465.com.aniplex.nananiji.obb`）部署到
  `/sdcard/Android/obb/<包名>/`。

已发布的最终产物（下载页 `deploy/site/downloads/SHA256SUMS.txt` 为准）：

| 文件 | SHA-256 |
|---|---|
| `nanaon-2.4.0-ps227.apk` | `84643eb820c3f851e79db595a8f0c2ebc4b63fa175ddc971b596884808ce12bc` |
| `nanaon-2.4.0-ps227.xapk` | `1b3c07f34b65dbc622649cb6427258f57e00b068f44864ce66ead368862afe3` |
| `main.5465.com.aniplex.nananiji.ps227.obb` | `5f3403aa728349c4284ba8e8c06572531f588277606907a389e3b6911e4da3e2` |

## 构建流程思路（四层管线）

1. **基线重建**：从官方 APK（`tools/APK/`，SHA 见 `PLAN.md`）解包，改包名/应用名，
   重建为可重签的基线包；
2. **兼容性补丁**（共享基座 `../apktool/`）：AppGuard watchdog 入口 return-0、
   attach/oncreate native 补丁，跨过历史 ~190s 看门狗窗口；
3. **网络补丁**：NSC 窄域名改写（`apktool/build_patched_apk.py` 的 `build_nsc()`，
   只放行 `nanaon.0000227.xyz` 的 system 信任）+ `endpoint-domain` 的
   `UnityWebRequest` 域名改写（构造期精确替换两个原始 Host）；
4. **打包验收**：对齐/签名/静态校验（aapt2、ZIP 重复项、v1/v2/v3 签名），
   再按 `docs/TESTING.md` 做真机流程验收。

入口与配置见 `versions/endpoint-domain/`（`scripts/build.py` +
`config.example.env`），详细分析在 `versions/endpoint-domain/docs/`。
分发打包用 `../xapk/scripts/pack_xapk.py`（APK+OBB → XAPK，供下载页与安装器）。

## 目录结构

```
apk-build/
├── versions/endpoint-domain/   # 唯一维护版本（ps227 域名版）
├── archive/                    # 已退役方案（保持原结构，只读参考）
│   ├── dns-user-ca/            # 用户 CA + 外部 DNS 路由方案
│   ├── endpoint-direct/        # UnityWebRequest 构造期 IP 直改方案
│   ├── endpoint-rewrite/       # 延迟加载 resolver 方案
│   ├── endpoint-rewrite-v2-early-load/  # early-load resolver 方案
│   └── endpoint-embedded-ca/   # APK 内置 CA 方案文档
└── xapk/                       # XAPK 分发打包工具
```

## 共用规则

- 共享 patch 基座位于 `../apktool/`（endpoint-domain 的 build.py 直接依赖它，
  不可删除）；构建产物输出到 `../../apk-mod/out/`；临时文件只写 `../../_tmp/`。
- keystore、私钥、口令、`.env`、APK 输出、日志与临时目录一律不提交。
- 重新构建/修改补丁后，先静态校验再做真机流程验收，结论先写 `PLAN.md`。
