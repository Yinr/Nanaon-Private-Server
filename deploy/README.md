# deploy/ — 生产部署（Cloudflare → Caddy → app）

本目录是公网生产拓扑的全部定义，对上游文件**零修改**。上游 18e4b9f 起改为
standalone LAN server（`lan_launcher.py` 交互式入口、无自带容器方案），本目录
在不动上游文件的前提下为容器化生产部署提供自己的入口与编排。

## 拓扑

```
客户端 APK (ps227 / 域名版)
        │  HTTPS nanaon.0000227.xyz
        ▼
  Cloudflare（边缘缓存：API no-store，资产 immutable）
        │  Origin CA
        ▼
  nanaon-caddy (443)  ── 静态站点 /srv/www（含 /downloads）
        │  reverse_proxy
        ▼
  nanaon-app (8888，仅内部网络)  ← serve.py(waitress)：API + 资产路由同进程
```

`create_app` 在 API 进程内注册资产蓝图，因此应用容器只需要开放
8888 一个端口；Caddy 把 `/api*`、`/assets/*`、`/Android/*` 全部反代到它。

## 运行模型（适配上游 18e4b9f）

- `deploy/serve.py`：容器入口（新文件）。上游 `server.py` 是纯库
  （`create_app`/`load_config`，无 `__main__`），serve.py 用 waitress 起服务，
  并像 `lan_launcher.py` 一样把 `ASSET_BASE/CACHE_BASE/DOWNLOAD_CACHE` 钉到
  挂载的资源树上；
- **数据库**：上游已删除种子库，`api/storage.py` 通过 `NANAON_DB_PATH`
  环境变量定位活库，文件为空/不存在时自动建 schema（`data/schema.sql`），
  旧库启动时自动 `_upgrade_*` 迁移——不再需要任何播种步骤；
- 资源树由 `NANAON_RESOURCE_ROOT`（默认容器内 `/opt/nanaon`）定位，
  只读挂载，镜像内不含资源。

首次安装：

```bash
mkdir -p var/db
touch var/db/private_server.sqlite3   # 空文件 → storage 自动建 schema
# 或迁移旧库：cp <旧库> var/db/private_server.sqlite3
```

## 常用命令

```bash
docker compose -f deploy/compose.yaml build     # 构建应用镜像
docker compose -f deploy/compose.yaml up -d
docker compose -f deploy/compose.yaml logs -f
```

构建上下文由 `deploy/Dockerfile.dockerignore`（BuildKit 按 Dockerfile
专属 ignore）裁剪：仅进入 `api/ cdn/ crypto/ data/ requirements.txt
server.py deploy/serve.py`，不含下载大文件与 compat_assets（后者运行期
只读挂载）。需要 Docker Engine 23+/BuildKit；若版本过旧不支持，把
`deploy/site/downloads/` 外置到 `var/www/` 并同步 Caddyfile 挂载。

## 其他文件

- `Caddyfile`：站点、下载、缓存策略与反代路由；
- `config.cloudflare.yaml`：应用运行配置（公网域名、AES key；`game`/
  `crypto`/`environment` 键仍被上游 `create_app` 读取）；
- `secrets/`：Cloudflare Origin CA 证书与私钥，不进 git；
- `site/`：下载页静态站点（BGM、Artalk 评论），大文件在 `site/downloads/`
  （不进 git，部署时单独同步）；
- `README-cloudflare.md`、`nginx.conf.example`：Cloudflare 接入与 Nginx 备选；
- 2026-09-13：活库自旧 `data/` 布局迁移到 `var/db/`；同日适配上游
  standalone-server 重构（serve.py + NANAON_DB_PATH，取消种子机制）。
