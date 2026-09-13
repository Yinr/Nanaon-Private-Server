# deploy/ — 生产部署（Cloudflare → Caddy → app）

本目录是公网生产拓扑的全部定义，对上游文件**零修改**；上游的
`compose.yml` + `docker/`（单容器、网关在容器内直接监听 443）保持原样，
定位是"单机开箱即用"，与本目录互不影响。

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
  nanaon-app (8888，仅内部网络)  ← 上游 server.py：API + 资产路由同进程
```

`server.py` 原生在 API 进程内注册资产蓝图，因此应用容器只需要开放
8888 一个端口；Caddy 把 `/api*`、`/assets/*`、`/Android/*` 全部反代到它。

## 数据库模型（与上游一致）

- `data/private_server.sqlite3`（git 跟踪）只是**种子**，构建时被移到镜像内
  `seed.sqlite3`；
- 活库是宿主机 `var/db/private_server.sqlite3`，以单文件 bind-mount 覆盖
  容器内 `data/private_server.sqlite3`；
- 活库为空文件时，entrypoint 自动从种子重置；重置玩家数据 = 停服后清空
  该文件再启动；
- 上游 `api/storage.py` 启动时自动执行 `_upgrade_*` schema 迁移，旧库直接可用。

首次安装：

```bash
mkdir -p var/db
touch var/db/private_server.sqlite3   # 空文件 → 自动播种
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
server.py process_guard.py deploy/entrypoint.sh`，不含下载大文件与
compat_assets（后者运行期只读挂载）。需要 Docker Engine 23+/BuildKit；
若版本过旧不支持，把 `deploy/site/downloads/` 外置到 `var/www/` 并同步
Caddyfile 挂载。

## 其他文件

- `Caddyfile`：站点、下载、缓存策略与反代路由；
- `config.cloudflare.yaml`：应用运行配置（公网域名、AES key）；
- `secrets/`：Cloudflare Origin CA 证书与私钥，不进 git；
- `site/`：下载页静态站点（BGM、Artalk 评论），大文件在 `site/downloads/`
  （不进 git，部署时单独同步）；
- `README-cloudflare.md`、`nginx.conf.example`：Cloudflare 接入与 Nginx 备选；
- 2026-09-13 重建：活库自旧 `data/` 布局迁移到 `var/db/`（种子/活库分离，
  见仓库根 TODO.md）。
