# 探针全景大盘独立版

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/mail4tonyy-ship-it/myvps)

这是从 `a6216abcd/K-UI-workers` 的探针全景大盘思路中单独剥离出来的 Cloudflare Worker 项目。保留：

- 公开探针大盘：卡片、表格、地图、详情页、主题切换。
- 轻量管理：登录、添加/删除探针、复制 VPS 安装命令。
- VPS Agent：采集 CPU、内存、磁盘、网络、连接数、系统信息并上报。
- 实时刷新：主 Worker 内置 Durable Object，前台通过 `/public/ws` 接收更新。
- D1 持久化与 Cron 离线检查。

不包含原项目的代理节点、订阅、多用户、住宅代理、WARP、Telegram 等其它功能。

## 一键部署

部署模型与原项目一致：单一 Cloudflare Worker 托管前端 Assets、API、实时 WebSocket、Cron 和 D1。

使用前先把 README 顶部按钮里的仓库地址替换为你自己的公开 GitHub 仓库：

```md
[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/mail4tonyy-ship-it/myvps)
```

也可以直接打开：

```text
https://deploy.workers.cloudflare.com/?url=https://github.com/mail4tonyy-ship-it/myvps
```

更多细节见 [DEPLOY.md](./DEPLOY.md)。

## 本地部署

```bash
npm install
npx wrangler login
npx wrangler deploy
```

首次部署后请在 Cloudflare Worker 的 Settings -> Variables and Secrets 中把 `ADMIN_PASSWORD` 改成强密码，然后重新部署。

默认登录：

```text
用户名：admin
密码：admin
```

## 本地预览

```bash
npm run dev
```

## VPS 接入

1. 打开部署后的 Worker 地址。
2. 点击右上角“管理”，用管理员账号登录。
3. 添加 VPS 的公网 IP 和名称。
4. 复制生成的安装命令，以 root 在 VPS 执行。

Agent 会安装到 `/opt/probe-panorama`，systemd 服务名为 `probe-panorama-agent`。

## Cloudflare 绑定

需要保留这些绑定：

- D1 Database：`DB`
- Durable Objects：
  - `VPS_PRESENCE` -> `VpsPresence`
  - `DASHBOARD_HUB` -> `DashboardHub`
- Assets：`ASSETS`

如果部署后显示绑定错误，请在 Cloudflare Dashboard -> Workers & Pages -> 当前 Worker -> Settings 中补齐绑定后重新部署。
