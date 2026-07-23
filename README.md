# MyVps

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/YOUR_GITHUB_USERNAME/MyVps)

MyVps 是一个部署在单一 Cloudflare Worker 上的服务器监测面板。它保留 VPS 接入、Agent 上报、实时 WebSocket、公开探针大盘、主题设置、Telegram 告警与离线检查能力。

已移除代理节点添加、住宅 IP 代理、Realm 中转、第三方服务、第三方订阅、机场订阅导出等相关功能。

## 一键部署

1. 将本项目上传到公开 GitHub 或 GitLab 仓库。
2. 将上方按钮链接中的 `https://github.com/YOUR_GITHUB_USERNAME/MyVps` 替换为你的仓库地址。
3. 点击按钮，按 Cloudflare 页面提示完成授权与部署。
4. 部署完成后进入 Worker 设置，将 `ADMIN_PASSWORD` 改成强密码。

Cloudflare 一键部署会读取 `wrangler.jsonc` 并自动准备以下资源：

- D1 数据库：`DB`，名称按项目名自动生成，例如 `myvps123`
- Durable Objects：`VPS_PRESENCE`、`DASHBOARD_HUB`
- Worker Assets：`static`

预设登录信息：

```text
用户名：admin
密码：admin
```

生产环境请在 Cloudflare Variables and Secrets 中将 `ADMIN_PASSWORD` 覆盖为强 Secret。

## 手动部署

如果不使用按钮，也可以用 Wrangler 部署：

```bash
npm install
npx wrangler d1 create myvps123
```

手动部署时，D1 命名规则同样建议使用“项目名 + 3 位随机数字”，例如 `myvps123`。把 Cloudflare 返回的 `database_id` 写入 `wrangler.jsonc` 后执行：

```bash
npm run deploy
```

## VPS 接入

1. 登录 MyVps，进入“服务器监控”。
2. 添加 VPS 名称和公网 IP。
3. 复制页面生成的 Full Deploy Command，以 root 在 VPS 执行。
4. 等待 Agent 回连后即可在公开大盘和后台查看 CPU、内存、磁盘、网络、TCP/UDP、延迟与在线状态。

## 本地预览

```bash
npm install
npm run dev
```

## 开源协议

MIT
