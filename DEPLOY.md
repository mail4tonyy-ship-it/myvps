# 一键部署到 Cloudflare

## 方式一：Deploy to Cloudflare 按钮

把本项目推送到一个公开 GitHub 仓库后，将下面链接中的仓库地址替换为你的仓库地址：

```md
[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/mail4tonyy-ship-it/myvps)
```

点击后 Cloudflare 会引导你完成：

1. 连接 GitHub。
2. 连接 Cloudflare 账号。
3. 按 `wrangler.jsonc` 部署 Worker、Assets、D1、Durable Objects 和 Cron。

部署完成后，请进入 Worker 的变量设置，把 `ADMIN_PASSWORD` 改成强密码。

## 方式二：本地一条命令部署

```bash
npm install
npx wrangler login
npx wrangler deploy
```

## 必要绑定

`wrangler.jsonc` 已声明以下资源：

- `ASSETS`：静态前端和 VPS 脚本。
- `DB`：D1 数据库。
- `VPS_PRESENCE`：Durable Object，占位兼容原部署形态。
- `DASHBOARD_HUB`：Durable Object，用于前台实时推送。
- Cron：每 5 分钟检查离线状态。

如果 Cloudflare 一键流程没有自动创建 D1，请手动创建一个 D1 数据库并绑定为 `DB`。
