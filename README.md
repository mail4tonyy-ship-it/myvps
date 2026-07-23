# MyVps

MyVps 是一个部署在单一 Cloudflare Worker 上的服务器监测面板。它保留 VPS 接入、Agent 上报、实时 WebSocket、公开探针大盘、主题设置、Telegram 告警与离线检查能力。

已移除代理节点添加、住宅 IP 代理、Realm 中转、第三方服务、第三方订阅、机场订阅导出等相关功能。

## 一键部署

点击 Cloudflare Workers 部署后，确认已绑定：

- D1 数据库：`DB`
- Durable Objects：`VPS_PRESENCE`、`DASHBOARD_HUB`
- Worker Assets：`static`

预设登录信息：

```text
用户名：admin
密码：admin
```

生产环境请在 Cloudflare Variables and Secrets 中将 `ADMIN_PASSWORD` 覆盖为强 Secret。

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
