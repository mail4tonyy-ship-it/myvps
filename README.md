# 服务器全景探针

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/mail4tonyy-ship-it/myvps)

这是一个可部署到 **Cloudflare Workers + Static Assets + D1** 的 VPS 全景探针面板。项目已从 K-UI 中单独抽出，只保留服务器监控能力，不包含代理节点、订阅、住宅代理、用户流量管理、sing-box 配置下发等模块。

## 功能

- 管理员登录和退出
- 公开看板开关
- 卡片 / 表格两种视图
- VPS 纳管和一键安装命令
- Agent 周期上报 CPU、内存、磁盘、流量、连接数、延迟、系统信息
- D1 自动建表
- 历史曲线和离线状态判断
- 主题、上报间隔、月流量周期重置

## 一键部署

1. 把本目录上传到公开 GitHub 仓库 `mail4tonyy-ship-it/myvps`。
2. 在 GitHub 页面点击 **Deploy to Cloudflare**。
3. Cloudflare 会自动 clone 仓库、创建 Worker、创建 D1 数据库并绑定到 `DB`。
4. 部署页面里请把 `ADMIN_PASSWORD` 改成强密码。

Cloudflare 官方说明：Deploy Button 会根据 Wrangler 配置自动 provision D1 等资源，并在部署时补全资源 ID。

## 手动部署

如果你不用按钮，也可以手动部署：

```bash
npm install
cp .dev.vars.example .dev.vars
npm run deploy
```

手动部署时，如果 Wrangler 要求真实 D1 ID，请先创建数据库：

```bash
npx wrangler d1 create server-panorama-probe-db
```

然后把输出的 `database_id` 填进 `wrangler.jsonc`。

## 使用

1. 打开部署后的 Worker 地址。
2. 点击右上角“登录”，使用：
   - 用户名：`wrangler.jsonc` 中的 `ADMIN_USERNAME`，默认 `admin`
   - 密码：部署时填写的 `ADMIN_PASSWORD`
3. 点击“纳管服务器”，输入 VPS IP、名称和分组。
4. 复制生成的命令，在 VPS 上以 root 执行。
5. 等待下一次上报，面板会显示服务器数据。

## 文件结构

```text
server-panorama-probe/
  src/worker.js                Cloudflare Worker API 和 D1 数据逻辑
  static/index.html            全景探针看板
  static/vps/install.sh        VPS 一键安装脚本
  static/vps/panorama-agent.py VPS 指标采集 agent
  wrangler.jsonc               Cloudflare Workers 部署配置
  .dev.vars.example            本地/一键部署 secret 示例
```

## 上传 GitHub 前

建议只上传本目录内容，不要上传父目录：

```bash
cd server-panorama-probe
git init
git add .
git commit -m "Initial server panorama probe"
git branch -M main
git remote add origin https://github.com/mail4tonyy-ship-it/myvps.git
git push -u origin main
```
