# 服务器全景探针

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/mail4tonyy-ship-it/myvps)

这是一个可部署到 **Cloudflare Workers + Static Assets + D1** 的 VPS 全景探针面板。项目已从 K-UI 中单独抽出，只保留服务器监控能力，不包含代理节点、订阅、住宅代理、用户流量管理、sing-box 配置下发等模块。

## 功能

- 管理员登录和退出
- 首次登录自动设置管理员密码，管理页可修改密码
- 公开看板开关
- 卡片 / 表格两种视图
- 根据服务器 IP 所属地区显示国旗
- VPS 纳管和一键安装命令
- Agent 周期上报 CPU、内存、磁盘、流量、连接数、延迟、系统信息
- IPv4 延迟监控
- 管理页生成 Agent 在线升级命令
- D1 自动建表
- 历史曲线和离线状态判断
- 主题、上报间隔、月流量周期重置

## 一键部署

1. 把本目录上传到公开 GitHub 仓库 `mail4tonyy-ship-it/myvps`。
2. 在 GitHub 页面点击 **Deploy to Cloudflare**。
3. 部署命令使用 `npm run deploy`。这个命令会先根据项目名生成 D1 名称，再交给 Wrangler 部署。
4. Cloudflare 会自动 clone 仓库、创建 Worker、首次部署时自动创建 D1 数据库，并绑定到 `DB`。
5. `ADMIN_PASSWORD` 是可选环境变量；不设置也可以，首次登录时会自动初始化管理员密码。

D1 命名规则：读取 `wrangler.jsonc` 里的项目名，例如 `myvps`，自动生成 `myvps123` 这种格式，项目名后追加 3 位随机数字。`wrangler.jsonc` 里不要提前填写假的 `database_id`，Wrangler/Cloudflare 会在首次部署时自动创建并关联 D1。

Cloudflare 官方说明：Deploy Button 会根据 Wrangler 配置自动 provision D1 等资源，并在部署时补全资源 ID。项目里使用 `scripts/prepare-cloudflare.mjs` 只负责生成符合规则的 D1 名称，不负责手动创建数据库。

## 手动部署

如果你不用按钮，也可以手动部署：

```bash
npm install
cp .dev.vars.example .dev.vars
npm run deploy
```

如果你要换项目名，先改 `wrangler.jsonc` 的 `name`，或者部署前设置环境变量：

```bash
CF_PROJECT_NAME=myvps npm run deploy
```

脚本会按最终项目名生成 D1 名称，例如 `myvps047`。

## 使用

1. 打开部署后的 Worker 地址。
2. 点击右上角“登录”。
   - 用户名：`wrangler.jsonc` 中的 `ADMIN_USERNAME`，默认 `admin`
   - 首次部署如果还没设置密码，直接输入一个至少 8 位的新密码，系统会自动初始化
   - 如果你在 Cloudflare 环境变量里设置了 `ADMIN_PASSWORD`，也可以使用该密码登录
3. 点击“纳管服务器”，输入 VPS IP、名称和分组。
4. 复制生成的命令，在 VPS 上以 root 执行。
5. 等待下一次上报，面板会显示服务器数据。

## Agent 在线升级

旧节点升级到最新 Agent：

1. 登录管理页。
2. 点击右上方管理面板里的“升级 Agent”。
3. 复制生成的命令。
4. 在旧 VPS 上以 root 执行。

升级命令会下载当前部署版本里的 `/vps/panorama-agent.py`，校验 Python 语法，然后重启 `panorama-probe` 服务。

## 文件结构

```text
server-panorama-probe/
  src/worker.js                Cloudflare Worker API 和 D1 数据逻辑
  static/index.html            全景探针看板
  static/vps/install.sh        VPS 一键安装脚本
  static/vps/panorama-agent.py VPS 指标采集 agent
  static/vps/upgrade-agent.sh  Agent 在线升级脚本
  scripts/prepare-cloudflare.mjs 自动生成 D1 名称
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
