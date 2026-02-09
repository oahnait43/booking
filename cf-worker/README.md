## Cloudflare Workers + KV 版本

这份 Worker 版本用 Cloudflare KV 存储用户/教练/会员/时间配置/预约数据，并提供同样的移动端页面入口：

- `/login` 登录
- `/member` 会员预约
- `/coach` 教练确认/拒绝
- `/admin` 管理端

### 1) 创建 KV

```bash
wrangler kv namespace create BOOKING_KV
```

把输出里的 `id` 填到 [wrangler.toml](file:///Users/BONNIE3T/Desktop/booking/cf-worker/wrangler.toml) 的 `kv_namespaces` 中。

### 2) 配置环境变量

至少需要：

- `SECRET_KEY`：会话签名密钥（务必设置为随机长字符串）

可选：

- `BOOTSTRAP_ADMIN_USERNAME` / `BOOTSTRAP_ADMIN_PASSWORD`：首次访问自动创建管理员账号
- `COOKIE_SECURE`：生产环境建议设为 `true`
- `DEFAULT_SLOT_MINUTES`：默认单节分钟数（例外时间段会用它生成时间段）

配置方式（任选其一）：

- 在 Cloudflare Dashboard 的 Worker -> Settings -> Variables 配置
- 或用 `wrangler secret put SECRET_KEY`

### 3) 本地启动

先确保本机有 Node.js（推荐 18+ / 20+）。

如果你看到 `zsh: command not found: brew`，说明没有安装 Homebrew，可以任选其一：

- 安装 Node 官方安装包（最省事）：到 nodejs.org 下载 macOS Installer 安装
- 安装 Homebrew 后再装 Node：
  - 安装 Homebrew：`/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
  - 安装 Node：`brew install node`
- 用 nvm 安装（适合多版本）：按 nvm 官方文档安装后 `nvm install --lts`

```bash
cd cf-worker
npm i
npm run dev
```

### 4) 部署

```bash
cd cf-worker
npm run deploy
```

### 重要说明（KV 一致性）

KV 是最终一致性存储：高并发抢同一时间段时，可能出现“超卖”（容量被突破）的极端情况。
如果你的业务需要强一致的“同一时间段不超卖”，建议把“创建预约/占用名额”迁移到 Durable Objects 或 D1。
