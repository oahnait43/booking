# 预约协作系统（公众号 H5）

## 本地启动

1. 安装依赖

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. 配置环境变量（可选）

创建 `.env`：

```env
SECRET_KEY=dev-secret
DATABASE_URL=sqlite:///./booking.db
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=admin123
```

3. 启动

```bash
uvicorn app.main:app --reload
```

打开：`http://127.0.0.1:8000`

首次启动会自动创建一个管理员账号（用户名/密码取自上述 BOOTSTRAP_* 配置）。

## Docker 部署（推荐）

```bash
docker compose up -d --build
```

健康检查：`/health`

SQLite 数据文件默认在 compose 卷里：`booking-data`。

## 备份（SQLite）

```bash
./scripts/backup_sqlite.sh ./booking.db ./backups
```

## Cloudflare Workers + KV 部署

当前仓库包含一份可部署到 Cloudflare Workers 的实现（KV 存储）：

- 目录：[cf-worker](file:///Users/BONNIE3T/Desktop/booking/cf-worker)
- 部署说明：见 [cf-worker/README.md](file:///Users/BONNIE3T/Desktop/booking/cf-worker/README.md)

## 发布到 GitHub

```bash
git add -A
git commit -m "init"
```

在 GitHub 新建一个空仓库（不要勾选初始化 README/License），然后把远端地址替换进来：

```bash
git branch -M main
git remote add origin https://github.com/<your>/<repo>.git
git push -u origin main
```
