# mlist

一个轻量的文件目录 Web 应用：后端使用 Rust（Axum），前端使用 React（Vite + shadcn/ui）。

项目目标是把指定目录安全地暴露为可浏览、可预览、可下载的网页界面，适合家庭媒体库、私有文件分发等场景。

## 重要说明

本项目当前版本的大部分代码、样式与文档由 AI 协助生成与迭代，人工负责需求提出、方向决策与最终验收。

## 功能概览

- 目录浏览与文件列表展示
- 常见文件在线预览
  - 图片
  - 音频
  - 视频
  - PDF
  - Markdown
  - 纯文本（txt/log/text）
- 用户名 + 6 位 TOTP 动态码登录
- 首次空库初始化管理员
- 管理员用户管理
  - 新建用户
  - 启用/禁用用户
  - 删除用户
  - 重置 TOTP
- 下载直链（`/d/...`）与 7 天签名播放链接
- 基于 URL 的目录/预览定位，可直接分享链接
- 已复制/已播放文件高亮持久化到后端，按用户区分
- 管理员可查看资源访问审计、用户流量统计和文件访问进度

## 登录与用户

- 所有目录列表、文件拉流和下载都需要登录。
- 登录方式为用户名 + TOTP 动态码，不提供传统密码。
- 空数据库首次访问时需要初始化，第一个完成 TOTP 绑定的用户会成为管理员。
- 管理员可进入 `/_mlist/admin` 管理用户。
- 禁用、删除用户或重置用户 TOTP 后，该用户现有会话和签名播放链接会失效。
- 为避免锁死，系统禁止禁用或删除最后一个启用的管理员。

## 私有目录规则

支持 `.private` 标记文件：

- `.private`
  - 作用：将该目录标记为管理员专属目录
  - 管理员：列表中可见，可访问
  - 普通用户：列表中不可见，直连访问也会返回不可见结果
  - 说明：文件内容会被忽略

`.password` 不再参与权限控制，也不会被特殊隐藏或禁止下载。

## 播放链接

- `/d/...` 是唯一文件拉流入口。
- 浏览器内访问 `/d/...` 使用登录会话 cookie 鉴权。
- 复制链接时，前端会生成 `/d/...?token=...` 签名播放链接，默认 7 天有效，适合 mpv 等不带浏览器 cookie 的播放器。
- 签名播放链接绑定具体文件和生成用户，访问流量会计入该用户。

## 安全设计（后端）

- 严格相对路径解析，拒绝绝对路径、`..`、反斜杠与控制字符
- 防路径穿透：解析后必须仍位于配置的根目录内
- 禁止符号链接（路径段与目标文件都会检查）
- `.private` 标记文件不会在列表中暴露，也不能直接下载
- 登录有失败限速，降低暴力猜解风险
- 会话、用户、审计、播放进度和文件状态使用 SQLite 持久化
- 默认附加常见安全响应头（CSP、`X-Content-Type-Options`、`X-Frame-Options` 等）

## 项目结构

```text
.
├─ backend/    # Rust 后端
├─ frontend/   # React 前端
├─ Dockerfile  # 单镜像构建前后端
└─ justfile    # 本地开发命令
```

## 本地开发

前置环境：

- Rust（建议 stable）
- Node.js 22+
- npm（项目前端命令使用 npm）
- just（可选，但推荐）

常用命令：

```bash
# 同时启动后端与前端 dev
just dev

# 仅后端
just backend-dev

# 仅前端
just frontend-dev
```

默认情况下：

- 后端地址：`http://127.0.0.1:3000`
- 前端开发服务器：`http://127.0.0.1:5173`

## 配置

后端只通过环境变量配置；未指定时使用内置默认值。

可用环境变量：

- `MLIST_ROOT_DIR`：文件根目录，必须是绝对路径，默认 `/mlist-files`
- `MLIST_DATABASE_PATH`：SQLite 数据库路径，必须是绝对路径，默认 `/mlist-data/mlist.sqlite3`
- `MLIST_BIND_ADDR`：后端监听地址，默认 `0.0.0.0:3000`
- `MLIST_SESSION_TTL_SECONDS`：登录会话有效期，单位秒，默认 `2592000`
- `MLIST_SIGNED_FILE_LINK_TTL_SECONDS`：签名播放链接有效期，单位秒，默认 `604800`
- `MLIST_LOGIN_MAX_FAILURES`：登录失败限速阈值，默认 `5`
- `MLIST_LOGIN_BLOCK_SECONDS`：登录失败限速阻断时间，单位秒，默认 `60`
- `MLIST_CONTENT_SECURITY_POLICY`：响应使用的 CSP 头，默认使用项目内置策略

## Docker

构建镜像：

```bash
docker build -t mlist:local .
```

运行示例（将宿主机目录挂载到容器默认根目录，并挂载数据库持久卷）：

```bash
docker run --rm -p 3000:3000 \
  -e MLIST_ROOT_DIR=/mlist-files \
  -e MLIST_DATABASE_PATH=/mlist-data/mlist.sqlite3 \
  -e MLIST_SESSION_TTL_SECONDS=2592000 \
  -e MLIST_SIGNED_FILE_LINK_TTL_SECONDS=604800 \
  -v /your/files:/mlist-files \
  -v mlist-data:/mlist-data \
  mlist:local
```

最终镜像使用 `tini` 作为入口进程，负责转发 SIGTERM/SIGINT 并回收子进程。
