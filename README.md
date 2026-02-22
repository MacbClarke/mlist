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
- 下载直链（`/d/...`）与复制链接
- 基于 URL 的目录/预览定位，可直接分享链接
- 前端本地高亮（仅保存在浏览器本地，不写入服务端）

## 私有目录规则

支持两个标记文件（可同时存在）：

- `.private`
  - 作用：将该目录从父目录的列表中隐藏
  - 说明：文件内容会被忽略，不参与密码校验
- `.password`
  - 作用：该目录（及其子内容）需要密码访问
  - 说明：密码为文件文本内容（去除首尾空白）  

组合行为：

- 仅 `.private`：目录在父级列表中不可见，但知道路径可直接访问
- 仅 `.password`：目录可见，但访问需要先登录
- `.private` + `.password`：目录既隐藏，又需要密码

## 安全设计（后端）

- 严格相对路径解析，拒绝绝对路径、`..`、反斜杠与控制字符
- 防路径穿透：解析后必须仍位于配置的根目录内
- 禁止符号链接（路径段与目标文件都会检查）
- 标记文件（`.private`/`.password`）不会在列表中暴露，也不能直接下载
- 私有目录登录有失败限速，降低暴力猜解风险
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

后端读取 `backend/config.toml`（或通过 `MLIST_CONFIG` 指定配置文件）。

关键配置：

- `root_dir`：文件根目录（必须是绝对路径）
- `bind_addr`：后端监听地址
- `session_ttl_seconds`：会话有效期
- `secure_cookies`：生产 HTTPS 环境建议设为 `true`
- `login_max_failures` / `login_block_seconds`：登录限速策略

## Docker

构建镜像：

```bash
docker build -t mlist:local .
```

运行示例（将宿主机目录挂载到容器默认根目录）：

```bash
docker run --rm -p 3000:3000 \
  -v /your/files:/tmp/mlist-files \
  mlist:local
```

