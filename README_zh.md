# SlashChat

[English](README.md) | 中文

当前版本：`v1.0.0`

SlashChat 是一个使用 Go 构建的套接字聊天系统。基于 Bubbletea 的终端客户端通过自定义的长度前缀 JSON 协议与 TCP 服务器通信，实现身份认证、聊天室消息以及基于 SHA 校验的文件分享，同时保持依赖轻量。

## 项目亮点
- 纯 Go（CGO_DISABLED）的 TCP 服务器，提供 JWT 会话、聊天室广播、SQLite 持久化，以及带状态的命令 ACK 响应与结构化日志。
- Bubbletea TUI 客户端支持命令/插入模式、ANSI 渲染的消息列表、命令补全、状态栏，以及空闲时显示 ASCII 横幅。
- 文件分享流程会复用 SHA-256 已存在的二进制文件，将上传内容保存到 `uploads/` 并持久化元数据，方便通过 `/download <message_id>` 取回文件。
- `/pipe` 传输检查器实时呈现 JSON 信封并支持快速清空，用于调试协议。
- GitHub Actions 在打标签时构建 Linux/Mac/Windows 三个平台的二进制，并借助 `softprops/action-gh-release` 发布制品。

## 环境要求
- Go 1.25 或更新版本（模块目标：Go 1.25.3）。
- CGO 需禁用（`CGO_ENABLED=0`），以便无依赖地跨平台构建。
- 无需外部数据库；服务器通过 pure-Go SQLite 驱动工作。
- 可选：安装 GNU Make 以使用项目提供的构建脚本。

## 快速开始
1. 克隆仓库并进入项目目录。
2. 若需全新环境，可删除已有的 `goslash.db` 文件和 `uploads/` 目录。
3. 构建服务器与客户端：
   ```
   make build
   ```
   可执行文件会输出到 `build/`（`goslash-server`, `goslash-client`）。也可以分别执行 `go build ./cmd/server` 与 `go build ./cmd/client`。
4. 启动服务器（默认监听 `:9000`，数据库 `goslash.db`，上传目录 `uploads/`）：
   ```
   ./build/goslash-server
   ```
5. 启动客户端（默认连接 `localhost:9000`）：
   ```
   ./build/goslash-client
   ```

建议打开第二个终端运行额外客户端。全部交互都在 TUI 内通过斜杠命令或普通聊天输入完成。

## 配置项
服务器与客户端均可通过环境变量定制：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `GOSLASH_LISTEN_ADDR` | `:9000` | 服务器监听地址 |
| `GOSLASH_DB_PATH` | `goslash.db` | SQLite 数据库文件路径 |
| `GOSLASH_UPLOAD_DIR` | `uploads` | 上传文件的存储目录（文件名为 SHA-256） |
| `GOSLASH_JWT_SECRET` | `replace-me` | JWT 签名密钥，生产环境务必替换 |
| `GOSLASH_JWT_ISSUER` | `goslash` | JWT issuer 字段 |
| `GOSLASH_JWT_EXPIRATION` | `24h` | Token 有效期 |
| `GOSLASH_READ_TIMEOUT` / `GOSLASH_WRITE_TIMEOUT` | `15s` | 套接字读写超时 |
| `GOSLASH_MAX_FRAME_BYTES` | `1048576` | 单帧最大字节数 |
| `GOSLASH_SERVER_ADDR` | `localhost:9000` | 客户端默认服务器地址 |
| `GOSLASH_COMMAND_PREFIX` | `/` | 客户端命令前缀（仅使用首个字符） |

## 客户端常用命令
- `/connect [addr]` – 连接到服务器（未给参数时使用默认地址）。
- `/register <username> <password>` – 注册账号（密码使用 bcrypt 存储）。
- `/login <username> <password>` – 登录并缓存 JWT，用于后续命令。
- `/join <room>` / `/leave [room]` – 加入或离开聊天室；加入后会加载最近历史并接收广播。
- `/upload <path>` – 上传文件。客户端先发送 SHA-256 以尝试快速复用，否则按 `file_upload` 流程上传。
- `/download <message_id>` – 下载聊天中共享的文件，文件保存到当前工作目录。
- `/pipe [clear]` – 切换到传输检查器，查看原始 JSON 信封或清空缓冲。
- `/chat` / `/help` / `/quit` – 切换视图、查看帮助或退出程序。
- 在插入模式下直接输入文本即可发送当前聊天室消息；状态栏会使用不同颜色区分提示与错误。

## 手动验证清单
- 使用 `make build` 重新编译，并删除旧的 `goslash.db`/`uploads/` 目录。
- 启动服务器，连接两个客户端，分别注册/登录不同账号。
- 加入同一房间，确认历史消息加载成功，并互发文本消息。
- 从一个客户端上传文件，检查服务器返回 `upload_required`/`ok`，并确认另一端收到广播。
- 在另一客户端执行 `/download <message_id>` 下载文件并核对磁盘内容。
- 在整个流程中使用 `/pipe` 观察 `file_upload_prepare`、`file_upload`、`chat_message` 与对应 ACK。

## 发布流程
- 确认文档（README、AGENTS）与配置已更新，执行 `go fmt ./...` 并完成上述手动验证。
- 打标签触发发布：`git tag vX.Y.Z && git push origin vX.Y.Z`，GitHub Actions 会运行 `.github/workflows/build-release.yml`。
- 工作流会构建禁用 CGO 的 Linux/Mac/Windows 二进制、上传构建产物，并通过 `softprops/action-gh-release` 创建 GitHub Release。
- 若需无标签重构制品，可手动触发 workflow，并在 `tag` 输入中指定目标版本号。

## 开发须知
- 提交前请运行 `go fmt ./...` 或使用编辑器自动格式化代码。
- 当前仓库缺少自动化测试，`go test ./...` 会立即返回；建议在新增功能时补充测试。
- `make build` 仅是便捷封装，直接 `go build ./cmd/server` 与 `go build ./cmd/client` 亦可。
- 服务器日志包含启动信息、认证结果、房间事件与文件传输；客户端在状态栏记录关键事件。

## 已知限制
- 传输仍为明文 TCP，缺少 TLS、心跳或重连退避逻辑。
- 尚未实现 `/users` 命令，成员变动仅能通过聊天事件感知。
- 文件上传一次性发送整文件，`file_chunk` 类型尚未启用。
- 缺乏端到端自动化测试，目前只能依赖手动验证或自行拓展脚本。

## 后续规划
- 增强传输安全性（TLS）、速率限制与重连/退避策略。
- 引入房间成员与状态查询指令、历史分页与搜索功能。
- 编写客户端/服务器端到端自动化测试，覆盖上传/下载流程。
- 利用现有 `file_chunk` 类型实现大文件的流式上传与下载。
