# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 在此代码库中工作时提供指导。

## 项目概述

whatsmeow 是一个实现 WhatsApp Web 多设备 API 的 Go 库。它使用 Noise 协议和 Signal 协议处理与 WhatsApp 服务器的端到端加密通信。

## 构建和测试命令

```bash
# 构建
go build -v ./...

# 运行测试
go test -v ./...

# 运行单个测试
go test -v -run TestName ./...

# 代码质量检查（来自 pre-commit 钩子）
go-imports-repo -local go.mau.fi/whatsmeow -w
go-vet-repo-mod
go-mod-tidy
```

## 架构

### 核心组件

- **Client** (`client.go`): 主入口点。管理 WebSocket 连接、认证、事件处理和自动重连逻辑。

- **Socket 层** (`socket/`): 实现 Noise 协议加密的 WebSocket 通信。
  - `NoiseSocket`: 使用 AEAD 的加密套接字
  - `FrameSocket`: 帧级别的 WebSocket 处理
  - `NoiseHandshake`: 协议握手

- **二进制协议** (`binary/`): WhatsApp 专有的二进制 XML 格式编解码器。
  - `Node`: XML 节点表示，包含 `Tag`、`Attrs`、`Content`
  - `Encoder`/`Decoder`: 序列化/反序列化二进制 XML

- **类型** (`types/`): 核心数据结构。
  - `JID`: WhatsApp Jabber ID（用户/群组标识符），服务器类型包括：`s.whatsapp.net`（用户）、`g.us`（群组）、`broadcast`（广播）
  - `events/`: 事件系统（QR、Connected、Message、GroupUpdate 等）

- **存储** (`store/`): 数据持久化接口。
  - `sqlstore/`: 支持多种数据库的 SQL 实现
  - 存储内容：身份密钥、Signal 会话、预密钥、应用状态同步密钥

- **应用状态** (`appstate/`): 使用 LTHash 进行增量更新，管理同步的应用状态（联系人、聊天设置）。

- **Proto** (`proto/`): 56+ 个 protobuf 包，定义 WhatsApp 协议消息。
  - `waE2E`: 端到端加密
  - `waMsgTransport`/`waMsgApplication`: 消息层
  - `waHistorySync`: 消息历史同步

### 主包文件

| 文件 | 用途 |
|------|------|
| `pair.go`, `pair-code.go` | QR 码配对和认证 |
| `send.go` | 消息发送逻辑 |
| `message.go` | 消息处理和创建 |
| `group.go` | 群组操作（创建、编辑、权限） |
| `download.go`, `upload.go` | 媒体处理 |
| `receipt.go` | 已读/已送达回执 |
| `presence.go` | 在线状态 |
| `handshake.go` | 协议握手 |
| `keepalive.go` | 连接心跳 |

### 事件流程

1. 使用设备存储创建 `Client`
2. 连接并接收 `QR` 事件进行配对（如果之前已配对则自动登录）
3. 认证后处理 `Connected` 事件
4. 处理传入事件：`Message`、`Receipt`、`GroupUpdate` 等
5. 使用客户端方法发送消息、管理群组、同步状态

### 关键依赖

- `go.mau.fi/libsignal`: Signal 协议（端到端加密）
- `github.com/coder/websocket`: WebSocket 客户端
- `google.golang.org/protobuf`: Protocol Buffers
- `github.com/rs/zerolog`: 结构化日志
