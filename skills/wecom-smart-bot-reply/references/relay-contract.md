# 企业微信智能机器人长连接回传契约

## 结论

可行，但需要一个长驻 relay 作为边界：它用企业微信智能机器人的凭据维持官方 WebSocket 长连接，接收消息时生成回传上下文；本 skill 和其他生成内容的 skill 只通过该 relay 投递结果。这样会话路由、鉴权和断线重连不散落在各个 skill 中。

企业微信智能机器人官方文档：<https://developer.work.weixin.qq.com/document/path/101463>。设计也参考了 `xmanrui/dsh-im` 的企业微信渠道：官方 WebSocket 长连接、原生进行中状态及流式/最终回答均由渠道适配器管理，而非由业务处理器自行连接：<https://github.com/xmanrui/dsh-im>。

## 组件与职责

| 组件 | 职责 | 不负责 |
| --- | --- | --- |
| WeCom relay（常驻进程） | 用 Bot ID/Secret 鉴权并维护官方 WebSocket、接收平台事件、确认平台回调、生成/保存 `replyContext`、向原会话回复、重连与幂等 | 生成业务答案 |
| 编排入口 | 将入站消息连同 `replyContext` 交给 Codex/其他 skill；等待产物并调用回传 skill | 保存机器人密钥或实现平台协议 |
| `wecom-smart-bot-reply` skill | 过滤并格式化产物，调用 relay 的投递能力，按返回状态决定是否停止 | 反向解析/伪造会话标识、重建 WebSocket |

```text
企业微信用户 → 官方 WebSocket → relay → 编排/其他 skill
                                      │
                                      └→ replyContext + 已生成内容 → 本 skill → relay → 原会话
```

## 集成接口：`wecom-aibot` CLI

relay 由 `wecom-aibot serve` 常驻，其他 skill 只通过同一台机器上的 CLI 与它通信。CLI 是唯一对外契约，没有进程内 `deliver` 函数。

| 命令 | 用途 | 关键参数 |
| --- | --- | --- |
| `wecom-aibot serve` | 建立官方 WebSocket 长连接并监听本地 IPC | `--endpoint`、`--config`、`--handler <程序> [参数...]`、`--context-ttl` |
| `wecom-aibot reply` | 投递最终回复 | `--context`、`--content-file`、`--endpoint` |
| `wecom-aibot status` | 查询 relay 是否在运行 | `--endpoint` |
| `wecom-aibot stop` | 请求 relay 退出 | `--endpoint` |
| `wecom-aibot upgrade` | 从 PyPI 升级并校验安装完整性 | `--yes` |

退出码对所有投递类命令统一：

| 退出码 | 含义 | 调用方动作 |
| --- | --- | --- |
| `0` | `delivered` / `running` / `stopping` | 结束 |
| `1` | 明确未送达、参数错误、凭据或权限不合格、relay 未运行 | 修复后最多再试一次 |
| `75` | `unknown`，无法确定是否已写入 | **不得重试**，转人工核对 |
| `3` / `4` / `5` / `6` / `7` | 仅 `upgrade`：索引不可达、用户拒绝、非交互、缺少 `uv`、完整性校验失败 | 见下文 |

`--content-file` 是回复正文的唯一入口，必须是 UTF-8 文件；正文不进命令行，避免出现在进程列表中。`replyContext` 由 relay 签发：它是绑定原始会话路由、签发时间和一次性投递键的不透明令牌，具有短 TTL，skill 不得解析其字段。

### 本地端点与认证

- relay 在专用运行目录内工作：Unix 上是 owner-only（`0700`）目录，Windows 上由 CLI 在启动 IPC 前以 protected owner-only DACL 原子创建并校验，不依赖普通 TEMP/profile ACL。
- 端点默认 `<运行目录>/relay.sock`，可用 `--endpoint` 或 `WECOM_AIBOT_ENDPOINT` 覆盖。Windows 上 relay 绑定 loopback HTTP，实际地址写入 `<endpoint>.endpoint` sidecar。
- IPC 认证 token 写在 owner-only 的 `<endpoint>.token` sidecar 中。CLI 自行读取，**不接受命令行传 token，也不打印 token**。
- IPC 报文为单行 JSON，动作为 `reply` / `status` / `stop`，回复投递的响应上限为 120 秒。

### 事件分发

`serve` 收到去重后的文本消息时，对每个事件只启动一次 `--handler` 进程，并向其 stdin 一次性写入一个 JSON 对象：

```json
{ "text": "...", "replyContext": "...", "eventId": "...", "receivedAt": "2026-09-10T00:00:00+00:00" }
```

handler 的 stdout 与退出码**不构成回复**；要回复必须显式调用 `wecom-aibot reply`。未配置 `--handler` 时 relay 只输出不含正文与 context 的结构化错误。

若要支持无原始消息的主动推送，应另设独立命令与显式授权策略；不得复用本 skill 的 `replyContext`。

## 投递与恢复策略

- 入站时：relay 先完成平台要求的确认，再把工作排入编排层；可先发一条有限频率的 `progress` 状态。
- 处理中：每个入站事件只允许一个活跃任务与一个最终投递键。重复平台事件应由 relay 去重，不能重复触发下游任务。
- 最终回传：relay 按官方消息回复接口发送，并记录平台确认后的 `deliveryId`。
- 明确未送达且可重试：最多重试 2 次，并采用带抖动的退避；鉴权、参数、权限和内容格式错误不重试。
- 状态未知（连接在写入后中断等）：不自动重试；标记为待人工核对，避免重复消息。
- 重连：仅 relay 负责，采用限速退避；成功后恢复订阅/认证并继续处理未完成但尚未投递的任务。

## 安全边界

- Bot ID/Secret 只来自环境变量 `WECHAT_BOT_ID` / `WECHAT_BOT_SECRET`，或 `--config` 指定的 owner-only JSON（`botId` / `botSecret`）。缺失凭据或文件权限过宽时 `serve` 直接拒绝启动，永不放进 `SKILL.md`、任务提示、日志或 `replyContext`。
- relay 的投递端点不能暴露到公网；Windows 上绑定 loopback HTTP，Unix 上使用 owner-only Unix socket，两者都要求 sidecar token 认证并限制请求体大小。
- 默认限制允许调用者/会话范围。智能体有主机工具权限时，企业微信输入应被当作不可信内容，按最小权限隔离工作区。
- 不记录完整用户消息、密钥、token、会话路由或平台原始帧；日志仅保留脱敏后的事件引用、投递状态和可诊断错误码。
- `upgrade` 只从固定的 PyPI JSON 接口取版本，只执行固定的 `uv tool upgrade wecom-aibot` 参数数组；升级后按 `.dist-info/RECORD` 重新校验安装文件的大小与摘要，校验失败以非零退出码报告“升级已执行但完整性校验失败”，绝不报告成功，也不自动回滚。

## 实施检查表

1. relay 基于官方 `wecom-aibot-python-sdk`（`aibot.WSClient`）的长连接实现，不依赖 webhook 公网回调。
2. 用真实机器人完成：建连、收一条私聊、生成 `replyContext`、最终回传、断线重连与重复事件去重。
3. 验证超长 Markdown 被平台拒绝时的明确失败分类，以及 `unknown` 状态不重发。
4. 接入此 skill：上游 skill 的最终字符串写入 UTF-8 文件后调用 `wecom-aibot reply`，且只持有 `replyContext`。
