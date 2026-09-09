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

## 最小集成接口

relay 对编排宿主暴露本地、受进程权限保护的接口即可（进程内函数、Unix socket 或 loopback HTTP 均可）。推荐逻辑接口：

```ts
type ReplyContext = string; // relay 签发的不透明、短时有效令牌

type DeliveryRequest = {
  context: ReplyContext;
  payload: {
    kind: "progress" | "final";
    markdown: string;
    attachments?: Array<{ path: string; filename?: string }>;
  };
};

type DeliveryResult =
  | { status: "delivered"; deliveryId: string }
  | { status: "not_delivered"; retryable: boolean; reason: string }
  | { status: "unknown"; reason: string };

deliver(request: DeliveryRequest): Promise<DeliveryResult>;
```

`ReplyContext` 应由 relay 将原始平台消息的回复路由信息封装后签发；skill 绝不依赖其内部字段名。它须绑定至少：机器人实例、原始会话/消息、签发时间和一次性投递键，并具有短 TTL。relay 在接收 `deliver` 时验证签名、TTL、机器人匹配及幂等键。

若要支持无原始消息的主动推送，应另设 `sendToTarget(target, payload)` 接口和显式授权策略；不得复用本 skill 的 `replyContext`。

## 投递与恢复策略

- 入站时：relay 先完成平台要求的确认，再把工作排入编排层；可先发一条有限频率的 `progress` 状态。
- 处理中：每个入站事件只允许一个活跃任务与一个最终投递键。重复平台事件应由 relay 去重，不能重复触发下游任务。
- 最终回传：relay 按官方消息回复接口发送，并记录平台确认后的 `deliveryId`。
- 明确未送达且可重试：最多重试 2 次，并采用带抖动的退避；鉴权、参数、权限和内容格式错误不重试。
- 状态未知（连接在写入后中断等）：不自动重试；标记为待人工核对，避免重复消息。
- 重连：仅 relay 负责，采用限速退避；成功后恢复订阅/认证并继续处理未完成但尚未投递的任务。

## 安全边界

- Bot Secret 只存在 relay 的受保护凭据存储或进程环境中，永不放进 `SKILL.md`、任务提示、日志或 `replyContext`。
- relay 的投递端点不能暴露到公网；若使用 HTTP，绑定 loopback、要求进程级认证，并限制请求体与附件路径。
- 默认限制允许调用者/会话范围。智能体有主机工具权限时，企业微信输入应被当作不可信内容，按最小权限隔离工作区。
- 不记录完整用户消息、密钥或附件内容；日志仅保留脱敏后的事件 ID、投递状态和可诊断错误码。

## 实施检查表

1. 采用官方企业微信智能机器人 Node SDK 或等价官方协议实现 relay，不依赖 webhook 公网回调。
2. 用真实机器人完成：建连、收一条私聊、生成 `replyContext`、`final` 回传、断线重连与重复事件去重。
3. 验证超长 Markdown 的 relay 分段、附件上传/失败回退及 `unknown` 状态不重发。
4. 接入此 skill：上游 skill 的最终字符串与附件清单经编排入口传入，且只持有 `replyContext`。
