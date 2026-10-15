# Vault 令牌批量续租预算与结果摘要 - 产品需求文档

## Overview
- **Summary**: 为 Vault 令牌续租新增一个批量端点 `auth/token/renew-batch`：调用者可通过 `max_total_duration` 限制整批续租授予的 TTL 总时长（续租预算），服务端按输入顺序逐项处理并返回每项的明确结果（成功 / 达到上限 / 已撤销 / 审计失败 / 错误）与整批摘要；通过客户端提供的 `idempotency_key` 在服务端持久化预算账本，保证重复请求（含网络重试、调用方时钟漂移）不会重复续租、不会扩大预算；部分失败后可用同一幂等键安全重试。
- **Purpose**: 现有 `auth/token/renew` 与 `auth/token/renew-orphan` 等端点一次只能续租一个令牌，且不区分"成功但被 TTL 上限截断"与"完全成功"，调用方在超时/审计失败后无法判断令牌是否已被续租，盲目重试可能再次延长 TTL、突破调用方自身的时长管控。批量 + 预算 + 幂等账本使大规模续租调用具备总量可控、结果可解释、重试安全三个性质。
- **Target Users**: 需要批量维护服务令牌生命周期的自动化系统（agent、控制器、作业平台），以及对单次续租最长授予时长有合规约束的 Vault 调用方。

## Goals
- 单次请求可提交多个续租项（令牌或 accessor），并对"整批授予的 TTL 总时长"设置调用方可配置的上限。
- 服务端逐项返回机器可读的状态与原因：`success`、`limit_reached`、`revoked`、`audit_failed`，外加兜底 `error`；并给出分类计数摘要。
- 幂等：同一 `idempotency_key` 的重复请求返回同一结果，不重新续租、不重复扣减/扩大预算；服务端时间为唯一权威时间，调用方时钟漂移不影响结果。
- 正确覆盖：永不过期的根令牌、父子令牌（含撤销树与 orphan 子令牌）、显式最大 TTL / 系统 max_ttl / period 截断、batch 令牌、过期/不存在的令牌。
- 支持部分失败：单项失败不影响其他项；同一幂等键重试时，已终结项回放原结果，`audit_failed` 项可被重试且绝不二次续租。
- 提供 Go API 客户端方法。

## Non-Goals
- 不改造现有 `renew`、`renew-self`、`renew-accessor` 端点的语义与响应（仅在内部复用其续租逻辑）。
- 不做 secret/lease（非令牌租约）的批量续租。
- 不新增 CLI 命令、不新增 website 文档页面。
- 不引入跨集群复制语义：幂等账本与令牌一样使用 local storage，仅在处理请求的单个集群内有效。
- 不改变令牌授权模型：端点的 ACL 要求与 `auth/token/renew` 一致（路径级 update 权限），不新增逐令牌鉴权。
- 不做账本的主动 GC 任务（采用读取时惰性过期），不做并发同键请求的排队执行（后来者等待后直接回放先到者结果）。

## Background & Context
- 续租主链路：[handleRenew](file:///e:/swe-like/runs/hashicorp--vault/a0b7a503f721/precheck-3623/vault/token_store.go#L3716-L3752) → [ExpirationManager.RenewToken](file:///e:/swe-like/runs/hashicorp--vault/a0b7a503f721/precheck-3623/vault/expiration.go#L1426-L1556) → [framework.CalculateTTL](file:///e:/swe-like/runs/hashicorp--vault/a0b7a503f721/precheck-3623/sdk/framework/lease.go#L36-L112)；TTL 截断以 warning 形式返回（"TTL ... exceeded the effective max_ttl ... capped accordingly"）。
- accessor 续租：[handleUpdateRenewAccessor](file:///e:/swe-like/runs/hashicorp--vault/a0b7a503f721/precheck-3623/vault/token_store.go#L2617-L2666) 先将 accessor 解析为 token ID，再走 `handleRenew`，响应中抹掉 `client_token`。
- 根令牌：初始 root 令牌 `TTL == 0`、策略仅 `root`、不注册租约（[rootToken](file:///e:/swe-like/runs/hashicorp--vault/a0b7a503f721/precheck-3623/vault/token_store.go#L971-L9985)）；Lookup 对其快速放行；常规续租因租约不存在返回 "invalid lease ID"。带 TTL 租约的 root 策略令牌则可以正常续租（见 TestTokenStore_HandleRequest_Renew）。
- 不可续租判定集中在 [leaseEntry.renewable()](file:///e:/swe-like/runs/hashicorp--vault/a0b7a503f721/precheck-3623/vault/expiration.go#L3053-L3084)：租约不存在、已过期、非 renewable、batch/JWT。
- 撤销：`RevokeByToken`/撤销树会移除父令牌及其全部非 orphan 子令牌；orphan 子令牌在父令牌撤销后仍可续租。
- 审计：[audit.Broker.LogResponse/LogRequest](file:///e:/swe-like/runs/hashicorp--vault/a0b7a503f721/precheck-3623/audit/broker.go#L255-L385) 要求至少一个 audit sink 成功，否则返回错误；未配置 audit backend 时返回 nil。请求外层审计只覆盖整批请求，无法表达"某项因审计失败"，因此批量处理器需要逐项审计钩子。
- 存储：TokenStore 基于 `core.systemBarrierView` 的 `token/` 子视图（屏障加密），按命名空间隔离；`token_store_util.go` 存在 OSS/Enterprise 两份视图助手，新视图必须经 `ts.baseView(ns)` 派生而非直接引用 OSS 字段。
- API 客户端续租方法位于 [api/auth_token.go](file:///e:/swe-like/runs/hashicorp--vault/a0b7a503f721/precheck-3623/api/auth_token.go)。

## Functional Requirements

- **FR-1（端点与请求）**: 新增 `auth/token/renew-batch`（UpdateOperation，HTTP POST/PUT）。请求体：
  - `idempotency_key`（string，必填，1–128 字符）；
  - `max_total_duration`（duration 秒，可选；0 或缺省表示不设整批预算，各项仍受令牌/挂载点 TTL 上限约束）；
  - `tokens`（数组，1–100 项），每项恰好提供 `token` 或 `accessor` 之一，以及可选 `increment`（duration 秒；0/缺省表示沿用服务端默认 TTL）。
  - 同一请求内标识符不得重复；参数非法时返回 400 逻辑错误且不产生任何续租副作用。
- **FR-2（预算语义）**: 预算是"本批所有成功/截断成功项实际授予 TTL 的秒数总和"的上限。按输入顺序处理：项下一个续租项前计算剩余预算；剩余为 0 时不再调用续租逻辑，直接判 `limit_reached`（原因 `renewal budget exhausted`）；剩余小于请求增量时以剩余预算作为增量续租并判 `limit_reached`（原因注明预算截断）。每项实际授予 TTL 事后从续租响应中取准并扣减。
- **FR-3（逐项状态分类）**:
  - `success`：实际授予 TTL 未被预算或 TTL 上限截断；
  - `limit_reached`：续租成功但被预算/max_ttl/explicit_max_ttl/period 截断（reason 注明具体来源与有效上限），或令牌为永不过期、无需续租的根令牌（reason: `root token does not expire and cannot be renewed`）；
  - `revoked`：令牌或 accessor 不存在、租约不存在/已过期/不可续租、或令牌因撤销树已被撤销（reason 给出底层原因，如 `token not found`、`lease expired`、`invalid lease ID`）；
  - `audit_failed`：该项的逐项审计写入失败（reason 附带审计错误）；
  - `error`：不支持续租的类型（batch 令牌、JWT）、跨命名空间等确定性错误（reason 给出原因）。
- **FR-4（结果载荷与摘要）**: 每项返回输入位置序号、标识符类型（不回显原始令牌）、`status`、`reason`、`accessor`、`renewable`、`lease_duration`（授予 TTL 秒）、`expire_time`（绝对 RFC3339 时间）；token 类项额外返回 `client_token`，accessor 类项不返回。顶层返回 `requested_total_duration`、`granted_total_duration`、`max_total_duration`、`replayed`、`server_time` 与 `summary`（五个状态的计数 + `total`）。整批除 400/500 外一律以 200 返回，单项失败放在结果数组中。
- **FR-5（幂等账本）**: 服务端按 (命名空间, idempotency_key) 在 token 存储子视图下持久化账本记录（屏障加密、local storage），内容含：调用方绑定（请求令牌的不可逆哈希）、请求指纹（规范化请求体的 SHA-256）、预算、创建时间、惰性过期时间（创建后 24 小时）、每项的终态结果（含绝对 `expire_time` 与授予 TTL）、累计授予总量。
  - 同键重放：校验调用方绑定与请求指纹；不一致返回 400（`idempotency key already used with a different request/caller`）。
  - 命中有效账本时：终结项（success/limit_reached/revoked/error）原样回放，绝不再次调用续租逻辑；`replayed=true`；回放的 `lease_duration`/`expire_time` 为首次执行时持久化的值（绝对时间不随后续时间流逝或时钟差异而变化）。
- **FR-6（部分失败重试与审计失败）**: 逐项审计在续租前后各进行一次（请求事件 / 响应事件）。续租前审计失败：不续租、不扣预算，记 `audit_failed`（可重试）。续租后审计失败：续租已生效，账本如实记录授予量与绝对到期时间并记 `audit_failed`；重试时只补写审计、绝不二次续租，审计恢复后该项转为其真实终态（success/limit_reached）。重试时 `revoked`/`error` 为终态直接回放；此前未执行的项继续执行。
- **FR-7（时钟漂移）**: 所有时间判定使用服务端时钟；预算为相对时长但账本记录绝对到期时间。调用方重试时刻较首次请求延后（或调用方时钟与服务端存在偏差）时，重放结果中的 `expire_time`、授予 TTL 与预算消耗与首次完全一致。处理器的"当前时间"通过可注入的 `now` 函数获取（生产为 `time.Now`），供测试模拟时钟漂移。
- **FR-8（根令牌与子令牌）**:
  - 初始根令牌（TTL=0、策略仅 root、无租约）：`limit_reached` + 根令牌原因，不扣预算；
  - 带 TTL 租约的 root 策略令牌：按普通令牌续租分类；
  - 普通父子令牌：各自独立参与预算与分类；父令牌被撤销树撤销后，非 orphan 子令牌在批量中判 `revoked`；orphan 子令牌仍可 `success`。
- **FR-9（API 客户端）**: `api.TokenAuth` 新增 `RenewBatchWithContext(ctx, *TokenRenewBatchRequest) (*Secret, error)` 及无 context 包装；请求体与 FR-1 对齐，返回的 `Secret.Data` 含 FR-4 的完整结构。
- **FR-10（可观测性）**: 每项状态计入 metrics 计数器（`token.renew_batch.<status>`），审计日志可通过外层请求审计看到整批结果；不改变现有续租 metrics。

## Non-Functional Requirements
- **NFR-1（兼容性）**: 不改变任何既有端点的请求/响应与存储格式；新路径为纯增量；OSS 与 Enterprise 构建均须通过（不破坏 `token_store_util.go` 的 ent 变体）。
- **NFR-2（安全）**: 幂等记录中不得明文存放下发令牌值；token 类项回放所需的 `client_token` 从当次重放请求体取回；存储键与调用方绑定使用盐值/哈希；记录随 token 视图屏障加密；不配置 audit backend 时行为与现有续租一致（审计钩子返回 nil）。
- **NFR-3（一致性）**: 同一 idempotency_key 的并发请求通过 per-key 锁串行化，后来者回放先到者结果；单项续租沿用租约自身的 per-lease 锁。
- **NFR-4（性能）**: 单批最多 100 项；每项至多产生与单次 `renew` 相同量级的存储/路由操作；账本在每项完成后持久化一次。
- **NFR-5（可测试性）**: 当前时间与逐项审计函数均可在包内测试中替换，以确定性地覆盖时钟漂移与审计失败/恢复。
- **NFR-6（代码风格）**: 遵循仓库现有 framework.Path 注册、help 常量、错误分类（logical.ErrorResponse / ErrInvalidRequest）、changelog 与 Go API 客户端约定。

## Constraints
- **Technical**: Go（仓库工具链）；仅使用现有 SDK/framework、BarrierView、locksutil、ExpirationManager、audit.Broker 原语；新代码放在 `vault` 包（可同包访问 expiration 内部）与 `api` 包。
- **Business**: 纯 OSS 可实现、可测试；不依赖 Enterprise 特性。
- **Dependencies**: 复用 `ExpirationManager.RenewToken`、`TokenStore.Lookup/lookupByAccessor`、`framework.CalculateTTL` 的既有截断 warning、`audit.Broker`、BarrierView 存储。

## Assumptions
- `max_total_duration=0` 表示不限制整批预算（向后兼容的缺省语义）。
- 幂等账本保留 24 小时（惰性过期）；过期后同键视为新请求。
- 单项上限 100 项、键长上限 128 字符为合理固定默认值。
- 批量端点不做逐令牌 ACL 差异化判断，与现有 `auth/token/renew` 的信任模型一致。
- accessor 解析得到的 token ID 续租结果在响应中继续抹除 `client_token`（沿用 renew-accessor 行为）。

## Acceptance Criteria

### AC-1: 端点注册与请求校验
- **Type**: `rule`
- **Given**: 已解封的测试 Core 与有效调用令牌
- **When**: 调用 `auth/token/renew-batch`，分别提交：合法批量请求；缺少 `idempotency_key`；`tokens` 为空或超过 100 项；某项同时给 token 和 accessor（或都不给）；项内标识符重复；`max_total_duration` 为负
- **Then**: 合法请求返回 200 且 Data 含 `results`/`summary`；所有非法情形返回 400 逻辑错误且存储中不存在任何账本记录、任何令牌 TTL 均未改变
- **Pass Condition**: 新增测试对上述每种输入断言通过
- **Evidence**: `vault` 包新增测试输出 + 代码检查（路径注册于 token store paths）

### AC-2: 续租预算按序强制且可配置
- **Type**: `rule`
- **Given**: 两个各剩余 1 小时、请求 increment 均为 3600 秒的服务令牌
- **When**: 分别以 `max_total_duration=7200` 与 `3600` 提交同一对令牌（使用不同幂等键）
- **Then**: 7200 时两项 `success`、`granted_total_duration=7200`；3600 时第一项 `success`、第二项 `limit_reached`（reason 含 budget）、第二项续租前的到期时间不变、`granted_total_duration=3600`、摘要计数正确
- **Pass Condition**: 测试断言各项状态、授予总量与第二项到期时间未变
- **Evidence**: `vault` 包测试输出

### AC-3: TTL 上限截断归类为 limit_reached
- **Type**: `rule`
- **Given**: 一个设置了较短 explicit_max_ttl（或构造 issue time 使其接近 max_ttl）的可续租令牌
- **When**: 以明显大于剩余有效窗口的 increment 批量续租
- **Then**: 状态为 `limit_reached`，reason 指明 max_ttl/explicit_max_ttl 截断，授予 TTL 等于剩余有效窗口（±1 秒），该值参与预算扣减
- **Pass Condition**: 测试断言状态、reason 子串与授予 TTL
- **Evidence**: `vault` 包测试输出

### AC-4: 撤销/不存在/过期项归类为 revoked 且不影响其他项
- **Type**: `rule`
- **Given**: 一个有效令牌、一个已撤销令牌、一个不存在的令牌标识
- **When**: 在同一批中续租三者
- **Then**: 有效项 `success`；另两项 `revoked` 且 reason 分别可区分；整批 200；摘要 `success=1, revoked=2`
- **Pass Condition**: 测试断言
- **Evidence**: `vault` 包测试输出

### AC-5: 根令牌与父子/孤儿令牌
- **Type**: `rule`
- **Given**: 初始根令牌（TTL=0 无租约）；一对父子服务令牌；另一对中父令牌被撤销树撤销；一个 orphan 子令牌
- **When**: 批量续租上述令牌
- **Then**: 根令牌为 `limit_reached` 且 reason 表明根令牌不过期、不扣预算；正常父子均 `success`；撤销树后的子令牌为 `revoked`；orphan 子令牌仍 `success`
- **Pass Condition**: 测试断言全部五种情形
- **Evidence**: `vault` 包测试输出

### AC-6: 幂等重放不扩大预算（含时钟漂移）
- **Type**: `rule`
- **Given**: 批量续租成功后的账本记录
- **When**: 用完全相同的请求体与幂等键再次调用，且注入的服务端时钟向前推移 10 分钟；随后再用同键但不同 tokens/budget 调用；另用不同调用方令牌重放
- **Then**: 重放响应 `replayed=true`，每项 `expire_time` 与授予 TTL、`granted_total_duration` 与首次完全一致，令牌租约的持久化到期时间未发生第二次变化；参数不一致返回 400；调用方不一致返回 400
- **Pass Condition**: 测试直接比较两次响应与租约到期时间
- **Evidence**: `vault` 包测试输出（注入时钟）

### AC-7: 审计失败分类与部分失败重试安全
- **Type**: `rule`
- **Given**: 三个令牌；逐项审计钩子被配置为首次对第二项返回错误、之后恢复
- **When**: 首次批量调用；随后用同一幂等键重试至审计恢复
- **Then**: 首次：第 1、3 项 `success`，第 2 项 `audit_failed`（若失败发生在续租前则该项未续租、未扣预算；若发生在续租后则账本记录其授予量），整批 200；重试：第 1、3 项回放且到期时间不变（未二次续租），第 2 项经一次补审计/补执行后成功，`granted_total_duration` 与实际授予总量一致且不超过预算
- **Pass Condition**: 测试分别覆盖续租前/续租后审计失败两种位置，断言重试后无二次续租
- **Evidence**: `vault` 包测试输出（注入审计钩子与调用计数）

### AC-8: API 客户端
- **Type**: `rule`
- **Given**: httptest 模拟 Vault 服务端
- **When**: 调用 `api.TokenAuth.RenewBatchWithContext` 提交预算、幂等键与多项
- **Then**: 请求方法为 PUT、路径 `/v1/auth/token/renew-batch`、JSON 体字段正确；服务端返回的 results/summary 可从 `Secret.Data` 原样读取
- **Pass Condition**: `api` 包 httptest 测试断言
- **Evidence**: `api` 包测试输出

### AC-9: 既有行为无回归
- **Type**: `rule`
- **Given**: 仓库既有测试
- **When**: 运行 `go test ./vault/...`（至少 token_store、expiration 相关用例）与 `go test ./api/...`
- **Then**: 全部通过；`go vet ./vault/... ./api/...` 无告警
- **Pass Condition**: 命令退出码 0
- **Evidence**: 命令输出

### AC-10: 实现与仓库惯例的一致性
- **Type**: `rubric`
- **Dimension**: 代码惯用法契合度（路径注册、错误模型、存储视图、命名、测试夹具复用、changelog）
- **Scale**: 1-5
- **Anchors**: 1 = 另起炉灶或破坏 ent 构建；3 = 功能可用但存在重复逻辑/风格漂移；5 = 自然复用 RenewToken/handleUpdateRenewAccessor/BarrierView/locksutil，审查者认为与既有 token store 代码无割裂感
- **Pass Threshold**: >= 4
- **Evidence**: 独立评审代码走查

## Open Questions
- 无（关键歧义已在 Assumptions 中给出默认决策；如审批阶段有不同取舍可回调 Specify）。
