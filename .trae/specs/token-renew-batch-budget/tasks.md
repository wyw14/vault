# Vault 令牌批量续租预算与结果摘要 - 实施计划

## Task 1: 新文件骨架、端点注册与请求校验
- **Status**: `completed`
- **Priority**: high
- **Depends On**: None
- **Description**:
  - 新建 `vault/token_renew_batch.go`：状态常量（`renewBatchStatusSuccess/LimitReached/Revoked/AuditFailed/Error`）、请求/响应/账本结构体、`renew-batch$` 路径字段（`idempotency_key` TypeString、`max_total_duration` TypeDurationSecond、`tokens` TypeSlice）与 help 常量。
  - 在 [token_store.go paths()](file:///e:/swe-like/runs/hashicorp--vault/a0b7a503f721/precheck-3623/vault/token_store.go#L554-L612) 注册路径（UpdateOperation 回调 `handleRenewBatch`）；`PathsSpecial.LocalStorage` 增加账本前缀；TokenStore 增加 `renewBatchLocks`（locksutil）与可注入字段 `renewBatchNow func() time.Time`、`renewBatchAuditor func(...) error`，并在 NewTokenStore 初始化默认实现。
  - 实现请求解析与校验：键必填/长度、1–100 项、每项恰好 token|accessor、increment 经 parseutil 解析、项内不重复、预算非负；非法一律 `logical.ErrorResponse` + `logical.ErrInvalidRequest`（framework 字段级校验返回 error 响应）且无副作用。
  - 账本存储视图经 `ts.baseView(ns).SubView(renewBatchPrefix)` 派生（兼容 ent 变体）；存储键为命名空间内 SHA-256(idempotency_key)；记录 TTL 24h 惰性过期。
- **Acceptance Criteria Addressed**: AC-1, AC-10
- **Test Requirements**:
  - `rule` TR-1.1: 以 table-driven 测试调用 `ts.HandleRequest` 覆盖全部非法输入（缺键/空数组/超 100 项/同时给 token 与 accessor/都不给/重复标识符/负预算/错误 increment 类型），均返回逻辑错误响应且账本视图无任何键。
  - `rule` TR-1.2: 路径出现在 token store 的 Paths()/OpenAPI 中（`HandleRequest` 对合法骨架请求不报"unsupported path"）。
  - `rule` TR-1.3: OSS 构建通过：`go build ./vault/... ./api/...`。
- **Completion Evidence**:
  - TR-1.1: `TestTokenStore_RenewBatch_Validation` 10 个子用例全部 PASS（test-run-2.log），末尾断言账本视图零键。
  - TR-1.2: 全部 `TestTokenStore_RenewBatch*` 经 `ts.HandleRequest(..., "renew-batch")` 正常路由，证明路径注册生效。
  - TR-1.3: `go build ./vault/` 无输出（成功）；api 模块经独立模块构建/测试通过。

## Task 2: 幂等预算账本（持久化、指纹、调用方绑定、重放）
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 1
- **Description**:
  - 实现 `renewBatchRecord`/`renewBatchItemRecord` 的 JSON 持久化（经 BarrierView，jsonutil），字段：salted key、调用方令牌 SHA-256 绑定、规范化请求指纹（max_total_duration + 每项 kind/输入哈希/increment 的 SHA-256）、CreatedTime、ExpireTime(+24h)、GrantedTotal、每项 status/reason/grantedTTL/绝对 ExpireTime/accessor/renewable/kind。
  - per-key 锁（locksutil）保证并发同键串行：先到者创建 pending 记录并执行；后到者等待后读取终态记录回放。
  - 命中有效记录：校验调用方绑定与指纹，不一致返回 400；终结项原样回放（含首次绝对到期时间），`replayed=true`；过期记录删除后按新请求处理。
  - `now` 一律走 `ts.renewBatchNow`（默认 time.Now），账本持久化绝对时间。
  - 指纹/绑定 helper 为纯函数，便于单测。
- **Acceptance Criteria Addressed**: AC-6, AC-7（重试的账本部分）, AC-10
- **Test Requirements**:
  - `rule` TR-2.1: 相同键+相同请求执行两次，第二次响应与持久化记录逐项一致且执行器只被调用一次（以调用计数桩证明）。
  - `rule` TR-2.2: 同键不同请求体（不同 budget/tokens/increment）→ 400；同键不同调用方令牌 → 400。
  - `rule` TR-2.3: 注入时钟将 now 推进超过记录 TTL，同键请求被当作新请求；未超过 TTL 且推进 10 分钟时回放结果中的绝对 expire_time 不变。
  - `rule` TR-2.4: 两个 goroutine 同键并发只产生一次执行与一条存储记录（race 测试，`go test -race` 该用例）。
- **Completion Evidence**:
  - TR-2.1/2.2/2.3: `TestTokenStore_RenewBatch_IdempotentReplay` PASS——重放响应逐字段相等、granted_total 不增长、租约到期时间不变、异参/异调用方均 400、24h 后重新执行（replayed=false）。
  - TR-2.4: `TestTokenStore_RenewBatch_ConcurrentSameKey` 在 `go test -race` 下 PASS：恰一次 replayed、两响应到期时间一致、存储仅一条记录。

## Task 3: 逐项执行器：预算扣减与五类状态分类（success/limit/revoked/error，含根/子/orphan/accessor）
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 2
- **Description**:
  - 单项解析：token 类直接 `ts.Lookup`；accessor 类 `lookupByAccessor` 解析 token ID（不存在 → revoked，原因 invalid accessor）。
  - 根令牌判定：`te` 策略仅 root 且 TTL=0 时，经 expiration 计算 leaseID 并 `loadEntry`；无租约或 ExpireTime 零值 → `limit_reached`（root token does not expire and cannot be renewed），不扣预算；存在有效租约则继续普通续租。
  - 预算门控（FR-2）：increment=0 时经 `MatchingSystemView(te.Path)` 取 DefaultLeaseTTL 作为期望值；剩余预算为 0 → 不续租直接 `limit_reached`（budget exhausted）；期望值大于剩余 → 以剩余秒作为续租增量并标记 budget 截断。
  - 续租执行：token 类复用 `ts.expiration.RenewToken(ctx, req, te, effIncrement)`；按返回区分：ErrInvalidRequest 配逻辑错误响应时取响应消息，"not found/expired/not renewable/invalid lease" → `revoked`（reason 透传底层消息）；"batch tokens cannot be renewed"/"JWTs cannot be renewed" → `error`；其他内部错误 → `error`。
  - 截断识别：续租成功后，若响应带 max_ttl capped warning 或授予 TTL < 期望增量 → `limit_reached`（原因区分 budget 与 TTL 上限）；否则 `success`；以响应 Auth.TTL 扣减预算，记录绝对 ExpireTime。
  - accessor 项响应抹除 client_token（沿用 renew-accessor 语义）；结果项字段按 FR-4 组装；顶层组装 requested/granted/summary/server_time。
  - 每处理完一项更新并持久化账本（pending→终态）。
  - metrics：`token/renew_batch/<status>` 计数。
- **Acceptance Criteria Addressed**: AC-2, AC-3, AC-4, AC-5, FR-10
- **Test Requirements**:
  - `rule` TR-3.1: 预算 7200/3600 两场景（AC-2 全断言：状态、granted_total、被预算阻止项的到期时间前后相等）。
  - `rule` TR-3.2: 手工构造接近 explicit_max_ttl 上限的 leaseEntry（同包直接写 issue/expire/auth 字段并 persistEntry），续租大增量 → `limit_reached` 且 reason 含 max_ttl，授予 TTL≈剩余窗口（±1s）。
  - `rule` TR-3.3: 有效 + 已撤销 + 不存在标识同批 → success=1/revoked=2/3，reason 可区分，HTTP 200。
  - `rule` TR-3.4: AC-5 五情形（初始根令牌、带租约 root 策略令牌、父子、撤销树后子令牌、orphan 子令牌）状态与预算扣减断言。
  - `rule` TR-3.5: batch 令牌项 → `error`；accessor 项成功且结果不含 client_token；无效 accessor → `revoked`。
  - `rule` TR-3.6: 摘要计数、granted_total、requested_total、结果顺序与输入顺序一致。
- **Completion Evidence**:
  - TR-3.1: `TestTokenStore_RenewBatch_Budget` PASS（含被阻止项 ExpireTime 相等断言）。
  - TR-3.2: `TestTokenStore_RenewBatch_TTLLimit` PASS（回拨 issue time 3595s，授予 3–7s，reason 含 max_ttl）。
  - TR-3.3: `TestTokenStore_RenewBatch_Revoked` PASS（not-found 与 not-renewable 原因可区分，success=1/revoked=3）。
  - TR-3.4: `TestTokenStore_RenewBatch_RootAndChildren` PASS（根 limit_reached 不扣预算、父子成功、撤销树后 revoked、orphan 存活，granted=180）。
  - TR-3.5/3.6: `TestTokenStore_RenewBatch_Accessor` PASS（含直接构造 batch 令牌→error）；各测试断言 summary 与 index 顺序。

## Task 4: 逐项审计钩子与 audit_failed 重试语义
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 3
- **Description**:
  - TokenStore 默认审计实现：续租前 `core.auditBroker.LogRequest`，续租后 `LogResponse`（未配置 backend 时 nil）；处理器经可替换字段 `renewBatchAuditor` 调用，签名含 phase（pre/post）、单项输入与 auth。
  - pre 审计失败：不续租、不扣预算，账本记 `audit_failed`（GrantedTTL=0，可重试）。
  - post 审计失败：续租已生效，账本记录授予量与绝对到期时间、状态 `audit_failed`；重放/重试时仅重放审计调用（不调用 RenewToken），成功后落为真实终态。
  - 重试时终结态直接回放；pending/audit_failed 按规则继续；granted_total 以账本累计授予为准，不因重试增长。
- **Acceptance Criteria Addressed**: AC-7, AC-6
- **Test Requirements**:
  - `rule` TR-4.1: pre 审计失败注入：首次 success/audit_failed/success，失败项未续租未扣预算；同键重试后 1、3 项到期时间不变、第 2 项成功；计数桩证明 1、3 项只续租一次。
  - `rule` TR-4.2: post 审计失败注入：首次 audit_failed 但账本记录授予 TTL/到期时间；重试仅补审计成功，租约到期时间不变、总授予量不变。
  - `rule` TR-4.3: 未配置 audit backend 的默认 Core 下批量续租全部 success。
- **Completion Evidence**:
  - TR-4.1: `TestTokenStore_RenewBatch_AuditFailurePreRenew` PASS（预算 180：首 120、重试 180；terminal 项 post 审计计数=1）。
  - TR-4.2: `TestTokenStore_RenewBatch_AuditFailurePostRenew` PASS（首次已扣 180；post 计数 2 但到期时间不变，证明无二次续租）。
  - TR-4.3: 其余全部新测试均运行在未配置 audit backend 的默认 Core 上且成功（默认钩子走 broker no-op 路径）。
  - 组合链路：`TestTokenStore_RenewBatch_PartialFailureClockDriftRetry` PASS（revoked+审计失败+success，时钟推进 10min/1h 三次调用，granted 60→120→120 稳定）。

## Task 5: Go API 客户端
- **Status**: `completed`
- **Priority**: medium
- **Depends On**: Task 1
- **Description**:
  - 在 [api/auth_token.go](file:///e:/swe-like/runs/hashicorp--vault/a0b7a503f721/precheck-3623/api/auth_token.go#L179-L207) 增加 `TokenRenewBatchItem`、`TokenRenewBatchRequest`、`RenewBatch`、`RenewBatchWithContext`；PUT `/v1/auth/token/renew-batch`，返回 `*Secret`。
- **Acceptance Criteria Addressed**: AC-8
- **Test Requirements**:
  - `rule` TR-5.1: httptest 测试断言方法/路径/JSON 字段，并回送夹具响应，断言 `Secret.Data["results"]/["summary"]/["granted_total_duration"]`。
  - `rule` TR-5.2: api 模块编译与 vet 无新增告警。
- **Completion Evidence**:
  - TR-5.1: `api` 模块 `TestTokenAuth_RenewBatch` PASS（PUT、路径、idempotency_key/max_total_duration/tokens 体字段、omitempty、json.Number 结果断言）。
  - TR-5.2: api 模块 `go test` 编译通过；`go vet ./` 仅报告既有的 client.go/client_test.go 问题，auth_token*.go 零告警。

## Task 6: 端到端场景测试与回归
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 4, Task 5
- **Description**:
  - 新建 [vault/token_renew_batch_test.go](file:///e:/swe-like/runs/hashicorp--vault/a0b7a503f721/precheck-3623/vault/token_renew_batch_test.go)：12 个测试（10 个 table 子用例 + 11 个场景），覆盖校验、预算、TTL 上限、撤销/不可续租/不存在、根/父子/orphan、幂等重放+时钟漂移、pre/post 审计失败重试、组合部分失败链路、accessor/batch、账本无明文、100 项边界、同键并发。
  - 账本前缀已加入 `PathsSpecial.LocalStorage`；存储 JSON 不含明文令牌测试通过。
  - 新测试 `-race` 通过；既有 token_store/expiration 套件回归。
- **Acceptance Criteria Addressed**: AC-6, AC-7, AC-9, NFR-2
- **Test Requirements**:
  - `rule` TR-6.1: 组合链路测试（部分失败+时钟推进+重试+再重放）。
  - `rule` TR-6.2: 扫描账本存储不含明文令牌。
  - `rule` TR-6.3: `go test ./vault/ -run 'TestTokenStore|TestExpiration'` 退出码 0；新增全部用例 `-race` 通过。
- **Completion Evidence**:
  - TR-6.1: `TestTokenStore_RenewBatch_PartialFailureClockDriftRetry` PASS。
  - TR-6.2: `TestTokenStore_RenewBatch_NoPlaintextInLedger` PASS（成功项响应回显 client_token，但持久化记录 grep 不到明文）。
  - TR-6.3: `go test ./vault/ -run 'TestTokenStore|TestExpiration'` 88.4s，仅 `TestExpiration_Metrics` 失败；经 `git stash` 在未改动原始树上复现同样失败（metrics sink 环境性问题），与本次改动无关。`go test ./vault/ -run TestTokenStore_RenewBatch -race` PASS（3.2s）。

## Task 7: Changelog、格式化与全量验证
- **Status**: `completed`
- **Priority**: low
- **Depends On**: Task 6
- **Description**:
  - 新增 `changelog/13409.txt`（`release-note:feature`）。
  - `gofmt -w` 全部新增/修改文件；`go build`、`go vet`（新文件零告警）。
- **Acceptance Criteria Addressed**: AC-9, AC-10
- **Test Requirements**:
  - `rule` TR-7.1: changelog 格式符合现有条目。
  - `rule` TR-7.2: vet、新增包测试全绿。
- **Completion Evidence**:
  - TR-7.1: `changelog/13409.txt` 使用 ```release-note:feature 围栏，格式对照 `changelog/13408.txt` 等现有条目。
  - TR-7.2: `gofmt -l` 对 5 个变更文件零输出；`go build ./vault/` 通过；`go vet ./vault/` 输出不含 token_renew_batch（既有 unkeyed-fields 告警与本改动无关）；新测试全部通过。

---

## Issue I-1: post 审计失败恢复后丢失 limit_reached 的 reason（Review R1 / F1）
- **Status**: `completed`
- **Priority**: medium
- **Depends On**: Task 4
- **Discovered By**: Review R1
- **Description**:
  - 被 budget/TTL 截断的续租（真实终态 limit_reached）若 post-renewal 审计失败，executeRenewBatchItem 以审计文案覆盖 Reason 且未持久化截断 reason；recoverPostAudit 成功落定时无条件 `Reason=""`，导致重试恢复后返回 `limit_reached` + 空 reason，违反 FR-3/FR-4。
  - 修复：`renewBatchItemRecord` 增加 `FinalReason string json:"final_reason,omitempty"`；post 失败分支持久化 FinalStatus + FinalReason；recoverPostAudit 落定时 `Reason = FinalReason` 并清空 Final*；新增"截断续租 + post 审计失败 + 同键重试"回归测试（max_ttl 截断），断言恢复后 reason 仍含截断来源。
- **Acceptance Criteria Addressed**: AC-7, AC-3
- **Test Requirements**:
  - `rule` TR-I-1.1: 接近 explicit_max_ttl 上限的令牌在 post 审计首次失败、重试恢复后，状态为 limit_reached 且 reason 非空并包含 "max_ttl"；granted/expire 不发生二次续租。
- **Completion Evidence**:
  - 账本结构新增 `FinalReason`；post 失败分支持久化 FinalStatus+FinalReason；recoverPostAudit 落定时 `Reason=FinalReason` 并清空 Final*；setResult 统一清空 Final*。
  - TR-I-1.1: `TestTokenStore_RenewBatch_LimitReasonSurvivesAuditRecovery` PASS（首次 audit_failed 且携带授予量；同键重试后 limit_reached 且 reason 含 max_ttl、lease_duration>0），见 test-run-3.log；全套 16 测试 -race 通过。

## Issue I-2: 账本持久化失败静默成功与损坏记录的防御性处理（Review R1 / F2+F4）
- **Status**: `completed`
- **Priority**: medium
- **Depends On**: Task 2
- **Discovered By**: Review R1
- **Description**:
  - 单项账本 Put 失败仅记日志仍返回 200，存储故障下重试可能二次续租；改为硬错误（返回错误响应），避免静默成功。
  - 账本 decode 失败/Items 长度与请求不一致时增加防御：decode 失败删除损坏的派生记录并返回逻辑错误（要求换新幂等键）；长度不匹配返回 400 而不是越界。
- **Acceptance Criteria Addressed**: AC-6, AC-7
- **Test Requirements**:
  - `rule` TR-I-2.1: 注入失败的 storage view（Put 返回错误）时批量请求返回错误而非 200。
  - `rule` TR-I-2.2: 手工写入损坏/截断的账本记录后，同键请求返回错误且不 panic、不发生续租。
- **Completion Evidence**:
  - executeRenewBatchItem/recoverPostAudit 改为返回 error；setResult 与各持久化点失败即向上返回（初始记录 Put 本就失败即 500）；decode 失败删除损坏派生记录并经 `errRenewBatchRecordCorrupt` 映射为 400 逻辑错误；Items 长度与请求不一致返回 400（长度守卫先于索引访问）。
  - TR-I-2.1: `TestTokenStore_RenewBatch_LedgerWriteFailure` PASS（failingRenewBatchStorage 注入，err 非空）。
  - TR-I-2.2: `TestTokenStore_RenewBatch_CorruptRecord` PASS（坏 JSON→400 且记录被清理；指纹/调用方匹配但 Items 截断→400，recover 保护无 panic）。

## Issue I-3: 测试缺口补齐与死代码清理（Review R1 / F3+F5）
- **Status**: `completed`
- **Priority**: low
- **Depends On**: Task 6
- **Discovered By**: Review R1
- **Description**:
  - 删除未被调用的 `allTerminal()` 死代码。
  - 增加用例：带 TTL 租约的 root 策略令牌在批量端点按普通令牌 success；increment 为负值的单项被 400 拒绝。
- **Acceptance Criteria Addressed**: AC-5, AC-1
- **Test Requirements**:
  - `rule` TR-I-3.1: 两个新断言通过；`allTerminal` 全仓无引用。
- **Completion Evidence**:
  - `allTerminal()` 已删除（`Select-String vault\*.go allTerminal` 零命中）；校验表新增 negative_increment 子用例（PASS）。
  - TR-I-3.1: `TestTokenStore_RenewBatch_RootTokenWithLease` PASS（初始 root→limit_reached，带 1h 租约的 root 策略令牌→success）；`TestTokenStore_RenewBatch_Validation/negative_increment` PASS。
