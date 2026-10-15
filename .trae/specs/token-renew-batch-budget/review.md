# Vault 令牌批量续租预算与结果摘要 - Independent Review

- [x] CP-R1: 端点注册与请求校验（AC-1）
  - **Type**: `rule`
  - **Covers**: AC-1 / TR-1.*
  - **Evidence**: R1/R2 pass；token_store.go:581-612 注册路径；TestTokenStore_RenewBatch_Validation 11 子用例（含负 increment）PASS，拒绝后账本视图零键。

- [x] CP-R2: 批量续租预算按序强制（AC-2）
  - **Type**: `rule`
  - **Covers**: AC-2 / TR-3.1
  - **Evidence**: R1/R2 pass；token_renew_batch.go 预算门控在审计/续租之前 return；TestTokenStore_RenewBatch_Budget 断言被阻止项 ExpireTime 前后相等、granted=3600/7200。

- [x] CP-R3: TTL 上限截断归类与原因（AC-3）
  - **Type**: `rule`
  - **Covers**: AC-3 / TR-3.2
  - **Evidence**: R1/R2 pass；classifyRenewalOutcome 识别 CalculateTTL capped warning；TestTokenStore_RenewBatch_TTLLimit（回拨 issue 3595s，授予 3–7s，reason 含 max_ttl）。

- [x] CP-R4: 撤销/不存在/不可续租逐项分类（AC-4）
  - **Type**: `rule`
  - **Covers**: AC-4 / TR-3.3
  - **Evidence**: R1/R2 pass；ErrInvalidRequest 分支优先取 resp.Data["error"]；TestTokenStore_RenewBatch_Revoked（success=1/revoked=3，原因可区分）。

- [x] CP-R5: 根令牌、父子、撤销树、orphan（AC-5）
  - **Type**: `rule`
  - **Covers**: AC-5 / TR-3.4
  - **Evidence**: R1/R2 pass；isNonexpiringRoot/tokenLeaseEntry；TestTokenStore_RenewBatch_RootAndChildren 与 I-3 新增 RootTokenWithLease（带租约 root→success）。

- [x] CP-R6: 幂等重放不扩大预算、时钟漂移、指纹/调用方绑定（AC-6）
  - **Type**: `rule`
  - **Covers**: AC-6 / TR-2.*
  - **Evidence**: R1/R2 pass；IdempotentReplay（+10min 漂移逐字段相等、+25h 过期重执行、异参/异调用方 400）、ConcurrentSameKey（-race，恰一次 replayed、单条记录）。

- [x] CP-R7: 审计失败分类与部分失败重试安全（AC-7）
  - **Type**: `rule`
  - **Covers**: AC-7 / TR-4.*、TR-6.1
  - **Evidence**: R2 重点复审 pass；pre/post 两位置审计失败用例 + PartialFailureClockDriftRetry（granted 60→120→120）；F1 修复由 LimitReasonSurvivesAuditRecovery 锁定（截断 reason 跨审计恢复保留）。

- [x] CP-R8: Go API 客户端（AC-8）
  - **Type**: `rule`
  - **Covers**: AC-8 / TR-5.*
  - **Evidence**: R1/R2 pass；api TestTokenAuth_RenewBatch（PUT/路径/JSON/omitempty/Secret.Data）。

- [x] CP-R9: 既有行为无回归、构建/格式化（AC-9）
  - **Type**: `rule`
  - **Covers**: AC-9 / TR-6.3、TR-7.*
  - **Evidence**: 17 个新测试 PASS、-race 干净；TestTokenStore_HandleRequest_Renew/RenewAccessor/RootToken 既有用例 PASS；TestTokenStore|TestExpiration 全套仅 TestExpiration_Metrics 失败，已在原始树 stash 复现为既有环境问题；gofmt 干净；vet 新文件零告警。

- [x] CP-R10: 存储安全与 Enterprise 兼容（NFR-1/NFR-2）
  - **Type**: `rule`
  - **Covers**: NFR-1、NFR-2 / TR-6.2
  - **Evidence**: 账本结构仅哈希不含明文令牌（NoPlaintextInLedger）；client_token 回放取自当次请求；视图经 ts.baseView(ns).SubView 派生兼容 ent；renew-batch/ 已注册 LocalStorage。

- [x] CP-U1: 代码与仓库惯例一致性（AC-10）
  - **Type**: `rubric`
  - **Covers**: AC-10
  - **Scale**: 1-5
  - **Anchors**: 1 = 另起炉灶或破坏 ent 构建；3 = 功能可用但存在重复逻辑/风格漂移；5 = 自然复用 RenewToken/handleUpdateRenewAccessor/BarrierView/locksutil，与既有 token store 无割裂感
  - **Pass Threshold**: >= 4
  - **Evidence**: R1=4；R2=4（自然复用既有续租/审计/存储原语，纯增量；扣分项仅为不可达的极端健壮性打磨空间）。

## Review History

### Review R1
- **Result**: `fail`（窄口径：所有检查点通过，1 条 actionable）
- **Evidence**:
  - CP-R1..CP-R10：`pass`（13 个 vault 新测试 + api httptest 全绿、-race 干净、既有 TestTokenStore/TestExpiration 仅既有环境失败 TestExpiration_Metrics，经 stash 在原始树复现）。
  - CP-U1：4/5（风格高度契合，扣分项为死代码 allTerminal、持久化失败静默、post-audit 恢复 reason 丢失）。
  - Findings：
    - F1（actionable，P3）：post 审计失败恢复后丢失 limit_reached reason → 已物化为 Issue I-1。
    - F2（advisory）：账本持久化失败静默 200 → 已物化为 Issue I-2。
    - F3（advisory）：root-with-lease/负 increment 覆盖缺口、F4 损坏记录防御、F5 死代码 → I-2/I-3。
  - 对抗性走查结论：存储正常前提下，未发现任何可扩大预算或二次续租的输入序列。
- **Blocked By**: 无（环境性 TestExpiration_Metrics 与本改动无关）

### Review R2
- **Result**: `pass`
- **Evidence**:
  - 全新上下文独立复跑：17/17 新测试 PASS、`-race` 0 报警、api TestTokenAuth_RenewBatch PASS、既有续租相关用例 PASS、构建与 gofmt 干净、新文件 vet 零告警、仓库无残留。
  - F1/F2/F3/F4/F5 全部独立验证 fixed：FinalReason 三截断路径保留、5 个持久化点错误上返（无静默 200）、损坏记录删除+400 与长度/nil 守卫、死代码清除、root-with-lease 与负 increment 覆盖补齐。
  - 对 8 种账本状态重新推演执行循环：存储健康前提下无任何二次续租/预算扩大路径。
  - 无 actionable；4 条 advisory（A1 已在评审后顺手加固 nil 守卫并复跑全绿；A2 client_token 仅 GrantedTTL>0 回显为保守语义；A3 无盐哈希符合 NFR"盐值/哈希"且屏障加密；A4 提交窗口为分布式固有限制，F2 已显式 500）。
