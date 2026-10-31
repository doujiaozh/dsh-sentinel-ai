# Sentinel-AI

> **Sentinel-AI：用 System 1 拦截风险，用 System 2 洞察漏洞，用状态机对抗时间的熵增。**
>
> *Sentinel-AI: System 1 to intercept risk, System 2 to see through vulnerabilities, a state machine to fight the entropy of time.*

一套**双系统异步代码审查流水线**：深度融合 Open Code Review (OCR) 的深度审查、Jev 的 System 1 极速决策，以及 Redis 风格的异步超时状态机。高并发、防阻塞、零幻觉。

A **dual-system async code review pipeline** fusing Open Code Review (OCR)-style deep review, Jev-style System 1 millisecond routing, and a Redis-style async timeout state machine. Concurrent, non-blocking, hallucination-resistant.

---

## 架构融合图 / Architecture

```
                    GitHub Webhook (diff / push payload)
                              │
                              ▼
        ┌─────────────────────────────────────────────────────┐
        │            sentinel_gate  ·  System 1 (Jev)          │
        │  纯启发式规则，<1ms 裁决，可选 Jev API 升级            │
        │  Choice: trivial | security_risk | full_review      │
        │  Noul:   maliciousObfuscation | hardcodedSecrets    │
        └───────┬───────────────┬───────────────┬─────────────┘
                │               │               │
        trivial │               │ security_risk │ full_review
        (跳过)   │               │ (强制人工)     │ (深度审查)
                ▼               ▼               ▼
           status=         status=       ┌─────────────────────────────┐
           skipped         skipped       │  sentinel_state · 状态机     │
                                        │  submit() → TaskID（立即返回）│
                                        │  TTL 看门狗 + 幂等锁 + 墓碑   │
                                        └──────────┬──────────────────┘
                                                   │ AbortController
                                                   ▼
                          ┌──────────────────────────────────────────┐
                          │      sentinel_reviewer · System 2 (OCR)  │
                          │  Pass 1: @babel/parser 确定性 AST 校验    │
                          │  Pass 2: LLM 审查（可被看门狗中止）        │
                          │  Pass 3: 防幻觉投影（行号漂移/空行/注释）  │
                          └────────────────────┬─────────────────────┘
                                               │
                                               ▼
                                     TaskStatus 终态落地
                          succeeded | timeout | failed | skipped
                                               │
                                               ▼
                                     SentinelReport JSON
                  (gate 裁决 / 状态轨迹 / findings / final decision)
```

**三系统如何咬合 / How the three systems interlock**

- **System 1（gate）是闸门**：毫秒级分流，恶意混淆与硬编码秘钥永远不接触 LLM，直接 escalate。
- **System 2（reviewer）是大脑**：AST 确定性校验给出不可伪造的行号，LLM 只做增量解读，防幻觉层把任何"漂移到空行/注释/不存在行"的结论当场丢弃。
- **状态机是对抗时间熵增的那层**：提交即返回 TaskID，TTL 看门狗超时即 `timeout` + 释放 payload（防 OOM），幂等锁防重复审查，终态墓碑让重放的 webhook 命中缓存。

---

## 快速开始 / Quick Start

```bash
npm install          # 纯 Node.js + TypeScript，零原生模块
npm test             # 构建 + 11 项烟测（含超时/幻觉/幂等路径）
npm run demo         # 三场景演示：trivial / security_risk / full_review
npm run demo:slow-llm   # 演示 TTL 看门狗：LLM 挂死 → 强制 timeout
npm run demo:llm-error  # 演示降级：LLM 503 → AST-only 审查 + degraded 标记
```

### CLI 用法 / CLI

```bash
# 模拟 GitHub Webhook 收到提交，跑完整流水线
sentinel demo [--out report.json] [--simulate llm-slow|llm-error] [--ttl 3000]

# 审查真实 diff 文件
sentinel review --diff ./my.patch --key repo@sha123 [--out report.json]

# 只跑 System 1 毫秒级裁决
sentinel gate --diff ./my.patch
```

### 编程式用法 / Programmatic

```ts
import { runPipeline } from 'dsh-sentinel-ai';

const report = await runPipeline({
  diff: unifiedDiffText,     // unified diff
  key: 'acme/payments@abc123', // 幂等键（仓库@commit）
  ttlMs: 30 * 60 * 1000,     // 超时阈值，默认 30 分钟
});
// report.gate.choice / report.state.status / report.review.findings / report.final
```

---

## 各模块设计 / Modules

### sentinel_gate — System 1 极速路由（Jev 风格）

不调用大模型，纯文本规则扫描（正则 + 熵分析）：< 1ms 出结果。

- **Choice**：`trivial`（跳过）/ `security_risk`（强制人工）/ `full_review`（深度审查）
- **Noul**：`maliciousObfuscation`（eval(atob)、new Function、_0x 标识符……）/ `hardcodedSecrets`（password 赋值、AKIA、ghp_、私钥块、JWT、高熵字面量……）
- **Score**：0–100 加权风险分 + 0–1 置信度
- 配置 `SENTINEL_JEV_URL` 后走真实 Jev API（2s 超时），失败静默降级启发式；双引擎"danger wins"——任一判险即 `security_risk`。
- **设计原则**：文本模式没命中 ≠ 安全。含真实代码且非 trivial 的改动一律 `full_review`，把"未知"交给 System 2。

### sentinel_reviewer — System 2 深度审查（OCR 风格）

三段流水线，LLM 永远在确定性检查之后：

1. **Pass 1 — AST 确定性校验**（`@babel/parser`，纯 JS）：只解析 diff 的 added 行，规则包括 `ast-sql-concat`（SQL 拼接注入）、`ast-dynamic-exec`（child_process 动态命令）、`ast-eval`、`ast-function-constructor`、`ast-high-entropy-literal`、`ast-obfuscated-identifier` 等。**行号从构造上真实**——diff 行号映射，不存在漂移。
2. **Pass 2 — LLM 审查**：OpenAI 兼容 API（`SENTINEL_LLM_BASE_URL`），`temperature: 0`，系统提示强约束"只引用变更行、返回严格 JSON"。未配置时走确定性 Mock（会故意制造两类幻觉用于演练防幻觉层）。支持 `AbortSignal`——看门狗超时能在途中掐断调用。
3. **Pass 3 — 防幻觉投影**：LLM 与 AST 的 findings 统一过 `filterHallucinatedFindings`，丢弃四类：未知文件、超出改动范围（位置漂移）、空行、注释行。`hallucinatedDropped` 计数写进报告，对人透明。

降级策略：LLM 报错（非中止）→ 任务仍 `succeeded`，review 标 `degraded: true` 并附加 `llm-degraded` finding——确定性 AST 裁决照常产出，不因 API 抽风丢失审查。

### sentinel_state — Redis 异步超时状态机

- **立即返回**：`submit()` 异步入队，马上拿到 TaskID，不阻塞 Webhook。
- **六态流转**：`queued → in_progress → succeeded | timeout | failed | skipped`；非法流转直接抛错。
- **TTL 看门狗**：默认 30 分钟，到期强制 `timeout` 并**释放 payload**（`purged: true`）——防内存 OOM 的关键设计。
- **幂等性**：`lock:` 前缀 + `SET NX TTL` 分布式锁语义，同一个 commit 的重复 webhook 复用同一任务。
- **墓碑机制**：终态后锁续期为墓碑（默认 60 分钟），重放同一 commit 直接读缓存裁决，不重审。
- **双模式存储**：`SENTINEL_REDIS_URL` 配置且 Redis 可达 → ioredis（**optionalDependencies**，按需 require，缺失自动降级）；否则内存 Map（自带 TTL + 容量淘汰）。**Win7 零原生模块红线下的优雅降级**。

### sentinel_cli — 流水线演示

模拟 GitHub Webhook 接收代码提交：接收 Diff → Jev 毫秒级分类 → 深度审查 → 状态机流转（成功/超时）→ 输出审查报告 JSON。内置三个示例 patch（`examples/`）：纯文档 typo、恶意混淆 + 硬编码密码、SQL 注入 + 命令注入的真实重构。

---

## 环境变量 / Configuration

| 变量 | 作用 | 默认 |
|---|---|---|
| `SENTINEL_REDIS_URL` | Redis 连接（不配则内存模式） | — |
| `SENTINEL_LLM_BASE_URL` | OpenAI 兼容 LLM 端点 | Mock |
| `SENTINEL_LLM_API_KEY` / `SENTINEL_LLM_MODEL` | LLM 凭据 / 模型 | — |
| `SENTINEL_JEV_URL` / `SENTINEL_JEV_API_KEY` | Jev System 1 API | 启发式 |
| `SENTINEL_TTL_MS` | 任务超时阈值 | 1800000 (30min) |
| `SENTINEL_LLM_SIMULATE` | 演示用：`llm-slow` / `llm-error` | — |

---

## 约束与红线 / Constraints

- 宿主 Windows 7 / 8G RAM：**零原生 C++ 模块**。ioredis 为 optionalDependencies，缺失即降级。
- 纯 Node.js + TypeScript（target ES2022），解析层 `@babel/parser`（纯 JS）。
- 幻觉零容忍：任何不能锚定到真实变更代码行的 LLM 结论一律丢弃并计数。

## 许可证 / License

MIT
