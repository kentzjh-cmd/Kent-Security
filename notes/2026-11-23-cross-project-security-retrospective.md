---
title: 跨项目安全成果盘点与方法论沉淀（脱敏版）
date: 2026-11-23
tags: [meta, ai-security, supply-chain, sec-eng]
status: published
confidence: verified
---

## 一句话结论

近期在不同开源与工程项目上的安全实践，本质上围绕三条主线收敛：**云基础设施合规基线工程化**、**AI/Agent 运行时与语义层攻防**、以及**东西向与自动化防御闭环**。

## 触发点

在建立本安全研究笔记本时，有必要先对散落在多个仓库与本地草稿中的近期安全产出做一次系统性盘点与脱敏归档，作为后续深入拆解具体漏洞、架构权衡与工程实现的索引基线。

## 成果盘点（已脱敏）

### 1. 云安全合规与 CSPM（`prowler-cloud/prowler`）

围绕主流公有云缺失的基线检查能力，在 Prowler 中补齐了 **HuaweiCloud** 两大批次的安全合规检查项（含服务层封装、元数据定义及完整单元测试）：

- **OBS 对象存储安全检查（5 项，PR #13509，Open）**
  - `obs_bucket_acl_everyone_access`：公网 / 全员 ACL 访问风险检测
  - `obs_bucket_cors_wildcard_origin`：CORS 通配符来源配置检测
  - `obs_bucket_event_notification_enabled`：存储桶事件通知启用检测
  - `obs_bucket_multi_az_redundancy`：多可用区冗余配置检测
  - `obs_bucket_object_lock`：对象锁（WORM 防篡改）合规检测
- **Tier-1 核心云服务安全检查（10 项，PR #13510，Open）**
  - **CTS（云审计）**：日志文件完整性校验（`cts_tracker_file_validation_enabled`）、LTS 日志转储（`cts_tracker_lts_enabled`）、OBS 加密转储（`cts_tracker_obs_encryption_enabled`）
  - **IAM（身份与访问管理）**：90 天访问密钥轮换（`iam_user_access_key_rotation_90_days`）、多访问密钥冗余检测（`iam_user_multiple_access_keys`）
  - **RDS（关系型数据库）**：多可用区高可用（`rds_instance_multi_az_enabled`）、SSL 传输加密启用（`rds_instance_ssl_enabled`）
  - **VPC（虚拟私有云）**：VPC 流日志启用检测（`vpc_flow_logs_enabled`）
  - **ELB（负载均衡）**：HTTPS 监听启用（`elb_listener_https_enabled`）、安全 TLS 策略校验（`elb_listener_secure_tls_policy`）

### 2. AI 红队与大模型 / Agent 安全（`Tencent/AI-Infra-Guard`）

聚焦 Prompt 注入评测算子与 Agent Skill 纯语义文档的投毒检测：

- **思维链注入算子（PR #775，已合并 Merged）**
  - 为 `AIG-PromptSecurity` 单轮红队框架新增静态 `CoTInjection` 攻击算子与单元测试，用于评估大模型在推理链（Chain-of-Thought）被诱导或劫持时的越狱风险。
- **纯语义文件基线锚定切片审计引擎（PR #809，Open）**
  - 针对 `SKILL.md`、`.md`、`.txt`、`.rst` 等纯语义文件设计了**基线锚定语义切片（Baseline-Anchored Semantic Slicing）**：
    - 按结构边界对纯语义文档切片（排除代码文件），先抽取脱敏后的 Skill 能力基线；
    - 在无状态隔离的 LLM 调用中分别评估每个切片的语义偏离度（`surprise_score`）与风险分（`risk_score`）；
    - 解析 XML 前剥离 `<think>` 推理块，将高偏离切片聚合送入 Code Audit 与 Verdict Review，并加入低并发控制与降级审计兜底机制。
  - 本地 240 项 `pytest` 与 `ruff` 校验通过；A/B 评测中恶意诱导切片偏离度达 `97–99/100`，正常对照组为 `0–3/100`。

### 3. AI Agent 运行时护栏与防失控守护（`dsh-plugin-watchdog`）

面向多子代理协作场景（DeepSeek Harness）实现旁路全局守护型看门狗插件：

- **权限最小化与防篡改**：剥夺受监控会话对规则的写权限，仅暴露只读自检工具 `watchdog_inspect`（且对审计子会话隐藏）。
- **蜂巢状态中枢与资源预算**：通过工作区级 Unix Domain Socket 守护进程维护父子代理拓扑树、并发/嵌套深度/工具调用预算、跨代理文件写锁表及超时心跳巡检。
- **L1 / L2 分层审计与三层无损干预**：
  - **L1 确定性规则**：零延迟拦截高危命令（`high_risk_shell`）、敏感路径变更（`sensitive_file_mutation`）、多代理写冲突与资源预算超限；
  - **L2 语义级审计**：按需唤醒独立 LLM 审计子代理核验虚假完成与连续错误循环；
  - **无损干预**：前置 `deny` 硬拦截、`inject`/`steer` 纠偏、向父协调者注入 `<watchdog_escalation>` 升级告警，避免直接粗暴 kill 子代理导致状态丢失。

### 4. 云安全标准与架构最佳实践（`OWASP` & `CIS Benchmark`）

- **`OWASP/CheatSheetSeries`（Issue #3025，Open）**
  - 针对 `Secure_Cloud_Architecture_Cheat_Sheet.md` 提交东西向流量检测与 TLS 卸载架构指导提案，剖析云内网普遍启用 HTTPS 后传统网络 IPS 的 L7 检测盲区，分析集中式 TLS 解密对 mTLS、内网 CA 分发与吞吐延迟的权衡，提出受控跨区解密、基于身份的微隔离及主机/Sidecar 层检测等实践路径。
- **CIS 云企业版基线提案草稿**
  - 起草了 5 项基线控制提案，覆盖：全地域控制面审计日志持久化留存（Level 1）、负载均衡强 TLS 策略、对象存储仅 HTTPS 传输、数据库传输层 SSL/TLS 加密，以及限制安全组同组自引用全通放行（Level 2 东西向微隔离）。

### 5. 自动化风险验证与防御闭环架构设计

沉淀了一套面向云原生 WAF 与终端防御的闭环工作流方案设计，核心思路包括：

- 基于 EPSS 与 CISA KEV 的威胁情报分级，以及本地大模型对 PoC 的无害化重构防线；
- 云原生 WAF 变异推演与精准阻断规则自动下发复测；
- 终端安全组件（Defender/EDR）只读非破坏性权限推演探针与加固闭环；
- 结合 SkillOpt（Prompt as Trainable State）的自演化策略卡片与防过拟合机制。

## 分析过程：共性模式提炼

从上述跨项目实践中可以归纳出三个反复出现的设计原则：

1. **基线锚定与旁路隔离（`verified`）**：无论是 `AI-Infra-Guard` 的语义切片审计（先抽基线再测偏离，无状态隔离调用），还是 `dsh-plugin-watchdog` 的旁路守护（剥夺被审计方写权限），核心都是**把裁判权与被测对象的上下文隔离**，避免「既当运动员又当裁判」或被单次上下文诱导污染。
2. **分层拦截优于单一重型检测（`verified`）**：`Watchdog` 的 L1 确定性规则 + L2 按需 LLM 审计，以及东西向流量检测中「L3/L4 边界 + 受控解密 + 主机/Sidecar 层检测」的组合，都是在控制延迟与误报率的前提下补齐可见性盲区。
3. **验证与合规必须可测试、可回溯（`verified`）**：在 Prowler 检查项与 `AI-Infra-Guard` 算子中，每条规则都配套边界用例与对照评测，确保规则演进时不会静默退化。

## 结论

- 当前跨项目安全成果已覆盖 **云原生合规检测（CSPM）**、**AI 攻防与 Agent 护栏**、**安全架构标准贡献** 与 **自动化闭环设计** 四个象限（`confidence: verified`）。
- 后续在本仓库的笔记中，将按单点技术问题逐一拆解其中的边界条件与踩坑过程，而非停留在成果清单层面。

## 未解问题 / 下一步

- [ ] 跟进 `prowler-cloud/prowler` PR #13509 与 #13510 的后续 CI / Review 状态，记录各云服务 API 分页与异常边界的踩坑细节。
- [ ] 跟进 `Tencent/AI-Infra-Guard` PR #809 的评审反馈，将「纯语义文件切片与 `<think>` 剥离」的误报边界单独成文分析。
- [ ] 跟进 `OWASP/CheatSheetSeries` Issue #3025，必要时补充对应 Cheat Sheet 的正式 PR。

## 参考

- [prowler-cloud/prowler#13509](https://github.com/prowler-cloud/prowler/pull/13509) — HuaweiCloud OBS 5 项安全检查 PR
- [prowler-cloud/prowler#13510](https://github.com/prowler-cloud/prowler/pull/13510) — HuaweiCloud Tier-1 10 项安全检查 PR
- [Tencent/AI-Infra-Guard#775](https://github.com/Tencent/AI-Infra-Guard/pull/775) — 单轮静态 CoTInjection 攻击算子 PR（已合并）
- [Tencent/AI-Infra-Guard#809](https://github.com/Tencent/AI-Infra-Guard/pull/809) — Skill Scan 基线锚定语义切片审计 PR
- [OWASP/CheatSheetSeries#3025](https://github.com/OWASP/CheatSheetSeries/issues/3025) — 云安全架构东西向流量检测与 TLS 卸载提案
- [kentzjh-cmd/dsh-plugin-watchdog](https://github.com/kentzjh-cmd/dsh-plugin-watchdog) — DeepSeek Harness 旁路看门狗插件
