---
title: Skill 安全分析中的语义切片困境：去语境化逻辑成立，但攻防信任假设不对等
date: 2026-11-26
tags: [ai-security, threat-modeling, sec-eng]
status: published
confidence: inferred
---

## 一句话结论

在 Agent Skill 纯语义文档的恶意意图检测中，**「通过独立切片剥离连续叙事上下文，在零信任基线下观测偏离度」的核心逻辑成立（`verified`）**；当前切片路线在工程上走得艰难，不是因为“不需要切片”，而是因为**切片仍由模型主观判善恶、复核阶段又重新引入全文语境、且整个审计闭环建立在“相信审计模型自身安全对齐”这一不对等假设之上（`inferred`）**。

---

## 触发点

在推进 `Tencent/AI-Infra-Guard`（`skill-scan` 模块）对纯语义文档（`SKILL.md` 及渐进披露目录 `references/`、`rules/`、`workflows/` 等）进行静态安全审计时，尝试了“基线锚定语义切片审计”方案，但在实际效果与工程权衡上遇到了明显阻力：

1. 直接对文本做结构切片后送入独立 LLM 审计，似乎并没有彻底跑通“稳定降漏报 + 低误报 + 可控成本”；
2. 然而从对抗直觉上看，如果不在独立切片中剥离上下文，恶意意图很容易被大段正常工程文档与渐进铺垫“催眠”掩盖；
3. 更深层的矛盾在于：`AI-Infra-Guard` 项目的 `AIG-PromptSecurity` 本身集成了大量系统性越狱与语境操纵手段，而防御侧的 `skill-scan` 却依然依赖自然语言规则去约束审计模型、默认模型自身的安全对齐能够扛住待审计文本的诱导。

---

## 观察到的现象

基于对 `AI-Infra-Guard` 仓库现有实现的源码走读（`verified`）：

1. **切片阶段的“去语境化”与复核阶段的“再语境化”并存**
   - `skill-scan/skill_scan/utils/semantic_slicer.py` 按 Markdown 结构边界（YAML frontmatter、标题、HTML 注释、引用块、列表、段落）切分纯语义文件，并结合 `SKILL.md` 抽取 `<skill_baseline ... untrusted="true">` 作为基线；
   - `skill-scan/skill_scan/agent/semantic_auditor.py` 与 `prompt/agents/semantic_slice_audit.md` 在无状态隔离的 LLM 调用中输出 `<verdict>`、`surprise_score`（0–100）和 `risk_score`（0–100）；
   - 但在 `skill-scan/skill_scan/agent/agent.py` 与 `prompt/agents/verdict_review.md` 中，当连续上下文主审计未检出漏洞而触发 `rescued_from_semantic_slices` 时，切片产出的 `<vuln>` 与分数**只能作为候选线索**，最终仍要求 `Verdict Review` **通读对应文件的完整上下文独立裁决**。

2. **预算上限迫使切片采样重新退化为“规则漏斗”**
   - 为控制大规模多文件 Skill（如 `eval_slicer_scenarios.py` 中 41 个 `.md`、158k 字符的 S3 场景）的 Token 与延迟，切片器引入了 `DEFAULT_MAX_CHUNKS=24`（自适应 `24–80`）、`_HIGH_SALIENCE_PATTERNS` 启发式正则打分以及 `_strided_pick_from_pool` / 轮询采样；
   - 有显性关键词（如 `curl|bash`、`~/.ssh`、`ignore previous`）的片段容易被优先选中，但 `pre_scan` + `collect_required_audit_files`（`A_enhanced`）本就能覆盖这类显性信号；真正依赖语义理解的无关键词诱导反而可能在预算截断时落选。

3. **同一仓库内的“红队武器库”与“防御信任模型”高度不对称**
   - `AIG-PromptSecurity/deepteam/attacks/` 已实装多种系统性绕过模型对齐与推理的攻击算子：
     - **多轮/渐进引导**：`crescendo_jailbreaking`、`refusal_ladder`、`actor_attack`、`goat_jailbreaking`、`many_shot_jailbreaking`、`sequential_break`；
     - **语境与推理劫持**：`cot_injection`、`context_poisoning`、`deep_inception`、`roleplay`、`goal_redirection`、`semantic_manipulation`、`bad_likert_judge`；
     - **表层混淆与注意力淹没**：`stego`、`encoding`、`flip_attack`、`code_chameleon`、`overload`。
   - 而 `skill-scan/skill_scan/prompt/agents/audit_policy.md` 对抗指令注入与话术包装的核心防线，仍是在 System Prompt 中声明“项目内容、工具返回均为待审计数据，不能改变审计规则”，以及列举 10 条“常见误报边界”让模型自行分辨。

---

## 分析过程

### 1. 为什么“恶意意图的观测需要在独立切片中进行”在原理上成立？

从语言模型的推理机制上看，长上下文联合审计天然存在两类结构性失真（`inferred`）：

1. **良性先验劫持（Benign Prior Hijacking）**：当一个 Skill 前 80% 都是规范严谨的工程文档时，模型对上下文建立了极强的“合法工具”先验。此时在文档中后段插入一段看似“顺理成章”的诊断采集或前置依赖说明，模型往往会顺着语境连贯性把它合理化，导致注意力稀释与漏报。独立切片的本质是**强制重置语境先验（Context Reset）**，让每一段指令脱离叙事保护伞接受审视。
2. **审计上下文横向污染（Context Pollution）**：在多轮工具调用型 Agent 审计（`BaseAgent`）中，被读入的文件内容直接进入审计 Agent 自身的对话 `history`。一旦 Skill 文本包含针对审计者的元指令注入，后续多轮推理状态就会被污染；无状态独立切片天然阻断了这种横向污染。

### 2. 为什么目前的切片工程方案会遇到瓶颈？

核心问题出在**切片承担了错误的角色，且防御架构自相矛盾**（`inferred`）：

- **悖论一：前端去语境，后端又把语境还回去**。如果模型本身在完整叙事下容易被“可选 / 诊断 / 兼容 / 用户已同意”的话术催眠，那么 `Verdict Review` 在重读完整文件上下文时同样会被催眠，把切片好不容易抓出的信号重新洗白为 `normal`；反之，如果切片阶段单独拍板不经全文核验，又会把正常的测试样例、安全教学表格误判为恶意。
- **悖论二：物理分块割裂了“分布式诱导链”**。按 Markdown 标题/段落做物理切片，只对“单段内爆发的显性载荷”（如 ClickFix、恶意 hook、隐藏 HTML 注释）有效；面对类似 `crescendo`、`deep_inception` 或跨段落/跨文件拼装的渐进式诱导，单个物理切片里每句话都合规，拼合后的因果链反而被切碎。

### 3. 为什么“建立在相信模型自身安全对齐上”在攻防上是不对等的？

这是整个 LLM-as-a-Security-Auditor 范式中最容易被忽视的错位（`inferred`）：

1. **安全对齐护栏不覆盖“误判放行（False Negative）”**：大模型的安全对齐训练（RLHF / Safety Alignment）主要防御的是“输出有害/违禁内容”。而针对 Skill 安全审计员的对抗攻击，不需要诱骗模型生成攻击载荷，只需要诱骗模型**相信一段恶意指令是“合法工程需求”并输出 `normal`**。这完全不会触发模型的拒答对齐，甚至恰好迎合了模型默认的顺从偏置（Sycophancy）。
2. **防御侧的“误报白名单”可能变成攻击者的对齐靶标**：`audit_policy.md` 为了降低误报，详细列出了合法依赖安装、本地诊断、测试夹具、用户授权参数等豁免条件。一旦攻击者把恶意行为包装成符合这些豁免条件的语境（例如伪造“测试样例上下文”或“仅用于本地诊断的兼容开关”），**越是严格遵守系统 Prompt 的模型，反而越容易按规则将其放行**。
3. **规则提示词是软边界，红队算子是结构化搜索**：攻击侧可以用 `AIG-PromptSecurity` 里的 `cot_injection`、`context_poisoning`、`encoding`、`overload` 等手段系统性探索模型判断盲区；而防御侧仅靠自然语言 Prompt 嘱咐“不要被安抚措辞欺骗”，本质上是把安全边界完全交给模型概率输出的不确定性。

---

## 破局方向（待验证假设）

如果要保留“独立切片观测”的核心优势，同时摆脱对模型自身对齐的盲信，需要把切片从“主观安全裁判”重定位为“**去修辞编译前端**”（`speculative`）：

1. **切片职责降维：从“判善恶”改为“去修辞的行为原语抽取（De-framing Normalization）”**
   - 切片 LLM 不再直接输出 `normal / suspicious / malicious`，只负责剥离一切修辞、背景故事和安抚话术，将文本压缩规约成冷冰冰的结构化原语：
     - `Trigger`（触发时机：加载时 / 用户请求 / 每次输出固定附加）
     - `DataSource`（读取目标：用户输入 / `~/.ssh` / `.env` / 上下文记忆）
     - `Action & Sink`（执行动作与外发终点：本地文件 / 持久记忆 / Shell / 外部 URL）
     - `Stealth & Override`（是否存在静默、对用户隐瞒、覆盖既定约束或强迫输出）
   - **关键收益**：下游全局关联与 `Verdict Review` 主要基于“**去修辞后的跨切片行为清单**”做因果拼图与测试上下文核验，而不是重新通读攻击者的完整催眠原文，从而打破“去语境 → 再语境”悖论。

2. **从“物理段落切片”升级为“按安全关注点聚类的语义切片（Concern-based Slicing）”**
   - 借鉴静态分析中 **Program Slicing（程序切片）** 思路，不再用有限预算平均采样无关说明文本，而是按威胁维度（如：① 指令/输出控制流、② 凭据与敏感路径读取、③ 网络外发与外部依赖加载）将分散在全项目中的相关片段聚合成少数高密度切片视图，既压低 Token 成本，又能观测跨段落/跨文件的组合意图。

3. **用确定性硬不变量替代部分主观对齐判断**
   - 对已经静态解码出的高危隐藏载体（Unicode Tag 隐写、畸形 HTML 注释指令、frontmatter `hooks:`）以及原语层出现的硬冲突组合（如：`非对应服务凭据读取 + 无关外域外发 + 要求对用户隐瞒`），在代码层设置**不可被自然语言免责声明覆盖的底线门禁**：除非存在代码级控制流证据证明不可达，否则禁止下游仅凭原文的“可选/诊断”措辞降级为 `normal`。

4. **用 `AIG-PromptSecurity` 闭环反向标定 `skill-scan`**
   - 将当前评测里偏直白的 `_NEEDLE_SPECS` 升级为由 `AIG-PromptSecurity` 算子（`context_poisoning`、`cot_injection`、`deep_inception`、反 `audit_policy` 豁免话术伪装等）生成的对抗性 Skill 样本集，直接度量防御侧在不同编码/包装/切片策略下的抗催眠能力，消除“左右手互不知情”的攻防不对等。

---

## 工程收口：代码化可控切片工具 + System 1/2 快慢协同

结合工程可维护性与对抗鲁棒性，进一步收敛出一套**「代码化受控切片工具 + System 1 正交三路判断 + System 2 最终合并复核」**架构（`speculative`）：

### 1. System 1 的三个正交观测用途与交叉指纹

相比慢思考（System 2）模型在长 CoT 中容易出现**过度脑补合理化（Over-rationalization）**且易受 `cot_injection` 干扰，将快响应的 **System 1** 用于去语境切片不仅降本提速（从而取消依赖正则关键词的 `DEFAULT_MAX_CHUNKS` 预算漏斗、实现全量切片扫描），更能在“不给自我说服空间”的前提下提供三个彼此补盲的观测信号：

| System 1 用途 | 观测输入 | 核心问题 | 专抓威胁与独立盲区 |
| --- | --- | --- | --- |
| **切片内容判断**（`S_local`） | 单个独立切片（无上下文、不喂基线） | 这段内容**本身**是否存在绝对越界原语？ | 抓指令覆盖、隐瞒用户、隐蔽外传、恶意命令；盲区是“操作本身常见但超出本 Skill 所需” |
| **切片 vs 主旨偏离**（`S_drift`） | 去授权清洗后的能力主旨 + 单个切片 | 完成声明的能力，**需要**这一步吗？ | 抓能力漂移与夹带私货；盲区是**基线投毒**（作者在简介里主动宣称收集凭据/遥测） |
| **去语境后全局判断**（`S_global`） | 全项目切片压缩而成的「去语境行为账本」 | 剥掉故事包装后，所有动作**拼在一起**构成什么意图？ | 抓跨切片/跨文件渐进拼接诱导（如 `crescendo`）；强依赖账本去修辞提纯质量 |

**交叉指纹与 System 1 短板兜底：**
- **三路交叉指纹**：
  - `S_local` 高 + `S_drift` 低 → 高度疑似**基线投毒**（试图用主旨声明合法化恶意行为）；
  - `S_local` 均低 + `S_global` 高 → 高度疑似**跨片分布式拼装诱导**；
  - `S_drift` 高 + `S_local` 中低 → 典型**能力漂移 / 过度授权**（`suspicious` 高发区）。
- **System 1 自身短板兜底**：
  1. **L0 确定性预处理先行**：编码/Base64/Unicode Tag 隐写/UTF-16 乱码与注释隔离先由代码解码展开，不依赖快模型硬解混淆；
  2. **离散特征 + 原句锚点代替 0–100 主观分**：用强 Schema 布尔/枚举位 + 触发原句摘录（Quote Anchor）+ 一句话去修辞动作条目替代连续打分，抑制小模型评分漂移与幻觉；
  3. **基线清洗与 Fail-Closed 升级**：提取基线时剥离权限/诊断豁免措辞，防止污染 `S_local`；若发生 Schema 解析失败或 L0 硬特征命中但 L1 返回全绿（L0/L1 矛盾），强制升级交由 System 2 复核。

### 2. 切片封装为代码化工具，交由模型在可控范围内自主调用

放弃维护脆弱的纯静态启发式 Markdown 切块器（如千行级规则硬适配 XML 嵌套/中英混排/无标题长文），改为**工具层只收策略/行号参数，原文提取、去语境封装与覆盖率校验全部由确定性代码完成**（严禁模型通过复述/改写原文来切片，防漏抄与注入篡改）：

- **5 个最小完备工具原语**：
  1. `inspect_doc_skeleton(file)`：仅返回目录结构、frontmatter、各级标题大纲（起止行号与字符数）、代码块/注释/外链分布及 L0 静态隐写告警，**不注入大段散文**；
  2. `slice_by_plan(file, strategy_or_ranges)`：按模型指定的 `by_heading` / `by_line_ranges` / `by_block_type` / `by_sliding_window(chars, overlap)` 精确提取不可变 `slice_id`，并实时更新行级覆盖位图；
  3. `lock_clean_baseline(source_file, core_capability)`：锁存去除授权/免责修辞后的极简功能基线；
  4. `dispatch_sys1_audit(slice_ids, tasks=["local", "drift", "ledger"])`：在工具内部完成去语境隔离包装并高并发调用 System 1，返回 `S_local`、`S_drift` 与去修辞行为条目，汇总行为账本后自动触发 `S_global`；
  5. `verify_coverage_and_finalize()`：核验行级覆盖位图完整性后再交接下游。
- **3 条代码层硬护栏（不靠 Prompt 劝说）**：
  1. **单块尺度上限（Anti-Dilution Cap）**：单切片超过字符/行数阈值（如 `<= 1200 chars` 或 `<= 40 lines`）则拒绝或自动二次滑窗拆分，防止把恶意段与大段良性文本混装稀释；
  2. **100% 行级覆盖不变量（Anti-Skip Invariant）**：全部目标文件非空行必须被切片区间并集 100% 覆盖，未覆盖行自动按默认滑窗补切补审，彻底堵死“通过伪造 `## License` / `## Appendix` 标题诱导跳过审计”的逃逸路径；
  3. **规划步数预算与确定性退化（Bounded Autonomy）**：限定规划轮次上限（如 `max_steps=3`），小文件直接跳过规划走默认切分，超步自动退化为默认滑窗。

### 3. 三段隔离数据流与 System 2 最终合并复核

```text
Stage A：受控切片与去语境编排（只看骨架，不吞长篇散文）
  └── 模型调用 inspect_doc_skeleton → slice_by_plan → lock_clean_baseline
  └── 代码强校验：单块上限 + 100% 行级覆盖不变量（漏区自动滑窗补齐）

Stage B：System 1 隔离判断层（工具内部无状态高并发调度）
  ├── S_local（独立切片内在越界判断 + 提取去修辞行为条目）
  ├── S_drift（切片 vs 去授权基线偏离判断）
  └── S_global（全项目去语境行为账本全局组合意图判断）
        │
        ├── [Fast Path] L0 零命中 + 无代码脚本 + 三路全绿 ──► 直接收敛 normal（0 次 System 2 调用）
        │
        ▼ [Slow Path] 任一信号触发 / 交叉指纹命中 / 存在可执行脚本
Stage C：System 2 最终合并与复核（干净新上下文启动）
  ├── 初始上下文仅注入：L0 静态事实 + 全项目去语境行为账本 + 命中切片坐标与交叉指纹
  ├── 合并：去重相邻/重叠切片告警，串联跨切片/跨文件完整攻击链（Source → Sink）
  └── 复核：按坐标定向回查原文/脚本，执行「技术硬反证」
```

其中 Stage C 的合并复核必须执行**证据分轨**：普通 `S_drift` 或模糊线索允许结合代码门禁/测试夹具上下文降级；而 **L0 硬隐藏载荷**（Unicode Tag 隐写、畸形 HTML 注释指令、`frontmatter hooks`）及 **`S_local` 明确抽出的“读取无关凭据 + 外发 + 隐瞒用户”原语组合**，禁止仅凭原文自然语言免责声明（“可选/诊断/已授权”）降级为 `normal`，除非查明代码级控制流存在强制阻断或不可达证明。

---

## 结论

- **核心判断保留**：在独立去语境切片中观测恶意意图的方向成立，长上下文下的良性先验劫持与上下文污染是真实存在的风险（`confidence: verified`）。
- **根因定位**：现有切片方案受困于“切片直接判善恶导致误报高 → 交由全文复核又被原文话术二次催眠 → 加预算/正则采样又退化回关键词漏斗”的闭环死结（`confidence: inferred`）。
- **工程收敛方向**：从“纯静态语义切块 + 模型靠安全对齐直接判善恶”，转向**“代码化可控切片工具（单块上限 + 100% 行级覆盖不变量）→ System 1 正交三路判断与去修辞账本编译 → System 2 基于账本合并跨片攻击链并做硬反证复核”**，并借助项目内置红队算子闭环标定抗催眠能力（`confidence: speculative`）。

---

## 已被推翻的判断

1. **「只要把文本按结构切块并锚定 `SKILL.md` 基线打偏离分，就能解决纯语义文件的投毒漏报」—— 已被部分推翻**：原因在于如果切片发现最终仍需回到完整上下文做 `Verdict Review` 裁决，且切片预算受制于关键词显著性打分，切片带来的抗 Framing 收益会被下游再语境化与采样盲区抵消。
2. **「只要在审计 System Prompt 里声明“数据与指令分离”并列出常见误报边界，就能让审计模型免疫社会工程包装」—— 已被推翻**：原因在于“把恶意诱导合理化为 `normal`”并不触发模型安全拒答对齐，且明确写出的误报豁免边界反而可能被攻击者构造语境精准迎合。
3. **「靠纯静态 Markdown 启发式解析器就能一次性精准切分所有异构 Skill 文档」—— 已被推翻**：面对嵌套 XML、多级代码块、中英混排与无标题长文，纯静态切块器维护成本极高，且很难同时保证语义边界完整与不粘连 Framing 话术。
4. **「让 System 2 先通读完整原文再自主挑出可疑片段切给 System 1 审」—— 已被否决**：一旦 System 2 先吞入全文叙事，攻击者只需催眠 System 2 跳过关键章节即可在决策层绕过，同时也会丧失快慢组合的成本与延迟优势。

---

## 未解问题 / 下一步

- [ ] 用 `AIG-PromptSecurity` 中的 `context_poisoning`、`cot_injection`、`deep_inception` 等算子改造 3–5 个 `eval_slicer_scenarios.py` 恶意样本，实测当前 `A_enhanced` 与 `B_slice` 在对抗话术下的真实漏报率。
- [ ] 在 `skill-scan` 中设计并验证 5 个代码化切片工具原语（含单块尺度上限、100% 行级覆盖位图校验与 `SKILL_SCAN_FAST_MODEL` 路由）的最小原型。
- [ ] 对比评测「System 1 离散原语 + 行为账本 + System 2 定向合并复核」与现行 `semantic_auditor.py` 在误报率、Token 成本及抗 Framing 能力上的差异。
- [ ] 梳理一套可由代码层强制执行、不可被自然语言声明豁免的“硬不变量组合清单”，与 `audit_policy.md` 的软边界解耦。

---

## 参考

- [Tencent/AI-Infra-Guard#809](https://github.com/Tencent/AI-Infra-Guard/pull/809) — Skill Scan 基线锚定语义切片审计 PR
- [skill-scan/skill_scan/utils/semantic_slicer.py](https://github.com/Tencent/AI-Infra-Guard/blob/main/skill-scan/skill_scan/utils/semantic_slicer.py) — 语义切片器与渐进披露层级实现（本地分支 `feat/skill-scan-slicer-followup`）
- [skill-scan/skill_scan/agent/semantic_auditor.py](https://github.com/Tencent/AI-Infra-Guard/blob/main/skill-scan/skill_scan/agent/semantic_auditor.py) — 独立无状态切片审计与基线偏离量化
- [AIG-PromptSecurity/deepteam/attacks](https://github.com/Tencent/AI-Infra-Guard/tree/main/AIG-PromptSecurity/deepteam/attacks) — 项目内置单轮/多轮越狱与语境操纵攻击算子库
