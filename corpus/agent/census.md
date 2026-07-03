# Skill Registry 普查报告

数据源：`claude-skill-registry-data`（浅克隆全量工作树，3.8G）
方法：全量遍历 SKILL.md + 附带脚本，跑两层扫描（脚本能力提取 + SKILL.md 词法匹配）。

## 语料真实构成（202,660 个 skill）

- **99.9% 是纯文本 skill**：只有 `SKILL.md` + `metadata.json`，没有可执行脚本。
- **仅 1,263 个脚本文件**，分布在极少数 skill；带脚本的 skill ≈ 0.1%。
- 脚本语言：python 122 / shell 121 / js 64 / powershell 7 / ts 6（按 skill 计）。
- **0 个 MCP 配置文件**（`.mcp.json`），930 个 skill 有 hook 命名文件，1 个二进制。

**结论**：这个语料的攻击面主要在 **SKILL.md 文本（LLM 指令）**，而不是脚本执行。脚本分析（L2）在公开 registry 上覆盖面极小；语义层（SKILL.md 意图）才是主战场。

## 词法扫描（argus 现有层）在真实语料上的表现

| 模式 | 命中 | 抽查结论 |
|------|------|----------|
| exfil_instruction | 3,509 | **几乎全是 FP**：`POST /token`、`postgresql://user:password`、渗透测试 skill 的正常文档 |
| curl_pipe_sh | 1,571 | **绝大多数 FP**：`curl ... astral.sh/uv/install.sh \| sh`、`bun.sh/install`——合法安装命令 |
| autorun_hint | 1,461 | **FP**：`Auto-approve`、`--yolo` 出现在说明文字里 |
| override_lang | 210 | 混合：真有 `Ignore previous instructions`，但需上下文区分是攻击还是"防注入教学" |
| concealment | 244 | 混合：`Hide from` 多为 UI/CSS 语境 |

**直接印证：词法层给出的 badge 不可用。** 高计数项 FP 率极高，真阳性淹没在合法安装命令和安全教学文档里。发 badge 等于制造"clean=安全"的错觉。

## 脚本能力提取（L2 原型）结果

245 个脚本文件命中能力模式（net_egress 59 / sensitive_read 121 / persistence 52 / exec_eval 37 / obfuscation 4 / pipe_to_shell 2 / agent_config_write 1）。

真正值得看的组合信号（能力错配，L3 雏形）：

- `aiskillstore-marketplace`：curl + API_KEY 读取 + base64 解码 —— 三件套齐了
- `k-dense-ai-scientific-agent`：requests.post + API_KEY + b64decode
- `tuan3w-obsidian-vault-agent`：脚本写 `.claude/settings` —— 持久化改 agent 配置
- 多个 `install-nextflow.sh`：`curl \| bash` 真实存在

这些是"陈述能力"而非"判断坏词"，误报低、对用户有直接价值（等价于 App 权限页）。

## 对 argus 方向的结论

1. **别急着发 trust badge**。当前词法层做 badge 会误导。
2. **重心放语义层**，因为 99.9% 的攻击面是 SKILL.md 文本，不是脚本。词法正则不够，需要意图-能力错配判断（规则分类 + 可选 LLM judge）。
3. **脚本 L2 仍要做但覆盖小**，价值在"能力清单/权限页"叙事，不在恶意判定。用上面 245 个命中当第一批 fixture。
4. **建 eval 集**：先人工标注 override_lang(210)、concealment(244)、脚本能力(245) 这三批小样本，得出 precision，再定义"够强"。
5. 现有词法层降级为**第一道粗筛**，不作为最终 verdict。
