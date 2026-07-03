# Product Spec

## Linked Issue

GH-58

## 用户问题

`argus agent scan`（GH-57 落地的 MVP）目前只有词法层规则（AGT-01/03/05），
但没有针对 agent 面的回归语料，也没有测过精度。我们无法区分"真正的检测
改进"和"把噪音换个标签"。

为了给这条线定基线，对公开语料 `claude-skill-registry-data`（202,660 个
skill）做了一次全量普查，结论明确：

- **99.9% 的 skill 是纯文本**（只有 SKILL.md + metadata.json）。主要攻击面是
  **SKILL.md 里喂给 LLM 的指令**，不是脚本执行。
- 全库只有 **1,263 个脚本文件**，其中 **245 个**带可提取能力。
- 现有词法模式在真实数据上被误报主导：
  - `exfil_instruction`：3,509 命中，几乎全 FP（`POST /token`、
    `postgresql://user:password`、渗透测试 skill 文档）。
  - `curl_pipe_sh`：1,571 命中，绝大多数 FP（`curl https://astral.sh/uv/install.sh | sh`
    等官方安装器）。
  - `autorun_hint`：1,461 命中，FP（说明文字里的 `Auto-approve`、`--yolo`）。
  - `override_lang`（210）、`concealment`（244）为混合 TP/FP。

在这一层直接发 trust badge 会制造"clean = 安全"的错觉。必须先有语料 +
eval 基线。

## 目标

- 在 argus 现有语料 schema 下新增 `agent-skill` 回归语料
  （`corpus/agent/index.json` + `fixtures/`），全合成、无害
  （`.example.invalid` host，不执行任何东西），由 `argus corpus test` 断言。
- 提供真实普查命中的标注 worklist（带上下文），用于量化现有词法层精度。
- 包含两个**负例** fixture，检测器必须不 block（合法安装器、合法 API 工具），
  把普查暴露的 FP 失败锁进回归。

## 非目标

- 本 issue 不引入新检测算法（GH-59 跟进）。
- 不做 trust badge / registry 集成。
- 不改 npm/PyPI/crates 扫描路径。

## 行为不变量

1. `argus corpus test` 对 6 个 agent-skill fixture 的判决全部通过。
2. 两个负例 `skill-benign-installer`（allow）与 `skill-benign-net-tool`
   （allow-with-approval）必须**非 block**；任一被判 block 视为回归失败。
3. 所有 fixture 内所有 URL/host 指向 `.example.invalid`，DNS 不可解析。
4. 语料新增不改变现有 npm/PyPI/crates fixture 的判决。
5. worklist 为只读证据文件，不参与 `corpus test` 判决逻辑。

## Acceptance Criteria

- [ ] `corpus/agent/index.json` + 6 个 fixture 落地，遵循现有 schema。
- [ ] `argus corpus test` 断言全部 6 个期望判决，含两个负例。
- [ ] 标注 worklist（849 条真实命中：245 script-capability、210 override、
      244 concealment、150 FP 采样）提交到 `corpus/agent/`。
- [ ] 普查方法学 + 数字文档化，基线可复现。

## Edge Cases

- 纯文本 skill（无脚本）：`skill-injection-md` 覆盖，验证纯 SKILL.md 攻击。
- 能力与意图一致的合法工具：`skill-benign-net-tool` 覆盖。
- 官方安装器文档：`skill-benign-installer` 覆盖 curl_pipe_sh 的 FP 陷阱。

## Rollout Notes

纯新增语料 + 文档，无行为变更，无兼容性影响。合并后 GH-59 的检测层以这批
fixture 的判决和 worklist 的精度数字为验收依据。
