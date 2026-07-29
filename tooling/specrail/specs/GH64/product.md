# Product Spec

## Linked Issue

GH-64

## 用户问题

argus 的 agent 面扫描（GH-57）是一次性无状态词法/结构检测：它能在安装当下
拦住明显恶意的文本，但无法发现 **rug-pull**——一个曾经被人工审核通过的
MCP tool description、skill 元数据或高上下文指令，在初次批准之后被悄悄改成
恶意内容。用户批准 v1 的描述后，v2 的漂移当前没有任何工具能察觉。

AGT-02 在 GH-57 的 MVP 中被显式 defer，因为它需要**持久化基线状态**：必须
先把"已批准"的描述固化下来，之后每次扫描才能对比出漂移。

## 目标

- 给 `argus agent scan` 增加一个显式的 **baseline（基线）** 机制：把 agent 面
  中 description 类元数据的稳定哈希记录进一个基线文件。
- 之后的扫描把当前输入与基线对比，当**已批准的 agent 面描述发生漂移**时
  产出一条 AGT-02 finding，证据包含 file/path 与 old/new 哈希。
- 完全复用现有 `Finding` JSON 形状与三档决策派生（block / allow-with-approval
  / allow），不新增顶层输出结构。

## 非目标

- 动态执行或网络调用被扫描内容（沿用 GH-57 安全边界）。
- registry 级批量扫描（另行跟踪）。
- 语义级判断描述"是否变恶意"——AGT-02 只回答"是否相对已批准态发生变化"，
  语义判断留给 AGT-01 词法层与 GH-59 意图错配层。
- 自动信任新出现（基线中不存在）的描述：新面由 AGT-01/03/05 首过负责，
  AGT-02 只覆盖"曾批准→现漂移"。

## Behavior Invariants

1. 扫描过程从不执行被扫描目录中的任何代码；基线文件与被扫描文件都只作为
   文本/不透明字节读取（与 GH-57 同一安全边界）。
2. **基线内容**：AGT-02 对以下 description 类元数据计算稳定哈希——
   (a) MCP 配置（`.mcp.json` / `mcp.json` / `.claude.json` / `.claude/settings*.json`）
   中每个工具/server 的 `description` 字段；(b) `SKILL.md` frontmatter 的
   `description` / `name` 元数据。每条基线项以稳定 key（surface 相对路径 +
   条目定位符，如 tool 名或 frontmatter 字段名）标识。
3. **基线初始化/更新**是一个显式动作（`--update-baseline`）：把当前扫描面的
   description 哈希写入基线文件并标记为"已批准"。该动作本身不产出 AGT-02
   漂移 finding（它定义新的信任基准）。这是 AGT-02 的信任边界：只有用户
   显式运行更新，才会把当前描述固化为可信。
4. **漂移检测**：普通扫描携带 `--baseline <file>` 时，对每条既存在于基线、
   又存在于当前扫描面的条目，比较哈希；哈希不同 → 产出一条 AGT-02 finding，
   `detail` 说明漂移条目，证据含 file/path 与 old/new 哈希前缀。
5. **决策映射**：AGT-02 漂移为 **medium → allow-with-approval**（强制重新
   批准，而非硬拦截）。理由：合法的描述更新与恶意 rug-pull 在词法上不可区分，
   硬 block 会高 FP；重新批准既暴露漂移又不误伤正常维护。硬拦截交给 AGT-01
   对漂移后新内容的词法判断（漂移后若新内容本身命中 AGT-01，则 critical→block
   照常生效，两条规则叠加）。
6. **基线缺失时**不静默降级：未提供 `--baseline` 时，AGT-02 完全不参与，
   扫描行为与 GH-57 完全一致（no baseline = no drift check，明确而非伪装成
   "已检查"）。提供了 `--baseline` 但文件不可读/解析失败 → info 级 finding
   （unreadable/unparseable baseline）并继续其余规则，不 panic、不静默当作
   "无漂移"。
7. 基线中存在、当前面已删除的条目：产出 info 级 finding（baseline entry
   missing），不升级为漂移 block，供用户判断是移除还是被绕过。
8. 良性未变 fixture（基线与当前描述一致）扫描 → 无 AGT-02 finding。

## 验收标准

- [ ] `argus agent scan --update-baseline <file> <paths...>` 能初始化或刷新
      受支持 agent 面的基线文件。
- [ ] 基线建立后，某 MCP tool description 变更再扫描 → 产出 AGT-02 finding，
      证据含 file/path 与 old/new 哈希。
- [ ] 良性未变 fixture 扫描无 AGT-02 finding。
- [ ] 测试覆盖：基线创建、未变扫描、漂移检测三条路径。
- [ ] README 记录基线工作流与其信任边界（谁能更新基线、更新即批准）。
- [ ] `cargo test` 全 workspace 通过。

## 边界情况

- 基线文件路径可与被扫描树同处一目录：更新基线时不得把基线文件自身纳入
  扫描面（避免自指哈希）。
- 同一 description 文本出现在多个文件：以 (path + 条目定位符) 为 key，不做
  跨文件去重，各自独立追踪。
- JSON 配置本身解析失败：沿用 GH-57，报 info 级 finding，跳过其 description
  抽取，不影响其他文件的漂移检测。
- 哈希算法需稳定跨平台、跨运行确定（对同一字节输入恒定输出）；证据只展示
  哈希前缀，不展示描述明文（描述可能含注入语，避免在报告中二次渲染）。
