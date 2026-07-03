# Product Spec

## Linked Issue

GH-57

## 用户问题

argus 目前只守护经典包供应链（npm/PyPI/crates 等 8 个生态），但 2026 年
增长最快的攻击面是 **agent 面**：MCP server 配置、agent skills、hook 脚本、
高上下文指令文件（`AGENTS.md`/`CLAUDE.md`）。已有公开事故类型包括
tool-description 提示注入、恶意 skill 投毒、依赖安装期 AGENTS.md 注入。
目前没有任何开源静态扫描器覆盖这个面——用户在安装第三方 skill 或连接
MCP server 前没有工具可以回答"这个东西装进来安不安全"。

## 目标

- 新增 `argus agent scan <paths...>` 子命令，静态扫描 agent 面，
  复用 argus 现有三档决策（block / allow-with-approval / allow）。
- MVP 覆盖三类无状态静态规则：AGT-01（注入语）、AGT-03（危险能力组合）、
  AGT-05（高危配置旗标）。
- 与现有 `scan` 输出同构：同一 `Finding` JSON 形状、同一 CLI 体验。

## 非目标

- AGT-02（description 哈希漂移基线）与 AGT-04（安装期高上下文文件 diff）
  ——需要持久化基线状态，另开 issue。
- 动态分析 / 沙箱执行被扫描内容。
- registry 侧批量扫描集成（MVP 之后跟进）。
- 不承诺语义级注入检测（domain-aligned 攻击），MVP 只做词法/结构层。

## Behavior Invariants

1. 扫描过程从不执行被扫描目录中的任何代码；文件只作为文本或不透明
   字节读取（与 argus-rules 同一安全边界）。
2. AGT-01：MCP tool description、`SKILL.md`、`AGENTS.md`/`CLAUDE.md` 中
   出现 authority-claim / override / 隐匿指示语（含中文等价语）→
   critical finding → block。
3. AGT-03：skill/hook 可执行脚本中出现远程下载管道执行（curl|sh 类）、
   secret 路径读取 + 网络外发组合 → high finding → block。
4. AGT-05：`.mcp.json` / `.claude/settings*.json` / `~/.claude.json` 形状
   的配置中出现 `alwaysLoad: true`、`enableAllProjectMcpServers: true`、
   非空 `enabledMcpjsonServers`、PostToolUse hook 对非 MCP 工具重写
   `updatedToolOutput` → medium finding → allow-with-approval。
5. 无任何 finding → allow。良性 fixture（正常 skill、正常 MCP 配置）
   不得误报（每条规则至少一个良性反例进 corpus）。
6. 防御性引用豁免：规则文档/测试 fixture 内引用攻击字符串本身不在
   扫描目标形状内时不触发（只扫描 agent 面文件形状，不扫普通源码）。

## 验收标准

- [ ] `argus agent scan` 对恶意 fixture 目录输出预期 AGT 规则 + block。
- [ ] 每条规则 ≥1 恶意 + ≥1 良性 fixture，corpus 断言 decision 与 rules。
- [ ] `cargo test` 全 workspace 通过。
- [ ] README 增加 agent scan 用法段落。

## 边界情况

- 扫描目标可能是用户家目录（`~/.claude`）：必须容忍不可读文件（跳过并
  继续），不得因单个文件 IO 错误整体失败。
- 超大文件（>1 MiB）按 argus 现有惯例视为二进制/跳过文本规则。
- JSON 配置解析失败：报 info 级 finding（unparseable config），不 panic。
- 中英文注入语均需覆盖；大小写不敏感。
