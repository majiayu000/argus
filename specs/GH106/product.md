# Product Spec

## Linked Issue

GH-106

complexity: large

## 用户问题

`argus agent scan` 已能扫描 `AGENTS.md`、`CLAUDE.md`、MCP 描述、skills 与
hooks，并用 AGT-02 对描述元数据做 hash baseline。但依赖安装、生成器或更新
脚本会新增、删除或修改这些高信任输入，而单次语义扫描只能回答“当前内容是否
可疑”，无法回答“本次安装具体改了什么”。

AGT-02 的 baseline 以描述条目为键，只覆盖 MCP/skill 的 description 字段；
它不覆盖高上下文文件集合的增删，也不覆盖 `AGENTS.md`、`.cursorrules` 等
指令文件的完整内容。因此一次安装可以写入新的高上下文文件，或把现有文件换成
symlink，而下一次普通扫描无法证明这次变更的边界。

## 目标

- 提供显式的安装前 snapshot / 安装后 check 工作流，覆盖受支持的高上下文路径。
- 报告新增、删除、内容修改、文件/目录类型变化与 symlink 变化，证据稳定可审计。
- 任何无法完整完成的比较都显式失败，且不得丢弃失败前已完成的变化证据。
- snapshot 的创建或更新是显式批准动作，普通 check 永不隐式覆盖 snapshot。

## 非目标

- 不执行包安装器、package manager、hook 或被扫描代码。
- 不保存或输出高上下文文件正文、正文片段或 symlink target 明文。
- 不替代版本控制 diff、代码审查或 AGT-01 语义检测。
- 不实现动态 sandbox。
- 不自动信任新的或变化后的 snapshot。
- 不改变未启用 AGT-04 时 AGT-01/AGT-02/AGT-03/AGT-05 的 finding ID、
  severity、决策或输出结构。

## Behavior Invariants

1. B-001 snapshot 对受支持高上下文成员生成持久化 inventory。每个成员记录
   规范化的 UTF-8 逻辑相对路径与闭集类型 `file | directory | symlink`；
   file digest 是对文件从首字节到 EOF 的全部原始字节计算的 SHA-256，不能
   因文件较大、为 binary 或不是 UTF-8 而截断、跳过或改写。snapshot 文件
   自身是唯一的显式成员排除项。条目按路径确定性排序；同一输入重复生成必须
   逐字节一致。完整遍历后没有任何受支持成员是合法的空 inventory，必须能
   确定性保存为合法空 snapshot。
2. B-002 snapshot 使用严格的版本化 schema。未知版本、未知字段、未知类型、
   非 64 位小写十六进制 digest，以及类型与字段的非法组合都必须拒绝：
   file 必须且只能有 `digest`，directory 不得有 digest，symlink 必须且只能有
   `link_target_digest`。不得猜测、补默认值或忽略越界字段。
3. B-003 完整 check 只产生以下五个 AGT-04 rule ID，severity 均为
   `Medium`：`AGT-04-entry-added`、`AGT-04-entry-removed`、
   `AGT-04-content-modified`、`AGT-04-entry-type-changed`、
   `AGT-04-symlink-changed`。若旧/新任一侧为 symlink，优先使用
   `AGT-04-symlink-changed`（含 symlink 新增、移除、目标变化及与
   file/directory 互换）；其余依次按单侧存在、file/directory 类型互换、
   file digest 变化判定。每个 finding 携带逻辑路径、变化类型、旧/新类型与
   适用的旧/新 digest；缺失侧或 directory digest 明确为 `null`。evidence
   精确为无空格分号 grammar
   `change=<kind>;old_kind=<kind|null>;new_kind=<kind|null>;old_digest=<hex|null>;new_digest=<hex|null>`；
   所有值只能来自已声明闭集、64 位小写 hex 或 `null`，不允许 escaping。
4. B-004 check 是只读且幂等：不得改变 snapshot 或被扫描树的 bytes/mtime，
   输入不变时 finding 的内容与顺序相同。inventory 比较完成后才运行既有语义
   扫描；语义扫描的 operational error（包括受保护 symlink hard error）
   不得丢弃已完成的 AGT-04 finding。此时输出保留这些 finding、明确标为未完整
   执行并返回 operational failure，绝不输出 clean/allow 结论。仅在这一
   partial 情形，JSON stdout 使用 camelCase envelope
   `{schemaVersion:1, executionSuccessful:false, operationalError:
   {kind:"agent_scan_incomplete", message:<sanitized>}, report:<existing
   ScanReport>}`；内嵌 report 的 decision 为 `block`。完整 snapshot check、
   update、普通无 snapshot scan 的 JSON 继续直接输出既有 `ScanReport`，不得
   加 envelope 或改字段。
5. B-005 snapshot 缺失、损坏、版本不支持、schema 字段组合非法、条目路径
   为空/绝对/含 `.` 或 `..`/含反斜线、路径非 UTF-8、目标或成员不可读、遍历
   或 hash 未覆盖全部字节、或扫描期间观察到成员变化时，必须返回 operational
   failure，不得报告 clean，也不得把未覆盖部分当作“无变化”。合法空 snapshot
   与非空 current 比较时，每个新增成员产生 `AGT-04-entry-added`；合法非空
   snapshot 与空 current 比较时，每个旧成员产生 `AGT-04-entry-removed`；
   两侧都合法为空才是 clean。
6. B-006 `--update-snapshot` 采用同目录原子替换。创建临时文件、写入、flush、
   文件 sync 或 replace 任一阶段失败时，命令返回 operational failure，旧
   snapshot 的 bytes/mtime 保持不变，临时文件被清理；不存在旧 snapshot 时
   不得留下半成品。
7. B-007 CLI 契约固定为
   `argus agent scan <PATH> --check-snapshot <FILE>`（读取并比较）与
   `argus agent scan <PATH> --update-snapshot <FILE>`（不存在则创建，存在则
   显式批准并替换）。两者互斥，且任一 snapshot/baseline 模式都只接受一个
   `<PATH>`。只读组合 `--check-snapshot <S> --baseline <B>` 允许共存；任一
   update flag（`--update-snapshot` 或 `--update-baseline`）与另外三个
   snapshot/baseline flag 全部互斥，避免把两个批准动作或批准与检查绑定为
   非原子命令。无这些 flag 时现有 CLI 行为不变。
8. B-008 symlink snapshot 条目只保存
   `link_target_digest = SHA-256(read_link 返回的原始目标字节)`；不得保存
   target 明文。snapshot 与 text/JSON/SARIF 输出只能包含逻辑路径、闭集类型、
   变化类型、内容 digest 或 link-target digest，不得包含文件正文、正文片段、
   symlink target 明文或其可逆编码。
9. B-009 五类 AGT-04 Medium finding 都进入 `allow-with-approval`，除非既有
   更高 severity finding 或 operational failure 将结论升级。check 永不表示
   批准；只有显式成功的 `--update-snapshot` 记录批准。update 不得删除、压低
   或用 exit 0 覆盖同次扫描的 AGT-01/02/03/05/LLM finding；扫描或写入未完整
   成功时不得更新 snapshot。
10. B-010 AGT-04 与普通 agent scan 对“高上下文成员”的判定必须一致，不能
    出现两套随时间漂移的名单。受支持集合至少包含现有
    `AGENTS.md`、`CLAUDE.md`、`SKILL.md`、MCP/Claude 配置、hook/skill scripts，
    并扩展到 issue 声明的全部 `.claude/**` 以及现有攻击规则/文档列出的
    `.cursorrules`、`.aider.conf.yml`、`.continuerules`、`.codexrules`、
    `.windsurfrules`；新增一种受支持路径形状时，普通扫描与 snapshot inventory
    必须在同一版本同时看到它。

## 验收标准

- [ ] 固定离线 fixture 覆盖 snapshot 创建、无变化、五类 rule、空 current
      inventory，以及 symlink target 原始字节 digest。
- [ ] 五类 finding 的 evidence 逐字节匹配 B-003 分号 grammar，值域无 escaping。
- [ ] schema 严格拒绝未知字段/非法字段组合/非规范或非 UTF-8 路径；合法
      `entries: {}` 可 round-trip。
- [ ] `empty approved → nonempty current` 逐项产生 `AGT-04-entry-added`；
      `nonempty approved → empty current` 逐项产生 `AGT-04-entry-removed`。
- [ ] file digest 流式覆盖全部字节；snapshot 自身不进入 inventory。
- [ ] check 不改变 snapshot 的 bytes/mtime；原子写入各阶段可故障注入并证明
      失败保留旧 bytes/mtime、无临时文件泄漏。
- [ ] 语义扫描成功时，既有 finding 之后追加按逻辑路径稳定排序的 AGT-04
      finding；语义 symlink hard error 时仍输出已完成的 AGT-04 finding，并将
      text/JSON/SARIF 标为执行失败；partial JSON 精确匹配 B-004 envelope，
      普通/完整 JSON 仍是 bare `ScanReport`。
- [ ] CLI help、互斥矩阵、单路径守卫、AGT-02 check 与 AGT-04 check 共存均有测试。
- [ ] README 文档化审批边界、推荐流程、五个 rule ID、存放建议与限制。
- [ ] `cargo test --workspace --all-targets`、agent corpus 与 SpecRail 门禁通过；
      新代码行覆盖率至少 80%，schema/hash/atomic/fail-closed 关键路径 100%。

## 边界情况清单

| 类别 | 判定（covered: B-xxx / N/A + 原因） |
| --- | --- |
| 空/缺失输入 | covered: B-001, B-005；合法空 snapshot 可保存，empty→nonempty 为 added，nonempty→empty 为 removed，缺失 snapshot 仍失败 |
| 错误与失败路径 | covered: B-002, B-004, B-005, B-006 |
| 授权/权限 | covered: B-007, B-009；check 与 update 的授权边界及组合已闭合 |
| 并发/竞态 | covered: B-005, B-006；扫描期变化失败，写入失败保留旧 snapshot |
| 重试/幂等 | covered: B-001, B-004, B-006 |
| 非法状态转换 | covered: B-002, B-007, B-009；非法 schema/flag 组合及失败 update 不得变为批准 |
| 兼容/迁移 | covered: B-007, B-010；默认行为与 AGT-02 check-only 组合保持兼容 |
| 降级/回退 | covered: B-004, B-005；partial 或语义 hard error 不能伪装成 clean |
| 证据与审计完整性 | covered: B-003, B-008；规则、优先级、digest 与隐私字段均冻结 |
| 取消/中断 | covered: B-006；中断等同写入阶段失败，旧 snapshot 保持不变 |

## 发布说明

新增可选的 AGT-04 安装前后高上下文 diff。推荐流程是安装前运行
`--update-snapshot` 创建受保护 snapshot，安装后运行 `--check-snapshot`，
人工审查任何 Medium 变化后再显式 update。无 snapshot flag 的扫描保持现状；
snapshot 是信任锚点，应放在被安装脚本无法写入的位置或由独立版本控制保护。
