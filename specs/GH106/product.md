# Product Spec

## Linked Issue

GH-106

complexity: large

## 用户问题

`argus agent scan` 已能扫描 `AGENTS.md`、`CLAUDE.md`、MCP 描述、skills 与
hooks，并用 AGT-02 对描述元数据做 hash baseline。但依赖安装、生成器或更新
脚本会新增、删除或修改这些高信任输入，而单次词法扫描只能回答“当前内容是否
可疑”，无法回答“本次安装具体改了什么”。

AGT-02 的 baseline 以描述条目为键，只覆盖 MCP/skill 的 description 字段；
它不覆盖文件集合的增删，也不覆盖 `AGENTS.md`、`.cursorrules` 等指令文件的
正文变化。因此一个恶意 postinstall 脚本可以写入一份全新的 `AGENTS.md`，
在下一次扫描中该文件只会被当作“存在且当前看起来正常”的输入。

## 目标

- 提供显式的安装前 snapshot / 安装后 check 工作流，覆盖受支持的高上下文路径。
- 报告新增、删除、内容修改、文件类型变化与 symlink 变化，且证据可审计。
- 任何无法完整完成的比较都显式失败，绝不降级为 clean。
- snapshot 的更新是显式批准动作，不能由普通 check 隐式覆盖。

## 非目标

- 不执行包安装器、package manager、hook 或被扫描代码。
- 不保存或输出高上下文文件明文。
- 不替代版本控制 diff、代码审查或 AGT-01 语义检测。
- 不实现动态 sandbox。
- 不自动信任新 snapshot。
- 不改变 AGT-01/AGT-02/AGT-03/AGT-05 既有 finding ID、severity 或输出结构。

## Behavior Invariants

1. B-001 snapshot 模式对受支持高上下文路径集合生成持久化快照，记录逻辑
   相对路径、内容 digest 与条目类型；条目按路径确定性排序，同一输入重复
   生成必须逐字节一致。
2. B-002 snapshot 必须带版本化 schema。读取到未知或不受支持的版本时必须
   显式失败，不得按当前版本猜测解释。
3. B-003 check 模式比较 snapshot 与当前树，并区分五类变化：新增、删除、
   内容修改、条目类型变化（文件/目录互换）、symlink 变化（新增、移除或
   目标改变）。每类变化产生带逻辑路径、变化类型与旧/新 digest 的 finding。
4. B-004 check 模式为只读且幂等：不写入 snapshot、不修改被扫描树，重复
   运行在输入不变时产生相同结论。
5. B-005 snapshot 缺失、损坏、版本不受支持、目标路径不可读、或扫描未能
   完整覆盖声明范围时，必须产生显式失败结论与 operational error，不得
   报告 clean，也不得把未覆盖部分当作“无变化”。
6. B-006 update 模式采用原子替换写入新 snapshot；写入任一阶段失败时必须
   保留原 snapshot 不被破坏，并返回错误。
7. B-007 update 是独立的显式动作。check 模式在任何情况下都不得写入或
   刷新 snapshot。
8. B-008 snapshot 与所有输出格式（text、JSON、SARIF）只包含逻辑路径、
   digest、条目类型与变化类型，不得包含高上下文文件正文、正文片段或可还原
   正文的编码。
9. B-009 被判定为高风险的变化必须要求人工批准，不能仅凭 check 通过就
   被视为已接受；批准状态由显式 update 动作体现。
10. B-010 AGT-04 复用既有 surface 分类与 baseline 持久化抽象；不得为特定
    包管理器、特定文件名或特定安装器新增特判路径。

## 验收标准

- [ ] 创建 snapshot、未变化复查、新增、删除、修改、symlink/类型变化均有
      离线 fixture。
- [ ] snapshot 使用版本化 schema、确定性排序与内容 digest；输出不泄露明文。
- [ ] snapshot 缺失、损坏、版本不支持、目标不可读或扫描不完整时显式失败。
- [ ] check 模式只读且幂等；update 模式原子替换，失败保留旧 snapshot。
- [ ] finding 与 JSON/text/SARIF 输出保留变化类型、路径与旧/新 digest。
- [ ] README 文档化审批边界、推荐流程与限制。
- [ ] `cargo test --workspace --all-targets` 与 corpus 门禁通过。

## 边界情况清单

| 类别 | 判定（covered: B-xxx / N/A + 原因） |
| --- | --- |
| 空/缺失输入 | covered: B-005；snapshot 缺失与空目标集合都必须显式区分于 clean |
| 错误与失败路径 | covered: B-002, B-005, B-006 |
| 授权/权限 | covered: B-007, B-009；批准边界由显式 update 动作表达 |
| 并发/竞态 | covered: B-006；原子替换避免半写 snapshot 被读取 |
| 重试/幂等 | covered: B-001, B-004 |
| 非法状态转换 | covered: B-002；不受支持的 schema 版本不得被降级解释 |
| 兼容/迁移 | covered: B-002, B-010 |
| 降级/回退 | covered: B-005；不存在“部分覆盖即通过”的降级路径 |
| 证据与审计完整性 | covered: B-003, B-008 |
| 取消/中断 | covered: B-006；中断的 update 必须保留旧 snapshot |

## 发布说明

新增显式的安装前后高上下文文件 diff 能力。默认行为不变：不带 AGT-04 参数
的扫描与现状一致。启用后新增 AGT-04 类 finding 与 snapshot 文件；snapshot
只含路径与 digest，不含文件正文。
