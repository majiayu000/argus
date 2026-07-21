# Product Spec

## Linked Issue

GH-112

complexity: medium

## 用户问题

PR #105 合并后，连接器在已通过 pre-merge 门禁的提交上又报出三条 P1 绕过面。
它们的共同形态是：真实的凭证外泄路径在语法层已经存在结构化信息，但分类层
没有消费该信息，于是高风险行为被静默降级为非阻断，用户会误以为扫描结果干净。

- exec argv 形态只检查 argv token 0，`["env", "-S", "curl …"]` 实际执行的是
  curl，却被判定为执行 `env`。
- curl 的文件来源关联只扫描 curl 自身的 operand，
  `curl --data-binary @- … < ~/.aws/credentials` 的凭证内容从 fd0 进入，
  从未作为 operand 出现。
- 文件读取分类只识别 `open(...)`，
  `requests.post(..., data=Path("…/.aws/credentials").read_text())`
  发送的是文件内容，却被当作普通字符串参数。

## 目标

- exec argv 与 command-string 两种形态在 wrapper 解码上收敛为同一有界路径。
- 重定向保留类型化来源（fd、方向、目标），并只在客户端语义确实消费 stdin
  时参与网络关联。
- 嵌套接收者调用产生的文件内容与 `open(...)` 使用同一结构化文件读取来源。
- 三类反例各自阻断，相邻良性输入保持非阻断。

## 非目标

- 不执行被扫描脚本，不联网验证。
- 不放宽有界解析预算，不新增递归解释层级。
- 不新增凭证目录、agent 配置目录或网络客户端清单。
- 不改变已有 finding ID、severity、decision 或 JSON 输出结构。
- 不新增针对样本 payload 的特判或裸 substring 兜底。

## Behavior Invariants

1. B-001 当 exec 调用为 argv 形态且 argv token 0 是受支持的 shell wrapper
   （`sudo`/`env`）时，必须通过与 command-string 形态相同的有界 wrapper
   解码器还原被包装的实际客户端与 operand，并保持 argv 的 StaticValue
   形状与 provenance。
2. B-002 wrapper 解码必须沿用既有的一次性 split-string 预算；第二层
   split-string、动态命令与无法静态取得的 wrapper 目标不得被猜测，必须
   保持非阻断。
3. B-003 被包装的客户端不属于受支持网络客户端时，不得因为解码而产生
   网络相关 finding。
4. B-004 shell 重定向必须保留类型化来源：描述符、方向与目标。方向未被
   本解析器建模时保守视为输出，以保留既有写入检测行为。
5. B-005 只有输入方向且作用于 stdin（隐式或显式 fd0）的重定向，且客户端
   自身语义确实从 stdin 读取 payload 时，重定向目标才参与敏感来源关联。
6. B-006 输出重定向写入其目标，输入重定向读取其目标；输入重定向不得再
   被判定为 agent 配置写入。
7. B-007 产出文件内容的嵌套接收者调用（`Path(path).read_text()` 等）必须
   与 `open(path)` 归一为同一结构化文件读取来源，供网络参数消费。
8. B-008 接收者解码只接受可静态取得的字面路径；动态路径、非读取方法与
   仅出现凭证路径文本而未读取的输入不得产生 secret-exfil。
9. B-009 三类修复必须复用既有 fact 形状、静态值与有界解析抽象，不得依赖
   逐个新增 callee 分支或针对样本的字符串匹配。
10. B-010 任一输入无法安全解析时必须保守保留既有 capability 或
    analysis-incomplete 证据，不得静默伪造干净结论。

## 验收标准

- [ ] 三条 issue 反例分别被阻断，且证据来自结构化语法/来源数据。
- [ ] 相邻良性输入（良性 operand、非网络客户端、非 stdin 描述符、
      `nc -z`、动态值、仅路径文本）保持非阻断。
- [ ] 输入重定向不再被计为 agent 配置写入，输出重定向仍被计入。
- [ ] `cargo test --workspace --all-targets` 与仓库确定性检查通过。

## 边界情况清单

| 类别 | 判定（covered: B-xxx / N/A + 原因） |
| --- | --- |
| 空/缺失输入 | covered: B-002, B-004 |
| 错误与失败路径 | covered: B-002, B-010 |
| 授权/权限 | N/A：离线静态扫描，不读取外部权限状态 |
| 并发/竞态 | N/A：单次扫描只消费内存中的不可变脚本内容 |
| 重试/幂等 | covered: B-009；同一输入重复扫描走同一结构化事实路径 |
| 非法状态转换 | N/A：不引入持久化状态机 |
| 兼容/迁移 | covered: B-003, B-006, B-008 |
| 降级/回退 | covered: B-004, B-010 |
| 证据与审计完整性 | covered: B-001, B-005, B-007 |
| 取消/中断 | N/A：扫描中断由现有调用方处理 |

## 发布说明

向后兼容的检测正确性修复。用户可见变化：此前漏报的三类输入现在产生既有
finding；此前把输入重定向误计为 agent 配置写入的情况不再产生该 finding。
不新增 CLI 参数、配置迁移或输出字段。
