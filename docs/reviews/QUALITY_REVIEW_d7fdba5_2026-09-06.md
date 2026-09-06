# PwnCraft 完成质量审查

审查日期：2026-09-06。

审查版本：[d7fdba508fd68e45ffc2e4ffbb04cd2552588465](https://github.com/YHalo-wyh/PwnCraft/commit/d7fdba508fd68e45ffc2e4ffbb04cd2552588465)。本地 HEAD 与远端 main/HEAD 一致，审查开始及测试结束时，Git 工作区均无修改。

结论：已有可用的实现增量和单元测试，但当前证据不足以将 M0—M5 判定为完成。验收门禁和跨领域运行仍有接入断点，新增识别规则存在已复现的误确认，栈金标准和数据集拆分尚不能提供独立泛化证明。当前适合作为继续开发的阶段版本。

## 验证范围与结果

- 阅读近期实现、比较器、领域适配器、接受注册表、行为绑定、栈断言生成、数据治理、封存结果和相关测试。
- 框架及重点新增测试：32 passed。
- Windows 默认编码环境下，项目全量测试：26 failed、432 passed、1 skipped。失败集中于桥接输出按 UTF-8 解码时的编码异常。
- 仅对测试进程设置 `PYTHONUTF8=1` 后，全量测试：458 passed、1 skipped，耗时 24.49 秒。编码相关失败不计为近期实现新增回归。
- 独立检查使用合成普通代码、内存字典、临时注册表及已提交的分析产物；未运行题目程序、修改识别规则、覆盖真值或刷新基线。
- 将已提交的两道 `generated/m2-final/pwncraft_output.json` 分别按现行合同和不带合同重新比较，用于核对宣称的完成范围。

全量测试通过说明现有断言通过；以下反例均未被现有测试覆盖。

## 阻断性发现

### F01 · P1：正式比较入口没有调用完整性门禁

位置：[comparator_v4.py:317](C:/Users/WYH/Desktop/pwn宝/autocorrect/comparator_v4.py:317)、[evaluation_contract.py:105](C:/Users/WYH/Desktop/pwn宝/autocorrect/evaluation_contract.py:105)。

`compare()` 直接返回汇总结果，没有执行 `evaluation_contract.enforce()`。`cmd_diverge` 和 `cmd_truthregress` 同样直接消费比较器结果。检索当前生产代码，`enforce()` 的调用仅出现在测试中。

独立检查：

| 输入 | 实际结果 | 应有结果 |
|---|---|---|
| 真值仅含 case_id，实际输出为空 | MATCH | INCONCLUSIVE |
| 上述输入，合同要求 RENDERER_PLAN、缺失产物和至少 999 项断言 | 总结果 MATCH；RENDERER_PLAN=SKIPPED | 不得通过 |

此外，`required_artifacts` 在门禁中只是复制到报告，未验证产物是否存在；计数主要依据层名估算，缺少实际逐断言执行记录。即使补上调用，也应验证材料完整性和真实计数。

修复验收：通过正式入口复测空输入、缺必需产物、缺 run_id、未执行必需断言及跳过必需层，全部阻止 MATCH。

### F02 · P1：任意三参数函数都会被提升为 EDIT

位置：[resolver.py:225](C:/Users/WYH/Desktop/pwn宝/pwn宝/pwnbao/features/heapviz/contracts/resolver.py:225)、[resolver.py:246](C:/Users/WYH/Desktop/pwn宝/pwn宝/pwnbao/features/heapviz/contracts/resolver.py:246)。

新增调用点参数提升路径检查参数数量一致，但没有验证文档声称的 index/data 实参形态，也没有要求目标写入的正证据。三个及以上参数直接使 UNKNOWN 变为 EDIT，置信度为 STRUCTURAL。

独立反例：

```python
def combine(a, b, c):
    return a + b + c

combine(1, 2, 3)
```

输出：`combine → edit / structural / CALLSITE_ARGUMENT_BINDING`。仅打印三种颜色的普通三参数函数也得到相同结果。

影响：新增规则用实参数量替代行为证据，会扩大非堆误识别，破坏“证据不足保持未知”的训练约束。

修复验收：普通运算、日志与传参函数必须作为负例；只有参数数量而无行为证据时，不得输出确定的 EDIT。

### F03 · P1：SHOW 提升没有证明收到的数据属于该调用

位置：[resolver.py:316](C:/Users/WYH/Desktop/pwn宝/pwn宝/pwnbao/features/heapviz/contracts/resolver.py:316)、[resolver.py:332](C:/Users/WYH/Desktop/pwn宝/pwn宝/pwnbao/features/heapviz/contracts/resolver.py:332)。

扫描先收集接收变量的后续使用，再将使用事件归给最近的待定 helper；消费时没有证明接收发生在该 helper 之后。

独立反例：

```python
def inspect_item(idx):
    pass

data = io.recv(8)
inspect_item(1)
print(data)
```

输出：`inspect_item → show / structural / CALLSITE_OUTPUT_FLOW`。该函数体为空，数据来自调用之前，因此这条强证据不成立。

修复验收：调用前已接收的数据、变量重赋值及无关接收流，不得用于确认该 helper 的输出行为。

### F04 · P1：最新行为绑定注入实际没有接通

位置：[pwncraft_adapter.py:301](C:/Users/WYH/Desktop/pwn宝/autocorrect/pwncraft_adapter.py:301)、[challenge_profile.py:107](C:/Users/WYH/Desktop/pwn宝/pwn宝/pwnbao/features/heapviz/semantics/challenge_profile.py:107)。

`run_case()` 接收 corpus 案例目录，并从该目录读取 `behavior_bindings.json`。两份新增绑定实际位于 `autocorrect/cases/<id>/`，适配器读取位置均没有文件。

即使将文件传入，其条目使用 `helper` 字段，而 `ChallengeCallBehavior.from_dict()` 要求 `function`。按适配器当前组装方式独立解析，得到 `ValueError: helper.function ... <empty>`。加载处的宽泛异常处理会静默退回未注入路径。

两份已提交 m2-final 运行清单的 `truth_id` 也为空：真值查找存在同样的 corpus 与 autocorrect/cases 路径分离问题。

修复验收：明确输入材料与评测目录的职责；绑定格式错误必须显式报错；运行清单须能证明绑定被读取和使用。人工行为模型驱动的回放需单独标记，不能直接作为盲识别能力证明。

### F05 · P1：跨领域适配器存在，但正式训练仍只走堆入口

位置：[loop.py:113](C:/Users/WYH/Desktop/pwn宝/autocorrect/loop.py:113)、[pwncraft_adapter.py:285](C:/Users/WYH/Desktop/pwn宝/autocorrect/pwncraft_adapter.py:285)、[domain_adapters.py:85](C:/Users/WYH/Desktop/pwn宝/autocorrect/domain_adapters.py:85)。

`CaseMaterial` 和 `run_domain()` 已实现，正式 run/generate/truthregress 以及有真值的封存执行路径仍使用 `pwncraft_adapter.run_case()`。入口归一化没有接入这些调用路径。

将现有栈案例 brop 交给当前 run_case，立即得到：`TypeError: expected str, bytes or os.PathLike object, not dict`，发生在 `Path(exp_rel)`，尚未进入领域分析。

直接调用领域适配器也不能视为金标准验收：空源码在 stack 中得到 MATCH、1/1，在 fmt 中得到 MATCH、3/3；它们没有消费独立期望。fmt 语义层提取 facts 后固定标 MATCH。将这种报告手动送入现有 enforce，又因使用不同计数结构被判为空断言集，说明两侧协议也尚未接通。

修复验收：真实字符串/对象入口均须通过正式命令到达正确适配器；领域结论依赖独立断言；空源码与缺材料得到无法判定状态。

### F06 · P1：同一来源簇仍会跨越训练集与封存集

位置：[resource_baseline.py:42](C:/Users/WYH/Desktop/pwn宝/autocorrect/resource_baseline.py:42)。

拆分使用 `hash(cluster + case_id)`，因此同簇不同编号不保证进入同一个集合。独立构造 12 个同仓库、同题目路径的变体，结果为训练集 10 个、封存集 2 个。

这会让变体进入训练和测试两端，无法使用相应结果证明独立泛化。现有 note2 也已参与修复，仍列在 validation 中，其曝光状态需要明确记录。

修复验收：以稳定来源簇一次性分配分区；镜像、同题多解和重编译变体保留簇关系；拆分前后均验证簇不跨集合。

### F07 · P1：已接受规则与局部断言没有进入真值回归

位置：[loop.py:325](C:/Users/WYH/Desktop/pwn宝/autocorrect/loop.py:325)。

注册表分为 rule/assertion/case 三类，但 truthregress 只枚举 case_acceptances。只接受局部断言、整题尚未接受的案例不会被回归。

在临时目录创建仅含一条 HELPER_CONTRACT 断言接受记录的注册表，即使相应案例和真值均不存在，命令仍报告注册表为空，结果为 exit 0、检查 0 项。

当前 case_acceptances 还有同题多条历史记录，命令会重复运行并重复计入结果。接受记录未固定 truth/contract/实现版本，无法区分不同评测范围的历史接受。

修复验收：规则、局部断言和整题的已接受范围分别回归；不存在的已接受对象阻断验收；重复历史记录不增加独立案例数。

## 栈金标准的质量缺口

### F08 · P2：栈写入位宽被错误记录为 8 字节

位置：[x86_trace.py:193](C:/Users/WYH/Desktop/pwn宝/pwn宝/pwnbao/core/x86_trace.py:193)。

当前按 mnemonic 后缀判断写入大小，普通 `mov` 默认 8 字节。实际反汇编常用寄存器宽度表达操作大小。

给解析器传入合成片段 `mov %eax,-0x4(%rbp)`，输出为 `offset=-4, size=8`；这是一条 4 字节写入。错误会污染槽位范围、重叠判断和后续界面解释。

修复验收：覆盖普通 mov 的不同操作数宽度，以及显式后缀和无法确定宽度的情况。

### F09 · P1：所谓独立栈金标准实际是被测解析器的输出

位置：[stack_gold_assertions.py:45](C:/Users/WYH/Desktop/pwn宝/autocorrect/stack_gold_assertions.py:45)、[stack_gold_assertions.py:106](C:/Users/WYH/Desktop/pwn宝/autocorrect/stack_gold_assertions.py:106)。

脚本使用项目自己的 `trace_stack_layouts()` 解析反汇编，将解析结果写为 `status=OK` 和 `OBSERVED`；不存在独立期望与实际结果的比较。byte_ranges 又来自项目自己的 ExploitIR，given_state 是同一布局结果的摘要。

因此“23/24 OK”只能说明收集过程完成，不能说明 23 题布局正确。F08 展示了会被直接写进此数据集的错误。当前 M3_real_failure 记录来自堆案例 lab13，也不能补充栈领域的失败覆盖。

修复验收：先将这些文件定位为待复核候选事实；建立独立标注、来源记录和锁定版本，再用解析器结果与之比较。

## 完成范围核对

两道堆题当前合同仅要求 HELPER_CONTRACT、STATIC_RECOGNITION、CANONICAL_IR、ARGUMENT_BINDING 四层，将 TARGET_BEHAVIOR、ALLOCATOR、BINS、PHYSICAL_MEMORY、SNAPSHOT、CANVAS_TRUTH、RENDERER_PLAN 七层列入 not_applicable_layers，比较器将其标为 DEFERRED。

对已提交 m2-final 产物重新比较：

| 案例 | 按当前合同 | 不传收缩合同 |
|---|---|---|
| lab13 | MATCH，七层 DEFERRED | DIVERGED@TARGET_BEHAVIOR |
| note2 | MATCH，七层 DEFERRED | MATCH，但仍受 F01 及内部一致性检查范围限制 |

按明确限定范围登记局部通过可以保留，但“尚未实现”不应写成领域“不适用”。四层通过也不能作为物理状态、内部多动作或完整画布正确的证据。最新提交标题关于 TARGET_BEHAVIOR 完成的描述，与 lab13 产物复核结果不一致。

封存评测当前只有 1 个案例，结果为 INCONCLUSIVE，原因为缺独立真值。该记录诚实反映了材料不足，但没有构成一次可判定的封存泛化验收。

| 里程碑 | 审查判断 |
|---|---|
| M0 验收可信 | 门禁函数和测试已有，生产接入与断言回归未完成 |
| M1 跨域接入 | 有归一化与适配模块，正式运行未贯通 |
| M2 公共语义 | 有实际增量，但 EDIT/SHOW 强证据误判需要阻断 |
| M3 栈首期 | 完成候选事实收集，尚未形成独立金标准验收 |
| M4 领域深化 | 局部组件已实现，不能据此宣称完整领域识别完成 |
| M5 泛化与稳定 | 有基线与拆分文件，拆分存在泄漏，封存结果不可判定 |

## 整改优先级

1. 先处理正式验收入口、实际断言计数和缺件检查，修正完成口径。
2. 用普通代码负例约束 EDIT/SHOW 提升，阻止无依据强确认。
3. 打通领域路由、输入归一化和行为绑定路径，验证真实命令级接入。
4. 补齐局部接受对象回归；固定真值、合同和实现版本。
5. 修正来源簇拆分，建立独立栈标注并补字节宽度反例，再进行封存验收。

审查未修改产品代码、训练规则或历史评测结果。新增内容仅为本报告。
