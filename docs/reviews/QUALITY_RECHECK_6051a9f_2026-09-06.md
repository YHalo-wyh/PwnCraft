# 质量审查九项发现修复复验

日期：2026-09-06。

复验版本：`6051a9f427d896fe97badf713eafbc6318f7eb47`，复验开始时本地 HEAD 与远端 main 一致。对照版本：`d7fdba5`。

结论：九项发现目前均未达到完整关闭条件。其中 F01、F02、F08 有局部改善；F03 原反例仍失败；F04 引入运行入口异常；F05、F06、F07、F09 的相关实现未改变，原问题继续存在。

本次提交修改了四个实现文件，并纳入上一份审查报告，没有新增或修改测试。现有测试继续通过，但不能证明九项修复生效。

## 逐项结果

| 编号 | 状态 | 复验结果 |
|---|---|---|
| F01 门禁 | 部分修复 | 带合同时空验收被阻止；不带合同时仍 MATCH。声明必需证据但实际为空，仍可得到 MATCH、1/1 |
| F02 EDIT 误判 | 部分修复 | 普通加法函数恢复 UNKNOWN；增加无关的常量发送后，仍被认成 EDIT / structural |
| F03 SHOW 归属 | 未解决 | 原来“调用前接收、调用后打印”的反例仍为 SHOW / structural |
| F04 行为绑定 | 新增阻断，未关闭 | 路径修正引用未定义 ROOT，run_case 对普通合成输入直接 NameError；绑定字段不匹配也未修复 |
| F05 跨域接入 | 未解决 | 真实栈题仍在对象形式入口处 TypeError；空源码的 stack/fmt 适配器仍返回 MATCH |
| F06 来源簇拆分 | 未解决 | 上次相同的 12 个同簇变体仍为训练集 10、封存集 2 |
| F07 局部断言回归 | 未解决 | 仅注册一项局部断言时仍执行 0 项、exit 0 |
| F08 栈位宽 | 部分修复并出现回归 | `%eax` 写入改为 4 字节；显式 movb/movl 立即数写入反而被记成 8 字节 |
| F09 独立金标准 | 未解决 | 生成脚本和断言文件均未变化，仍由被测解析器输出直接生成 OK 记录 |

## 需要优先处理的阻断

### F04：运行入口新增 NameError

位置：[pwncraft_adapter.py:302](C:/Users/WYH/Desktop/pwn宝/autocorrect/pwncraft_adapter.py:302)。

新增语句使用 `ROOT / "autocorrect" / "cases"`，模块只定义了 `_OUTER` 和 `_PROJECT_ROOT`，没有 `ROOT`。错误发生在绑定加载的异常处理之前。

复验使用临时合成案例：入口文件只含 `pass`，manifest 使用正常字符串入口，不含目标程序。调用 `run_case()` 得到：

```text
NameError: name 'ROOT' is not defined
```

因此常规堆案例的 run/generate/truthregress 路径会在这里终止。绑定 JSON 的 `helper` 与解析器要求的 `function` 仍不匹配；直接解析已提交的 lab13 绑定仍得到：

```text
ValueError: helper.function 必须是 Python 函数名: <empty>
```

关闭条件：正式入口能使用合成案例贯通；绑定路径、schema 与身份均有效；格式错误不能静默退回无绑定路径。

### F01：门禁仍有缺口

位置：[comparator_v4.py:319](C:/Users/WYH/Desktop/pwn宝/autocorrect/comparator_v4.py:319)、[evaluation_contract.py:105](C:/Users/WYH/Desktop/pwn宝/autocorrect/evaluation_contract.py:105)。

门禁只在 `contract is not None and not collect_all` 时调用，因此无合同的原空输入反例仍为 MATCH。带合同的原反例已变为 INCONCLUSIVE，这一局部修复有效。

另一个检查给真值声明一项第 10 行后的 bin_empty 断言，合同要求 BINS 和 physical_memory.json，而实际输出为空。结果仍为：

```text
MATCH
planned=1, executed=1, matched=1
```

原因是必需产物未被验证，BINS 在找不到对应操作时跳过，计数又按层名将其算作执行成功。

关闭条件：区分实际执行断言与跳过断言；验证必需输入、输出及身份；无合同也应阻止空验收。

### F02：发送存在不等于编辑证据

位置：[resolver.py:231](C:/Users/WYH/Desktop/pwn宝/pwn宝/pwnbao/features/heapviz/contracts/resolver.py:231)。

修正增加了“函数体含 send”的条件，能挡住原普通加法函数，但仍未证明参数与编辑动作的关系。

独立反例：

```python
def ping(a, b, c):
    io.sendline(b"ping")

ping(1, 2, 3)
```

三个参数完全未使用，只发送固定文本，结果仍为 `edit / structural / CALLSITE_ARGUMENT_BINDING`。

关闭条件：无关发送、未使用参数及普通消息函数不能作为 EDIT 强证据。

### F03：检查了消费顺序，没有检查数据来源

位置：[resolver.py:353](C:/Users/WYH/Desktop/pwn宝/pwn宝/pwnbao/features/heapviz/contracts/resolver.py:353)。

新增条件只要求消费行晚于 helper 调用行；原反例正好满足这个条件，所以根因仍在：

```python
def inspect_item(idx):
    pass

data = io.recv(8)
inspect_item(1)
print(data)
```

结果仍为 `show / structural / CALLSITE_OUTPUT_FLOW`。数据接收发生在 helper 调用之前，不能证明空函数产生了输出。

关闭条件：建立该调用与实际接收定义的关联，不能只比较消费行号。

### F08：寄存器补丁丢失了显式指令位宽

位置：[x86_trace.py:194](C:/Users/WYH/Desktop/pwn宝/pwn宝/pwnbao/core/x86_trace.py:194)。

当前改为只查源寄存器表，未知源默认 8。立即数不在寄存器表内，因此显式位宽被忽略：

| 指令 | 应有字节数 | 当前输出 |
|---|---:|---:|
| `mov %eax,-0x4(%rbp)` | 4 | 4，原反例已修正 |
| `movb $0x1,-0x1(%rbp)` | 1 | 8，新增回归 |
| `movw $0x1,-0x2(%rbp)` | 2 | 8 |
| `movl $0x1,-0x4(%rbp)` | 4 | 8，新增回归 |
| `mov %sil,-0x1(%rbp)` | 1 | 8 |

关闭条件：保留显式位宽，覆盖操作数寄存器宽度，对无法确定的情况避免默认输出错误确定值。

## 未改变的四项

- **F05**：[正式入口](C:/Users/WYH/Desktop/pwn宝/autocorrect/loop.py:113)和领域适配器未改变。真实 brop 案例仍在 `Path(exp_rel)` 处报 `TypeError: expected str, bytes or os.PathLike object, not dict`。空源码分别得到 stack MATCH 1/1、fmt MATCH 3/3。
- **F06**：[拆分逻辑](C:/Users/WYH/Desktop/pwn宝/autocorrect/resource_baseline.py:42)未改变。完全复用上次来源簇输入，仍有训练 10、封存 2，簇隔离不成立。
- **F07**：[注册表枚举](C:/Users/WYH/Desktop/pwn宝/autocorrect/loop.py:325)未改变。临时注册一个缺材料的已接受局部断言，执行结果仍为检查 0 项、exit 0。
- **F09**：[栈金标准生成](C:/Users/WYH/Desktop/pwn宝/autocorrect/stack_gold_assertions.py:45)及 stack_gold_assertions.json 与对照版本无差异。解析器产出仍直接写为 OK，没有独立断言比较。

## 测试与范围说明

- 设置 `PYTHONUTF8=1` 后，项目现有全量测试：458 passed、1 skipped，耗时 38.47 秒。
- autocorrect 框架测试：8 passed。
- 所有新增反例均为静态解析、比较器数据检查或临时材料检查，没有执行题目程序。
- 未运行会覆盖现有真值回归产物的正式批处理；局部注册表检查在临时目录执行。
- 产品代码、历史真值与基线保持原样，本轮新增内容仅为复验报告。

下一次关闭验收应同时包含原始反例、相邻边界反例以及正式命令入口。当前全量测试未覆盖未定义 ROOT 这一直接入口异常，绿灯结果不能代替修复项验收。
