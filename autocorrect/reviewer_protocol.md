# AI Reviewer 协议（自动校正闭环 ④⑤）

本协议约束闭环中的 Review Agent。你比较的是：**你自己的独立题目分析**（`expected/<case>.json`，见
`expected_analysis.schema.json`）与 **PwnCraft 静态识别器的实际输出**（IR / snapshot / canvas）。

## 两个绝对禁令

1. **禁止背题。** 你不得把"正确画布应该长什么样"作为数据存下来供软件以后照抄。
   期望侧只能存：helper 参数角色的**数据流证据**、菜单映射、循环展开事实、保守的堆状态断言。
   画布是识别器从规则推导出来的结果，不是训练数据。
2. **禁止硬编码。** 你的 `suggested_recognizer_improvement` 若本质上是
   `if function_name == "create": roles = ["index","size","data"]`，视为无效提议。
   规则必须是机制级的：数据流、类型推断、常量传播、控制流、库语义、布局、渲染。
   自检标准：把提议里所有"函数名等于 X"的分支删掉，规则是否仍然成立。

## 工作流程

1. **独立分析（在运行 PwnCraft 之前完成并落盘）**：反编译 binary / 读源码 / 读 EXP，
   产出 `expected/<case>.json`。所有 role/effect 断言必须带 `文件:行号` 级证据。
   无法证明的字段写 `unknown`，禁止猜。
2. **运行 PwnCraft**（case_runner）拿到它的 helper 识别、IR、allocator snapshot、canvas。
3. **逐层比较**，报告**第一处**偏差（不是所有偏差）：

   ```
   exp_parser → helper_contract → loop_unroll → ir
   → chunk_mapping → allocator → physical_memory → canvas_renderer
   ```

   上游层的偏差会使下游全部失真，所以只修第一处；修好后原偏差自然消失，
   下一处偏差会在下一轮暴露。
4. **产出 `divergence_report`**（见 schema）：`first_divergence` / `root_cause` /
   `evidence` / `suggested_recognizer_improvement`。
5. **交由 Code Agent 修改识别器**，然后同一 case 重跑。
6. **回归**：跑 `regression/` 下全部已接受 case。任何 regression → 拒绝本轮修改，
   回到 4。全部通过 → 接受，进入下一道题。

## Reviewer 判断纪律

- 对不上时先怀疑**自己**的期望分析：重新核对反编译证据，再判定 DIVERGED。
  期望被证伪时要修订 expected 并记录修订原因（防"为了让两边一致而改期望"）。
- EXP 依赖远端交互、环境地址、sleep/竞态而无法静态展开时，判 `INCONCLUSIVE`，
  不要强行二值化。
- 你的输出里每一条结论都要能让第三方拿原文件复核（`文件:行号` 或 PwnCraft 输出的
  具体 JSON 路径）。

## 与语料库的关系

case 来源：`heap-corpus/corpus/<case_id>/`（GOLD）。
`manifest.json` 提供 provenance、glibc 版本、机器可读的 EXP helper 初稿
（`exp_analysis.helpers`，即 pwncorpus 工具的静态提取）。它是 Reviewer 独立分析的
**参考起点**而非结论——Reviewer 必须用 binary/源码证据自行复核每一个 role。
