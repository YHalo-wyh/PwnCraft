# pwn宝 v0.7.1 验证记录

## 自动化回归

Windows Python + PyQt5 offscreen：

```text
python -m unittest discover -s tests -p "test_*.py" -v
Ran 114 tests in 8.030s
OK

python -m ruff check .
All checks passed!

python -m compileall -q pwnbao tests run_pwnbao.py build.py
通过
```

## 本地 WriteUp 语料

- 输入目录：`F:\PWN\PWN\99PWN\00_WriteUp`
- PDF：5 份，461 页；原件未复制到项目。
- 扫描：165 个题目段，123 个可恢复 Python case，23 个 Heap corpus case。
- PDF SHA256、来源页、glibc/架构证据和 technique split 均写入本地清单；未知 glibc 标记为 `unspecified; review required`，模拟默认版本不宣称为题目真实版本。
- 23 题静态批处理全部完成：IR 总数由旧基线 351 提升到 419，`unmapped_call` 从 2 降到 0。
- 关键增量：pwn144 `1 -> 9`、pwn163 `1 -> 25`、pwn164 `0 -> 35`、pwn161 `17 -> 18`；其他题保持稳定。

## Qwen 实机审计

- 服务：`http://127.0.0.1:1234/v1`
- 模型：`qwen3-coder-30b-a3b-instruct`
- 预算：4096 context / 3584 input / 512 output / temperature 0.1 / 180 秒。
- pwn173：模型给出错误源码锚点，validator 拒绝，未重放、未学习。
- pwn179：helper 没有暴露 malloc size，模型提交 `request_size=null` 且锚点无效，validator 拒绝；程序保持 unknown，没有伪造 chunk size。
- pwn144：模型把已正确识别的 `edit_heap(3,0x90,payload)` 改写成十进制 size。新增等价 IR 归一化后，该候选被判为 no-op，不能进入 fixture 或规则库。

## 事实边界

- EXP/静态 AST 是 source truth，严格 allocator replay 是 derived truth，Pwndbg 解析结果才可成为 observed truth。
- 本版“训练”只指规则证据、正负反馈、fixture 和 holdout 晋升，不修改 Qwen 权重。
- AI 不能直接修改画布；任何接受后的图仍由新的 Heap IR 重新执行 allocator replay 生成。
