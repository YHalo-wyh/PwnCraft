# pwn宝 v0.7.2 验证记录

## 自动化回归

```text
python -m unittest tests.test_heapviz_analyzer -v
Ran 27 tests
OK

python -m unittest tests.test_ai_integration -v
Ran 23 tests
OK

python -m unittest tests.test_ai_corpus -v
Ran 16 tests
OK

python -m unittest discover -s tests -p "test_*.py" -v
Ran 126 tests in 14.333s
OK

python -m ruff check .
All checks passed!

python -m compileall -q pwnbao tests run_pwnbao.py build.py
通过
```

## WriteUp 静态基线

命令：

```text
python -m pwnbao.tools.heap_ai_corpus artifacts\heap_ai_writeups\ctfshow_v2\manifest.json --output artifacts\heap_ai_writeups\ctfshow_v2\static_v6_all --knowledge artifacts\heap_ai_writeups\ctfshow_v2\knowledge.sqlite3 --no-resume
```

结果：

```text
23/23 completed
static_v3_all: 419 ops, aborted_cases=2
static_v4_all: 454 ops, aborted_cases=3
static_v5_all: 449 ops, aborted_cases=3
static_v6_all: 449 ops, aborted_cases=3
```

重点核查：

- pwn160：11 ops，未 abort。
- pwn164：35 ops，未 abort。
- pwn166：20 ops，未 abort，`bad_size` 消失。
- pwn179：9 ops，只保留真实 `create/delete/delete/delete` 语义；`sendMessage(payload)` 不再误识别为 free/show。

## Qwen 实机审计

命令：

```text
python -m pwnbao.tools.heap_ai_corpus artifacts\heap_ai_writeups\ctfshow_v2\manifest.json --output artifacts\heap_ai_writeups\ctfshow_v2\qwen_rules_v11 --knowledge artifacts\heap_ai_writeups\ctfshow_v2\knowledge.sqlite3 --with-ai --case local.ctfshow.pwn166 --case local.ctfshow.pwn179 --case local.ctfshow.pwn164 --no-resume
```

结果：

- pwn164：模型候选 operation 为空，validator 拒绝。
- pwn166：模型想把已识别 `add(0x68, payload+'\n', '123')` 替换成缺 data 的 alloc，strict replay 拒绝：会丢失已有静态事实。
- pwn179：模型想在已包含两个 `delete()` 的源码范围再插入 `op.free`，strict replay 拒绝：重复已有 Heap IR。

本轮没有候选满足“严格重放 + 不丢事实 + 不重复 + 晋升策略”的条件，因此没有新增全局静态规则。
