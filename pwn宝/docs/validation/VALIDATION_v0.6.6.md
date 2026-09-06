# pwn宝 v0.6.6 验证记录

## 实机环境

- CPU：Intel Core i9-14900HX
- RAM：32GB
- GPU：RTX 4060 Laptop 8GB
- 模型：Qwen3.6-27B-Q4_K_M GGUF（约 15.4GiB 主文件）
- LM Studio：Local Server `127.0.0.1:1234`

## 实际 EXP

- 文件：`C:\Users\WYH\Desktop\软安决赛\traditional\solve.py`
- 规模：133 行 / 2908 bytes
- 静态分析：valid，56 个语义事件，1 个非阻断 Assert 诊断
- 已验证循环 add/free、show/u64 泄漏、safe-linking edit、copy、最终 ROP payload。

## LM Studio 结果

- `/v1/models` 正常返回 `qwen3.6-27b`。
- 模型加载为 context=4096、parallel=1、GPU offload=35%。
- 完整 EXP + 紧凑静态 IR 请求：估算 3017/3200 input tokens。
- 结构化请求成功耗时 175.078 秒。
- 有效候选：`add(size,idx) -> alloc roles=[size,index]`，confidence=0.98。
- 第二候选因非标准 length 角色被严格校验拒绝；经人工反馈校正后保存为 copy 精确规则。

## 学习回放

- 知识库：`%LOCALAPPDATA%\pwnbao\ai\knowledge.sqlite3`
- add 规则回放匹配 27 个 alloc 操作。
- copy 规则回放匹配 2 个 copy 操作。
- 学习后 HeapPanel 构造真实请求预算：3162/3200，仍可在 4K 上下文内分析完整 EXP。
- 未运行 EXP、未调用题目服务；所有输入均只做 AST 静态分析。

## 回归

```text
python -m unittest discover -s tests -v
Ran 87 tests
OK
```

新增专项：嵌套 show 顺序、ROP/fake-chunk 区分、紧凑 wire payload、role alias、精确 helper 规则不跨题污染。
