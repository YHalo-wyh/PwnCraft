# v0.7.5 验证记录

## 模型/语料验证

- 小探针：
  - 已识别 `add/free`：Qwen 返回空 proposals。
  - `do4(slot)` 菜单 free：静态规则已识别，Qwen 返回空 proposals。
  - `do7(a,b,n)` 菜单 copy：静态规则已识别，Qwen 返回空 proposals。
- 软安决赛语料：
  - v11：`artifacts/heap_ai_corpus/ruanan_finals_v1_ai_v11_minimal_dedupe`
    - 12/12 completed，0 over_budget。
  - v13：`artifacts/heap_ai_corpus/ruanan_finals_v1_ai_v13_negative_rules`
    - 12/12 completed，0 over_budget，0 raw candidate，0 strict reject。

## 新增/更新测试点

- Qwen role object slip：`{'name':'index'}` 会规范化为 `index`。
- compact catalog slip：`operation:{id,args,need}` 会规范化并由 strict validator/replay 继续把关。
- nested catalog slip：`operation:{op:{type,args}}` 会规范化。
- `index=0` 不再被 catalog required 参数检查误判为缺失。
- minimal static prompt 会折叠重复 timeline 行。
- 菜单 helper `choice=4/7/3` 在证据充分时可无 AI 识别为 free/copy/show。

## 已执行回归

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
python -m ruff check .
python -m compileall -q pwncraft tests run_pwncraft.py build.py
```

## 结果

- 全量回归：133 项通过。
- `ruff`：All checks passed。
- `compileall`：通过。
