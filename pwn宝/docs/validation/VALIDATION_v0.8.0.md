# v0.8.0 验证记录

## 覆盖重点

- receiver 假阳性与本题行为模型优先级。
- helper 0/1/N effect 展开、typed safe-linking expression 和场景 schema 4 roundtrip。
- heap/bin 固定列、真实 heap base、top chunk、紧邻 chunk、地址栏缩放映射和 snapshot diff。
- compact 主图不泄漏 `PROTECT_PTR(...)` 长表达式，完整字段仍可在详细模式与 Inspector 查看。
- 行为模型 JSON 错误可见、非破坏性，非法导入不会中断 GUI。

## 视觉验证

- 使用 Windows Qt 平台、`Qt.WA_DontShowOnScreen` 和 `QWidget.render()` 生成：
  - `artifacts/ui_audit/canvas_v08_windows_final.png`
- 已核对：地址无重叠或省略、chunk 上下紧邻、top chunk 对齐、bin 固定在右栏、上低下高。

## 回归命令

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
python -m ruff check .
python -m compileall -q pwnbao tests run_pwnbao.py build.py
```

## 结果

- unittest：144 项通过。
- `ruff`：All checks passed。
- `compileall`：通过。
- AI 错误模型用例打印的 `model_mismatch` JSON 为预期测试输出，不是回归失败。
