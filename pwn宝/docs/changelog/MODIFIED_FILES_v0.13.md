# v0.13 修改文件清单

## 应用与打包

- `pwnbao/__init__.py`
- `pwnbao/core/pwndbg_manager.py`
- `pwnbao/core/external_process.py`
- `pwnbao/gui/main_window.py`
- `pwnbao/gui/adaptive_tabs.py`
- `pwnbao/gui/debugger/font_resolver.py`
- `pwnbao/gui/debugger/terminal_widget.py`
- `pwnbao/gui/debugger/workspace.py`
- `pwnbao/gui/panels/pwndbg_bridge.py`
- `requirements.txt`
- `build.py`
- `pwn宝.spec`

## Heap 物理真值与可编辑画布

- `pwnbao/features/heapviz/memory/physical_memory.py`
- `pwnbao/features/heapviz/memory/provenance.py`
- `pwnbao/features/heapviz/presentation/layout.py`
- `pwnbao/features/heapviz/presentation/visual_model.py`
- `pwnbao/features/heapviz/engine.py`
- `pwnbao/gui/heap/chunk_layout.py`
- `pwnbao/gui/heap/inline_editor.py`
- `pwnbao/gui/panels/heap_canvas.py`
- `pwnbao/gui/panels/heap_panel.py`

## pwndbg-mogai Fork

- `third_party/pwndbg-mogai/`：固定 upstream 源码与 Pwnbao 扩展的完整目录。
- `third_party/pwndbg-mogai/UPSTREAM_COMMIT`
- `third_party/pwndbg-mogai/UPSTREAM_RELEASE`
- `third_party/pwndbg-mogai/pwndbg/lib/version.py`
- `third_party/pwndbg-mogai/launcher.py`
- `third_party/pwndbg-mogai/launcher.sh`
- `third_party/pwndbg-mogai/input_proxy.py`
- `third_party/pwndbg-mogai/pwndbg/commands/__init__.py`
- `third_party/pwndbg-mogai/pwndbg/ui.py`
- `third_party/pwndbg-mogai/pwndbg/pwnbao/localization/`
- `third_party/pwndbg-mogai/pwndbg/pwnbao/slash/`
- `third_party/pwndbg-mogai/pwndbg/pwnbao/tutor/`
- `third_party/pwndbg-mogai/pwndbg/pwnbao/bridge/`

## 删除的 GUI 伪实现

- `pwnbao/gui/debugger/command_palette.py`
- `pwnbao/gui/debugger/tutor_model.py`
- `pwnbao/gui/debugger/tutor_renderer.py`
- `pwnbao/pwndbg_ext/` 全目录

## 测试与审计工具

- `tests/test_heap_canvas_edit_v013.py`
- `tests/test_heapviz_gui.py`
- `tests/test_pwndbg_fork_v013.py`
- `tests/test_v013_adaptive_truth_ui.py`
- `tests/test_v013_runtime_ui_hardening.py`
- `pwnbao/tools/ui_audit_v013.py`
- `pwnbao/tools/performance_audit_v013.py`
- `pwnbao/tools/pwndbg_interactive_performance.py`

## 文档

- `README.md`
- `ARCHITECTURE.md`
- `MIGRATION_PLAN_v0.13.md`
- `DEBUGGER_ARCHITECTURE.md`
- `HEAP_CANVAS_EDITING.md`
- `PWNDBG_FORK_ARCHITECTURE.md`
- `CHANGELOG_v0.13.0.md`
- `VALIDATION_v0.13.0.md`
- `V013_ACCEPTANCE_REPORT.md`
- `MODIFIED_FILES_v0.13.md`
