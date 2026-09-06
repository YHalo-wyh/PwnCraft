# v0.13 修改文件清单

## 应用与打包

- `pwncraft/__init__.py`
- `pwncraft/core/pwndbg_manager.py`
- `pwncraft/core/external_process.py`
- `pwncraft/gui/main_window.py`
- `pwncraft/gui/adaptive_tabs.py`
- `pwncraft/gui/debugger/font_resolver.py`
- `pwncraft/gui/debugger/terminal_widget.py`
- `pwncraft/gui/debugger/workspace.py`
- `pwncraft/gui/panels/pwndbg_bridge.py`
- `requirements.txt`
- `build.py`
- `pwncraft.spec`

## Heap 物理真值与可编辑画布

- `pwncraft/features/heapviz/memory/physical_memory.py`
- `pwncraft/features/heapviz/memory/provenance.py`
- `pwncraft/features/heapviz/presentation/layout.py`
- `pwncraft/features/heapviz/presentation/visual_model.py`
- `pwncraft/features/heapviz/engine.py`
- `pwncraft/gui/heap/chunk_layout.py`
- `pwncraft/gui/heap/inline_editor.py`
- `pwncraft/gui/panels/heap_canvas.py`
- `pwncraft/gui/panels/heap_panel.py`

## pwndbg-mogai Fork

- `third_party/pwndbg-mogai/`：固定 upstream 源码与 PwnCraft 扩展的完整目录。
- `third_party/pwndbg-mogai/UPSTREAM_COMMIT`
- `third_party/pwndbg-mogai/UPSTREAM_RELEASE`
- `third_party/pwndbg-mogai/pwndbg/lib/version.py`
- `third_party/pwndbg-mogai/launcher.py`
- `third_party/pwndbg-mogai/launcher.sh`
- `third_party/pwndbg-mogai/input_proxy.py`
- `third_party/pwndbg-mogai/pwndbg/commands/__init__.py`
- `third_party/pwndbg-mogai/pwndbg/ui.py`
- `third_party/pwndbg-mogai/pwndbg/pwncraft/localization/`
- `third_party/pwndbg-mogai/pwndbg/pwncraft/slash/`
- `third_party/pwndbg-mogai/pwndbg/pwncraft/tutor/`
- `third_party/pwndbg-mogai/pwndbg/pwncraft/bridge/`

## 删除的 GUI 伪实现

- `pwncraft/gui/debugger/command_palette.py`
- `pwncraft/gui/debugger/tutor_model.py`
- `pwncraft/gui/debugger/tutor_renderer.py`
- `pwncraft/pwndbg_ext/` 全目录

## 测试与审计工具

- `tests/test_heap_canvas_edit_v013.py`
- `tests/test_heapviz_gui.py`
- `tests/test_pwndbg_fork_v013.py`
- `tests/test_v013_adaptive_truth_ui.py`
- `tests/test_v013_runtime_ui_hardening.py`
- `pwncraft/tools/ui_audit_v013.py`
- `pwncraft/tools/performance_audit_v013.py`
- `pwncraft/tools/pwndbg_interactive_performance.py`

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
