# v0.13.0

- 删除顶部 `ELF 工具` / `Pwndbg` 重复菜单，仅保留下方主工作区导航。
- 引入固定 upstream commit 的完整 `Pwndbg-Pwnbao Fork`，移除 GUI Tutor、GUI Slash Palette、GUI command catalog 和旧 `pwnbao/pwndbg_ext`。
- 在 Fork 内实现中文 Context、原生主题、Slash live registry/argparse、Frame/Ret/RBP、Safe-Linking、`cyclic-find` 和轻量 Runtime Bridge。
- 修复 Slash OSC 过滤器滞留 `pwndbg>` 尾部导致交互卡住的问题。
- Terminal 使用独立 CJK 字体、双 cell clip、dirty-row 和 ASCII run 批绘；中文不再粘连，context burst P95 从约 80 ms 降至 16 ms。
- Heap Canvas 增加 8 个 resize handles、纵向/Alt 二维拖动、网格吸附、响应式 ChunkLayoutEngine、结构化 Chunk Size 编辑和原子快照重建。
- overlap 颜色由当前 PhysicalMemory provenance/真实交集驱动；normal reuse 和视觉碰撞不变色；partial overwrite 按 byte span 着色。
- 更新 UI/性能审计、Fork 静态/动态回归和 PyInstaller 数据收集。
