# 项目内部命名统一

项目目录、Python 包、Electron 包、通信接口、环境变量、启动脚本与文档统一采用 PwnCraft 命名。外层检出目录可以任意命名。

- 仓库内主项目位于 `pwncraft/`，Python 包位于 `pwncraft/pwncraft/`，Electron 位于 `pwncraft/pwncraft-electron/`。
- 在主项目目录运行 Python 桥：`python -m pwncraft.electron_bridge`。
- 在 Electron 目录运行 `npm start`；仓库根目录的一键启动脚本仍然可用。
- Python 解释器覆盖变量为 `PWNCRAFT_PYTHON`，截图目标变量为 `PWNCRAFT_SHOT_IMPORT`。
- 工作副本目录使用 `.pwncraft/`；本次已迁移当前工作区内的既有目录。其他检出目录中的旧缓存可通过重新导入目标生成。
- 数据集默认划分种子现在为 `pwncraft-v1`，重新生成划分时结果可能变化。既有划分清单未重新生成；比较训练结果时应固定同一份划分清单。

界面功能保持原有行为。本次同时收录代码分析页的回归测试。
