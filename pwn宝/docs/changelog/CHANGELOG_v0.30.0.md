# CHANGELOG v0.30.0 — PwnCraft 品牌 + 多 ELF 工作区 + checksec 竖排卡片

> 日期：2026-08-29。上一版本 v0.29.0（Electron Phase B 全量迁移）。
> 本版本完成三件事：产品更名 **PwnCraft**；概览首页瘦身（删引导/能力介绍，
> 拖入区旁竖排 checksec 卡片）；**一个 ELF 一个工作区**（多 Target 并存、互不串扰）。

## 一、品牌更名 pwn宝 → PwnCraft

- 用户可见面全部更名：Electron 窗口标题（index.html）、状态栏、欢迎页大字、
  package.json `productName`、主进程文件对话框（"PwnCraft 场景"）、启动日志；
  PyQt 版窗口标题（主窗 + PlaceholderDialog）、启动日志、heap_panel / AI 提示文案；
  `build.py` 打包名 → `PwnCraft.exe`；README 标题与正文（目录路径保持不变）。
- 真值层身份：`pwnbao.__init__` `APP_NAME = "PwnCraft"`、`APP_VERSION = "v0.30.0"`。
  Python 包名 `pwnbao`、`.pwnbao` 项目目录、localStorage 键名**不变**（代码身份，非品牌）。
- 契约同步：`test_v028_electron_bridge` 的 ping 断言（app=PwnCraft，version 前缀 v0.3）、
  `main.js` 冒烟的版本前缀断言同步更新。

## 二、概览首页（Electron）

- 删除：标题下副标题、"我要做什么"目标跳转格（GOALS）、"能力（规则式，诚实呈现）"卡。
- 新增 **checksec 竖排卡片**：与 Binary 页"架构"卡同构（card + fact-row），位于拖入区旁，
  PIE / NX / CANARY / RELRO / FORTIFY / STRIPPED 每行一项，✓ 开启（绿）/ ◐ 部分（琥珀）/
  ✗ 关闭（灰）/ ? 未知（灰）；checksec 输出缺失时诚实提示"保护状态未知"。
- 修复一个存量渲染 bug：`parse_checksec_output` 归一化值域是
  `ON/OFF/FULL/PARTIAL/NONE/UNKNOWN`，而旧 chip 判定找 `"enabled"` 子串，
  导致所有保护芯片永远显示 ✗。现在 `secInfo()`（app.js 暴露，pages.js/sidebar 共用）
  按真实值域判定，Binary 页芯片与侧栏芯片一并修正。
- 修复拖放监听重复绑定：renderWelcome 重建 drop-square 但把 dragover/drop 绑在
  `#page-welcome` 上，多次渲染会叠加监听导致一次 drop 触发多次导入；
  现改为 `data-drop-bound` 守卫的一次性委托绑定。

## 三、一个 ELF 一个工作区（Electron + bridge）

- Renderer：`state.workspaces: Map<elfPath, entry>`。每个工作区独立保存
  context / facts / static_report / patch 摘要 / arch / bits / **EXP 草稿**；
  `#tabbar` 下新增 `#workspace-bar`（"工作区"标签 + 每 ELF 一枚 tab，点击切换、✕ 关闭，
  关闭当前工作区自动回落到最近一个，全部关闭回到空态并重启 shell 终端）。
- 切换工作区 = bridge `import_target { light: true }` 重绑单一真值：
  bridge 端按 `路径|mtime|size` 缓存首次导入的 facts / static_report / patch 结论，
  light 命中时跳过 WSL patch/checksec/readelf 重跑，但 `PwnWorkspace`
  的 project / target / binary section / entry 变量**完整重绑**（UI 不造第二真值）；
  缓存未命中或缓存不完整自动回退完整导入。响应形状与完整导入完全一致。
- 工作区切换时：EXP 草稿随工作区保存/恢复（Monaco），shell 终端随新 project 目录重启，
  当前数据页（Binary/ROP/Format/Syscall/Stack/Tools/Debug）按新 Target 重渲染；
  Heap 画布是独立仿真沙盘，保持原状。EXP 模板的 `ELF('./…')` 现按当前工作区文件名生成。
- `pwnbao/core/session/target.py`：`import_target` 幂等修复（`_refresh_copy`）——
  原始副本导入后被 chmod 只读，重复导入同一 ELF 时 Windows 上覆盖拷贝会
  PermissionError；现在字节一致直接跳过，不一致先清只读位再拷贝。

## 四、测试

- 新增 `tests/test_v030_electron_bridge_light_import.py`：ping 报 PwnCraft；
  light 导入响应形状与完整导入一致、静态报告缓存复用；A→B→A 切换后
  workspace 真值（project_name / working_binary）指向最后选中的 ELF；
  未导入路径 light 自动回退完整导入。
- 更新 `tests/test_v028_electron_bridge.py` 契约断言（PwnCraft / v0.3 前缀）。
- 验证：`pytest tests/ -q` 全量；`npm run smoke`（bridge.ping / terminal.start /
  terminal.bytes）；`npx electron . --shot` 人工核对 `artifacts/ui_audit_v030/` 六张截图
  （欢迎页无引导区 + checksec 卡、Binary 页工作区条 + 芯片真实状态）。
