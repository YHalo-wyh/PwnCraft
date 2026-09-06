# CHANGELOG v0.31.0 — 闪退根治 + checksec 本地解析 + 概览页瘦身 + glibc/IOFILE 版本校准 + 堆活操作表单

> 日期：2026-08-29。上一版本 v0.30.1（PyQt 版退役）。本轮响应用户实测反馈：
> 导入 ELF 闪退、checksec 未正常调用、概览页信息重复、glibc/IOFILE 版本切换准确性、
> 以及堆工作台核心设计规格（用户操作 glibc 而不是图）。

## 一、闪退根治（多层崩溃防护）

定位到的真实崩溃链：Python 桥进程死亡后 `bridge.stdin.write` 裸写在已销毁的流上抛
EPIPE 未捕获异常 → **Electron 主进程崩溃 → 窗口闪退**。此外 node-pty 在 kill/create
竞态下 write/resize 已销毁 ConPTY 同样可能带崩主进程。修复：

- `startBridge`：新增 `child.on('error')`；桥意外退出时**拒绝所有在途请求**（不再傻等
  300s 超时）、记录 `artifacts/logs/crash.log` 并提示；下一次请求经 `ensureBridge()`
  **自动重启桥**（目标绑定随桥丢失，日志明确提示重新导入 ELF）。
- `bridgeWrite`：stdin 已销毁/已死时抛可恢复错误并转成明确的请求失败，绝不裸写。
- 主进程 `uncaughtException` / `unhandledRejection` 兜底 → crash.log + 「日志/诊断」面板，
  不再静默退出。
- `render-process-gone` → 记录 + 800ms 后自动 reload（渲染层崩溃不再留下白屏）。
- `terminal:input` / `terminal:resize` 全部 try/catch + 存活校验。
- 渲染端 `restartShellTerminal` 加代币序列化：快速连续导入/切换工作区时丢弃过期重启，
  消除 kill/create 竞态；`importElf` 加在途守卫（导入中忽略新请求）。

## 二、checksec 本地 ELF 解析（不再依赖 WSL checksec 工具）

用户实测：WSL 里没有 `checksec` 工具 → 导入后所有保护显示未知，即「checksec 没有正常调用」。
修复（诚实呈现原则不破）：

- 新增 `core/workbench.parse_elf_security(path)`：直接从 ELF 字节解析
  PIE（e_type）/ NX（PT_GNU_STACK RWE）/ RELRO（PT_GNU_RELRO + DT_FLAGS·BIND_NOW /
  DT_FLAGS_1·NOW，经 PT_LOAD vaddr→offset 翻译）/ CANARY（`__stack_chk*` 符号）/
  FORTIFY（`__*_chk` 符号）/ STRIPPED（.symtab 缺失），值域与 `parse_checksec_output`
  一致（ON/OFF/FULL/PARTIAL/NONE/UNKNOWN），全程有界扫描（符号表 ≤8MB）防畸形文件。
- `BinaryInspector.inspect`：checksec 工具输出优先、本地解析兜底，`facts.security_source`
  标注来源（elf-parser / checksec / checksec+elf-parser）。
- 导入流程**去掉 WSL checksec 调用**（导入更快、离线可用）；Binary 页有 checksec 按钮
  供工具级输出，并新增来源提示「保护状态由本地 ELF 解析得出」。
- 验证：WSL 真实 `/bin/true`（PIE ON/NX ON/CANARY ON/RELRO FULL/FORTIFY ON/STRIPPED ON）与
  `gcc -z execstack -no-pie -z norelro -fno-stack-protector` 裸二进制（全 OFF/NONE）双向比对正确；
  新增 `tests/test_v031_elf_security.py` 6 项（纯字节构造 ELF，不依赖 WSL/gcc）。

## 三、概览页瘦身

Binary 页已完整呈现 Target 信息，概览页不再重复：删除 checksec 卡、当前状态卡、快捷键卡，
只保留大导入方框 + 最近导入（居中布局，拖放区加大）。保护/架构/libc 统一在侧栏 target 卡
与 Binary 页查看。

## 四、glibc / IOFILE 版本校准

- 发现：IO FILE 页下拉含 **2.29**，但后端 `GlibcFileLayoutDatabase.SUPPORTED` 没有
  （选了就报「不支持的 glibc IO FILE 布局」）；且缺 2.37 / 2.39。
- 修复：`iofile_layout` 响应新增 `supported_versions`（单一真值），IO FILE 下拉从响应渲染；
  ≥2.40 的钳位结果回写到选中项。
- 堆画布 glibc 下拉补全 2.37 / 2.39（`GlibcPolicy.for_version` 全版本通用，2.29/2.33 有效）。
- 顺带核实：safe-linking 阈值 `>= 2.32`、tcache key 检查 `>= 2.29`、malloc/free hook 移除
  `>= 2.34`，与 glibc 实际一致。

## 五、全局 bug 扫描修复

- **heap/IOFILE 架构恒为 amd64**：`heap.js` 读 `window.PwnApp.arch` / `.bits`，但 PwnApp
  从未暴露这两个属性 → 32 位目标一直按 amd64/64 位仿真。现在 PwnApp 暴露 `arch`/`bits`
  getter（跟随当前工作区事实）。
- 概览页拖放监听重复绑定导致一次拖入多次导入的隐患（v0.30 已修，本轮回归确认）。

## 六、堆工作台：活操作表单 + 画布视觉层（核心设计规格落地）

规格：用户操作的是 glibc 而不是图——`表单 → HeapOperation → AllocatorEngine →
PhysicalMemory → Snapshot → Canvas`，Canvas 只显示结果。审计结论：真值层四层架构
（PhysicalMemory/provenance、AllocatorState（engine 内 chunks/bins/arena）、TypedViews、
serialize_snapshot 的 CurrentModelSnapshot）与 HeapOperation（ALLOC/FREE/EDIT/SHOW/…）
**本就按此架构存在**；缺口是"活会话单操作入口"和表单 UI。本轮补齐：

- `HeapSession.append_operation(kind, …)` + 桥 `heap_operation` RPC：表单字段只构造
  `HeapOperation` 追加进 scenario，然后**整段确定性重放**（同一管线，无第二真值）。
  alloc 未填标签按已有 ALLOC 次数自动命名 A/B/C…；edit 的 offset 走引擎既有的
  `meta["offset"]` → `user_addr + offset → PhysicalMemory.write()`，越界天然产生
  OverwriteEdge/CoverageSpan（跨对象写自动显形）。
- 操作序列页顶部新增**常驻四表单**（malloc：请求大小/填充数据/标签；free：chunk；
  edit：chunk/offset/data；show：chunk），执行后显示引擎解释行
  （如 `request=0x78 -> chunk size=0x80`、`从 top chunk 切出`、`user ptr=…`）与警告，
  时间线自动步进到最新 snapshot。
- 画布：每 chunk 一个**稳定身份色**（标题+顶边地址刻度；左沿 accent 条保留 lifecycle
  语义色与图例不冲突）；gutter 顶部新增 `─ 0x…` 绝对地址刻度（地址空间视图标尺点）；
  卡片拖动改为**仅纵向 + 8px 网格吸附 + chunk 顶/底边对齐参考线**（±6px 吸附，虚线显示，
  松手消失）——拖动只改视觉布局，地址/顺序真值永远来自 snapshot；拖动不再要求
  编辑画布模式（语义修改仍走 editMode 双击校正）。
- 契约测试 `tests/test_v031_heap_operation.py`：malloc 表单走完整 allocator 管线
  （request2size/top chunk/user ptr 断言）、edit offset 记录 OverwriteEdge、未知 kind 干净拒绝。

仍属规格但**本轮未做**（需新增操作语义，记入遗留）：fake chunk 必须对应真实
PhysicalMemory（BSS/STACK/mapped）的"把一段内存解释成 chunk view"操作。

## 七、验证

- `pytest tests/test_v031_elf_security.py` 6 项；`tests/test_v031_heap_operation.py` 3 项；
  26 个测试文件分片跑（offscreen）全绿。
- `npm run smoke`（bridge.ping v0.31.0 / terminal.start / terminal.bytes）OK。
- `npx electron . --shot` 六页截图人工核对（欢迎页单列大框、Binary 页保护芯片 + 来源提示）。
