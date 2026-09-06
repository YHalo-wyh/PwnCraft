# pwncraft v0.10.2

## Chunk overlap

- 删除 chunk 之间额外的 overlap ownership 条、间距和标记。
- 普通 `free(A) -> malloc(B)` 的旧 stale view 只作为历史保留，不触发 overlap 换色；物理卡直接显示新 chunk B 的正常颜色。
- 按真实物理地址边界切分 chunk body：单 owner 区段使用所属 chunk 的稳定色，多 owner 交集仅对对应方块换成独立 clay 色。
- logical alias 只在 chunk header 第二行显示完整色签，不使用右下角按钮或 `QGraphicsProxyWidget`。
- header 增高并重新排版 chunk id、idx/size 与 views，避免文字相撞或截断；普通审计场景继续保持横纵滚动范围为 0。

## ELF tools

- 新增 `ELF 工具` 菜单以及主窗口、EXP 编辑器、Pwndbg 工作区的 ELF 拖放入口。
- 自动按优先级寻找同目录 `ld-linux*.so* / ld-*.so*` 和 `libc.so.6 / libc-*.so*`。
- 通过 `wsl.exe --exec patchelf` 设置 interpreter、`$ORIGIN` rpath，并在本地 libc 文件名不是 `libc.so.6` 时替换 `DT_NEEDED`。
- 原 ELF 同名写回前生成微秒时间戳备份；patch 后核对 interpreter、rpath、needed，失败自动回滚。

## Pwndbg linked workspace

- 新增独立 `Pwndbg 2026.07.29` 工作区和菜单；不再把 Pwndbg 校准塞进 HeapViz 控制页。
- 固定官方 x86_64 portable release、下载 URL 与 SHA256，首次使用按需安装到 WSL 用户目录。
- 内置交互式 Pwndbg/GDB 终端；启动后和每条手动命令结束后自动采集 `tcachebins`、`fastbins`、`bins`、`heap --count 128`。
- marker 快照会实时 diff 当前 HeapViz step，并同步显示 matched/mismatch/unknown；调试器证据只标为 `CALIBRATED`，不静默改写 allocator 真值。

## HeapViz cleanup

- 删除 `Pwndbg 校准` 控制页签。
- 删除重复的 `Bin 文本` 控制页签；bin 与 show 内容统一保留在右侧独立 `BIN / SHOW` 画布。
- HeapViz 控制区现在固定为 6 页：语义操作、自定义 Chunk、函数适配、同步时间线、当前步骤细节、AI 校正。
