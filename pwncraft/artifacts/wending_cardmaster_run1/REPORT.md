# 网鼎杯 Semis/cardmaster 训练报告

## 结论

已完成静态识别与 WSL 运行时验证。核心确认项是 `set info` 将 `suit_count=0` 后进入 shuffle，触发 `SIGFPE`，属于可复现拒绝服务；尚无 Canary 泄漏和 RIP 控制证据，不判定 RCE。

## 关键证据

- 目标为 x86-64 PIE、Full RELRO、Canary、NX。
- `set info` 的 scanf 输入缺少完整范围约束，`suit_count=0` 可达除零路径。
- `show cards` 使用固定牌组数组，超出 52 的数量存在越界写/DoS 候选，但当前未证明控制返回地址。
- 自动报告初始摘要：high=1、info=7、confirmed=0；运行时除零证据单独记录在训练产物中。

## 利用链状态

- `input-division-dos`：运行时确认，链状态为 `candidate/runtime_proven`（影响已确认，尚未涉及代码执行）。
- `integer-boundary-bypass`：blocked，需证明计数值传播到越界访问。
- 栈控制流/R​​OP：blocked，Canary、PIE 和 Full RELRO 均要求额外泄漏或写原语。

## AWDP 修复思路

1. 对 suit_count、randomize_level 等整数做显式范围检查，拒绝 0、负值和超上限。
2. shuffle 前保证分母/计数非零，异常输入安全返回。
3. show cards 以数组容量为边界，禁止数量超过 52；所有索引统一使用无符号校验。
4. 保留 PIE、Canary、Full RELRO、NX，并对 scanf 使用长度/格式约束。
