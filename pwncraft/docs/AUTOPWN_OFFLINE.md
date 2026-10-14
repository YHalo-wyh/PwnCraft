# AutoPwn 离线 MVP（实验性）

这是 **真实可执行的第一阶段后端**，不是“拖入任意题目即可自动解出 Flag”。

## 已实现

- 只读识别 ELF 架构、大小端与 SHA-256；不执行输入文件。
- 有界、可重复的 stdin 崩溃探测，保存触发样本与复验信息（不是 AFL++，不含覆盖率反馈）。
- 对人工准备的多个 Python EXP 并发执行、条件命中后取消其他任务、独立复验、保存 JSON。
- 全部采用 Python 标准库，不访问公网、不依赖云端模型。

## 在独立、可销毁的 Linux VM 中运行

在仓库内层 \`pwncraft/\` 目录下：

\`\`\`bash
python3 -m unittest tests.test_autopwn_offline -v
python3 -m pwncraft.features.autopwn inspect ./challenge
python3 -m pwncraft.features.autopwn probe ./challenge --out ./artifacts/autopwn/probe --runs 100 --execute-untrusted
python3 -m pwncraft.features.autopwn verify ./challenge --manifest ./candidates.json --out ./artifacts/autopwn/verify --expected-regex 'GOAL_OK' --workers 3 --replays 2 --execute-untrusted
\`\`\`

候选清单的相对脚本路径相对于清单文件解析：

\`\`\`json
{"candidates":[
  {"name":"ret2win","script":"exp_ret2win.py","priority":20},
  {"name":"rop","script":"exp_rop.py","priority":10}
]}
\`\`\`

候选脚本第一个参数是目标 ELF 的绝对路径。脚本 stdout 命中用户提供的正则且退出码为 0 才满足条件。

## 重要的限制

- **不是沙箱**：仅隔离工作目录、限制执行时间；WSL/宿主环境运行不可信文件存在风险。建议独立 VM 关闭联网、禁用共享宿主目录。
- **匹配 stdout 不等于实际利用成功**。候选脚本可以伪造输出，不能把结果当成已拿到 Shell/Flag 的证明。
- 未实现 AFL++ 覆盖率 Fuzz、菜单/TCP Harness、GDB 自动偏移推断、任意 ELF 自动 EXP 生成、实际 GUI 一键工作流。
- Electron 桥当前只提供只读 \`autopwn_inspect\` / \`autopwn_capabilities\` 接口；执行功能保持 CLI 显式授权。

## 后续集成

接下来需要在 Linux 隔离服务进程中实现异步任务状态、真实 Oracle、Fuzz Harness，再把状态显示到 Electron Binary 页；复用原 Synth/ROP/Heap 模块而不是重新写一套未验证的漏洞推理器。
