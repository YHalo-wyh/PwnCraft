# 中国公开 CTF Pwn 赛题：离线训练候选库

此目录管理 **已核对来源路径、已锁定 Git 提交的题源清单**，而非“已经解出/已经完成训练”的题目。它遵守 [General Pwn Training Protocol](GENERAL_PWN_TRAINING_PROTOCOL.md)。

## 来源与固定划分

| 赛事 | 题目数 | 固定 split | 原始题目材料 |
|---|---:|---|---|
| LitCTF 2026（官方） | 6 | train | 六道 Pwn 的 `Attachment/main.c`、Docker 构建文件及出题方 EXP；需本地编译 |
| 0xGame 2024（公开题库） | 8 | train | 各周 Pwn 题的 dist tar.gz / 源码 / 目录 |
| LilCTF 2025（官方） | 5 | validation | `challenges/pwn-*/attachment` 与 `build` 构建流程，部分附件为脚本或符号链接 |
| CISCN / 长城杯 2024（第三方存档） | 4 | frozen_test | `attachments/` 内的 `anote.zip`、`anyip.zip`、`avm.zip`、`novel1.zip` |

共 **23 道**。赛事级拆分，防止同源题的相似样本跨训练/验证/测试泄漏。

来源：<https://github.com/ProbiusOfficial/LitCTF2026>、<https://github.com/X1cT34m/0xGame2024>、<https://github.com/Lil-House/LilCTF-2025>、<https://github.com/CTF-Archives/2024-CCB-CISCN-Quals>。

## 一键审核候选库（断网也可）

仓库根目录运行：

```bash
python3 autocorrect/public_china_pwn_catalog.py
python3 -m unittest autocorrect.tests.test_public_china_pwn_catalog -v
```

审核器仅读取 JSON 和本地 manifest。没有附件就显示 `pending_material_import`，**绝不**显示训练就绪。它不发网络请求，不执行 ELF，不导入已知 EXP，不自动下载外部代码。

## 进入真实训练的步骤

1. 在在线机器上按 JSON 的 `source_url` 下载**公开原题材料**，严格使用固定 `revision` 对应的版本，并自行确认对应题目的复用许可。
2. 在离线虚拟机中解压并生成二进制（如需要），保存原题二进制、libc/ld、生成过程、原始源码、已审查 EXP；记录每件材料的 SHA-256。
3. 依照 [challenge_intake.py](challenge_intake.py) 所需的结构，创建 `autocorrect/cases/<case_id>/manifest.json`。固定 split 已注册在 `splits.json`。
4. 在**任何** PwnCraft 分析结果产生前执行 material-readiness / split gate；Phase A 独立真值固定后再进行 Phase B 基线评测。
5. 仅用 `train` 做差异驱动与修复，`validation` 只测泛化，`frozen_test` 只最终验收。

建议指标：ELF 可导入率、Fuzz 真实崩溃复现率、受控 RIP/EIP 证明率、利用链真实运行成功率、错误成功判定数、平均本地耗时。**不使用“输出了 PWN_SYNTH_OK”作为独立利用成功证据**。

## 重要边界

- 这里只存题目元数据和来源链接，**不复制可能受版权约束的第三方二进制、题解或 EXP**。
- 类型标签是预期训练能力，不等同于已经独立确认的漏洞事实。
- 对 PwnCraft而言“训练”目前是**真实题回归 + 确定性规则修复**，不是训练神经网络。
- 不可信文件只在无外网、无宿主共享挂载的隔离 Linux VM 中执行；GitHub 仓库中的二进制不直接运行。
