# elf-seccomp-patcher

面向 AWD 场景的 Linux x86-64 ELF 运行时保护注入器。当前版本将保护代码放入一个新增的只读可执行 `PT_LOAD`，在原始入口点前安装：

- Landlock 文件系统白名单：默认不允许访问 `/flag`；
- seccomp-BPF：阻止 `execve`、`connect`、`ptrace`、内核模块、mount、BPF、io_uring 等危险接口；
- `PR_SET_NO_NEW_PRIVS`、`PR_SET_DUMPABLE=0`，并清空进程 capabilities；
- x86-64 syscall ABI 和 x32 syscall 检查。

项目不会覆盖 `.eh_frame`，也不会把已有 `PT_NOTE` 改成 `PT_LOAD`。C++ 异常展开信息、GNU notes 和原始入口代码均保留。

## 支持范围

- Linux x86-64；
- ELF64、小端、`EM_X86_64`；
- PIE 和 No-PIE；
- Linux 5.13+，并且内核启用了 Landlock；
- 运行 patcher 的机器需要 Python 3、GCC、GNU objcopy 和 LIEF。

Landlock 不可用或安装失败时，注入代码会在进入原程序前退出，而不会静默降级成不完整保护。动态链接 ELF 的加载器和重定位发生在主程序入口前，因此动态加载器本身不受本 guard 保护。

## 安装

```bash
python3 -m pip install -r requirements.txt
sudo apt-get install gcc binutils
```

## 基本使用

```bash
python3 patcher.py ./vuln -o ./vuln.protected
./vuln.protected
```

默认 Landlock 规则如下：

| 权限 | 路径 |
|---|---|
| 只读 | `/lib`、`/lib64`、`/usr`、`/etc`、`/dev`、输入 ELF 所在目录 |
| 读写 | `/tmp` |
| 不允许 | 其他路径，包括默认的 `/flag` |

“只读”在这里指 Landlock 文件操作权限；底层 Unix DAC 权限仍然同时生效。seccomp 会阻止再次执行程序，所以即使 `/usr/bin/sh` 位于只读允许树中也不能被执行。

### 增加业务目录

```bash
python3 patcher.py ./service -o ./service.protected \
  --allow-ro /opt/service/config \
  --allow-rw /opt/service/data
```

路径在 patch 时转换为绝对路径。移动已保护 ELF 后，原来嵌入的路径不会自动改变。

### 保护其他 flag 路径

```bash
python3 patcher.py ./service \
  --protected-path /game/flag \
  --no-default-paths \
  --allow-ro /lib \
  --allow-ro /lib64 \
  --allow-ro /usr \
  --allow-ro /opt/service \
  --allow-rw /tmp
```

Landlock 是 deny-by-default 的层级白名单，不能表达“允许 `/game` 但单独拒绝 `/game/flag`”。如果某个 allow path 是 protected path 的祖先，patcher 会拒绝生成文件，避免错误安全配置。

### 单线程服务

默认允许 `clone`，从而兼容 pthread。确认服务为单线程时可以进一步阻止线程和进程创建：

```bash
python3 patcher.py ./service --single-threaded
```

### 完全禁止运行期打开文件

程序进入原入口后不再需要配置、日志、locale、NSS 或动态插件时，可以增加：

```bash
python3 patcher.py ./service --deny-open
```

这会阻止 `open`、`creat`、`openat` 和 `openat2`。通常应先使用 Landlock 路径策略，因为完全禁止打开文件很容易破坏正常业务。

### 允许主动外连

默认阻止 `connect(2)`，服务仍可执行 `socket`、`bind`、`listen`、`accept` 和在已有连接上读写。确有数据库或上游依赖时可显式放开：

```bash
python3 patcher.py ./service --allow-connect
```

## 运行期失败码

guard 在安装失败时使用 `_exit` 退出：

| 退出码 | 含义 |
|---:|---|
| 120 | `PR_SET_NO_NEW_PRIVS` 失败 |
| 121 | Landlock ABI 不可用 |
| 122 | 创建 Landlock ruleset 失败 |
| 123 | 添加 Landlock 路径规则失败 |
| 124 | `landlock_restrict_self` 失败 |
| 125 | 安装 seccomp 失败 |
| 126 | 清空进程 capabilities 失败 |

被 seccomp 禁止的 syscall 使用 `SECCOMP_RET_KILL_PROCESS`，进程通常表现为收到 `SIGSYS`。

## 安全边界

- 如果业务本来就必须读取 flag，任意代码执行者拥有相同权限；不能仅靠本工具区分“正常读取”和“恶意读取”。
- 本工具降低 RCE 后的能力，不修复原始内存安全漏洞。
- 它不能防止拥有 ELF 文件写权限的人重新替换或修改 ELF。
- guard 在主程序 OEP 运行；动态链接器、重定位和 IFUNC 可能早于它运行。
- `/tmp` 是允许写入的，因此不要把 guard、策略或其他可信组件放在 `/tmp`；所有保护代码都已嵌入 ELF 的 RX 段。
- 默认 syscall 策略需要针对真实业务做回归测试。线程、JIT、插件、DNS、locale 和日志是常见兼容性点。

## 自动验证

GitHub Actions 在 `ubuntu-latest` x86-64 上验证：

- PIE 和 No-PIE 均能启动；
- `/etc/hostname` 等允许路径可读；
- `/flag` 返回 `EACCES`；
- `execve` 和 `connect` 触发 `SIGSYS`；
- 默认配置兼容 pthread，`--single-threaded` 会阻止 clone；
- C++ 异常仍可捕获；
- `.eh_frame` 和 `.note*` 内容保持不变；
- 重复 patch 和覆盖 protected path 的不安全 allow rule 会被拒绝。

本地 Linux x86-64 验证：

```bash
sudo sh -c 'umask 077; printf %s LOCAL_TEST_FLAG > /flag'
python3 -m pip install -r requirements.txt pytest==8.4.2
pytest -v
```
