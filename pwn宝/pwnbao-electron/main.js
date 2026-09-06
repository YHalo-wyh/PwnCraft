/**
 * PwnCraft Electron Workbench — main process (v0.31).
 *
 * Responsibilities stay deliberately thin: one BrowserWindow, one Python
 * truth bridge (stdio JSON-RPC to `pwnbao.electron_bridge`), and terminal
 * instances through node-pty — the same terminal stack VS Code uses.
 * Terminals are *instances* now: a WSL bash per project plus one fresh
 * instance per debug session (pwndbg-mogai, the isolated fork — the
 * official pwndbg is never touched).  All Pwn truth stays in Python.
 */
const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const readline = require('readline');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const PYTHON = process.env.PWNBAO_PYTHON || 'python';
const SMOKE = process.argv.includes('--smoke');
const SHOT = process.argv.includes('--shot');

// 截图/冒烟验证可以与用户正在使用的 Workbench 并行运行，不抢占
// 正常 Electron profile 的 SingletonLock。该 profile 只是临时验证产物。
if (SHOT || SMOKE) {
  app.setPath('userData', path.join(app.getPath('temp'), `pwnbao-check-profile-${process.pid}`));
}

let mainWindow = null;
let bridge = null;
let bridgePending = new Map();
let bridgeSeq = 1;
let bridgeExpectedExit = false;
const terminals = new Map();
let terminalSeq = 0;

// ---------------------------------------------------------------------------
// Crash diagnostics：任何一层意外崩溃都落到 artifacts/logs 并在「日志/诊断」面板
// 可见 —— 绝不让窗口静默消失（闪退）。

const fs = require('fs');
function crashLog(message) {
  try {
    const dir = path.join(PROJECT_ROOT, 'artifacts', 'logs');
    fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(path.join(dir, 'crash.log'),
      `[${new Date().toISOString()}] ${message}\n`);
  } catch { /* 日志失败不追加深错 */ }
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('bridge:event', { event: 'log', message: `[崩溃防护] ${message}` });
  }
}

process.on('uncaughtException', (error) => {
  crashLog(`主进程未捕获异常: ${error.stack || error}`);
});
process.on('unhandledRejection', (reason) => {
  crashLog(`主进程未处理的 Promise 拒绝: ${reason && reason.stack ? reason.stack : reason}`);
});

// ---------------------------------------------------------------------------
// Python truth bridge

function startBridge() {
  const child = spawn(PYTHON, ['-u', '-m', 'pwnbao.electron_bridge'], {
    cwd: PROJECT_ROOT,
    env: { ...process.env, PYTHONPATH: PROJECT_ROOT, PYTHONIOENCODING: 'utf-8' },
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
  const rl = readline.createInterface({ input: child.stdout });
  rl.on('line', (line) => {
    let payload;
    try {
      payload = JSON.parse(line);
    } catch {
      return;
    }
    if (payload.id !== undefined && payload.id !== null && bridgePending.has(payload.id)) {
      const { resolve, reject } = bridgePending.get(payload.id);
      bridgePending.delete(payload.id);
      if (payload.ok) resolve(payload.result);
      else reject(new Error(payload.error || 'bridge error'));
      return;
    }
    if (payload.event && mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('bridge:event', payload);
    }
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => {
    stderr = (stderr + chunk).slice(-4000);
  });
  child.on('error', (error) => {
    crashLog(`Python 桥进程错误: ${error}`);
  });
  child.on('exit', (code) => {
    bridge = null;
    // 未预期退出：拒绝所有在途请求（否则要等 300s 超时），并提示可自动重启
    for (const [, { reject }] of [...bridgePending.entries()]) {
      reject(new Error(`Python 桥已退出(code=${code})，请重试；下次请求会自动重启桥`));
    }
    bridgePending.clear();
    if (bridgeExpectedExit) return;
    crashLog(`Python 桥意外退出(code=${code})${stderr ? ' · ' + stderr.slice(-300) : ''}`);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('bridge:event', {
        event: 'bridge_exit',
        code,
        stderr: stderr.slice(-800),
      });
    }
  });
  return child;
}

function ensureBridge() {
  if (bridge) return bridge;
  // 桥死亡后的下一次请求自动重启（目标绑定随桥丢失，需重新导入 ELF）
  bridgeExpectedExit = false;
  bridge = startBridge();
  mainWindow?.webContents?.send('bridge:event', {
    event: 'log', message: 'Python 桥已自动重启；若 Target 丢失请重新导入 ELF。',
  });
  return bridge;
}

function bridgeWrite(request) {
  // 桥已死时 stdin 是销毁的流：裸 write 会抛 EPIPE 未捕获异常直接带崩主进程（闪退根源之一）
  const child = ensureBridge();
  if (!child.stdin || child.stdin.destroyed || child.killed) {
    throw new Error('Python 桥 stdin 不可用，请稍后重试');
  }
  child.stdin.write(request);
}

function bridgeRequest(method, params = {}, timeoutMs = 300000) {
  let id;
  try {
    id = bridgeSeq++;
    bridgeWrite(JSON.stringify({ id, method, params }) + '\n');
  } catch (error) {
    return Promise.reject(new Error(`桥请求发送失败: ${error.message}`));
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      bridgePending.delete(id);
      reject(new Error(`桥请求超时: ${method}`));
    }, timeoutMs);
    bridgePending.set(id, {
      resolve: (value) => { clearTimeout(timer); resolve(value); },
      reject: (error) => { clearTimeout(timer); reject(error); },
    });
  });
}

// ---------------------------------------------------------------------------
// Terminal instances (node-pty — the VS Code terminal stack)
//
// kind "shell": WSL bash in the project directory (the pre-arranged working
// terminal).  kind "debug": one fresh instance per session running the
// pwndbg-mogai launch script prepared by the Python bridge — real PTY,
// ELF preloaded, startup flags applied, `starti` for x86 ELFs.

function toWslPath(value) {
  // ConPTY-spawned wsl.exe rejects Windows paths on --cd (Wsl/E_INVALIDARG);
  // the /mnt form is accepted, same translation as core.wsl.WslToolRunner.
  const match = /^([A-Za-z]):[\\/](.*)$/.exec(String(value || ''));
  if (!match) return '';
  return `/mnt/${match[1].toLowerCase()}/${match[2].replace(/\\/g, '/')}`;
}

function trackTerminal(term, kind, name) {
  const id = ++terminalSeq;
  terminals.set(id, { term, kind, name });
  term.onData((data) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('terminal:data', { id, data });
    }
  });
  term.onExit(({ exitCode }) => {
    terminals.delete(id);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('terminal:exit', { id, exitCode, kind });
    }
  });
  return id;
}

function startShellTerminal(cwd) {
  const pty = require('node-pty');
  const wslCwd = toWslPath(cwd);
  const args = ['--exec', 'bash', '--login', '-i'];
  if (wslCwd) args.unshift('--cd', wslCwd);
  const term = pty.spawn('wsl.exe', args, {
    name: 'xterm-256color',
    cols: 100,
    rows: 28,
    cwd: cwd || undefined,
    env: { ...process.env, TERM: 'xterm-256color', COLORTERM: 'truecolor' },
    // In-proc conpty.dll: kill() takes the clean DLL path — the legacy path
    // forks conpty_console_list_agent via process.execPath, which under
    // Electron launches electron.exe and dies with "AttachConsole failed".
    useConptyDll: true,
  });
  const id = trackTerminal(term, 'shell', 'WSL bash');
  return { id, backend: 'node-pty', kind: 'shell' };
}

function startDebugTerminal(scriptWslPath) {
  const pty = require('node-pty');
  if (!scriptWslPath) throw new Error('缺少调试启动脚本路径');
  // `bash <script>` with no -c and no quoting: the script path arrives as a
  // plain argv entry, so Windows/WSL argument translation can never mangle it.
  const term = pty.spawn('wsl.exe', ['--exec', 'bash', String(scriptWslPath)], {
    name: 'xterm-256color',
    cols: 110,
    rows: 32,
    env: {
      ...process.env,
      TERM: 'xterm-256color',
      COLORTERM: 'truecolor',
      FORCE_COLOR: '1',
      PY_COLORS: '1',
    },
    useConptyDll: true,
  });
  const id = trackTerminal(term, 'debug', 'pwndbg-mogai');
  return { id, backend: 'node-pty', kind: 'debug' };
}

function killTerminal(id) {
  const entry = terminals.get(Number(id));
  if (!entry) return false;
  try { entry.term.kill(); } catch { /* already gone */ }
  terminals.delete(Number(id));
  return true;
}

function stopTerminals() {
  for (const [, entry] of terminals) {
    try { entry.term.kill(); } catch { /* already gone */ }
  }
  terminals.clear();
}

// ---------------------------------------------------------------------------
// Window

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1600,
    height: 960,
    minWidth: 1180,
    minHeight: 700,
    backgroundColor: '#1f1f1f',
    show: false,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      spellcheck: false,
    },
  });
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  mainWindow.webContents.on('console-message', (_e, level, message, line, sourceId) => {
    if (level >= 2) console.log(`CONSOLE[${level}]: ${message} (${path.basename(String(sourceId))}:${line})`);
  });
  mainWindow.once('ready-to-show', () => mainWindow.show());
  // 渲染进程崩溃 → 记录并自动恢复，白屏/闪退感降到最低
  mainWindow.webContents.on('render-process-gone', (_event, details) => {
    crashLog(`渲染进程退出: ${details.reason} (exitCode=${details.exitCode})`);
    if (details.reason === 'clean-exit') return;
    setTimeout(() => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        crashLog('渲染进程自动重载恢复');
        mainWindow.webContents.reload();
      }
    }, 800);
  });
  app.on('child-process-gone', (_event, details) => {
    if (details.type === 'GPU' || details.type === 'Utility') return; // 噪声
    crashLog(`子进程退出: ${details.type} ${details.reason}`);
  });
  if (SMOKE) {
    mainWindow.webContents.on('console-message', (_e, level, message, line, sourceId) => {
      console.log(`SMOKE RENDERER[${level}]: ${message} (${sourceId}:${line})`);
    });
  }
  mainWindow.on('closed', () => { mainWindow = null; });
}

// ---------------------------------------------------------------------------
// IPC surface

ipcMain.handle('bridge:request', (_event, method, params) => bridgeRequest(method, params));
ipcMain.handle('terminal:start', (_event, { cwd, kind, name }) => {
  if (kind === 'debug') return startDebugTerminal(name);
  return startShellTerminal(cwd);
});
ipcMain.handle('terminal:kill', (_event, id) => killTerminal(id));
ipcMain.handle('terminal:input', (_event, { id, data }) => {
  const entry = terminals.get(Number(id));
  if (!entry) return false;
  // kill/create 竞态下 write 到已销毁的 ConPTY 会带崩主进程，必须吞掉
  try { entry.term.write(String(data)); return true; }
  catch (error) { crashLog(`终端写入失败(#${id}): ${error}`); return false; }
});
ipcMain.handle('terminal:resize', (_event, { id, cols, rows }) => {
  const entry = terminals.get(Number(id));
  if (!entry) return false;
  try { entry.term.resize(Math.max(10, cols | 0), Math.max(2, rows | 0)); return true; }
  catch (error) { crashLog(`终端 resize 失败(#${id}): ${error}`); return false; }
});
ipcMain.handle('dialog:openElf', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: '选择 ELF 绑定为 Target',
    properties: ['openFile'],
    filters: [{ name: 'ELF / All Files', extensions: ['*'] }],
  });
  if (result.canceled || !result.filePaths.length) return '';
  return result.filePaths[0];
});
ipcMain.handle('dialog:saveFile', async (_event, defaultName, kind) => {
  const filters = kind === 'json'
    ? [{ name: 'PwnCraft 场景', extensions: ['json'] }]
    : [{ name: 'Python', extensions: ['py'] }];
  const result = await dialog.showSaveDialog(mainWindow, {
    title: kind === 'json' ? '保存堆场景' : '保存 exp 文本',
    defaultPath: String(defaultName || 'exp.py'),
    filters,
  });
  if (result.canceled || !result.filePath) return '';
  return result.filePath;
});
ipcMain.handle('dialog:openFile', async (_event, kind) => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: kind === 'json' ? '打开堆场景' : '打开文件',
    properties: ['openFile'],
  });
  if (result.canceled || !result.filePaths.length) return '';
  return result.filePaths[0];
});

// ---------------------------------------------------------------------------
// Lifecycle

app.whenReady().then(() => {
  bridge = startBridge();
  createWindow();
  if (SMOKE) runSmoke();
  if (SHOT) runShots();
});

app.on('window-all-closed', () => {
  bridgeExpectedExit = true;
  stopTerminals();
  if (bridge) { try { bridge.kill(); } catch { /* gone */ } }
  app.quit();
});

// ---------------------------------------------------------------------------
// Screenshot verification: welcome → import temp ELF → binary → heap →
// debug → rop → palette.

async function runShots() {
  const fs = require('fs');
  const outDir = path.join(PROJECT_ROOT, 'artifacts', 'ui_audit_v030');
  fs.mkdirSync(outDir, { recursive: true });

  // PWNBAO_SHOT_IMPORT=<绝对路径>：用真实 ELF 复现导入链路（默认仍造最小假 ELF）。
  const importPath = process.env.PWNBAO_SHOT_IMPORT || '';
  let elfDir;
  let targetPath;
  if (importPath) {
    targetPath = importPath;
    elfDir = path.dirname(importPath);
  } else {
    // Minimal amd64 ELF, same shape as the unit tests use.  Fresh folder per
    // run: import_target marks the original read-only, so reusing a directory
    // would fail the copy on the second pass.
    elfDir = path.join(app.getPath('temp'), `pwnbao-shot-target-${Date.now()}`);
    fs.mkdirSync(elfDir, { recursive: true });
    const header = Buffer.alloc(64);
    Buffer.from('\x7fELF\x02\x01\x01\x00', 'binary').copy(header, 0);
    header.writeUInt16LE(0x3e, 18);
    header.writeUInt32LE(1, 16);
    header.writeBigUInt64LE(BigInt(0x401000), 24);
    fs.writeFileSync(path.join(elfDir, 'pwn'), header);
    targetPath = path.join(elfDir, 'pwn');
  }

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const shot = async (name) => {
    const image = await mainWindow.webContents.capturePage();
    fs.writeFileSync(path.join(outDir, name), image.toPNG());
    console.log(`SHOT ${name}`);
  };
  const run = async (script) => {
    try {
      return await mainWindow.webContents.executeJavaScript(script, true);
    } catch (error) {
      console.log(`RUN ERR: ${error.message} :: ${script.slice(0, 80)}`);
      return null;
    }
  };

  await sleep(7000); // bridge + xterm + monaco settle
  await shot('01-welcome.png');

  await run(`window.__pwnbaoDebug.importElf(${JSON.stringify(targetPath)})`);
  await sleep(9000); // WSL static tools + terminal restart
  await shot('02-binary.png');

  await run('window.__pwnbaoDebug.switchPage("heap")');
  // EXP 驱动：写堆构造行 → 自动识别上屏（Semantic Round Trip 主链路）
  await run(`window.PwnApp.insertExpText([
    "add(0, 0x80, b'A')",
    "add(1, 0x80, b'B')",
    "add(2, 0x80, b'C')",
    "edit(0, 0x88, p64(0x421))",
    "free(1)",
  ].join('\\n') + '\\n')`);
  await sleep(12000); // 识别 + 回放 + 物理沉降（冷 WSL 桥可能排队）
  await run('window.__pwnbaoDebug.switchPage("heap")');
  await run('window.__pwnbaoDebug.heapAdvance && window.__pwnbaoDebug.heapAdvance(6)');
  await sleep(2500);
  await shot('03-heap.png');

  await run('window.__pwnbaoDebug.switchPage("rop")');
  await sleep(1500);
  await shot('04-rop.png');

  await run('window.__pwnbaoDebug.switchPage("debug")');
  await sleep(1500);
  await shot('05-debug.png');

  await run('window.__pwnbaoDebug.switchPage("welcome"); window.__pwnbaoDebug.openPalette()');
  await sleep(1200);
  await shot('06-palette.png');

  console.log('SHOTS DONE');
  app.exit(0);
}

async function runSmoke() {
  const results = [];
  const ok = (name, pass, detail = '') => {
    results.push(pass);
    console.log(`SMOKE ${pass ? 'PASS' : 'FAIL'}: ${name}${detail ? ' · ' + detail : ''}`);
  };
  setTimeout(() => {
    ok('overall-timeout', false, 'smoke did not finish in 45s');
    console.log(`SMOKE RESULT ${results.every(Boolean) ? 'OK' : 'BROKEN'}`);
    app.exit(results.every(Boolean) ? 0 : 1);
  }, 45000).unref?.();

  try {
    const pong = await bridgeRequest('ping', {}, 20000);
    ok('bridge.ping', pong.version.startsWith('v0.3'), pong.version);
  } catch (error) {
    ok('bridge.ping', false, String(error));
  }

  let termId = null;
  try {
    const started = await startShellTerminal('');
    termId = started.id;
    ok('terminal.start', started.backend === 'node-pty', started.backend);
  } catch (error) {
    ok('terminal.start', false, String(error));
  }

  // VNext.3: EXP 拖拽代码块 UI 契约 (API 存在 / 面板渲染 / Monaco 落点插入)
  try {
    const dnd = await mainWindow.webContents.executeJavaScript(
      "(function(){" +
      "  const api = window.PwnExpDnD;" +
      "  if (!api) return {present:false};" +
      "  const palette = document.querySelectorAll('#exp-chip-palette .pwncraft-code-chip').length;" +
      "  const editor = api.editor;" +
      "  let inserted = null;" +
      "  if (editor) {" +
      "    const before = editor.getValue();" +
      "    const dt = new DataTransfer();" +
      "    dt.setData('text/pwncraft-code', 'leak = u64(leak.ljust(8, b\x00) = 0)');" +
      "    const node = editor.getDomNode();" +
      "    const rect = node.getBoundingClientRect();" +
      "    const drop = new DragEvent('drop', {bubbles:true, cancelable:true," +
      "      clientX: rect.left + 40, clientY: rect.top + 40, dataTransfer: dt});" +
      "    node.dispatchEvent(drop);" +
      "    inserted = editor.getValue() !== before;" +
      "  }" +
      "  let editable = null, edited = null;" +
      "  const chip = document.querySelector('.pwncraft-code-chip');" +
      "  if (chip && window.PwnExpDnD) {" +
      "    window.PwnExpDnD.beginInlineEdit(chip);" +
      "    const box = chip.querySelector('.pwncraft-chip-edit');" +
      "    editable = !!box;" +
      "    if (box) { box.value = 'edited_payload_test';" +
      "      (chip.__pwncraftCommitEdit || (() => {}))();" +
      "      edited = chip.__pwncraftDnd === 'edited_payload_test'; }" +
      "  }" +
      "  let noElfLinkage = null, codeDragFlag = null;" +
      "  try { const dt = new DataTransfer(); dt.setData('text/pwncraft-code', 'x=1');" +
      "    const ev = new DragEvent('dragstart', {dataTransfer: dt});" +
      "    Object.defineProperty(ev, 'target', {value: chip});" +
      "    chip.dispatchEvent(ev);" +
      "    codeDragFlag = window.__pwncraftCodeDrag === true;" +
      "    const end = new DragEvent('dragend', {dataTransfer: dt});" +
      "    chip.dispatchEvent(end);" +
      "    noElfLinkage = window.__pwncraftCodeDrag === false;" +
      "  } catch (e) { noElfLinkage = null; }" +
      "  return {present:true, palette: palette, editorReady: !!editor, inserted: inserted," +
      "          editable: editable, edited: edited," +
      "          noElfLinkage: noElfLinkage, codeDragFlag: codeDragFlag};" +
      "})()", true);
    ok('exp.dnd.present', dnd.present === true);
    ok('exp.dnd.palette', dnd.palette > 0, `${dnd.palette} chips`);
    if (dnd.editorReady) ok('exp.dnd.insert', dnd.inserted === true);
    ok('exp.dnd.editable', dnd.editable === true,
       `editable=${dnd.editable} edited=${dnd.edited}`);
    ok('exp.dnd.no-elf-linkage', dnd.noElfLinkage === true,
       `codeDragFlag=${dnd.codeDragFlag}`);
  } catch (error) {
    ok('exp.dnd', false, String(error));
  }

  const waitData = setInterval(() => {
    // terminal:data already flows to the renderer; check via renderer console.
    mainWindow?.webContents.executeJavaScript(
      'window.__smokeTermBytes ? window.__smokeTermBytes : 0', true,
    ).then((n) => {
      if (n > 0 && !results.includes('terminal.bytes-done')) {
        results.push('terminal.bytes-done');
        ok('terminal.bytes', true, `${n} chars from WSL bash`);
        console.log(`SMOKE RESULT ${results.every(Boolean) ? 'OK' : 'BROKEN'}`);
        app.exit(results.every(Boolean) ? 0 : 1);
      }
    }).catch(() => {});
  }, 500);
  setTimeout(() => clearInterval(waitData), 40000);
}
