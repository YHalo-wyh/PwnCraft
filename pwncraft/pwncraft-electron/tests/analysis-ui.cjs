// Run: node node_modules/electron/cli.js tests/analysis-ui.cjs
// Real renderer + preload; deterministic IPC fixtures, no target/terminal execution.
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const assert = require('assert/strict');
const root = path.resolve(__dirname, '..');
const out = path.resolve(root, '../artifacts/analysis-ui');
app.setPath('userData', fs.mkdtempSync(path.join(app.getPath('temp'), 'pwncraft-analysis-ui-')));
app.disableHardwareAcceleration();
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let terminal = 0;
let failNext = false;
let slowNext = false;
let checksecOutput = 'RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH\tSymbols\t\tFORTIFY\tFortified\tFortifiable\tFILE\n' +
  '\x1b[32mFull RELRO   \x1b[m   \x1b[32mCanary found   \x1b[m   \x1b[32mNX enabled \x1b[m   \x1b[32mPIE enabled  \x1b[m   \x1b[32mNo RPATH \x1b[m  \x1b[32mNo RUNPATH \x1b[m  \x1b[32mNo Symbols\t\x1b[m  \x1b[32mYes\x1b[m\t2\t\t2\t\t/bin/true\n' +
  'wsl: 检测到 localhost 代理配置，但未镜像到 WSL。';
const calls = [];
ipcMain.handle('terminal:start', () => ({ id: ++terminal }));
for (const channel of ['terminal:kill', 'terminal:resize', 'terminal:input']) ipcMain.handle(channel, () => ({}));
ipcMain.handle('bridge:request', async (_event, method, params = {}) => {
  if (method === 'heap_templates') return { templates: [] };
  if (method === 'ping') return { app: 'PwnCraft UI test', version: 'test' };
  if (method === 'import_target') return {
    context: { working_binary: params.path, original_binary: params.path },
    facts: { architecture: 'amd64', bits: 64, endian: 'little', entry: 0x1000,
      security: { RELRO: 'PARTIAL', CANARY: 'OFF', NX: 'ON', PIE: 'OFF', FORTIFY: 'OFF', STRIPPED: 'OFF' } },
    project: { project_path: 'C:/测试', project_name: '界面验证' }, static_report: 'ELF fixture',
  };
  if (method === 'binary_reports') {
    await sleep(params.path.includes('slow') ? 450 : 20);
    return { reports: { checksec: checksecOutput, file: `${params.path}: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped`, ldd: `libc.so.6 => /lib/libc.so.6 (${params.path})` }, diagnostics: { ldd: { returncode: 0, notice: 'wsl: 检测到 localhost 代理配置，但未镜像到 WSL。' } } };
  }
  if (method === 'code_analysis') {
    calls.push(params);
    if (slowNext) { slowNext = false; await sleep(450); }
    if (failNext) { failNext = false; throw new Error('fixture objdump unavailable'); }
    return { binary: params.path, notice: 'wsl: 检测到 localhost 代理配置，但未镜像到 WSL。', function_count: 2, stripped: false, functions: [
      { name: 'main', address: '0x1000', section: '.text', instruction_count: 2, assembly: '1000: 55    push %rbp\n1001: c3    ret' },
      { name: 'helper<int>', address: '0x1020', section: '.text', instruction_count: 1, assembly: '1020: c3    ret' },
    ], diagnostics: [{ severity: 'warning', code: 'UI_FIXTURE', line: 3, message: '界面测试提示：请复核当前 EXP 的输入长度。', impact: '这是一条界面测试数据。', evidence: [{ text: '<script>must remain text</script>' }] }] };
  }
  return {};
});

app.whenReady().then(async () => {
  fs.mkdirSync(out, { recursive: true });
  const win = new BrowserWindow({ width: 1280, height: 900, show: false,
    webPreferences: { preload: path.join(root, 'preload.js'), contextIsolation: true, nodeIntegration: false, backgroundThrottling: false, offscreen: true } });
  const js = source => win.webContents.executeJavaScript(source);
  const until = async condition => {
    for (let i = 0; i < 100; i++) { if (await js(condition)) return; await sleep(100); }
    throw new Error(`Timed out: ${condition}`);
  };
  const click = selector => js(`document.querySelector(${JSON.stringify(selector)}).click()`);
  const shot = async name => {
    await sleep(150);
    fs.writeFileSync(path.join(out, name), (await win.webContents.capturePage()).toPNG());
  };
  try {
    await win.loadFile(path.join(root, 'renderer/index.html'));
    await until('!!window.PwnApp && !!document.querySelector(".activity-item")');
    await click('[data-key="analysis"]');
    assert.match(await js('document.querySelector("#page-analysis").innerText'), /导入 ELF/);
    await js('window.__pwncraftDebug.importElf("C:/测试/slow-a")');
    await js('window.__pwncraftDebug.importElf("C:/测试/target-b")');
    await until('PwnApp.state.reportsFor === "C:/测试/target-b"');
    await sleep(500);
    assert.match(await js('PwnApp.state.reports.ldd'), /target-b/);
    assert.doesNotMatch(await js('document.querySelector("#ldd-rows").innerText'), /wsl/);
    assert.equal(await js('document.querySelector("#page-binary .analysis-notice")'), null);
    const securityRows = () => js('Object.fromEntries([...document.querySelectorAll("#sec-rows .sec-row")].map(row => [row.querySelector(".sec-key").textContent, row.querySelector(".sec-val").textContent]))');
    const tableRows = await securityRows();
    assert.equal(tableRows['RELRO:'], 'Full RELRO');
    assert.equal(tableRows['Stack:'], 'Canary found');
    assert.equal(tableRows['NX:'], 'NX enabled');
    assert.equal(tableRows['PIE:'], 'PIE enabled');
    assert.equal(tableRows['FORTIFY:'], 'Yes');
    assert.equal(tableRows['Stripped:'], 'No');
    assert.doesNotMatch(await js('document.querySelector("#sec-rows").innerText'), /wsl|localhost|\x1b/);
    await shot('ldd.png');
    for (const output of ['wsl: proxy notice', 'ERROR: checksec unavailable', '', '\x1b[32mNX: NX disabled\x1b[m\nStack: No canary found\nwsl: proxy notice']) {
      checksecOutput = output;
      await click('#sec-refresh');
      assert.equal((await securityRows())['RELRO:'] !== undefined, true, 'facts stay visible during refresh');
      await until('!PwnApp.state.reportsInFlight');
      const rows = await securityRows();
      assert.equal(rows['RELRO:'], 'Partial RELRO');
      assert.equal(rows['NX:'], output.includes('NX disabled') ? 'NX disabled' : 'NX enabled');
      assert.doesNotMatch(await js('document.querySelector("#sec-rows").innerText'), /wsl|ERROR|\x1b/);
      assert.equal(await js('document.querySelector(".sec-source").textContent'), output.includes('NX disabled') ? 'checksec（WSL）' : '本地 ELF 解析');
    }
    await click('[data-key="analysis"]');
    await until('document.querySelectorAll(".analysis-function").length === 2 && !PwnApp.state.workspaces.get(PwnApp.state.activePath).analysis.loading');
    assert.equal(calls.length, 1);
    assert.doesNotMatch(await js('document.querySelector("#page-analysis").innerText'), /环境提示|localhost/);
    assert.equal(await js('!!document.querySelector("[data-key=analysis] svg")'), true);
    await shot('functions.png');
    await js('let filter = document.querySelector("#analysis-filter"); filter.value = "helper"; filter.dispatchEvent(new Event("input"))');
    assert.equal(await js('document.querySelectorAll(".analysis-function").length'), 1);
    assert.match(await js('document.querySelector(".analysis-function-heading").innerText'), /helper<int>/);
    await click('[data-tab="diagnostics"]');
    assert.equal(await js('document.querySelector("#analysis-functions").hidden'), true);
    await click('.analysis-diagnostic summary');
    assert.equal(await js('!!document.querySelector(".analysis-diagnostic script")'), false);
    await shot('suggestions.png');
    await click('#analysis-open-exp');
    await click('[data-key="analysis"]');
    assert.equal(calls.length, 1, 'unchanged source reuses cache');
    failNext = true;
    await click('#analysis-refresh');
    await until('!!document.querySelector(".analysis-error")');
    assert.match(await js('document.querySelector(".analysis-error").innerText'), /fixture objdump unavailable/);
    await click('#analysis-refresh');
    await until('!document.querySelector(".analysis-error") && !PwnApp.state.workspaces.get(PwnApp.state.activePath).analysis.loading');
    slowNext = true;
    await click('#analysis-refresh');
    await js('window.__pwncraftDebug.importElf("C:/测试/target-c")');
    await click('[data-key="analysis"]');
    await until('!!PwnApp.state.workspaces.get(PwnApp.state.activePath).analysis.data');
    await sleep(500);
    assert.equal(await js('PwnApp.state.workspaces.get(PwnApp.state.activePath).analysis.data.binary'), 'C:/测试/target-c');
    win.setSize(800, 700);
    await shot('compact.png');
    assert.equal(await js('document.documentElement.scrollWidth <= innerWidth'), true);
    console.log('PASS: checksec table/ANSI/pwntools/fallback, hidden environment notices, navigation, function search, escaping, cache, retry, workspace races, compact layout');
    app.exit(0);
  } catch (error) {
    console.error(error);
    await shot('failure.png');
    app.exit(1);
  }
});
