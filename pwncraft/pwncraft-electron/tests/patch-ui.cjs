// Run: node node_modules/electron/cli.js tests/patch-ui.cjs
// Real renderer + preload; deterministic IPC fixtures, no target/terminal execution.
// Verifies the AWDP Patch page: manual instruction patching, recipe preview/apply,
// bytecode catalog + disasm + rel32 calculator, patch log management and exports.
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const assert = require('assert/strict');
const root = path.resolve(__dirname, '..');
const out = path.resolve(root, '../artifacts/patch-ui');
app.setPath('userData', fs.mkdtempSync(path.join(app.getPath('temp'), 'pwncraft-patch-ui-')));
app.disableHardwareAcceleration();
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let terminal = 0;
const calls = [];
const reply = (method, result) => ({ method, result });
let appliedLog = [];

const MAIN_INSTRUCTIONS = [
  { address: '0x1000', size: 1, bytes: '55', text: 'push %rbp' },
  { address: '0x1001', size: 3, bytes: '48 89 e5', text: 'mov %rsp,%rbp' },
  { address: '0x1004', size: 5, bytes: 'ba 2c 01 00 00', text: 'mov $0x12c,%edx' },
  { address: '0x1009', size: 5, bytes: 'e8 12 10 00 00', text: 'call 2010 <read@plt>' },
  { address: '0x100e', size: 1, bytes: 'c3', text: 'ret' },
];
const FUNCTIONS = [
  { name: 'main', address: '0x1000', section: '.text', instruction_count: MAIN_INSTRUCTIONS.length,
    assembly: MAIN_INSTRUCTIONS.map(i => `${i.address.slice(2)}: ${i.bytes}  ${i.text}`).join('\n') },
  { name: 'read@plt', address: '0x2010', section: '.plt', instruction_count: 2, assembly: '2010: ff 25 00 00 00 00  jmp *0x0(%rip)\n2016: 90 90 90 90 90 90 90 90 90 90  nop...' },
  { name: 'exit@plt', address: '0x2020', section: '.plt', instruction_count: 2, assembly: '2020: ff 25 01 00 00 00  jmp *0x1(%rip)\n2026: 90 90 90 90 90 90 90 90 90 90  nop...' },
];
const RECIPES = [
  { id: 'seccomp', name: 'seccomp 沙箱注入', usage: '入口注入 BPF 过滤器。\n应用后务必本地跑一次服务。', warnings: ['白名单过严会杀掉程序自身系统调用。'],
    fields: [{ key: 'preset', label: '预设规则', kind: 'select', dynamic: true }, { key: 'policy', label: '自定义规则', kind: 'policy' }] },
  { id: 'plt_call', name: '危险函数调用点劫持', usage: 'call rel32 位移重算。', warnings: [],
    fields: [{ key: 'source', label: '被劫持函数（PLT）', kind: 'select', dynamic: true }, { key: 'target', label: '重定向目标（PLT）', kind: 'select', dynamic: true }] },
];
let functionsPayload = FUNCTIONS;
const PRESETS = { blacklist_min: { name: '黑名单 · 仅禁 execve 系', default: 'allow' } };
let opSequence = 0;
const OP = (kind, vaddr, note) => ({ op_id: `op-${kind}`, kind, vaddr, file_offset: vaddr - 0x1000,
  original_bytes: 'ba 2c 01 00 00', new_bytes: '90 90 90 90 90', note: note || '',
  batch_id: `batch-${++opSequence}`, applied_at: 1788796800, state: 'applied', current_bytes: '90 90 90 90 90' });
const patchSummary = () => ({ total: appliedLog.length,
  applied: appliedLog.filter(op => op.state === 'applied').length,
  restored: appliedLog.filter(op => op.state === 'restored').length,
  conflict: appliedLog.filter(op => op.state === 'conflict').length,
  healthy: appliedLog.every(op => op.state === 'applied') });

ipcMain.handle('terminal:start', () => ({ id: ++terminal }));
for (const channel of ['terminal:kill', 'terminal:resize', 'terminal:input']) ipcMain.handle(channel, () => ({}));
ipcMain.handle('dialog:saveFile', async (_event, defaultName) => `C:/测试导出/${defaultName}`);
ipcMain.handle('bridge:request', async (_event, method, params = {}) => {
  calls.push(reply(method, params));
  if (method === 'ping') return { app: 'PwnCraft UI test', version: 'test' };
  if (method === 'import_target') return {
    context: { working_binary: params.path, original_binary: params.path },
    facts: { architecture: 'amd64', bits: 64, endian: 'little', entry: 0x1000,
      security: { RELRO: 'PARTIAL', CANARY: 'OFF', NX: 'ON', PIE: 'OFF', FORTIFY: 'OFF', STRIPPED: 'OFF' } },
    project: { project_path: 'C:/测试', project_name: '界面验证' }, static_report: 'ELF fixture',
  };
  if (method === 'heap_templates') return { templates: [] };
  if (method === 'code_analysis') return { binary: params.path, function_count: functionsPayload.length, stripped: false,
    functions: functionsPayload, diagnostics: [], notice: '' };
  if (method === 'patch_instructions') {
    const fn = functionsPayload.find(f => f.name === params.function);
    if (!fn) throw new Error(`函数 ${params.function} 不存在`);
    return { function: fn.name, address: fn.address, instructions: fn.name === 'main' ? MAIN_INSTRUCTIONS : [] };
  }
  if (method === 'patch_recipes') return { recipes: RECIPES, seccomp_presets: PRESETS };
  if (method === 'patch_preview') {
    const kind = (params.request || {}).kind;
    return { ops: [OP(kind || 'custom', 0x1004, `预览-${kind}`)], warnings: ['预览警示'], binary: 'fixture' };
  }
  if (method === 'patch_apply') {
    const op = OP((params.request || {}).kind, 0x1004, `应用-${(params.request || {}).kind}`);
    appliedLog = [...appliedLog, op];
    return { applied: [op], backup: 'C:/测试/.pwncraft/runtime/pwn.patchbak.123', warnings: [], binary: 'fixture', log: appliedLog };
  }
  if (method === 'patch_list') return { ops: appliedLog, summary: patchSummary(), binary: 'fixture', log_path: 'C:/测试/.pwncraft/patch_log.json' };
  if (method === 'patch_undo') {
    const target = appliedLog.find(op => op.op_id === params.op_id);
    const batch = target && target.batch_id;
    const count = appliedLog.filter(op => op.batch_id === batch).length;
    appliedLog = appliedLog.filter(op => op.batch_id !== batch);
    return { restored: target || {}, count, batch_id: batch, log: appliedLog };
  }
  if (method === 'patch_clear') { appliedLog = []; return { count: 1, log: [] }; }
  if (method === 'patch_reconcile') { return { count: 0, removed: [], log: appliedLog }; }
  if (method === 'patch_test_conflict') {
    appliedLog[0].state = 'conflict'; appliedLog[0].current_bytes = 'cc cc cc cc cc'; return {};
  }
  if (method === 'patch_test_heal') {
    appliedLog[0].state = 'applied'; appliedLog[0].current_bytes = appliedLog[0].new_bytes; return {};
  }
  if (method === 'patch_export') {
    if (params.kind === 'patched') return { path: params.dest, count: appliedLog.length, sha256: 'abcdef0123456789', size: 12345 };
    return { text: `# patch script fixture\nelf.write(0x1004, bytes.fromhex('90 90 90 90 90'))\n`, path: params.dest || '', count: appliedLog.length };
  }
  if (method === 'patch_bytecode_lookup') {
    const needle = String(params.query || '').toLowerCase();
    const all = [
      { mnemonic: 'nop', bytes: '90', note: '单字节 NOP', tag: 'nop 填充' },
      { mnemonic: 'jmp rel32', bytes: 'e9 cd', note: '位移=目标-(当前+5)', tag: '跳转' }];
    return { entries: all.filter(e => !needle || `${e.mnemonic}|${e.bytes}|${e.tag}`.toLowerCase().includes(needle)) };
  }
  if (method === 'patch_disasm_raw') return { bytes: '5548 89e5', machine: 'i386:x86-64',
    instructions: [{ offset: 0, text: '55    push rbp' }, { offset: 1, text: '48 89 e5  mov rbp,rsp' }] };
  if (method === 'patch_encode') return { bytes: 'e9 fb 0f 00 00', note: '0x1000 → 0x2000（rel32 = 0xffb）' };
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
  const lastCall = method => [...calls].reverse().find(call => call.method === method);
  try {
    await win.loadFile(path.join(root, 'renderer/index.html'));
    await until('!!window.PwnApp && !!document.querySelector(".activity-item")');
    assert.equal(await js('!!document.querySelector("[data-key=patch] svg")'), true, 'patch activity has an icon');
    await click('[data-key="patch"]');
    assert.match(await js('document.querySelector("#page-patch").innerText'), /导入 ELF/);
    await js('window.__pwncraftDebug.importElf("C:/测试/awdp-pwn")');
    await until('PwnApp.state.activePath === "C:/测试/awdp-pwn"');
    await click('[data-key="patch"]');
    await until('document.querySelectorAll(".analysis-function").length === 3');
    await until('document.querySelectorAll(".patch-insn").length === 5');
    assert.match(await js('document.querySelector("#page-patch .analysis-path").innerText'), /awdp-pwn/);
    assert.match(await js('document.querySelector(".analysis-function-heading").innerText'), /main/);
    await shot('manual.png');

    // 手动 NOP：选中第 3 条指令（mov $0x12c,%edx）→ 预览 → 应用
    await click('.patch-insn[data-index="2"]');
    assert.equal(await js('document.querySelector(".patch-insn.selected td").innerText'), '0x1004');
    await click('#patch-nop-insn');
    await until('!!document.querySelector(".patch-preview")');
    assert.match(await js('document.querySelector(".patch-preview").innerText'), /预览-nop_range/);
    assert.match(await js('document.querySelector(".patch-preview").innerText'), /90 90 90 90 90/);
    assert.equal(lastCall('patch_preview').result.request.kind, 'nop_range');
    assert.equal(lastCall('patch_preview').result.request.start, '0x1004');
    await shot('preview.png');
    await click('#patch-preview-apply');
    await until('!!document.querySelector(".patch-message")');
    assert.match(await js('document.querySelector(".patch-message").innerText'), /已应用 1 条补丁/);
    assert.equal(lastCall('patch_apply').result.request.kind, 'nop_range');

    // 条件跳转反转（off-by-one 一键修复）；先等 apply 触发的指令表重拉完成
    await until('document.querySelectorAll(".patch-insn").length === 5 && !document.querySelector(".patch-preview")');
    await click('.patch-insn[data-index="2"]');
    await until('document.querySelector(".patch-insn.selected") !== null');
    await click('#patch-jcc-invert');
    await until('!!document.querySelector(".patch-preview")');
    assert.equal(lastCall('patch_preview').result.request.kind, 'jcc_invert');
    assert.equal(lastCall('patch_preview').result.request.vaddr, '0x1004');
    await click('#patch-preview-cancel');
    await until('!document.querySelector(".patch-preview")');

    // 一键通防：seccomp 卡片预览 + 应用
    await click('[data-tab="recipes"]');
    await until('document.querySelectorAll(".recipe-card").length === 2');
    assert.match(await js('document.querySelector(".recipe-card").innerText'), /seccomp 沙箱注入/);
    await click('.patch-usage summary');
    assert.match(await js('document.querySelector(".patch-usage").innerText'), /入口注入/);
    const presetOptions = () => js('[...document.querySelectorAll(".recipe-card select option")].map(o => o.value)');
    assert.deepEqual(await presetOptions(), ['blacklist_min', 'custom', 'read', 'exit', 'read', 'exit']);
    await click('.patch-recipe-preview[data-recipe="seccomp"]');
    await until('!!document.querySelector(".patch-preview")');
    assert.equal(lastCall('patch_preview').result.request.kind, 'seccomp');
    await click('#patch-preview-apply');
    await sleep(300);
    await shot('recipes.png');

    // 字节码查询：目录 + 填入手动 Patch + 反汇编 + rel32 计算器
    await click('[data-tab="bytecode"]');
    await js('let q = document.querySelector("#patch-catalog-query"); q.value = "jmp"; q.dispatchEvent(new Event("input"))');
    await click('#patch-catalog-search');
    await until('document.querySelectorAll(".patch-use-bytes").length === 1');
    assert.match(await js('document.querySelector("#patch-panel-bytecode .data-table").innerText'), /jmp rel32/);
    await click('.patch-use-bytes');
    await until('document.querySelector("#patch-panel-manual") && !document.querySelector("#patch-panel-manual").hidden');
    assert.equal(await js('document.querySelector("#patch-hex").value'), 'e9 cd');
    assert.match(await js('document.querySelector(".patch-message").innerText'), /已填入字节 e9 cd/);
    await click('[data-tab="bytecode"]');
    await js('let d = document.querySelector("#patch-disasm-input"); d.value = "55 48 89 e5"; d.dispatchEvent(new Event("input"))');
    await click('#patch-disasm-run');
    await until('!!document.querySelector(".patch-disasm .report-pre")');
    assert.match(await js('document.querySelector(".patch-disasm .report-pre").innerText'), /push rbp/);
    await js('const f = document.querySelector("#patch-rel-from"); f.value = "0x1000"; f.dispatchEvent(new Event("input")); const t = document.querySelector("#patch-rel-to"); t.value = "0x2000"; t.dispatchEvent(new Event("input"));');
    await click('#patch-rel-jmp');
    await until('document.querySelectorAll(".patch-disasm .report-pre").length === 2');
    assert.match(await js('document.querySelectorAll(".patch-disasm .report-pre")[1].innerText'), /e9 fb 0f 00 00/);
    await shot('bytecode.png');

    // 补丁管理：记录表 + 撤销 + 三种导出
    await click('[data-tab="manage"]');
    await until('document.querySelectorAll(".patch-undo").length === 2');
    assert.match(await js('document.querySelector("#patch-panel-manage").innerText'), /seccomp/);
    assert.match(await js('document.querySelector(".patch-integrity").innerText'), /补丁完整性正常/);
    assert.equal(await js('document.querySelectorAll(".patch-state.applied").length'), 2);
    await js('window.pwncraft.request("patch_test_conflict", {})');
    await click('#patch-refresh-log');
    await until('document.querySelectorAll(".patch-state.conflict").length === 1');
    assert.match(await js('document.querySelector(".patch-integrity").innerText'), /工作副本与补丁记录不一致/);
    assert.match(await js('document.querySelector(".patch-bytes-conflict").innerText'), /cc cc cc cc cc/);
    assert.equal(await js('document.querySelector(".patch-undo").disabled'), true);
    assert.equal(await js('document.querySelector("#patch-export-elf").disabled'), true);
    await js('window.pwncraft.request("patch_test_heal", {})');
    await click('#patch-refresh-log');
    await until('document.querySelectorAll(".patch-state.applied").length === 2');
    await click('#patch-export-script');
    await until('!!document.querySelector(".patch-export-text")');
    assert.match(await js('document.querySelector(".patch-export-text pre").textContent'), /elf\.write/);
    assert.equal(lastCall('patch_export').result.kind, 'script');
    assert.equal(lastCall('patch_export').result.dest, 'C:/测试导出/patch_awdp-pwn.py');
    await click('#patch-export-diff');
    await until('document.querySelectorAll(".patch-export-text").length === 2');
    assert.equal(lastCall('patch_export').result.kind, 'diff');
    await click('#patch-export-elf');
    await until('document.querySelectorAll(".patch-export-text").length === 2');
    assert.equal(lastCall('patch_export').result.kind, 'patched');
    assert.match(await js('document.querySelector(".patch-message").innerText'), /已导出补丁后 ELF/);
    await shot('manage-populated.png');
    await click('.patch-undo');
    await until('document.querySelectorAll(".patch-undo").length === 1');
    await click('#patch-undo-all');
    await until('document.querySelectorAll(".patch-undo").length === 0');
    assert.match(await js('document.querySelector("#patch-panel-manage").innerText'), /还没有已应用的补丁/);
    await shot('manage.png');

    // XSS：恶意函数名只以文本呈现
    functionsPayload = [{ ...FUNCTIONS[0], name: '<script>alert(1)</script>' }, ...FUNCTIONS.slice(1)];
    await js('window.__pwncraftDebug.importElf("C:/测试/evil-name")');
    await until('PwnApp.state.activePath === "C:/测试/evil-name"');
    await click('[data-key="patch"]');
    await until('document.querySelectorAll(".analysis-function").length >= 1');
    await sleep(400);
    assert.equal(await js('!!document.querySelector(".analysis-function script")'), false);
    console.log('PASS: patch activity icon, manual insn selection + NOP preview/apply, recipe cards with usage, '
      + 'bytecode catalog fill-in, disasm + rel32 calculator, patch log undo, three export formats, escaping');
    app.exit(0);
  } catch (error) {
    console.error(error);
    await shot('failure.png');
    app.exit(1);
  }
});
