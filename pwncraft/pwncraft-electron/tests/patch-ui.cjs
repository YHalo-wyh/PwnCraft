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
const previews = new Map();

const MAIN_INSTRUCTIONS = [
  { address: '0x1000', size: 1, bytes: '55', text: 'push %rbp' },
  { address: '0x1001', size: 3, bytes: '48 89 e5', text: 'mov %rsp,%rbp' },
  { address: '0x1004', size: 5, bytes: 'ba 2c 01 00 00', text: 'mov $0x12c,%edx' },
  { address: '0x1009', size: 5, bytes: 'e8 12 10 00 00', text: 'call 2010 <read@plt>' },
  { address: '0x100e', size: 2, bytes: '75 04', text: 'jne 1014 <main+0x14>' },
  { address: '0x1010', size: 1, bytes: 'c3', text: 'ret' },
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
    fields: [{ key: 'function', label: '作用函数', kind: 'select', dynamic: true },
      { key: 'vaddr', label: '单处地址', kind: 'number' },
      { key: 'source', label: '被劫持函数（PLT）', kind: 'select', dynamic: true }, { key: 'target', label: '重定向目标（PLT）', kind: 'select', dynamic: true }] },
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
  if (method === 'patch_audit') return { summary: { critical: 1, high: 1, medium: 0, info: 0, total: 2, risk_score: 45 },
    findings: [
      { id: 'import:system', severity: 'critical', title: 'system@plt：命令执行入口', detail: '发现 1 处直接调用。',
        evidence: ['handler @ 0x1030'], request: { kind: 'plt_call', source: 'system', target: 'exit' }, action: '预览 system→exit' },
      { id: 'length:read:main:1004', severity: 'high', title: 'main 中 read 读取长度为 0x12c', detail: '读取长度较大。',
        locations: [{ function: 'main', address: '0x1004', instruction: 'mov $0x12c,%edx' }], confidence: 'review',
        evidence: ['0x1004: mov $0x12c,%edx'], request: { kind: 'readlen', function: 'main', callee: 'read', size: '0x40' }, action: '预览长度收紧' },
    ], function_count: 3, plt_imports: ['exit', 'read', 'system'], binary: 'fixture' };
  if (method === 'vuln_points') return { binary: params.path, points: [
    { function: 'main', vaddr: '0x1009', callee: 'read', verdict: 'overflow_confirmed',
      reason: '长度 0x12c > 栈缓冲 0x40', length: 300, bound: 64, evidence: [] },
  ], confirmed: 1, total: 1 };
  if (method === 'patch_preview') {
    const requests = Array.isArray(params.requests) ? params.requests : [params.request || {}];
    const previewId = `preview-${previews.size + 1}`;
    previews.set(previewId, { request: requests[0] || {}, requests });
    return { preview_id: previewId,
      ops: requests.map((entry, index) => OP(entry.kind || 'custom', 0x1004 + index, `预览-${entry.kind}`)),
      warnings: ['预览警示'], binary: params.path };
  }
  if (method === 'patch_apply') {
    const request = previews.get(params.preview_id);
    assert.ok(request, 'apply must consume a server preview');
    const op = OP(request.request.kind, 0x1004, `应用-${request.request.kind}`);
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
    if (params.kind === 'bundle') return { path: params.dest, count: appliedLog.length, batch_count: appliedLog.length,
      sha256: '1122334455667788', size: 4567, files: ['awdp-pwn_patched', 'patch.py', 'patch.diff', 'manifest.json'] };
    return { text: `# patch script fixture\nelf.write(0x1004, bytes.fromhex('90 90 90 90 90'))\n`, path: params.dest || '', count: appliedLog.length };
  }
  if (method === 'patch_probe') return {
    patched: { label: 'patched', path: 'C:/测试/awdp-pwn', returncode: 0, timed_out: false, ok: true,
      stdout: 'READY patched\n', stderr: '', elapsed_ms: 18, output_truncated: false },
    original: { label: 'original', path: 'C:/测试/original', returncode: 0, timed_out: false, ok: true,
      stdout: 'READY original\n', stderr: '', elapsed_ms: 15, output_truncated: false },
    comparison: { same_returncode: true, same_stdout: false, both_healthy: true }, args: ['--smoke'], input_size: 5 };
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
  if (method === 'patch_assemble') {
    if (params.text === 'mov edi, 0') return { bytes: 'bf 00 00 00 00', size: 5, count: 1 };
    if (params.text === 'xor edx, edx') return { bytes: '31 d2', size: 2, count: 1 };
    if (params.text === 'mov rax, 0x1122334455667788') return {
      bytes: '48 b8 88 77 66 55 44 33 22 11', size: 10, count: 1 };
    throw new Error('fixture: 无法汇编');
  }
  if (method === 'ida_status') return { available: false, hint: 'fixture: 未安装 IDA-CLI' };
  if (method === 'ida_patch_bytes') return { ok: true };
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
    await until('!!PwnApp.state.workspaces.get(PwnApp.state.activePath).patch?.audit?.summary');
    await until('!!PwnApp.state.workspaces.get(PwnApp.state.activePath).patch?.vulnPoints');
    assert.equal(lastCall('patch_audit').result.path, 'C:/测试/awdp-pwn');
    assert.equal(lastCall('vuln_points').result.path, 'C:/测试/awdp-pwn');
    assert.match(await js('document.querySelector(".binary-auto-audit").textContent'), /发现 2 个/);
    await click('[data-key="patch"]');
    await until('document.querySelectorAll(".analysis-function").length === 3');
    await until('document.querySelectorAll(".patch-insn").length === 6');
    assert.match(await js('document.querySelector("#page-patch .analysis-path").innerText'), /awdp-pwn/);
    assert.match(await js('document.querySelector(".analysis-function-heading").innerText'), /main/);
    await shot('manual.png');

    // 手动 NOP：选中第 3 条指令（mov $0x12c,%edx）→ 预览 → 应用
    await click('.patch-insn[data-index="2"]');
    assert.equal(await js('document.querySelector(".patch-insn.selected td").innerText'), '0x1004');
    await click('#patch-nop-insn');
    await until('!!document.querySelector(".patch-preview")');
    assert.match(await js('document.querySelector(".patch-preview").innerText'), /预览-nop_instructions/);
    assert.match(await js('document.querySelector(".patch-preview").innerText'), /90 90 90 90 90/);
    assert.equal(lastCall('patch_preview').result.request.kind, 'nop_instructions');
    assert.equal(lastCall('patch_preview').result.request.start, '0x1004');
    await shot('preview.png');
    await click('#patch-preview-apply');
    await until('!!document.querySelector(".patch-message")');
    assert.match(await js('document.querySelector(".patch-message").innerText'), /已应用 1 条补丁/);
    assert.equal(previews.get(lastCall('patch_apply').result.preview_id).request.kind, 'nop_instructions');
    assert.equal(lastCall('patch_apply').result.path, 'C:/测试/awdp-pwn');
    assert.equal(calls.some(call => call.method === 'ida_status'), false, 'IDA must not block import or patch');

    // IDA 联动条：徽章渲染为不可用（fixture 环境），按钮在位
    assert.match(await js('document.querySelector("#patch-ida-badge").textContent'), /IDA：/);

    // Keypatch 式汇编补丁对话框：实时编译 + NOP 填充 + 生成预览
    await click('.patch-insn[data-index="2"]');
    await click('#patch-asm-open');
    await until('!!document.querySelector("#patch-patcher-modal")');
    assert.match(await js('document.querySelector("#patch-patcher-modal .patcher-origin").textContent'), /0x1004/);
    await js('const i = document.querySelector("#patcher-input"); i.value = "xor edx, edx"; i.dispatchEvent(new Event("input"))');
    await until('document.querySelector("#patcher-encode").textContent.includes("31 d2")');
    assert.match(await js('document.querySelector("#patcher-encode").textContent'), /差 3 字节/);
    await js('document.querySelector("#patcher-apply").click()');
    await until('!!document.querySelector(".patch-preview")');
    assert.equal(lastCall('patch_preview').result.request.kind, 'assembly');
    assert.equal(lastCall('patch_preview').result.request.text, 'xor edx, edx');
    assert.equal(lastCall('patch_preview').result.request.start, '0x1004');
    assert.equal(lastCall('patch_preview').result.request.end, '0x1009');
    assert.equal(lastCall('patch_preview').result.request.pad, true);
    await click('#patch-preview-cancel');
    await until('!document.querySelector(".patch-preview") && !document.querySelector("#patch-patcher-modal")');

    // 超长汇编通过可执行 code cave 跳板承载，再回到选区之后。
    await click('.patch-insn[data-index="2"]');
    await click('#patch-asm-open');
    await js('(() => { const caveInput = document.querySelector("#patcher-input"); caveInput.value = "mov rax, 0x1122334455667788"; caveInput.dispatchEvent(new Event("input")); })()');
    await until('!document.querySelector("#patcher-cave").disabled');
    assert.equal(await js('document.querySelector("#patcher-apply").disabled'), true);
    await click('#patcher-cave');
    await until('!!document.querySelector(".patch-preview")');
    assert.equal(lastCall('patch_preview').result.request.kind, 'cave_hook');
    assert.equal(lastCall('patch_preview').result.request.mode, 'replace');
    await click('#patch-preview-cancel');

    // 条件跳转反转（off-by-one 一键修复）；先等 apply 触发的指令表重拉完成
    await until('document.querySelectorAll(".patch-insn").length === 6 && !document.querySelector(".patch-preview")');
    await click('.patch-insn[data-index="4"]');
    await until('document.querySelector(".patch-insn.selected") !== null');
    await click('#patch-jcc-invert');
    await until('!!document.querySelector(".patch-preview")');
    assert.equal(lastCall('patch_preview').result.request.kind, 'jcc_mode');
    assert.equal(lastCall('patch_preview').result.request.mode, 'invert');
    assert.equal(lastCall('patch_preview').result.request.vaddr, '0x100e');
    await click('#patch-preview-cancel');
    await until('!document.querySelector(".patch-preview")');
    await click('#patch-jcc-always');
    await until('!!document.querySelector(".patch-preview")');
    assert.equal(lastCall('patch_preview').result.request.mode, 'always');
    await click('#patch-preview-cancel');

    // 调用筛选与单点 NOP 请求：只作用于 main 的 call，保留其余指令。
    await click('#patch-calls-only');
    assert.equal(await js('document.querySelectorAll(".patch-insn").length'), 1);
    await click('.patch-nop-call-row');
    await until('!!document.querySelector(".patch-preview")');
    assert.equal(lastCall('patch_preview').result.request.kind, 'nop_call');
    assert.equal(lastCall('patch_preview').result.request.function, 'main');
    assert.equal(lastCall('patch_preview').result.request.start, '0x1009');
    assert.equal(lastCall('patch_preview').result.request.end, '0x100e');
    await click('#patch-preview-cancel');
    await click('.patch-zero-call-row');
    await until('!!document.querySelector(".patch-preview")');
    assert.equal(lastCall('patch_preview').result.request.kind, 'skip_call_result');
    assert.equal(lastCall('patch_preview').result.request.value, 0);
    await click('#patch-preview-cancel');
    await click('#patch-calls-only');
    await click('.patch-insn[data-index="1"]');
    await js('document.querySelector(".patch-insn[data-index=\\"2\\"]").dispatchEvent(new MouseEvent("click", { bubbles: true, shiftKey: true }))');
    assert.match(await js('document.querySelector(".patch-selection").textContent'), /2 条指令 \/ 8 字节/);
    await click('#patch-nop-insn');
    await until('!!document.querySelector(".patch-preview")');
    assert.equal(lastCall('patch_preview').result.request.start, '0x1001');
    assert.equal(lastCall('patch_preview').result.request.end, '0x1009');
    await click('#patch-preview-cancel');

    // 一键通防：seccomp 卡片预览 + 应用
    await click('[data-tab="recipes"]');
    await until('document.querySelectorAll(".recipe-card").length === 2');
    await until('document.querySelectorAll(".patch-audit-item").length === 2');
    assert.match(await js('document.querySelector(".patch-audit-summary").innerText'), /风险分 45/);
    await click('.patch-audit-preview');
    await until('!!document.querySelector(".patch-preview")');
    assert.equal(lastCall('patch_preview').result.request.kind, 'plt_call');
    await click('#patch-preview-cancel');
    // 组合通防：审计项默认全选，一次预览合并后的补丁
    assert.equal(await js('document.querySelectorAll(".patch-audit-pick input:checked").length'), 2);
    await click('#patch-audit-batch');
    await until('!!document.querySelector(".patch-preview")');
    assert.equal(lastCall('patch_preview').result.requests.length, 2);
    assert.match(await js('document.querySelector(".patch-preview").innerText'), /组合通防 · 2 项/);
    await click('#patch-preview-cancel');
    await until('!document.querySelector(".patch-preview")');
    assert.match(await js('document.querySelector(".recipe-card").innerText'), /seccomp 沙箱注入/);
    assert.equal(await js('document.querySelector(".patch-usage")'), null, '使用说明折叠块已移除');
    const presetOptions = () => js('[...document.querySelectorAll(".recipe-card select option")].map(o => o.value)');
    assert.deepEqual(await presetOptions(), ['blacklist_min', 'custom', '', 'main', 'read', 'exit', 'read', 'exit']);
    await click('.patch-recipe-preview[data-recipe="plt_call"]');
    await until('!!document.querySelector(".patch-preview")');
    assert.equal(lastCall('patch_preview').result.request.source, 'read');
    assert.equal(lastCall('patch_preview').result.request.target, 'exit');
    await click('#patch-preview-cancel');
    await click('.patch-audit-location');
    await until('document.querySelector("#patch-tab-manual").getAttribute("aria-selected") === "true"');
    assert.equal(await js('document.querySelector(".patch-insn.selected td").textContent'), '0x1004');
    await click('[data-tab="recipes"]');
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

    // 补丁管理：完整性、存活探测、撤销与四种导出
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
    for (let i = 0; i < 50 && (!lastCall('patch_export') || lastCall('patch_export').result.kind !== 'patched'); i++) await sleep(100);
    assert.equal(lastCall('patch_export').result.kind, 'patched');
    assert.match(await js('document.querySelector(".patch-message").innerText'), /已导出补丁后 ELF/);
    await click('#patch-export-bundle');
    for (let i = 0; i < 50 && (!lastCall('patch_export') || lastCall('patch_export').result.kind !== 'bundle'); i++) await sleep(100);
    assert.equal(lastCall('patch_export').result.kind, 'bundle');
    assert.match(await js('document.querySelector(".patch-message").innerText'), /已导出 AWDP 比赛包/);
    await js('(() => { const probeArgs = document.querySelector("#patch-probe-args"); probeArgs.value = "--smoke"; probeArgs.dispatchEvent(new Event("input")); const probeInput = document.querySelector("#patch-probe-input"); probeInput.value = "ping\\n"; probeInput.dispatchEvent(new Event("input")); })()');
    await click('#patch-probe-run');
    await until('document.querySelectorAll(".patch-probe-result").length === 2');
    assert.equal(lastCall('patch_probe').result.args, '--smoke');
    assert.equal(lastCall('patch_probe').result.input, 'ping\n');
    assert.match(await js('document.querySelector(".patch-probe-results").innerText'), /退出码一致/);
    assert.match(await js('document.querySelector(".patch-probe-results").innerText'), /stdout 不同/);
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
    console.log('PASS: patch manual/Keypatch, risk audit preview, recipes, bytecode, integrity, runtime probe, '
      + 'four export formats, undo and escaping');
    app.exit(0);
  } catch (error) {
    console.error(error);
    await shot('failure.png');
    app.exit(1);
  }
});
