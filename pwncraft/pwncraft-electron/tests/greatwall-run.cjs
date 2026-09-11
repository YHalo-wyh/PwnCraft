// 长城杯 7 题全流程实测（真软件 + 真桥）：拖入 → 绑定/checksec/自动分诊 →
// 代码分析 → AWDP 各手法可用性 → IDA 联动。逐题输出 JSONL 结果。
const { app, BrowserWindow } = require('electron');
const path = require('path');
const fs = require('fs');
const root = path.resolve(__dirname, '..');
const base = path.resolve(root, '../artifacts/greatwall');
const outPath = path.resolve(root, '../artifacts/greatwall_results.jsonl');
const sleep = ms => new Promise(r => setTimeout(r, ms));
app.setPath('userData', fs.mkdtempSync(path.join(app.getPath('temp'), 'pwncraft-gw-')));
app.disableHardwareAcceleration();
require(path.join(root, 'main.js'));

const TARGETS = [
  { name: 'chall', dir: 'chall/x', binary: 'chall' },
  { name: 'CreditMarket', dir: 'CreditMarket', binary: 'shop' },
  { name: 'HashArchive', dir: 'HashArchive/x', binary: 'pwn' },
  { name: 'HeroEditor', dir: 'HeroEditor', binary: 'game' },
  { name: 'SomeBox2.0', dir: 'SomeBox2.0/x', binary: 'pwn' },
  { name: 'SomeMin', dir: 'SomeMin', binary: 'pwn' },
  { name: 'SomePloys', dir: 'SomePloys/x', binary: 'someploys' },
];

app.whenReady().then(async () => {
  for (let i = 0; i < 80 && BrowserWindow.getAllWindows().length === 0; i++) await sleep(100);
  const win = BrowserWindow.getAllWindows()[0];
  const js = async s => {
    for (let a = 0; a < 3; a++) {
      try { return await win.webContents.executeJavaScript(s, true); }
      catch (e) { if (a === 2) return { __jsError: String(e.message).slice(0, 120) }; await sleep(300); }
    }
  };
  const until = async (cond, ms) => {
    for (let i = 0; i < ms / 150; i++) { if (await js(cond)) return true; await sleep(150); }
    return false;
  };
  const log = line => { fs.appendFileSync(outPath, JSON.stringify(line) + '\n'); console.log(line.name + ': ' + line.phase); };
  fs.writeFileSync(outPath, '');
  await until('!!window.PwnApp && !!window.pwncraft', 30000);

  for (const t of TARGETS) {
    const full = path.join(base, t.dir, t.binary);
    const rec = { name: t.name, binary: full, phases: {} };
    try {
      // --- 导入（= 拖入） ---
      await js(`window.__pwncraftDebug.importElf(${JSON.stringify(full)})`);
      rec.phases.import = (await until(
        `PwnApp.state.workspaces.get(${JSON.stringify(full)})?.importState === "bound" || ` +
        `(PwnApp.state.workspaces.get(${JSON.stringify(full)}) !== undefined && PwnApp.state.importState === "bound" && PwnApp.state.activePath === ${JSON.stringify(full)})`, 60000))
        ? 'ok' : 'timeout';
      const entryExpr = `PwnApp.state.workspaces.get(${JSON.stringify(full)})`;
      const ctx = await js(`(()=>{const e=${entryExpr}; if(!e) return null; const c=e.context||{};
        return {arch:c.architecture, bits:c.bits, pie:c.pie, nx:c.nx, canary:c.canary, relro:c.relro,
        working:c.working_binary, patchSummary:(e.patchSummary||'').slice(0,80), patchError:(e.patchError||'').slice(0,120)};})()`);
      rec.context = ctx;

      // --- 自动分诊（后台 ROPgadget/seccomp/fmt） ---
      const triageDone = await until(
        `(()=>{const e=${entryExpr}; return !!(e && e.triage && !e.triage.running);})()`, 150000);
      const triage = await js(`(()=>{const e=${entryExpr}; if(!e||!e.triage) return null;
        const s=e.triage.stages||{};
        return {running:e.triage.running, stages:Object.fromEntries(Object.entries(s).map(([k,v])=>
          [k, {status:v.status||'', error:(v.error||'').slice(0,60), lines:(v.lines||v.text||'').length || (v.items?v.items.length:undefined)}]));};})()`);
      rec.phases.triage = triageDone ? 'ok' : 'timeout(150s)';
      rec.triage = triage;

      // --- 代码分析（objdump 函数列表） ---
      const analysis = await js(`window.pwncraft.request('code_analysis', {path: ${entryExpr}?.context?.working_binary, include_assembly: true})
        .then(r => ({fns: r.function_count, err: (r.assembly_error||'').slice(0,60),
          plt: (r.functions||[]).filter(f => String(f.name).endsWith('@plt')).map(f => f.name.slice(0,-4)).slice(0, 12),
          hasMain: (r.functions||[]).some(f => f.name === 'main')}))`);
      rec.analysis = analysis;

      // --- AWDP 手法可用性 ---
      const wb = `${entryExpr}?.context?.working_binary`;
      rec.awdp = {};
      rec.awdp.seccomp = await js(
        `window.pwncraft.request('patch_preview', {request:{kind:'seccomp', preset:'blacklist_min'}})
         .then(r => ({ok:true, ops:r.ops.length, bytes:r.ops.reduce((n,o)=>n+o.new_bytes.split(' ').length,0),
                      cave: (r.ops[1]||{}).note || ''}))
         .catch(e => ({ok:false, err:String(e.message).slice(0,90)}))`);
      for (const src of ['system', 'gets', 'read', 'printf', 'puts']) {
        const r = await js(
          `window.pwncraft.request('patch_preview', {request:{kind:'plt_call', source:${JSON.stringify(src)}, target:'exit'}})
           .then(r => ({ok:true, sites:r.ops.length}))
           .catch(e => ({ok:false, err:String(e.message).slice(0,80)}))`);
        if (r.ok || !/没有 exit@plt/.test(r.err || '')) rec.awdp['plt_' + src] = r;
      }
      const fnForReadlen = analysis && analysis.hasMain ? 'main' : null;
      if (fnForReadlen) {
        rec.awdp.readlen_main = await js(
          `window.pwncraft.request('patch_preview', {request:{kind:'readlen', function:'main', callee:'read', size:'0x30'}})
           .then(r => ({ok:true, sites:r.ops.length, note:r.ops[0].note}))
           .catch(e => ({ok:false, err:String(e.message).slice(0,90)}))`);
      }

      // --- IDA 联动 ---
      rec.ida = {};
      rec.ida.status = await js(`window.pwncraft.request('ida_status', {})
        .then(r => ({available:r.available, backend:r.backend?String(r.backend.ida_version||r.backend.version||'9.x'):'', err:(r.error||'').slice(0,60)}))`);
      if (rec.ida.status.available) {
        rec.ida.overview = await js(`window.pwncraft.request('ida_analyze', {})
          .then(r => {const o=r.overview||{}; return {danger:(o.dangerous_imports||[]).map(i=>i.name),
            symbols:(o.interesting_symbols||[]).map(i=>i.name),
            strings:(o.string_hits||[]).map(i=>i.value).slice(0,4)};})
          .catch(e => ({err:String(e.message).slice(0,80)}))`);
        rec.ida.decompileMain = await js(`window.pwncraft.request('ida_decompile', {function:'main'})
          .then(r => ({ok:true, len:(r.pseudocode||'').length}))
          .catch(e => ({ok:false, err:String(e.message).slice(0,70)}))`);
      }
      rec.phases.overall = 'done';
    } catch (e) {
      rec.phases.error = String(e.message).slice(0, 120);
    }
    log(rec);
  }
  console.log('GREATWALL RUN DONE');
  app.exit(0);
});
