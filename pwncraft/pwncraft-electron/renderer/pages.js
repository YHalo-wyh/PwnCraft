/**
 * PwnCraft Workbench pages (v0.31) — Binary / ROP / Debug / Format / Syscall /
 * Stack / Tools plus the EXP editor's tool column.
 *
 * Every page is a thin form over the Python truth bridge: forms collect
 * user intent, the bridge returns facts, pages render them and offer
 * "插入 EXP" / "在终端运行" actions.  No page fabricates addresses or
 * gadget text on its own.
 */
(() => {
  'use strict';

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => [...(root || document).querySelectorAll(sel)];
  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const esc = (value) => String(value ?? '').replace(/[&<>"]/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;',
  }[c]));
  const icon = (name) => window.lucideIcon ? window.lucideIcon(name) : '';

  const app = () => window.PwnApp;
  const log = (message, level) => app() ? app().log(message, level) : console.log(message);
  const insertExp = async (text) => {
    if (app()) await app().insertExpText(text);
  };
  const runInTerminal = async (command) => {
    if (app()) return app().runInTerminal(command);
    log('终端未就绪', 'warn');
  };

  // =====================================================================
  // Binary page

  function renderBinary() {
    const host = $('#page-binary');
    const state = app().state;
    if (state.importState !== 'bound' || !state.facts) {
      host.innerHTML = '<div class="sidebar-empty" style="padding:26px">尚未绑定 Target。回欢迎页导入 ELF。</div>';
      return;
    }
    const facts = state.facts;
    const context = state.context || {};
    const working = context.working_binary || '';
    const original = context.original_binary || '';
    const reports = state.reports || {};
    const reportsFresh = state.reportsFor === working;
    const auditEntry = state.workspaces.get(state.activePath);
    const scan = auditEntry?.patch;
    const auto = auditEntry?.autoVuln;

    host.innerHTML = `
      <div class="binary-header">
        <div class="file-name"></div>
        <div class="file-path"></div>
      </div>
      <section class="card binary-auto-audit" aria-live="polite">
        <div class="card-title">自动安全扫描
          <span class="flex-spacer"></span>
          <button class="mini-btn" id="binary-audit-refresh" ${scan?.auditLoading ? 'disabled' : ''}>重新扫描</button>
          <button class="mini-btn primary" id="binary-audit-open">查看证据 / 定位修复</button></div>
        <div>${scan?.auditLoading ? '正在检查危险 API、输入长度与 ELF 保护配置…'
          : scan?.auditError ? `扫描失败：${esc(scan.auditError)}`
          : scan?.audit?.summary ? `发现 ${scan.audit.summary.total} 个复核 / 加固项：严重 ${scan.audit.summary.critical} · 高危 ${scan.audit.summary.high} · 中危 ${scan.audit.summary.medium} · 提示 ${scan.audit.summary.info || 0}`
          : '文件导入后自动开始扫描。'}</div>
        <div class="hint-dim">结果为静态规则线索，查看调用证据和扫描限制后再确定修复方式。</div>
        <div class="binary-synth">
          <button class="mini-btn primary" id="binary-auto-vuln" ${auto?.loading ? 'disabled' : ''}>${auto?.loading ? '自动识别中…' : '一键全量漏洞识别'}</button>
          ${auto?.report?.summary ? `<span class="chip">风险分 ${Number(auto.report.summary.risk_score || 0)}</span>
            <span class="chip">确认 ${Number(auto.report.summary.confirmed || 0)}</span>
            <span class="chip">合并 ${Number(auto.report.summary.total || 0)} 项</span>` : ''}
        </div>
        ${auto?.error ? `<div class="analysis-error">自动识别失败：${esc(auto.error)}</div>` : ''}
        ${auto?.report?.summary ? `<div class="hint-dim">全量识别：严重 ${auto.report.summary.critical || 0} · 高危 ${auto.report.summary.high || 0} · 中危 ${auto.report.summary.medium || 0} · 提示 ${auto.report.summary.info || 0}；覆盖 ${auto.report.coverage?.functions || 0} 个函数、${auto.report.coverage?.call_sites || 0} 个调用点。</div>
          ${(auto.report.pwn_profile?.routes || []).length ? `<div class="hint-dim">Pwn 路线候选：${auto.report.pwn_profile.routes.map((route) => esc(route.id)).join(' · ')}</div>` : ''}
          ${(auto.report.pwn_profile?.recommendations || []).length ? `<div class="hint-dim">建议：${auto.report.pwn_profile.recommendations.map(esc).join('；')}</div>` : ''}
          ${Object.keys(auto.report.semantic_summary || {}).length ? `<div class="hint-dim">语义行为：${Object.entries(auto.report.semantic_summary).map(([label, count]) => `${esc(label)} ${Number(count)}`).join(' · ')}</div>` : ''}
          ${(auto.report.strategies || []).length ? `<div class="hint-dim">利用策略：${auto.report.strategies.map((strategy) => `${esc(strategy.id || 'unknown')}=${esc(strategy.status || 'unknown')}`).join(' · ')}</div>` : ''}
          ${Object.keys(auto.report.gadgets || {}).length ? `<div class="hint-dim">关键 Gadget：${Object.entries(auto.report.gadgets).map(([role, address]) => `<span class="chip gadget-chip gadget-${esc(role)}">${esc(role)} ${esc(address)}</span>`).join(' ')}</div>` : ''}
          ${auto.report.gadget_error ? `<div class="hint-dim">Gadget 检测缺口：${esc(auto.report.gadget_error)}</div>` : ''}
          ${auto.report.fsop_profile?.status === 'candidate' ? `<div class="hint-dim">FSOP 画像：glibc ${esc(auto.report.fsop_profile.glibc)} · ${auto.report.fsop_profile.routes.map(esc).join(' / ')} · 仅为版本布局候选，需证明 FILE 写原语。</div>` : ''}
          ${(auto.report.exploit_chains || []).length ? `<details class="analysis-notice"><summary>组合利用链（${auto.report.exploit_chains.length}）</summary>${auto.report.exploit_chains.map((chain) => `<div class="vp-row chain-row"><span>${esc(chain.status || 'candidate')}</span><span>${esc(chain.title || chain.id)}</span><span>${esc((chain.stages || []).join(' → '))}</span><span>${chain.missing?.length ? `缺口：${esc(chain.missing.join('；'))}` : '前置条件已满足'}</span><button class="mini-btn chain-plan" data-chain="${esc(chain.id)}">生成 EXP 草稿</button></div>`).join('')}</details>` : ''}
          <details class="analysis-notice"><summary>查看统一风险清单（${auto.report.findings?.length || 0}）</summary>
            <div class="vp-block">${(auto.report.findings || []).slice(0, 80).map((item) => `<div class="vp-row"><span>${esc(String(item.severity || 'info').toUpperCase())}</span><span>${esc(item.title || item.reason || item.id || '风险')}</span><span>${esc(item.confidence || 'unknown')}</span><span>${esc(item.detail || item.reason || '')}</span></div>`).join('') || '<div class="hint-dim">没有发现需要复核的项目。</div>'}</div>
          </details>` : ''}
        <div class="binary-synth">
          <button class="mini-btn" id="binary-vulnpoints-run" ${scan?.vulnPointsLoading ? 'disabled' : ''}>${scan?.vulnPointsLoading ? '扫描中…' : '漏洞点扫描（数据流证明）'}</button>
          <button class="mini-btn" id="binary-synth-run" ${scan?.synthLoading ? 'disabled' : ''}>${scan?.synthLoading ? '合成中…' : '自动检测 + 生成 EXP 骨架'}</button>
          <button class="mini-btn" id="binary-synth-verify" ${scan?.synthVerifyLoading ? 'disabled' : ''}>${scan?.synthVerifyLoading ? '验证中…' : '运行时验证（gdb）'}</button>
          ${scan?.synth ? `<span class="chip">策略 ${esc(scan.synth.best?.id || '无')}</span>
            <span class="chip">状态 ${esc(scan.synth.best?.status || '-')}</span>
            <span class="chip">往返 ${esc((scan.synth.verdict || {}).verdict || '-')}</span>
            ${(scan.synth.unresolved || []).length ? `<span class="chip">未解析 ${scan.synth.unresolved.length}</span>` : ''}
            <button class="mini-btn primary" id="binary-synth-apply">写入 EXP 编辑器</button>` : ''}
          ${scan?.synthVerify ? `<span class="chip">偏移 ${scan.synthVerify.runtime?.offset !== null && scan.synthVerify.runtime?.offset !== undefined ? `0x${Number(scan.synthVerify.runtime.offset).toString(16)}` : '未测出'}</span>
            <span class="chip">验证 ${esc((scan.synthVerify.verification || {}).status || '-')}</span>` : ''}
        </div>
        ${scan?.synthVerifyError ? `<div class="analysis-error">运行时验证失败：${esc(scan.synthVerifyError)}</div>` : ''}
        ${scan?.synthVerify?.verification?.summary ? `<div class="hint-dim">运行时：${esc(scan.synthVerify.verification.summary)}</div>` : ''}
        ${scan?.vulnPoints ? (() => {
          const vp = scan.vulnPoints;
          const marker = { critical: '🔴', high: '🟠', medium: '🟡', info: '✓' };
          const rows = (vp.points || []).map((p, index) =>
            `<div class="vp-row" title="${esc((p.evidence || []).join(' · '))}">
              <span>${marker[p.severity] || '?'}</span>
              <span class="mono">${esc(p.callee)}${p.via ? ` via ${esc(p.via)}` : ''}@${esc(p.vaddr)}</span>
              <span>${esc(p.function)} · ${esc(p.category || 'review')}</span>
              <span>${esc(p.reason)}</span>
              ${p.request ? `<button class="mini-btn vp-fix" data-vp="${index}">预览修复</button>` : ''}</div>`);
          if (!rows.length) return '<div class="hint-dim">漏洞点扫描：没有识别到受支持的调用点或生命周期证据。</div>';
          const sev = vp.severity || {};
          const coverage = vp.coverage || {};
          return `<div class="hint-dim">发现风险 ${vp.risk_total ?? vp.total ?? rows.length} 处：严重 ${sev.critical || 0} · 高危 ${sev.high || 0} · 中危 ${sev.medium || 0}；
            已分析 ${coverage.functions || 0} 个函数、${coverage.call_sites || 0} 个调用点、${coverage.global_objects || 0} 个全局对象，启用 ${coverage.rules || 0} 条规则。</div>
            <div class="vp-block">${rows.join('')}</div>`;
        })() : ''}
        ${scan?.vulnPointsError ? `<div class="analysis-error">漏洞点扫描失败：${esc(scan.vulnPointsError)}</div>` : ''}
        ${scan?.synthError ? `<div class="analysis-error">合成失败：${esc(scan.synthError)}</div>` : ''}
        ${(scan?.synth?.best?.missing || []).length ? `<div class="hint-dim">缺口：${(scan.synth.best.missing || []).map(esc).join('；')}</div>` : ''}
      </section>
      <div class="binary-reports">
        <div class="card sec-card">
          <div class="card-title">checksec
            <span class="flex-spacer"></span>
            <span class="sec-source">${esc(sourceLabel(reportsFresh ? reports : {}, facts))}</span>
            <button id="sec-refresh" class="mini-btn" title="WSL 重新执行 checksec / file / ldd">重新检测</button>
          </div>
          <div id="sec-rows"></div>
        </div>
        <div class="card sec-card">
          <div class="card-title">file</div>
          <div id="file-rows"></div>
        </div>
        <div class="card sec-card">
          <div class="card-title">ldd</div>
          <div id="ldd-rows"></div>
        </div>
      </div>
      <div class="card-grid">
        <div class="card"><div class="card-title">标识</div>
          <div class="fact-stack"><span class="k">工作副本（运行用）</span><span class="v"></span></div>
          <div class="fact-stack"><span class="k">原始副本（只读）</span><span class="v"></span></div>
          <div class="fact-stack"><span class="k">项目目录</span><span class="v"></span></div>
        </div>
        <div class="card"><div class="card-title">架构</div>
          <div class="fact-row"><span class="k">架构</span><span class="v"></span></div>
          <div class="fact-row"><span class="k">端序</span><span class="v"></span></div>
          <div class="fact-row"><span class="k">入口</span><span class="v"></span></div>
        </div>
        <div class="card"><div class="card-title">运行时</div>
          <div class="fact-row"><span class="k">interpreter</span><span class="v"></span></div>
          <div class="fact-row"><span class="k">libc</span><span class="v"></span></div>
        </div>
      </div>
      <div class="card"><div class="card-title">静态分析输出（readelf -h 等）</div></div>
      <pre class="report-pre"></pre>`;
    $('.file-name', host).textContent = working.split(/[\\/]/).pop() || 'target';
    $('.file-path', host).textContent = working;
    const values = $$('.card-grid .v', host);
    const assignment = [
      working, original, (state.project && state.project.project_path) || '',
      `${facts.architecture || '?'} · ${facts.bits || '?'} 位`, facts.endian || '?',
      facts.entry !== undefined ? '0x' + Number(facts.entry).toString(16) : '?',
      context.interpreter || '(系统默认)',
      context.libc ? String(context.libc).split(/[\\/]/).pop() : '未发现',
    ];
    assignment.forEach((value, index) => { if (values[index]) values[index].textContent = value; });
    $('.report-pre', host).textContent = state.staticReport || '(no output)';

    renderChecksecRows(reportsFresh ? reports : {}, facts);
    renderFileRows(reportsFresh ? reports : {});
    renderLddRows(reportsFresh ? reports : {});
    $('#sec-refresh', host).addEventListener('click', () => fetchBinaryReports(working, true));
    $('#binary-audit-open', host).onclick = () => window.PwnPatch?.showAudit();
    $('#binary-audit-refresh', host).onclick = () => window.PwnPatch?.scan(auditEntry, true);
    $('#binary-auto-vuln', host).onclick = () => runAutoVuln(auditEntry, working, true);
    $('#binary-vulnpoints-run', host).onclick = () => runVulnPoints(auditEntry, working);
    $$('.vp-fix', host).forEach(button => {
      button.onclick = () => {
        const finding = scan?.vulnPoints?.points?.[Number(button.dataset.vp)];
        if (finding?.request) window.PwnPatch?.previewFinding(
          auditEntry, finding.request, `${finding.callee}@${finding.vaddr} 自动修复建议`);
      };
    });
    $('#binary-synth-run', host).onclick = () => runSynth(auditEntry, working);
    $$('.chain-plan', host).forEach((button) => {
      button.onclick = async () => {
        button.disabled = true;
        try {
          const plan = await window.pwncraft.request('exploit_chain_plan', { path: working, chain_id: button.dataset.chain });
          const source = String(plan.source || '');
          if (source) {
            app().replaceExpText(source);
            log(`已生成 ${button.dataset.chain} EXP 草稿${plan.safe_to_insert ? '' : '（含 TODO/未满足前置条件）'}`);
          }
        } catch (error) { log(`利用链草稿失败：${error.message || error}`, 'error'); }
        finally { button.disabled = false; }
      };
    });
    $('#binary-synth-verify', host).onclick = () => runSynthVerify(auditEntry, working);
    const synthApply = $('#binary-synth-apply', host);
    if (synthApply) synthApply.onclick = () => {
      app().replaceExpText((auditEntry?.patch?.synth?.source) || '');
    };
    if (!reportsFresh && !state.reportsInFlight) fetchBinaryReports(working, false);
    if (auditEntry && !auto?.report && !auto?.loading && !auto?.attempted) runAutoVuln(auditEntry, working, false);
  }

  async function runAutoVuln(entry, working, force) {
    if (!entry) return;
    const cache = entry.autoVuln ||= { loading: false, attempted: false, report: null, error: '' };
    if (cache.loading || (!force && cache.attempted)) return;
    cache.loading = true; cache.attempted = true; cache.error = '';
    renderBinary();
    try {
      cache.report = await window.pwncraft.request('auto_vuln_scan', { path: working });
    } catch (error) {
      cache.report = null; cache.error = error.message || String(error);
    } finally {
      cache.loading = false;
      if (app().state.activePath === entry.path && app().state.page === 'binary') renderBinary();
    }
  }

  /** 漏洞点确认：长度 vs 缓冲区边界，结论全部来自桥的静态证明。 */
  async function runVulnPoints(entry, working) {
    if (!entry) return;
    const cache = entry.patch ||= {};
    if (cache.vulnPointsLoading) return;
    cache.vulnPointsLoading = true; cache.vulnPointsError = '';
    const refresh = () => {
      if (app().state.activePath === entry.path && app().state.page === 'binary') renderBinary();
    };
    refresh();
    try {
      cache.vulnPoints = await window.pwncraft.request('vuln_points', { path: working });
    } catch (error) {
      cache.vulnPoints = null;
      cache.vulnPointsError = error.message || String(error);
    } finally {
      cache.vulnPointsLoading = false;
      refresh();
    }
  }

  function scanVulnPoints(entry, force = false) {
    if (!entry?.context) return;
    const cache = entry.patch ||= {};
    if (!force && (cache.vulnPoints || cache.vulnPointsLoading)) return;
    return runVulnPoints(entry, entry.context.working_binary || entry.path);
  }

  /** 自动检测 + 自动构造 EXP 骨架：断言全部来自桥的确定性事实，不在渲染层计算。 */
  async function runSynth(entry, working) {
    if (!entry) return;
    const cache = entry.patch ||= {};
    cache.synthLoading = true; cache.synthError = '';
    renderBinary();
    try {
      cache.synth = await window.pwncraft.request('synth_generate', { path: working, apply: false });
    } catch (error) {
      cache.synth = null;
      cache.synthError = error.message || String(error);
    } finally {
      cache.synthLoading = false;
      renderBinary();
    }
  }

  /** 运行时验证（opt-in）：gdb 测偏移 → 生成 → 真跑一次 EXP；结果含证据。 */
  async function runSynthVerify(entry, working) {
    if (!entry) return;
    const cache = entry.patch ||= {};
    cache.synthVerifyLoading = true; cache.synthVerifyError = '';
    renderBinary();
    try {
      const result = await window.pwncraft.request('synth_verify', { path: working, apply: false });
      cache.synth = result;
      cache.synthVerify = result;
    } catch (error) {
      cache.synthVerifyError = error.message || String(error);
    } finally {
      cache.synthVerifyLoading = false;
      renderBinary();
    }
  }

  function pre(text) {
    const clean = String(text || '').trim();
    if (!clean) return '（无输出）';
    if (/^ERROR:/i.test(clean)) return `${clean}\n（WSL 中缺少该工具；checksec 可 pip install pwntools 获取）`;
    return clean;
  }

  function sourceLabel(reports, facts) {
    if (parseChecksecRows(reports.checksec).length) return 'checksec（WSL）';
    return '本地 ELF 解析';
  }

  // checksec 逐行 key: value → 竖列卡片行；绿=开启，红=未开启，黄=部分
  function renderChecksecRows(reports, facts) {
    const host = $('#sec-rows');
    if (!host) return;
    const parsed = new Map(parseChecksecRows(reports.checksec).map(row => [row.key, row]));
    const rows = synthesizeChecksecRows(facts).map(row => {
      const value = parsed.get(row.key) || row;
      parsed.delete(row.key);
      return value;
    });
    rows.push(...parsed.values());
    host.innerHTML = rows.map((row) => `
      <div class="sec-row">
        <span class="sec-key">${esc(row.key)}:</span>
        <span class="sec-val ${row.tone}" title="${esc(row.value)}">${esc(row.value)}</span>
      </div>`).join('');
  }

  function secRowHtml(key, value, tone) {
    return `
      <div class="sec-row">
        <span class="sec-key">${esc(key)}</span>
        <span class="sec-val ${tone || 'neutral'}" title="${esc(value)}">${esc(value)}</span>
      </div>`;
  }

  // file 原文 → 结构化行（类型/架构/链接/interpreter/BuildID/Stripped）
  function renderFileRows(reports) {
    const host = $('#file-rows');
    if (!host) return;
    const raw = String(reports.file || '').trim();
    if (!raw) { host.innerHTML = '<div class="hint-dim">（无输出）</div>'; return; }
    if (/^ERROR:/i.test(raw)) {
      host.innerHTML = `<div class="sec-row"><span class="sec-key">错误</span>
        <span class="sec-val bad">${esc(raw)}</span></div>
        <div class="hint-dim">WSL 中缺少 file 工具（apt install file）。</div>`;
      return;
    }
    const rows = [];
    const firstLine = raw.split(/\r?\n/)[0] || '';
    const pathMatch = /^([^:]+):\s*(.*)$/.exec(firstLine);
    const description = pathMatch ? pathMatch[2] : firstLine;
    const fileName = pathMatch ? pathMatch[1].split('/').pop() : '';
    if (fileName) rows.push(['文件', fileName, 'neutral']);
    const classMatch = /ELF (\d{2}-bit)\s+([^,]+),\s*([^,]+)/.exec(description);
    if (classMatch) {
      rows.push(['类型', `ELF ${classMatch[1]} ${classMatch[2]}`.trim(), 'neutral']);
      const arch = classMatch[3];
      rows.push(['架构', arch, 'neutral']);
    }
    if (/pie executable|shared object/i.test(description)) rows.push(['PIE', 'PIE 执行文件', 'good']);
    if (/dynamically linked/.test(description)) rows.push(['链接', 'dynamically linked', 'neutral']);
    else if (/statically linked/.test(description)) rows.push(['链接', 'statically linked', 'neutral']);
    const interp = /interpreter ([^\s,]+)/.exec(raw);
    if (interp) rows.push(['interpreter', interp[1].split('/').pop(), 'neutral']);
    const buildId = /BuildID\[([^\]]+)\]=([0-9a-fA-F]+)/.exec(raw);
    if (buildId) rows.push([`BuildID[${buildId[1]}]`, buildId[2], 'neutral']);
    if (/not stripped/i.test(raw)) rows.push(['Stripped', 'No（符号可用）', 'good']);
    else if (/stripped/i.test(raw)) rows.push(['Stripped', 'Yes（已剥离）', 'bad']);
    const forVersion = /for GNU\/Linux ([\d.]+)/.exec(raw);
    if (forVersion) rows.push(['最低内核', `GNU/Linux ${forVersion[1]}`, 'neutral']);
    host.innerHTML = rows.map(([key, value, tone]) => secRowHtml(key, value, tone)).join('');
  }

  // ldd：按原文整行显示（每行一条依赖，等宽不拆列）——用户口径
  function renderLddRows(reports) {
    const host = $('#ldd-rows');
    if (!host) return;
    const raw = String(reports.ldd || '').trim();
    if (!raw) { host.innerHTML = '<div class="hint-dim">（无输出）</div>'; return; }
    if (/^ERROR:/i.test(raw)) {
      host.innerHTML = `<div class="sec-row"><span class="sec-key">错误</span>
        <span class="sec-val bad">${esc(raw)}</span></div>`;
      return;
    }
    if (/not a dynamic executable/i.test(raw)) {
      host.innerHTML = '<div class="hint-dim">静态链接或非 ELF：没有动态依赖。</div>';
      return;
    }
    const lines = raw.split(/\r?\n/).map((l) => l.trimEnd()).filter((l) => l.trim());
    host.innerHTML = lines.map((line) => {
      const tone = /not found/i.test(line) ? 'bad' : 'neutral';
      return `<div class="ldd-line"><span class="sec-val ${tone}">${esc(line)}</span></div>`;
    }).join('');
  }

  function parseChecksecRows(raw) {
    const rows = [];
    const keys = { ARCH: 'Arch', RELRO: 'RELRO', STACK: 'Stack', CANARY: 'Stack',
      'STACK CANARY': 'Stack', NX: 'NX', PIE: 'PIE', FORTIFY: 'FORTIFY',
      STRIPPED: 'Stripped', RPATH: 'RPATH', RUNPATH: 'RUNPATH', SYMBOLS: 'Symbols',
      SHSTK: 'SHSTK', IBT: 'IBT' };
    // checksec.sh prints an ANSI-coloured table; pwntools prints key/value lines.
    // Only recognised fields count as results: WSL notices and errors do not.
    const lines = String(raw || '').replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '').split(/\r?\n/);
    const add = (label, value) => {
      const key = keys[label.toUpperCase()];
      if (key && value) rows.push({ key, value, tone: secTone(key, value) });
    };
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*RELRO\s+STACK CANARY\s+NX\s+PIE\b/i.test(line)) {
        const headers = line.trim().split(/\s{2,}|\t+/);
        const values = (lines[i + 1] || '').trim().split(/\s{2,}|\t+/);
        if (/^(Full|Partial|No) RELRO$/i.test(values[0] || '') && values.length >= 4) {
          headers.forEach((header, index) => add(header, values[index]));
          i++;
        }
        continue;
      }
      const match = /^\s*([A-Za-z][A-Za-z0-9_]*)\s*:\s*(.+?)\s*$/.exec(line);
      if (match) add(match[1], match[2]);
    }
    return rows;
  }

  // WSL checksec 不可用时，用本地 ELF 解析的保护事实合成同样格式的行
  function synthesizeChecksecRows(facts) {
    const security = facts.security || {};
    const archText = `${facts.architecture || 'amd64'}-${Number(facts.bits) || 64}-${
      (facts.endian || 'little').toLowerCase()}`;
    const canonical = [
      ['Arch', archText],
      ['RELRO', synthValue('RELRO', security.RELRO)],
      ['Stack', synthValue('CANARY', security.CANARY)],
      ['NX', synthValue('NX', security.NX)],
      ['PIE', synthValue('PIE', security.PIE)],
      ['FORTIFY', synthValue('FORTIFY', security.FORTIFY)],
      ['Stripped', synthValue('STRIPPED', security.STRIPPED)],
    ];
    return canonical.map(([key, value]) => ({ key, value, tone: secTone(key, value) }));
  }

  // 本地解析值域（ON/OFF/FULL/PARTIAL/NONE/UNKNOWN）→ pwntools 风格展示文本
  function synthValue(key, raw) {
    const v = String(raw || '').trim().toUpperCase();
    if (!v || v === 'UNKNOWN') return 'unknown';
    if (key === 'RELRO') {
      return { FULL: 'Full RELRO', PARTIAL: 'Partial RELRO', NONE: 'No RELRO' }[v] || v;
    }
    if (key === 'CANARY') return { ON: 'Canary found', OFF: 'No canary' }[v] || v;
    if (key === 'NX') return { ON: 'NX enabled', OFF: 'NX disabled' }[v] || v;
    if (key === 'PIE') return { ON: 'PIE enabled', OFF: 'No PIE' }[v] || v;
    if (key === 'FORTIFY') return { ON: 'Yes', OFF: 'No' }[v] || v;
    if (key === 'STRIPPED') return { ON: 'Yes', OFF: 'No' }[v] || v;
    return v;
  }

  // 值域并集：pwntools checksec 短语 + checksec.sh 的 ON/OFF/NONE + 本地解析值
  function secTone(key, value) {
    const v = String(value || '').trim();
    const lower = v.toLowerCase();
    const k = String(key || '').toLowerCase();
    if (k === 'relro') {
      if (lower === 'full' || /full relro/i.test(v)) return 'good';
      if (lower === 'partial' || /partial/i.test(v)) return 'warn';
      if (lower === 'none' || /no relro/i.test(v)) return 'bad';
      return 'neutral';
    }
    if (k === 'stack') {
      if (/no canary/i.test(lower) || lower === 'off' || lower === 'no') return 'bad';
      if (/canary/i.test(lower) || lower === 'on' || lower === 'yes') return 'good';
      return secToneFallback(lower);
    }
    if (k === 'nx') {
      if (/enabled/i.test(lower) || lower === 'on' || lower === 'yes') return 'good';
      if (/disabled/i.test(lower) || lower === 'off' || lower === 'no') return 'bad';
      return 'neutral';
    }
    if (k === 'pie') {
      if (/no pie/i.test(lower) || lower === 'off' || lower === 'none') return 'bad';
      if (/enabled|dso|^on$|^yes$/.test(lower)) return 'good';
      return 'neutral';
    }
    if (k === 'shstk' || k === 'ibt') {
      if (lower === 'enabled' || lower === 'on' || lower === 'yes') return 'good';
      if (lower === 'disabled' || lower === 'off' || lower === 'no') return 'bad';
      return 'neutral';
    }
    if (k === 'fortify') {
      if (lower === 'yes' || lower === 'on' || /enabled/.test(lower)) return 'good';
      if (lower === 'no' || lower === 'off' || /disabled/.test(lower)) return 'bad';
      return 'neutral';
    }
    if (k === 'stripped') {
      if (lower === 'yes' || lower === 'on') return 'bad';
      if (lower === 'no' || lower === 'off') return 'good';
      return 'neutral';
    }
    return secToneFallback(lower);
  }

  // 兜底判定：checksec 工具的值域五花八门（Yes/No、ON/OFF、Enabled/Disabled、
  // Canary found…），不在已知键名里的值按前缀词判断——保证「开=绿 / 没开=红」永远成立
  function secToneFallback(lower) {
    if (/^(yes|on|enabled|found|full)/.test(lower) || /enabled|found$/.test(lower)) return 'good';
    if (/^(no|none|off|disabled)/.test(lower) || /disabled|not found/.test(lower)) return 'bad';
    if (/partial/.test(lower)) return 'warn';
    return 'neutral';
  }

  async function fetchBinaryReports(working, force) {
    const state = app().state;
    const entry = state.workspaces && state.workspaces.get(state.activePath);
    if (entry ? entry.reportsLoading : state.reportsInFlight) return;
    if (entry) entry.reportsLoading = true;
    state.reportsInFlight = true;
    let reports;
    try {
      const result = await window.pwncraft.request('binary_reports', { path: working });
      reports = { ...result.reports, diagnostics: result.diagnostics || {} };
    } catch (error) {
      reports = { checksec: `ERROR: ${error.message}`, file: `ERROR: ${error.message}`, ldd: `ERROR: ${error.message}` };
      log(`checksec/file/ldd 检测失败：${error.message}`, 'error');
    } finally {
      if (entry) { entry.reports = reports; entry.reportsFetched = true; entry.reportsLoading = false; }
      // A delayed WSL result must never overwrite another target's reports.
      if (state.context && state.context.working_binary === working &&
          (!entry || state.workspaces.get(state.activePath) === entry)) {
        state.reports = reports;
        state.reportsFor = working;
        state.reportsInFlight = false;
        if (state.page === 'binary') renderBinary();
      }
    }
  }

  function chip(label, raw) {
    const info = app().secInfo ? app().secInfo(raw) : { cls: 'unknown', mark: '?' };
    return `<span class="chip ${info.cls}">${label} ${info.mark}</span>`;
  }

  async function runCliTool(toolId, values, hostSelector) {
    const host = hostSelector ? $(hostSelector) : $('#page-binary .report-pre');
    if (host) host.innerHTML = `<div class="hint-dim">⏳ WSL 执行 ${esc(toolId)} 中…</div>`;
    try {
      const result = await window.pwncraft.request('cli_run', { tool_id: toolId, values });
      if (host) host.textContent = `$ ${result.command}\n\n${result.stdout || '(no output)'}`;
      log(`$ ${result.command}`);
    } catch (error) {
      if (host) host.innerHTML = `<div class="warn-line error">${esc(error.message)}</div>`;
      log(`${toolId} 失败：${error.message}`, 'error');
    }
  }

  // 导入时 seccomp-tools dump（WSL）的自动结果：结构化事实 + 原始 dump。
  function renderSeccompAuto() {
    const triage = app().state && app().state.triage;
    const info = triage && triage.stages ? triage.stages.seccomp : null;
    if (!info && triage && triage.running) {
      return '<div class="hint-dim">⏳ 正在 WSL 里执行 seccomp-tools dump…</div>';
    }
    if (!info) return '<div class="hint-dim">尚未检测：导入 ELF 后会自动在 WSL 里执行 seccomp-tools dump。</div>';
    if (info.status === 'failed') {
      return `<div class="warn-line error">自动检测失败：${esc(info.error || '未知错误')}</div>`;
    }
    if (!info.found) {
      return `<div class="hint-dim">${esc(info.error || '未捕获到 seccomp 过滤器：程序可能在安装过滤器前退出，或没有 seccomp（观察结论）。')}</div>`;
    }
    const compared = (info.compared || []).map((item) => item.name || item.nr).filter(Boolean);
    const timedOut = info.timed_out ? '（程序超时被截停，dump 为部分输出）' : '';
    return `
      <div class="explain-line">✓ 发现 seccomp 过滤器 · 架构 <b>${esc(info.arch || '?')}</b>
        · 默认动作 <b>${esc(info.default_action || '?')}</b>${esc(timedOut)}</div>
      <div class="explain-line">dump 中出现比较的 syscall（观察，通常为过滤白名单，需人工复核）：
        <span class="mono">${esc(compared.length ? compared.join(', ') : '（无显式比较）')}</span></div>
      ${info.raw ? `<details><summary style="cursor:pointer">seccomp-tools dump 原文</summary><pre class="report-pre" style="max-height:260px;overflow:auto">${esc(info.raw)}</pre></details>` : ''}`;
  }

  // =====================================================================
  // ROP page

  const ropState = { gadgets: [] };

  // 导入时自动分析（WSL）的状态条：三个页面共用同一份 state.triage。
  function triageStrip(stage, label) {
    const triage = app().state && app().state.triage;
    const info = triage && triage.stages ? triage.stages[stage] : null;
    if (!info && triage && triage.running) {
      return `<div class="hint-dim">⏳ ELF 导入后自动执行${label}（WSL 后台）…</div>`;
    }
    if (!info) return '';
    if (info.status === 'running') return `<div class="hint-dim">⏳ WSL 正在执行${label}…</div>`;
    if (info.status === 'failed') {
      return `<div class="warn-line error">自动${label}失败：${esc(info.error || '未知错误')}（仍可手动运行）</div>`;
    }
    return '';
  }

  function renderRop() {
    const host = $('#page-rop');
    const triage = app().state && app().state.triage;
    const ropAuto = triage && triage.stages ? triage.stages.ropgadget : null;
    if (ropAuto && ropAuto.status === 'done' && Array.isArray(ropAuto.gadgets)) {
      ropState.gadgets = ropAuto.gadgets;
    }
    const ropDone = ropAuto && ropAuto.status === 'done';
    const autoStrip = triageStrip('ropgadget', 'ROPgadget 扫描')
      || (ropDone ? `
        <div class="explain-line">✓ 导入时已自动执行（WSL）：<span class="mono">${esc(ropAuto.command || 'ROPgadget')}</span>
          · <b>${ropAuto.count}</b> 条 gadget${ropAuto.truncated ? '（结果截断至前 800 条，可用下方参数重扫）' : ''}</div>` : '');
    host.innerHTML = `
      <div class="rop-grid">
        <div class="card">
          <div class="card-title">Gadget Explorer · 真实 ROPgadget（WSL 执行）</div>
          ${autoStrip}
          <div class="form-grid">
            <label class="form-row"><span>--only</span><input id="rop-only" class="input" placeholder="pop|ret" value="pop|ret" /></label>
            <label class="form-row"><span>--badbytes</span><input id="rop-badbytes" class="input" placeholder="000a" /></label>
            <label class="form-row"><span>--depth</span><input id="rop-depth" class="input" placeholder="10" /></label>
          </div>
          <div class="cli-row">
            <button id="rop-run" class="btn primary">运行 ROPgadget</button>
            <button id="rop-run-terminal" class="btn" title="把 ROPgadget 命令写进当前终端直接运行">在终端运行</button>
            <button id="rop-env" class="btn" title="检查 WSL 中 ROPgadget/ropper/one_gadget 是否可用">环境体检</button>
          </div>
          <label class="form-row" style="margin-top:10px"><span>过滤结果</span><input id="rop-search" class="input" placeholder="例如 pop rdi / syscall / rdx" /></label>
          <div id="rop-results" class="rop-results"></div>
        </div>
        <div class="card">
          <div class="card-title">Chain Builder</div>
          <div class="form-grid">
            <label class="form-row"><span>function</span><input id="chain-func" class="input" placeholder="0x... 或 system" /></label>
            <label class="form-row"><span>rdi</span><input id="chain-rdi" class="input" placeholder="binsh_addr" /></label>
            <label class="form-row"><span>rsi</span><input id="chain-rsi" class="input" /></label>
            <label class="form-row"><span>rdx</span><input id="chain-rdx" class="input" /></label>
            <label class="form-row"><span>return_addr</span><input id="chain-ret" class="input" /></label>
          </div>
          <div class="cli-row">
            <button id="chain-build" class="btn primary">构造 Chain</button>
          </div>
          <div id="chain-report" class="chain-report"></div>
        </div>
        <div class="card">
          <div class="card-title">ret2libc 快速通道</div>
          <div class="form-grid">
            <label class="form-row"><span>泄露地址</span><input id="r2l-leak" class="input" placeholder="0x7f..." /></label>
            <label class="form-row"><span>符号偏移</span><input id="r2l-offset" class="input" placeholder="0x...（system 在 libc 中的偏移）" /></label>
          </div>
          <div class="cli-row"><button id="r2l-derive" class="btn">推导 libc_base</button></div>
          <div class="form-grid">
            <label class="form-row"><span>system 地址</span><input id="r2l-system" class="input" /></label>
            <label class="form-row"><span>/bin/sh 地址</span><input id="r2l-binsh" class="input" /></label>
          </div>
          <div class="cli-row"><button id="r2l-build" class="btn primary">构造 system("/bin/sh")</button></div>
          <div id="r2l-report" class="chain-report"></div>
        </div>
        <div class="card">
          <div class="card-title">SROP</div>
          <div class="cli-row"><button id="srop-plan" class="btn">生成 SROP 计划</button></div>
          <div id="srop-report" class="chain-report"></div>
        </div>
      </div>`;

    $('#rop-run').addEventListener('click', runRopgadget);
    $('#rop-search').addEventListener('input', () => renderGadgets(filterGadgets($('#rop-search').value)));
    $('#rop-env').addEventListener('click', showEnvDoctor);
    $('#rop-run-terminal').addEventListener('click', () => {
      const only = $('#rop-only').value.trim() || 'pop|ret';
      runInTerminal(`ROPgadget --binary ./pwn --only "${only}"`);
    });
    $('#chain-build').addEventListener('click', buildChain);
    $('#r2l-derive').addEventListener('click', deriveR2l);
    $('#r2l-build').addEventListener('click', buildR2l);
    $('#srop-plan').addEventListener('click', planSrop);
    // 导入时自动扫描的 gadget 直接落表，无需任何点击
    renderGadgets(filterGadgets($('#rop-search').value.trim()));
  }

  async function runRopgadget() {
    if (!app().state.context) { log('先绑定 Target，再运行 ROPgadget。', 'warn'); return; }
    const runButton = $('#rop-run');
    const originalLabel = runButton.textContent;
    runButton.disabled = true;
    runButton.textContent = '运行中…（WSL）';
    const values = {};
    for (const [id, key] of [['rop-only', 'only'], ['rop-badbytes', 'badbytes'], ['rop-depth', 'depth']]) {
      const value = $(`#${id}`).value.trim();
      if (value) values[key] = value;
    }
    try {
      const result = await window.pwncraft.request('cli_run', { tool_id: 'ropgadget', values });
      ropState.gadgets = result.parsed || [];
      renderGadgets(ropState.gadgets);
      log(`ROPgadget 完成：${ropState.gadgets.length} 条 gadget`);
    } catch (error) {
      log(`ROPgadget 失败：${error.message}`, 'error');
    } finally {
      runButton.disabled = false;
      runButton.textContent = originalLabel;
    }
  }

  function filterGadgets(query) {
    const needle = query.trim().toLowerCase();
    if (!needle) return ropState.gadgets;
    return ropState.gadgets.filter((gadget) => gadget.text.toLowerCase().includes(needle));
  }

  function renderGadgets(gadgets) {
    const host = $('#rop-results');
    if (!host) return;
    const triage = app().state && app().state.triage;
    const ropAuto = triage && triage.stages ? triage.stages.ropgadget : null;
    const waiting = !ropAuto && triage && triage.running;
    host.innerHTML = gadgets.length ? `
      <table class="data-table">
        <thead><tr><th>地址</th><th>Gadget</th></tr></thead>
        <tbody>
          ${gadgets.slice(0, 400).map((gadget) => `
            <tr>
              <td class="mono">${esc('0x' + Number(gadget.address).toString(16))}</td>
              <td class="mono">${esc(gadget.text)}</td>
            </tr>`).join('')}
        </tbody>
      </table>`
      : waiting ? '<div class="hint-dim">⏳ 导入时自动扫描（WSL）进行中，稍候自动出结果…</div>'
      : (ropAuto && ropAuto.status === 'failed')
        ? `<div class="hint-dim">自动扫描未成功：${esc(ropAuto.error || '')}（可用上方参数手动重试）</div>`
        : '<div class="hint-dim">没有匹配的 gadget：调整 --only / 过滤词后重新运行。</div>';
  }

  async function buildChain() {
    const args = {};
    for (const [id, reg] of [['chain-rdi', 'rdi'], ['chain-rsi', 'rsi'], ['chain-rdx', 'rdx']]) {
      const value = $(`#${id}`).value.trim();
      if (value) args[reg] = value;
    }
    try {
      const result = await window.pwncraft.request('rop_build', {
        function: $('#chain-func').value.trim(),
        arguments: args,
        return_addr: $('#chain-ret').value.trim(),
      });
      $('#chain-report').innerHTML = `
        <div class="explain-line">${result.entries.length} 项 · ${result.warnings.length ? esc(result.warnings.join('；')) : '无警告'}</div>
        <pre class="report-pre">${esc(result.pwntools)}</pre>
        <div class="cli-row">
          <button class="btn" id="chain-insert">插入 EXP</button>
          <button class="btn" id="chain-copy">复制</button>
        </div>`;
      $('#chain-insert').addEventListener('click', () => insertExp(result.pwntools));
      $('#chain-copy').addEventListener('click', () => navigator.clipboard.writeText(result.pwntools));
    } catch (error) {
      $('#chain-report').innerHTML = `<div class="warn-line error">${esc(error.message)}</div>`;
    }
  }

  async function deriveR2l() {
    try {
      const result = await window.pwncraft.request('leak_derive', {
        address: $('#r2l-leak').value.trim(),
        offset: $('#r2l-offset').value.trim(),
      });
      $('#r2l-report').innerHTML = `
        <div class="explain-line">libc_base = ${esc('0x' + result.libc_base.toString(16))} <span class="hint-dim">(${esc(result.formula)})</span></div>
        <div class="cli-row"><button class="btn" id="r2l-base-insert">插入 EXP</button></div>`;
      $('#r2l-base-insert').addEventListener('click', () => insertExp(`libc_base = ${result.formula}\nlog.success('libc_base -> ' + hex(libc_base))\n`));
      log(`libc_base = 0x${result.libc_base.toString(16)}`);
    } catch (error) {
      $('#r2l-report').innerHTML = `<div class="warn-line error">${esc(error.message)}</div>`;
    }
  }

  async function buildR2l() {
    const system = $('#r2l-system').value.trim();
    const binsh = $('#r2l-binsh').value.trim();
    if (!system) { log('先填 system 地址（可用泄露地址 - 偏移推导）。', 'warn'); return; }
    try {
      const result = await window.pwncraft.request('rop_build', {
        function: system,
        arguments: binsh ? { rdi: binsh } : {},
      });
      $('#r2l-report').innerHTML = `
        <pre class="report-pre">${esc(result.pwntools)}</pre>
        <div class="cli-row">
          <button class="btn" id="r2l-chain-insert">插入 EXP</button>
        </div>`;
      $('#r2l-chain-insert').addEventListener('click', () => insertExp(result.pwntools));
    } catch (error) {
      $('#r2l-report').innerHTML = `<div class="warn-line error">${esc(error.message)}</div>`;
    }
  }

  async function planSrop() {
    try {
      const result = await window.pwncraft.request('srop_plan', {});
      $('#srop-report').innerHTML = `
        <div class="explain-line">目标 ${esc(result.plan.target || '')} · ${esc(result.plan.architecture || '')}</div>
        <pre class="report-pre">${esc(result.pwntools || JSON.stringify(result.plan, null, 2))}</pre>`;
    } catch (error) {
      $('#srop-report').innerHTML = `<div class="warn-line error">${esc(error.message)}</div>`;
    }
  }

  async function showEnvDoctor() {
    try {
      const result = await window.pwncraft.request('cli_env_doctor', {});
      const missing = result.tools.filter((tool) => !tool.present);
      if (!missing.length) {
        log('WSL 工具链齐备：ROPgadget / ropper / one_gadget / seccomp-tools 全部可用。');
        return;
      }
      const install = missing.map((tool) => tool.install).join(' && ');
      log(`缺少: ${missing.map((tool) => tool.tool).join(', ')}。安装命令已写入终端（需要你确认执行）。`, 'warn');
      runInTerminal(install);
    } catch (error) {
      log(`环境体检失败：${error.message}`, 'error');
    }
  }

  // =====================================================================
  // Debug page (pwndbg-mogai)

  function renderDebug() {
    const host = $('#page-debug');
    const state = app().state;
    const bound = Boolean(state.context);
    const active = app().hasDebugSession();
    host.innerHTML = `
      <div class="debug-layout">
        <div class="debug-exp" id="debug-exp-slot">
          <div class="debug-exp-head">exp.py <span class="hint-dim">当前 Target · 只读随动</span></div>
        </div>
        <div class="debug-center">
          <div class="debug-center-head">
            <span class="debug-title">pwndbg-mogai 调试终端</span>
            <span class="hint-dim">隔离 fork · 官方 pwndbg 未改动</span>
            <span class="flex-spacer"></span>
            <span id="debug-status" class="hint-dim">检查中…</span>
            <button id="debug-start" class="btn primary" ${bound && !active ? '' : 'hidden'}>启动调试终端</button>
            <button id="debug-stop" class="btn" ${active ? '' : 'hidden'}>结束调试</button>
          </div>
          <div id="debug-term-slot" class="debug-term-slot">
            ${active
    ? ''
    : `<div class="debug-term-placeholder">
                 <div class="dt-main">${bound ? '尚未启动调试' : '先导入 ELF，再启动调试'}</div>
                 <div class="hint-dim">「启动调试终端」会校验/安装独立 pwndbg-mogai（官方 pwndbg 零改动），生成启动脚本
                 （工作副本 ELF 已加载、x86 自动 starti），然后在<b>本页正中</b>打开终端实例 ——
                 底部面板保留给程序运行终端。</div>
               </div>`}
          </div>
        </div>
        <div class="debug-cmd-col">
          <div class="card">
            <div class="card-title">命令历史</div>
            <div id="debug-cmd-history" class="debug-cmd-history">
              <div class="hint-dim" style="padding:6px">尚未发送命令</div>
            </div>
          </div>
          <div class="card">
            <div class="card-title">自定义命令</div>
            <input id="debug-custom" class="input" style="width:100%" placeholder="gdb 命令…" />
            <div class="cli-row">
              <button id="debug-send" class="btn primary">发送</button>
              <button id="debug-snapshot" class="btn" title="写入 pwncraft-snapshot 采集运行时快照">采集快照</button>
              <button id="debug-cheatsheet" class="btn" title="中文命令手册（F1）">命令手册 F1</button>
            </div>
            <div class="cli-row">
              <button id="debug-ensure" class="btn mini-btn" title="校验/安装隔离 pwndbg-mogai（官方 pwndbg 零改动）">安装 / 校验</button>
            </div>
          </div>
          <div class="card">
            <div class="card-title">说明</div>
            <div class="hint-dim">· 底部面板终端 = 程序运行用；本页终端 = pwndbg 调试实例。<br />
              · Heap 页静态回放与这里的运行时状态分开存放。</div>
          </div>
        </div>
      </div>`;
    $('#debug-start').addEventListener('click', startDebugSession);
    $('#debug-stop').addEventListener('click', () => app().stopDebugSession());
    $('#debug-ensure').addEventListener('click', ensurePwndbg);
    $$('#debug-commands .btn, .debug-cmd-grid .btn').forEach((button) => {
      button.addEventListener('click', () => sendToDebug(button.dataset.cmd));
    });
    $('#debug-send').addEventListener('click', () => {
      const value = $('#debug-custom').value.trim();
      if (value) { sendToDebug(value); $('#debug-custom').value = ''; }
    });
    $('#debug-snapshot').addEventListener('click', () => sendToDebug('pwncraft-snapshot'));
    if (window.PwnExpDnD) window.PwnExpDnD.renderCommandHistory();
    $('#debug-cheatsheet').addEventListener('click', () => {
      if (!app().debugSheetToggle || !app().debugSheetToggle()) {
        log('调试终端未开启：先点「启动调试终端」。', 'warn');
      }
    });
    // 持久实例挂载：EXP 编辑器（左 1/4，与 exp 页同一实例）+ 已有调试终端
    app().mountDebugTerminalNode();
    if (active) {
      const start = $('#debug-start');
      const stop = $('#debug-stop');
      if (start) start.hidden = true;
      if (stop) stop.hidden = false;
    }
    refreshDebugStatus();
  }

  async function refreshDebugStatus() {
    const host = $('#debug-status');
    if (!host) return;
    try {
      const result = await window.pwncraft.request('pwndbg_status');
      host.textContent = result.installed
        ? `pwndbg-mogai ${result.version} 已就绪`
        : 'pwndbg-mogai 尚未安装（启动时会自动安装）';
    } catch (error) {
      host.textContent = `状态未知：${error.message}`;
    }
  }

  async function ensurePwndbg() {
    log('正在校验/安装独立 pwndbg-mogai（首次约 108MB 下载，请稍候）…');
    try {
      const result = await window.pwncraft.request('pwndbg_ensure');
      log(`${result.command} 已就绪（${result.version}）；官方 pwndbg 未改动。`);
      refreshDebugStatus();
    } catch (error) {
      log(`pwndbg-mogai 安装失败：${error.message}`, 'error');
    }
  }

  async function startDebugSession() {
    if (!app().state.context) { log('先绑定 Target。', 'warn'); return; }
    try {
      const spec = await window.pwncraft.request('debug_launch', {});
      log(`调试脚本就绪：${spec.script_wsl_path}（${spec.architecture}${spec.auto_start ? ' · 自动 starti' : ' · 静态安全模式'}）`);
      const started = await window.pwncraft.terminalStart({
        kind: 'debug',
        name: spec.script_wsl_path,
        cwd: app().state.terminalCwd || '',
      });
      app().attachDebugTerminal(started.id);
      log('pwndbg-mogai 调试终端已开启（新终端实例）。');
      refreshDebugStatus();
    } catch (error) {
      log(`调试启动失败：${error.message}`, 'error');
    }
  }

  function sendToDebug(command) {
    if (app()) app().sendToDebugTerminal(command);
    else log('调试终端未开启。', 'warn');
  }

  // =====================================================================
  // Format page

  function renderFormat() {
    const host = $('#page-format');
    const triage = app().state && app().state.triage;
    const fmtAuto = triage && triage.stages ? triage.stages.fmt : null;
    const running = !fmtAuto && triage && triage.running;
    let autoBody = '';
    if (running) {
      autoBody = '<div class="hint-dim">⏳ 正在 WSL 里执行 fmt 探针（AAAAAAAA.%p×24 喂入 stdin）…</div>';
    } else if (!fmtAuto) {
      autoBody = '<div class="hint-dim">尚未探测：导入 ELF 后会自动在 WSL 里运行探针。</div>';
    } else if (fmtAuto.status === 'failed') {
      autoBody = `<div class="warn-line error">自动探测失败：${esc(fmtAuto.error || '未知错误')}</div>`;
    } else {
      const probe = fmtAuto.probe || {};
      const offset = probe.offset;
      const sinkLine = (fmtAuto.sinks || []).length
        ? `<div class="explain-line">导入的格式化函数（观察）：<span class="mono">${esc(fmtAuto.sinks.join(', '))}</span></div>`
        : '<div class="hint-dim">动态符号表中未见 printf 族导入（观察，不代表不存在漏洞）。</div>';
      const offsetLine = offset
        ? `<div class="explain-line">✓ 格式化偏移（自动定位）= <b>${offset}</b>，已填入下方 Write Planner。</div>`
        : `<div class="hint-dim">${esc(probe.note || '探针回显中未发现标记值。')}</div>`;
      autoBody = `
        ${sinkLine}
        <div class="explain-line">探针命令（WSL 真实执行）：<span class="mono">${esc(fmtAuto.command || '')}</span></div>
        ${offsetLine}
        ${(probe.output || '').trim() ? `<details><summary style="cursor:pointer">探针回显（前 4000 字符）</summary><pre class="report-pre" style="max-height:220px;overflow:auto">${esc(probe.output)}</pre></details>` : '<div class="hint-dim">程序无回显（可能等待菜单输入后直接退出）。</div>'}`;
    }
    host.innerHTML = `
      <div class="rop-grid">
        <div class="card">
          <div class="card-title">自动探测（ELF 导入时 · WSL 执行）</div>
          ${autoBody}
        </div>
        <div class="card">
          <div class="card-title">Offset Finder（%p 探针 → 格式化偏移）</div>
          <textarea id="fmt-probe" class="input area" rows="5"
            placeholder="粘贴探针输出，例如：&#10;0x1 0x2 0x3 0x4 0x5 0x4141414141414141 ..."></textarea>
          <div class="cli-row"><button id="fmt-find" class="btn primary">计算偏移</button></div>
          <div id="fmt-offset-report" class="chain-report"></div>
        </div>
        <div class="card">
          <div class="card-title">Write Planner（%hn 分段写入）</div>
          <div class="form-grid">
            <label class="form-row"><span>目标地址</span><input id="fmt-target" class="input" placeholder="0x..." /></label>
            <label class="form-row"><span>写入值</span><input id="fmt-value" class="input" placeholder="0x..." /></label>
            <label class="form-row"><span>格式化偏移</span><input id="fmt-offset" class="input" placeholder="6" /></label>
          </div>
          <div class="cli-row">
            <button id="fmt-plan" class="btn primary">生成写入计划</button>
            <button id="fmt-payload" class="btn" title="32 位 %hn 模板">32 位模板</button>
          </div>
          <div id="fmt-plan-report" class="chain-report"></div>
        </div>
      </div>`;
    $('#fmt-find').addEventListener('click', async () => {
      try {
        const result = await window.pwncraft.request('fmt_offset', { probe_output: $('#fmt-probe').value });
        $('#fmt-offset').value = result.offset;
        $('#fmt-offset-report').innerHTML = `<div class="explain-line">格式化偏移 = <b>${result.offset}</b></div>`;
        log(`格式化偏移 = ${result.offset}`);
      } catch (error) {
        $('#fmt-offset-report').innerHTML = `<div class="warn-line error">${esc(error.message)}</div>`;
      }
    });
    $('#fmt-plan').addEventListener('click', async () => {
      try {
        const result = await window.pwncraft.request('fmt_plan', {
          target: $('#fmt-target').value.trim(), value: $('#fmt-value').value.trim(),
        });
        const parts = result.plan.parts || [];
        const offset = Number($('#fmt-offset').value || 8);
        const lines = parts.map((part, index) => {
          const padding = Math.max(0, part.value - (index === 0 ? 0 : parts[index - 1].value));
          return `payload += fmtstr_payload({${offset}}, {{{part.address}: ${part.value}}}, write_size='short')  # ${part.address} <- ${part.value}`;
        });
        const text = `# %hn 分段写入计划（低半字优先）\n${lines.join('\n')}\n`;
        $('#fmt-plan-report').innerHTML = `
          <pre class="report-pre">${esc(result.plan.parts.map((p) => `${p.address} <- ${p.value}`).join('\n'))}</pre>
          <div class="cli-row"><button class="btn" id="fmt-plan-insert">插入 EXP</button></div>`;
        $('#fmt-plan-insert').addEventListener('click', () => insertExp(text));
      } catch (error) {
        $('#fmt-plan-report').innerHTML = `<div class="warn-line error">${esc(error.message)}</div>`;
      }
    });
    $('#fmt-payload').addEventListener('click', () => {
      insertExp([
        "# 32 位 %hn 分段写入（fmtstr_payload）",
        "payload = fmtstr_payload(FMT_OFFSET, {TARGET_ADDR: TARGET_VALUE}, write_size='short')",
        "p.sendline(payload)",
      ].join('\n'));
    });
    // 自动探测到的偏移直接填进 Write Planner（导入时 WSL 探针的结果）
    const autoOffset = fmtAuto && fmtAuto.probe && fmtAuto.probe.offset;
    if (autoOffset && $('#fmt-offset')) $('#fmt-offset').value = autoOffset;
  }

  // =====================================================================
  // Syscall page

  function renderSyscall() {
    const host = $('#page-syscall');
    const seccompAutoBody = renderSeccompAuto();
    host.innerHTML = `
      <div class="rop-grid">
        <div class="card">
          <div class="card-title">Syscall Explorer</div>
          <div class="cli-row">
            <label class="inline-label">架构
              <select id="sys-arch" class="input"><option>amd64</option><option>i386</option><option>aarch64</option></select>
            </label>
            <button id="sys-load" class="btn">加载</button>
            <button id="sys-seccomp" class="btn" title="seccomp-tools dump（WSL）">解析 Seccomp</button>
          </div>
          <div class="card-title" style="margin-top:8px">Seccomp 自动检测（ELF 导入时 · WSL）</div>
          <div id="sys-seccomp-report">${seccompAutoBody}</div>
          <div id="sys-table" class="rop-results"></div>
        </div>
        <div class="card">
          <div class="card-title">ORW Builder</div>
          <div class="form-grid">
            <label class="form-row"><span>flag 路径</span><input id="orw-path" class="input" value="/flag" /></label>
            <label class="form-row"><span>buffer</span><input id="orw-buffer" class="input" placeholder="0x0" /></label>
            <label class="form-row"><span>read size</span><input id="orw-size" class="input" value="0x100" /></label>
            <label class="form-row"><span>output fd</span><input id="orw-fd" class="input" value="1" /></label>
          </div>
          <div class="cli-row"><button id="orw-plan" class="btn primary">生成 ORW 计划</button></div>
          <div id="orw-report" class="chain-report"></div>
        </div>
      </div>`;
    $('#sys-load').addEventListener('click', loadSyscalls);
    $('#sys-seccomp').addEventListener('click', () => runCliTool('seccomp-tools', {}, '#sys-seccomp-report'));
    $('#orw-plan').addEventListener('click', async () => {
      try {
        const result = await window.pwncraft.request('orw_plan', {
          path: $('#orw-path').value.trim() || '/flag',
          buffer: $('#orw-buffer').value.trim() || '0x0',
          read_size: $('#orw-size').value.trim() || '0x100',
          output_fd: Number($('#orw-fd').value || 1),
        });
        const steps = (result.plan.steps || []).map((step) => `
          <div class="explain-line"><b>${esc(step.name)}</b> = ${esc(step.syscall)}
            ${step.missing_registers && step.missing_registers.length ? `<span class="warn-line error">缺 ${esc(step.missing_registers.join(','))}</span>` : ''}
          </div>`).join('');
        $('#orw-report').innerHTML = steps
          + `<div class="hint-dim">${esc((result.plan.warnings || []).join('；') || '计划可执行。')}</div>`;
      } catch (error) {
        $('#orw-report').innerHTML = `<div class="warn-line error">${esc(error.message)}</div>`;
      }
    });
    loadSyscalls();
  }

  async function loadSyscalls() {
    try {
      const result = await window.pwncraft.request('syscall_table', { arch: $('#sys-arch').value });
      $('#sys-table').innerHTML = `
        <table class="data-table">
          <thead><tr><th>#</th><th>name</th><th>寄存器</th><th></th></tr></thead>
          <tbody>${result.syscalls.map((syscall) => `
            <tr>
              <td class="mono">${syscall.number}</td>
              <td class="mono">${esc(syscall.name)}</td>
              <td class="mono">${esc(syscall.registers.join(', '))}</td>
              <td><button class="mini-btn" data-copy="${syscall.number}">复制号</button></td>
            </tr>`).join('')}</tbody>
        </table>`;
      $$('#sys-table button[data-copy]').forEach((button) => {
        button.addEventListener('click', () => navigator.clipboard.writeText(button.dataset.copy));
      });
    } catch (error) {
      log(`syscall 表加载失败：${error.message}`, 'error');
    }
  }

  // =====================================================================
  // Stack page

  function renderStack() {
    const host = $('#page-stack');
    host.innerHTML = `
      <div class="rop-grid">
        <div class="card">
          <div class="card-title">Offset Finder（cyclic 溢出偏移）</div>
          <div class="form-grid">
            <label class="form-row"><span>长度</span><input id="cyc-size" class="input" value="200" /></label>
            <label class="form-row"><span>周期 n</span><select id="cyc-n" class="input"><option>4</option><option>8</option></select></label>
          </div>
          <div class="cli-row">
            <button id="cyc-gen" class="btn primary">生成 Pattern</button>
            <label class="form-row" style="flex:1;margin:0"><span>崩溃值</span><input id="cyc-crash" class="input" placeholder="0x61616162 或 b'aaab'" /></label>
            <button id="cyc-find" class="btn">计算 Offset</button>
          </div>
          <div id="cyc-report" class="chain-report"></div>
        </div>
        <div class="card">
          <div class="card-title">Leak Manager</div>
          <div class="form-grid">
            <label class="form-row"><span>符号</span><input id="leak-symbol" class="input" placeholder="puts / write / printf" /></label>
            <label class="form-row"><span>泄露地址</span><input id="leak-addr" class="input" placeholder="0x7f..." /></label>
            <label class="form-row"><span>符号偏移</span><input id="leak-offset" class="input" placeholder="0x..." /></label>
          </div>
          <div class="cli-row"><button id="leak-add" class="btn primary">记录 Leak 并推导 libc_base</button></div>
          <div id="leak-list" class="leak-list"></div>
        </div>
      </div>`;
    $('#cyc-gen').addEventListener('click', async () => {
      try {
        const result = await window.pwncraft.request('cyclic_pattern', {
          size: Number($('#cyc-size').value || 200), n: Number($('#cyc-n').value || 4),
        });
        $('#cyc-report').innerHTML = `
          <textarea class="input area" rows="3" readonly>${esc(result.pattern)}</textarea>
          <div class="cli-row">
            <button class="btn" id="cyc-copy">复制 Pattern</button>
            <button class="btn" id="cyc-insert">插入 EXP 片段</button>
          </div>`;
        $('#cyc-copy').addEventListener('click', () => navigator.clipboard.writeText(result.pattern));
        $('#cyc-insert').addEventListener('click', () => insertExp(
          `payload = cyclic(${Number($('#cyc-size').value || 200)}, n=${Number($('#cyc-n').value || 4)})\np.sendline(payload)\n`,
        ));
      } catch (error) {
        log(`pattern 生成失败：${error.message}`, 'error');
      }
    });
    $('#cyc-find').addEventListener('click', async () => {
      try {
        const result = await window.pwncraft.request('cyclic_find', { value: $('#cyc-crash').value.trim() });
        $('#cyc-report').innerHTML = `<div class="explain-line">溢出偏移 = <b>${result.offset}</b></div>
          <div class="cli-row"><button class="btn" id="cyc-off-insert">插入 EXP 片段</button></div>`;
        $('#cyc-off-insert').addEventListener('click', () => insertExp(
          `OFFSET = ${result.offset}\npayload = b'A' * OFFSET + p64(TARGET)\n`,
        ));
        log(`溢出偏移 = ${result.offset}`);
      } catch (error) {
        $('#cyc-report').innerHTML = `<div class="warn-line error">${esc(error.message)}</div>`;
      }
    });
    $('#leak-add').addEventListener('click', async () => {
      try {
        const result = await window.pwncraft.request('leak_derive', {
          address: $('#leak-addr').value.trim(), offset: $('#leak-offset').value.trim(),
        });
        const leaks = stackLeaks();
        leaks.unshift({
          symbol: $('#leak-symbol').value.trim() || 'leak',
          address: $('#leak-addr').value.trim(),
          offset: $('#leak-offset').value.trim(),
          base: `0x${result.libc_base.toString(16)}`,
          formula: result.formula,
        });
        localStorage.setItem('pwncraft.leaks', JSON.stringify(leaks.slice(0, 20)));
        renderLeaks();
        log(`libc_base = 0x${result.libc_base.toString(16)}（${result.formula}）`);
      } catch (error) {
        log(`libc_base 推导失败：${error.message}`, 'error');
      }
    });
    renderLeaks();
  }

  function stackLeaks() {
    try { return JSON.parse(localStorage.getItem('pwncraft.leaks') || '[]'); }
    catch { return []; }
  }

  function renderLeaks() {
    const host = $('#leak-list');
    if (!host) return;
    const leaks = stackLeaks();
    host.innerHTML = leaks.length ? `
      <table class="data-table">
        <thead><tr><th>符号</th><th>泄露地址</th><th>偏移</th><th>libc_base</th></tr></thead>
        <tbody>${leaks.map((leak) => `
          <tr><td>${esc(leak.symbol)}</td><td class="mono">${esc(leak.address)}</td>
          <td class="mono">${esc(leak.offset)}</td><td class="mono">${esc(leak.base)}</td></tr>`).join('')}</tbody>
      </table>`
      : '<div class="hint-dim">暂无 Leak 记录。</div>';
  }

  // =====================================================================
  // Tools page

  function renderTools() {
    const host = $('#page-tools');
    host.innerHTML = `
      <div class="tools-grid">
        <div class="tools-left">
        <div class="card">
          <div class="card-title">编码转换</div>
          <div class="cli-row">
            <input id="conv-value" class="input" style="flex:1" placeholder="0x7ffff7a52290 或 123 或文本" />
            <select id="conv-mode" class="input"><option value="int">整数</option><option value="bytes">字节/字符串</option></select>
            <select id="conv-bits" class="input"><option>64</option><option>32</option></select>
            <button id="conv-run" class="btn primary">转换</button>
          </div>
          <div id="conv-results" class="rop-results"></div>
        </div>
        <div class="card">
          <div class="card-title">环境体检（WSL CLI 工具链）</div>
          <div class="cli-row"><button id="env-doctor" class="btn">体检</button></div>
          <div id="env-report" class="rop-results"></div>
        </div>
        <div class="card">
          <div class="card-title">命令提示（WSL 模板，点击复制）</div>
          <input id="tpl-filter" class="input" placeholder="筛选，例如 checksec / ROPgadget / one_gadget" />
          <div id="tpl-list" class="tpl-list"></div>
        </div>
        </div>
        <div class="card clib-card">
          <div class="card-title">C 函数速查
            <span class="flex-spacer"></span>
            <span class="hint-dim">原型 · 参数逐项 · 返回值 · pwn 笔记</span>
          </div>
          <div id="clib-tools-panel"></div>
        </div>
      </div>`;
    $('#conv-run').addEventListener('click', runConvert);
    $('#env-doctor').addEventListener('click', async () => {
      try {
        const result = await window.pwncraft.request('cli_env_doctor', {});
        $('#env-report').innerHTML = `
          <table class="data-table">
            <thead><tr><th>工具</th><th>状态</th><th></th></tr></thead>
            <tbody>${result.tools.map((tool) => `
              <tr><td class="mono">${esc(tool.tool)}</td>
              <td>${tool.present ? '<span class="ok-text">可用</span>' : '<span class="err-text">缺失</span>'}</td>
              <td>${tool.present ? '' : `<button class="mini-btn" data-install="${esc(tool.install)}">在终端安装</button>`}</td></tr>`).join('')}</tbody>
          </table>`;
        $$('#env-report button[data-install]').forEach((button) => {
          button.addEventListener('click', () => runInTerminal(button.dataset.install));
        });
      } catch (error) {
        log(`体检失败：${error.message}`, 'error');
      }
    });
    $('#tpl-filter').addEventListener('input', () => renderTemplates($('#tpl-filter').value));
    loadTemplates();
    renderClibPanel($('#clib-tools-panel'));
  }

  async function runConvert() {
    try {
      const result = await window.pwncraft.request('convert', {
        mode: $('#conv-mode').value,
        value: $('#conv-value').value.trim(),
        bits: Number($('#conv-bits').value || 64),
      });
      $('#conv-results').innerHTML = `
        <table class="data-table">
          <thead><tr><th>形式</th><th>值</th><th></th></tr></thead>
          <tbody>${result.results.map((item, index) => `
            <tr><td>${esc(item.title)}</td><td class="mono conv-value">${esc(item.value)}</td>
            <td><button class="mini-btn" data-copy="${index}">复制</button></td></tr>`).join('')}</tbody>
        </table>`;
      $$('#conv-results button[data-copy]').forEach((button) => {
        button.addEventListener('click', () => {
          navigator.clipboard.writeText(result.results[Number(button.dataset.copy)].value);
          log('已复制转换结果');
        });
      });
    } catch (error) {
      log(`转换失败：${error.message}`, 'error');
    }
  }

  let templateCache = [];
  async function loadTemplates() {
    try {
      const result = await window.pwncraft.request('command_templates');
      templateCache = result.wsl || [];
      renderTemplates('');
    } catch (error) {
      log(`命令模板加载失败：${error.message}`, 'error');
    }
  }

  function renderTemplates(query) {
    const host = $('#tpl-list');
    if (!host) return;
    const needle = String(query || '').trim().toLowerCase();
    const items = templateCache.filter((item) => !needle
      || item.title.toLowerCase().includes(needle)
      || item.command.toLowerCase().includes(needle));
    host.innerHTML = items.map((item) => `
      <div class="tpl-row">
        <div class="tpl-title">${esc(item.title)}</div>
        <div class="tpl-command mono">${esc(item.command)}</div>
      </div>`).join('') || '<div class="hint-dim">没有匹配模板。</div>';
    $$('.tpl-row', host).forEach((row, index) => {
      row.addEventListener('click', () => {
        navigator.clipboard.writeText(items[index].command);
        log(`已复制：${items[index].title}`);
      });
    });
  }

  // =====================================================================
  // C 函数速查（clib_catalog 桥真值）——工具箱卡片 + EXP 工具列 tab 共用

  const clibState = { cache: null, expanded: new Set() };

  async function loadClibCatalog() {
    if (clibState.cache) return clibState.cache;
    const result = await window.pwncraft.request('clib_catalog', {});
    clibState.cache = {
      functions: result.functions || [],
      operators: result.operators || [],
      categories: result.categories || [],
    };
    return clibState.cache;
  }

  function filterClib(catalog, query, category) {
    const needle = String(query || '').trim().toLowerCase();
    return catalog.functions.filter((fn) => {
      if (category && fn.category !== category) return false;
      if (!needle) return true;
      return fn.name.toLowerCase().includes(needle)
        || (fn.summary || '').toLowerCase().includes(needle)
        || (fn.prototype || '').toLowerCase().includes(needle)
        || (fn.tags || []).some((tag) => tag.toLowerCase().includes(needle));
    });
  }

  function clibDetailHtml(fn) {
    const params = (fn.params || []).map((param) => `
      <tr>
        <td class="mono">${esc(param.name)}</td>
        <td class="mono">${esc(param.type || '')}</td>
        <td>${esc(param.note || '')}</td>
      </tr>`).join('');
    const returns = (fn.returns || []).map((item) => `
      <div class="fact-row"><span class="k">${esc(item.condition || '返回')}</span>
      <span class="v">${esc(item.value)}</span></div>`).join('');
    const notes = (fn.notes || []).map((note) => `<li>${esc(note)}</li>`).join('');
    return `
      <div class="clib-detail">
        <div class="clib-proto mono">${esc(fn.prototype)}</div>
        <div class="hint-dim">${esc([fn.header, fn.category].filter(Boolean).join(' · '))}</div>
        ${params ? `<table class="data-table clib-table">
          <thead><tr><th>参数</th><th>类型</th><th>说明</th></tr></thead>
          <tbody>${params}</tbody></table>` : ''}
        ${returns ? `<div class="clib-returns">${returns}</div>` : ''}
        ${notes ? `<ul class="clib-notes">${notes}</ul>` : ''}
        <div class="cli-row"><button class="mini-btn" data-copy-proto="${esc(fn.prototype)}">复制原型</button></div>
      </div>`;
  }

  function renderClibList(host, catalog, query, category) {
    const items = filterClib(catalog, query, category);
    const listHtml = items.length ? items.map((fn) => {
      const open = clibState.expanded.has(fn.name);
      return `
        <div class="clib-row ${open ? 'open' : ''}" data-name="${esc(fn.name)}">
          <div class="clib-row-head">
            <span class="clib-name mono">${esc(fn.name)}</span>
            <span class="clib-cat">${esc(fn.category || '')}</span>
            <span class="hint-dim clib-summary">${esc(fn.summary || '')}</span>
          </div>
          ${open ? clibDetailHtml(fn) : ''}
        </div>`;
    }).join('') : '<div class="hint-dim">没有匹配的 C 函数。</div>';
    host.innerHTML = `
      <div class="clib-count hint-dim">${items.length} / ${catalog.functions.length} 个函数</div>
      ${listHtml}`;
    $$('.clib-row', host).forEach((row) => {
      row.addEventListener('click', (event) => {
        if (event.target.closest('[data-copy-proto]')) return;   // 复制按钮不折叠
        if (event.target.closest('.clib-detail')) return;        // 详情内选中文本不折叠
        const name = row.dataset.name;
        if (clibState.expanded.has(name)) clibState.expanded.delete(name);
        else clibState.expanded.add(name);
        renderClibList(host, catalog, query, category);
      });
    });
    $$('button[data-copy-proto]', host).forEach((button) => {
      button.addEventListener('click', () => {
        navigator.clipboard.writeText(button.dataset.copyProto);
        log('已复制函数原型');
      });
    });
  }

  async function renderClibPanel(host, options = {}) {
    const compact = Boolean(options.compact);
    let catalog;
    try {
      catalog = await loadClibCatalog();
    } catch (error) {
      host.innerHTML = `<div class="hint-dim">C 函数目录加载失败：${esc(error.message)}</div>`;
      return;
    }
    host.innerHTML = `
      <div class="cli-row clib-controls">
        <input class="input clib-q" style="flex:1;min-width:0" placeholder="搜索函数 / 摘要 / 标签，如 read、memset、低 8 位" />
        <select class="input clib-category">
          <option value="">全部分类</option>
          ${catalog.categories.map((name) => `<option value="${esc(name)}">${esc(name)}</option>`).join('')}
        </select>
      </div>
      <div class="clib-list"></div>
      ${compact ? '' : `
        <details class="clib-ops">
          <summary>运算符速查（&amp; &amp;&amp; | || ^ ~ &lt;&lt; &gt;&gt;）</summary>
          <table class="data-table">
            <thead><tr><th>符号</th><th>名字</th><th>类型</th><th>短路</th><th>作用</th><th>例子</th></tr></thead>
            <tbody>${catalog.operators.map((op) => `
              <tr>
                <td class="mono">${esc(op.symbol)}</td>
                <td>${esc(op.name)}</td>
                <td>${esc(op.kind)}</td>
                <td>${op.short_circuit ? '短路' : '不短路'}</td>
                <td>${esc(op.description)}</td>
                <td class="mono">${esc(op.example)}</td>
              </tr>`).join('')}</tbody>
          </table>
        </details>`}`;
    const list = $('.clib-list', host);
    const queryInput = $('.clib-q', host);
    const categorySelect = $('.clib-category', host);
    const refresh = () => renderClibList(
      list, catalog, queryInput.value, categorySelect ? categorySelect.value : '',
    );
    queryInput.addEventListener('input', refresh);
    if (categorySelect) categorySelect.addEventListener('change', refresh);
    refresh();
  }

  // =====================================================================
  // EXP tool column (代码块 / 转换 / 格式化 / 命令 / GDB)

  async function renderExpTools() {
    const host = $('#exp-tools');
    if (!host) return;
    host.innerHTML = `
      <div class="exp-tools-tabs">
        ${['代码块', '进制转换', '格式化', '命令提示', 'GDB 菜单', 'C 函数'].map((label, index) => `
          <button class="mini-tab ${index === 0 ? 'active' : ''}" data-etab="${index}">${label}</button>`).join('')}
      </div>
      <div class="exp-tools-pages"></div>`;
    const pages = $('.exp-tools-pages', host);
    const renderTab = async (index) => {
      pages.innerHTML = '';
      if (index === 0) await renderBlockCatalog(pages);
      if (index === 1) renderConvMini(pages);
      if (index === 2) renderFmtMini(pages);
      if (index === 3) await renderCommandHints(pages);
      if (index === 4) await renderGdbMenu(pages);
      if (index === 5) await renderClibPanel(pages, { compact: true });
    };
    $$('.exp-tools-tabs .mini-tab', host).forEach((tab) => {
      tab.addEventListener('click', () => {
        $$('.exp-tools-tabs .mini-tab', host).forEach((item) => item.classList.toggle('active', item === tab));
        renderTab(Number(tab.dataset.etab));
      });
    });
    await renderTab(0);
  }

  // 常用速记块：与目录块同处「代码块」一个面板，全部可拖入编辑器。
  const QUICK_BLOCKS = [
    { label: 'u64 ljust 补齐', code: "u64(leak.ljust(8, b'\\x00'))",
      hint: 'EXP_LEAK_001 · 6 字节泄露补齐 8 字节' },
    { label: 'p64 打包', code: 'p64(target_addr)', hint: 'amd64 地址打包' },
    { label: 'recvuntil 菜单同步', code: 'io.recvuntil(b"Choice:")', hint: 'PROMPT_SYNC' },
  ];

  function quickChipHtml(block) {
    return `
      <div class="pwncraft-code-chip" data-pwncraft-code="${esc(block.code)}">
        <div class="pwncraft-chip-label">${esc(block.label)}</div>
        <pre class="pwncraft-chip-code">${esc(block.code)}</pre>
        ${block.hint ? `<div class="pwncraft-chip-hint">${esc(block.hint)}</div>` : ''}
      </div>`;
  }

  function blockGroupHtml(title, count, body, open) {
    return `
      <details class="block-group" ${open ? 'open' : ''}>
        <summary>${esc(title)}<span class="block-group-count">${count}</span></summary>
        <div class="block-group-body">${body}</div>
      </details>`;
  }

  async function renderBlockCatalog(host) {
    host.innerHTML = `
      <input id="block-filter" class="input" placeholder="搜索 tcache / overlap / ret2libc…" />
      <div class="hint-dim block-catalog-hint">全部代码块可拖入编辑器；目录块双击可先填参数，速记块双击就地编辑。</div>
      <div id="block-list" class="block-list"></div>`;
    const quickFixes = Array.isArray(window.PwnExpDnD && window.PwnExpDnD.quickFixes)
      ? window.PwnExpDnD.quickFixes : [];
    let blocks = [];
    let query = '';
    const renderList = () => {
      const needle = query.trim().toLowerCase();
      const hit = (text) => text.toLowerCase().includes(needle);
      // 目录块按分类分组（保持 blocks_list 的目录顺序）
      const groups = new Map();
      for (const block of blocks) {
        const matched = !needle
          || hit(block.title) || hit(block.category)
          || hit(block.description || '')
          || (block.tags || []).some((tag) => hit(tag));
        if (!matched) continue;
        if (!groups.has(block.category)) groups.set(block.category, []);
        groups.get(block.category).push(block);
      }
      const quickHit = (item) => !needle
        || hit(item.label || '') || hit(item.code || '') || hit(item.hint || '');
      let html = '';
      const fixes = quickFixes.filter(quickHit);
      if (fixes.length) {
        html += blockGroupHtml('审计快速修复', fixes.length, fixes.map(quickChipHtml).join(''), true);
      }
      const quicks = QUICK_BLOCKS.filter(quickHit);
      if (quicks.length) {
        html += blockGroupHtml('常用速记', quicks.length, quicks.map(quickChipHtml).join(''), true);
      }
      for (const [category, items] of groups) {
        const body = items.map((block) => `
          <div class="block-row" data-id="${esc(block.id)}" data-pwncraft-code="${esc(block.snippet)}">
            <div class="block-title">${esc(block.title)}<span class="block-cat">${esc(block.category)}</span>
              <span class="block-drag-note">拖入编辑器 · 双击填参</span></div>
            <div class="hint-dim">${esc(block.description)}</div>
          </div>`).join('');
        // 搜索时自动展开分组；浏览时默认收起，保持面板紧凑
        html += blockGroupHtml(category, items.length, body, !!needle);
      }
      $('#block-list', host).innerHTML = html || '<div class="hint-dim">没有匹配代码块。</div>';
      $$('.block-row[data-id]', host).forEach((row) => {
        const block = blocks.find((item) => item.id === row.dataset.id);
        if (window.PwnExpDnD && block) window.PwnExpDnD.register(row, block.snippet);
        row.addEventListener('dblclick', async () => {
          const target = blocks.find((item) => item.id === row.dataset.id);
          if (target) await insertBlockWithPlaceholders(target);
        });
      });
      $$('.pwncraft-code-chip', host).forEach((chipEl) => {
        if (window.PwnExpDnD) {
          window.PwnExpDnD.register(chipEl, chipEl.getAttribute('data-pwncraft-code'),
            { editable: true });
        }
      });
    };
    $('#block-filter', host).addEventListener('input', (event) => {
      query = event.target.value;
      renderList();
    });
    renderList();   // 速记块同步先上屏；目录分组等桥返回后补充
    try {
      const result = await window.pwncraft.request('blocks_list');
      blocks = result.blocks || [];
    } catch (error) {
      $('#block-list', host).insertAdjacentHTML('beforeend',
        `<div class="hint-dim">代码块目录加载失败：${esc(error.message)}</div>`);
      return;
    }
    renderList();
  }

  async function insertBlockWithPlaceholders(block) {
    const names = block.placeholders || [];
    if (!names.length) {
      await insertExp(block.snippet);
      log(`已插入代码块：${block.title}`);
      return;
    }
    const fields = names.map((name) => `
      <label class="form-row"><span>${esc(name)}</span>
        <input class="input ph-input" data-name="${esc(name)}" placeholder="${esc(name)}" /></label>`).join('');
    app().openDialog(`填写代码块参数：${block.title}`, fields, async () => {
      let text = block.snippet;
      $$('.ph-input').forEach((input) => {
        const value = input.value.trim();
        if (value) text = text.split(`{{${input.dataset.name}}}`).join(value);
      });
      await insertExp(text);
      log(`已插入代码块：${block.title}`);
    });
  }

  function renderConvMini(host) {
    host.innerHTML = `
      <label class="form-row"><span>整数</span><input id="mini-int" class="input" placeholder="0x7f..." /></label>
      <button id="mini-int-go" class="btn">转换并展示</button>
      <div id="mini-int-out"></div>
      <label class="form-row" style="margin-top:10px"><span>字节/字符串</span><input id="mini-bytes" class="input" placeholder="b'AAAA' 或文本" /></label>
      <button id="mini-bytes-go" class="btn">转换并展示</button>
      <div id="mini-bytes-out"></div>`;
    $('#mini-int-go', host).addEventListener('click', async () => {
      try {
        const result = await window.pwncraft.request('convert', { mode: 'int', value: $('#mini-int', host).value.trim() });
        $('#mini-int-out', host).innerHTML = result.results.map((item) => `
          <div class="tpl-row"><div class="tpl-title">${esc(item.title)}</div>
          <div class="tpl-command mono">${esc(item.value)}</div></div>`).join('');
      } catch (error) {
        $('#mini-int-out', host).textContent = error.message;
      }
    });
    $('#mini-bytes-go', host).addEventListener('click', async () => {
      try {
        const result = await window.pwncraft.request('convert', { mode: 'bytes', value: $('#mini-bytes', host).value.trim() });
        $('#mini-bytes-out', host).innerHTML = result.results.map((item) => `
          <div class="tpl-row"><div class="tpl-title">${esc(item.title)}</div>
          <div class="tpl-command mono">${esc(item.value)}</div></div>`).join('');
      } catch (error) {
        $('#mini-bytes-out', host).textContent = error.message;
      }
    });
  }

  function renderFmtMini(host) {
    host.innerHTML = `
      <div class="hint-dim">常用格式化字符串片段（点击插入）</div>
      ${[
        ['low/high 分段写入', "payload = fmtstr_payload(FMT_OFFSET, {TARGET: VALUE}, write_size='short')"],
        ['%s 泄漏', "p.sendline(b'%9$s')\nleak = p.recvuntil(b'\\x7f', drop=False)"],
        ['%p 探针', "p.sendline(b'AAAAAAAA' + b'.'.join(b'%%%d$p' % i for i in range(1, 30)))"],
        ['fmtstr_payload 全量', "payload = fmtstr_payload(FMT_OFFSET, {GOT_ADDR: SYSTEM_ADDR})"],
      ].map(([title, snippet], index) => `
        <div class="tpl-row" data-index="${index}">
          <div class="tpl-title">${esc(title)}</div>
          <div class="tpl-command mono">${esc(snippet)}</div>
        </div>`).join('')}`;
    $$('.tpl-row', host).forEach((row) => {
      row.addEventListener('click', () => insertExp(host.querySelector(`.tpl-row[data-index="${row.dataset.index}"] .tpl-command`).textContent));
    });
  }

  async function renderCommandHints(host) {
    try {
      const result = await window.pwncraft.request('command_templates');
      const items = result.wsl || [];
      host.innerHTML = items.map((item, index) => `
        <div class="tpl-row" data-index="${index}">
          <div class="tpl-title">${esc(item.title)}</div>
          <div class="tpl-command mono">${esc(item.command)}</div>
        </div>`).join('');
      $$('.tpl-row', host).forEach((row) => {
        row.addEventListener('click', () => {
          navigator.clipboard.writeText(items[Number(row.dataset.index)].command);
          log('命令已复制到剪贴板');
        });
      });
    } catch (error) {
      host.textContent = error.message;
    }
  }

  async function renderGdbMenu(host) {
    try {
      const result = await window.pwncraft.request('command_templates');
      const items = result.gdb || [];
      host.innerHTML = items.map((item, index) => `
        <div class="tpl-row" data-index="${index}">
          <div class="tpl-title">${esc(item.title)}</div>
          <div class="tpl-command mono">${esc(item.command)}</div>
        </div>`).join('');
      $$('.tpl-row', host).forEach((row) => {
        row.addEventListener('click', async () => {
          const command = items[Number(row.dataset.index)].command;
          navigator.clipboard.writeText(command);
          log(`已复制：${command}`);
        });
      });
    } catch (error) {
      host.textContent = error.message;
    }
  }

  // =====================================================================
  window.PwnPages = {
    renderBinary,
    renderRop,
    renderDebug,
    renderFormat,
    renderSyscall,
    renderStack,
    renderTools,
    renderExpTools,
    runCliTool,
    scanVulnPoints,
  };
})();
