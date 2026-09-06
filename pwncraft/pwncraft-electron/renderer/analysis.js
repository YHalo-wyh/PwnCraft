/** Read-only code analysis, cached independently for each target workspace. */
(() => {
  'use strict';
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
  const app = () => window.PwnApp;
  const entryNow = () => app().state.workspaces.get(app().state.activePath);
  const host = () => document.getElementById('page-analysis');
  const query = (selector) => host().querySelector(selector);

  function render() {
    const entry = entryNow();
    if (!entry || app().state.importState !== 'bound') {
      host().innerHTML = '<div class="sidebar-empty" style="padding:26px">导入 ELF 后，可在这里查看汇编函数和漏洞建议。</div>';
      return;
    }
    const cache = entry.analysis ||= { tab: 'functions', filter: '', selected: 0, loading: false };
    const data = cache.data || {};
    const functions = data.functions || [];
    const diagnostics = data.diagnostics || [];
    host().innerHTML = `
      <div class="analysis-header"><div><h2>代码分析</h2>
        <div class="analysis-path">${esc(entry.context.working_binary)}</div></div>
        <button class="mini-btn" id="analysis-refresh" ${cache.loading ? 'disabled' : ''}>${cache.loading ? '分析中…' : '重新分析'}</button></div>
      <div class="analysis-tabs" role="tablist" aria-label="代码分析内容">
        <button id="analysis-functions-tab" role="tab" data-tab="functions" aria-controls="analysis-functions" aria-selected="${cache.tab === 'functions'}">汇编函数 <span>${cache.data ? data.function_count : '—'}</span></button>
        <button id="analysis-diagnostics-tab" role="tab" data-tab="diagnostics" aria-controls="analysis-diagnostics" aria-selected="${cache.tab === 'diagnostics'}">漏洞建议 <span>${cache.data ? diagnostics.length : '—'}</span></button>
      </div>
      ${cache.error ? `<div class="analysis-error" role="alert">分析失败：${esc(cache.error)}。可点击“重新分析”重试。</div>` : ''}
      <div class="analysis-hint" role="status">${cache.loading ? '正在读取当前文件并检查当前 EXP…' : '汇编来自静态反汇编；建议来自现有 EXP 审计规则。'}</div>
      <div id="analysis-functions" role="tabpanel" aria-labelledby="analysis-functions-tab" ${cache.tab !== 'functions' ? 'hidden' : ''}>
        <div class="analysis-hint">按符号识别函数边界${data.stripped ? '；此文件已剥离符号，列表可能不完整' : ''}。${data.truncated ? '列表已截断，仅展示前 1000 项。' : ''}</div>
        ${data.assembly_error ? `<div class="analysis-error">汇编读取失败：${esc(data.assembly_error)}。请检查 WSL 与 objdump 后重试。</div>` : ''}
        <div class="analysis-layout"><aside class="analysis-function-sidebar">
          <input id="analysis-filter" type="search" placeholder="搜索函数名 / 地址" aria-label="搜索汇编函数" value="${esc(cache.filter)}">
          <div id="analysis-function-list" aria-label="函数列表"></div>
        </aside><div class="analysis-function-detail" id="analysis-function-detail"></div></div>
        ${data.notice ? `<details class="analysis-notice"><summary>环境提示</summary><pre>${esc(data.notice)}</pre></details>` : ''}
      </div>
      <div id="analysis-diagnostics" role="tabpanel" aria-labelledby="analysis-diagnostics-tab" ${cache.tab !== 'diagnostics' ? 'hidden' : ''}>
        <div class="analysis-hint">检查对象：当前工作区的 EXP。这里展示代码检查提示；二进制漏洞仍需独立核实。</div>
        <div class="analysis-diagnostic-list">${diagnostics.map(d => `
          <article class="analysis-diagnostic">
            <div class="analysis-diagnostic-meta"><span class="analysis-severity ${['error', 'warning', 'suggestion'].includes(d.severity) ? d.severity : ''}">${esc(({ error: '错误', warning: '警告', suggestion: '建议' })[d.severity] || '提示')}</span>
              <code>${esc(d.code)}</code><span>${d.line > 0 ? `EXP 第 ${Number(d.line)} 行` : 'EXP'}</span></div>
            <p>${esc(d.message)}</p>${d.impact ? `<p class="analysis-hint">${esc(d.impact)}</p>` : ''}
            ${d.evidence && d.evidence.length ? `<details class="analysis-notice"><summary>查看依据</summary><pre>${esc(JSON.stringify(d.evidence, null, 2))}</pre></details>` : ''}
          </article>`).join('') || `<div class="analysis-empty">${cache.loading ? '正在检查…' : cache.error ? '未取得审计结果。' : cache.data ? '现有规则未发现需要提示的项目。' : '等待分析。'}</div>`}</div>
        <button class="mini-btn" id="analysis-open-exp">打开 EXP 编辑器</button>
      </div>`;
    query('#analysis-refresh').onclick = () => refresh(entry, true);
    query('#analysis-open-exp').onclick = () => app().switchPage('exp');
    host().querySelectorAll('[data-tab]').forEach(button => {
      button.onclick = () => { cache.tab = button.dataset.tab; render(); };
      button.onkeydown = event => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        cache.tab = event.key === 'Home' ? 'functions' : event.key === 'End' ? 'diagnostics' : cache.tab === 'functions' ? 'diagnostics' : 'functions';
        render();
        query(`[data-tab="${cache.tab}"]`).focus();
      };
      button.tabIndex = button.dataset.tab === cache.tab ? 0 : -1;
    });
    query('#analysis-filter').oninput = event => { cache.filter = event.target.value; renderFunctions(cache, functions); };
    renderFunctions(cache, functions);
    if (!cache.loading && (!cache.attempted || cache.source !== app().getExpText())) refresh(entry, false);
  }

  function renderFunctions(cache, functions) {
    const needle = cache.filter.toLowerCase().trim();
    const matches = functions.map((fn, index) => ({ fn, index }))
      .filter(({ fn }) => `${fn.name} ${fn.address}`.toLowerCase().includes(needle));
    if (!matches.some(item => item.index === cache.selected)) cache.selected = matches[0]?.index ?? -1;
    query('#analysis-function-list').innerHTML = matches.map(({ fn, index }) => `
      <button class="analysis-function ${cache.selected === index ? 'selected' : ''}" data-index="${index}" aria-pressed="${cache.selected === index}">
        <span>${esc(fn.name)}</span><code>${esc(fn.address)}</code></button>`).join('') ||
      `<div class="analysis-empty">${cache.loading ? '正在读取…' : needle ? '没有匹配的函数。' : '没有可展示的函数符号。'}</div>`;
    const fn = functions[cache.selected];
    query('#analysis-function-detail').innerHTML = fn ? `
      <div class="analysis-function-heading"><strong>${esc(fn.name)}</strong><code>${esc(fn.address)}</code><span>${esc(fn.section)} · ${fn.instruction_count} 条指令</span></div>
      <pre class="analysis-assembly">${esc(fn.assembly || '（无指令）')}</pre>
      ${fn.truncated ? '<div class="analysis-hint">此函数仅展示前 500 行。</div>' : ''}` : '<div class="analysis-empty">选择函数以查看汇编。</div>';
    query('#analysis-function-list').querySelectorAll('button').forEach(button => {
      button.onclick = () => { cache.selected = Number(button.dataset.index); renderFunctions(cache, functions); };
    });
  }

  async function refresh(entry, force) {
    const cache = entry.analysis;
    if (cache.loading) return;
    cache.loading = true;
    cache.error = '';
    cache.source = app().getExpText();
    cache.attempted = true;
    const includeAssembly = force || !cache.data || !!cache.data.assembly_error;
    render();
    try {
      const result = await window.pwncraft.request('code_analysis', {
        path: entry.context.working_binary, source: cache.source, include_assembly: includeAssembly,
      });
      cache.data = includeAssembly ? result : { ...cache.data, diagnostics: result.diagnostics };
    } catch (error) {
      cache.error = error.message || String(error);
      // Never present old diagnostics as results for the newly edited source.
      if (cache.data) cache.data = { ...cache.data, diagnostics: [] };
    } finally {
      cache.loading = false;
      if (entryNow() === entry && app().state.page === 'analysis') render();
    }
  }
  window.PwnAnalysis = { render };
})();
