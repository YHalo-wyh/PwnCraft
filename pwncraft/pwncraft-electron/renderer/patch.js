/** AWDP ELF 补丁页：手动字节 patch / 一键通防 / 字节码查询 / 补丁管理。
 * 一切地址与字节真值来自 Python 桥（patch_* RPC）；本页只展示与转发请求，
 * 原始 ELF 始终只读，补丁只写工作副本并自动备份。 */
(() => {
  'use strict';
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
  const app = () => window.PwnApp;
  const entryNow = () => app().state.workspaces.get(app().state.activePath);
  const host = () => document.getElementById('page-patch');
  const query = (selector) => host().querySelector(selector);

  const TABS = [
    ['manual', '手动 Patch'],
    ['recipes', '一键通防'],
    ['bytecode', '字节码查询'],
    ['manage', '补丁管理'],
  ];

  function cacheOf(entry) {
    return entry.patch ||= {
      tab: 'manual', filter: '', selectedFn: -1, selectedInsn: -1,
      functions: null, functionsError: '', loading: false,
      instructions: null, instructionsError: '', insnLoading: false,
      hex: '', recipes: null, recipesError: '', forms: {},
      preview: null, previewRequest: null, previewTitle: '', previewError: '',
      log: null, logSummary: null, logError: '',
      catalogQuery: '', catalogData: null,
      disasmInput: '', disasmData: null, disasmError: '',
      relFrom: '', relTo: '', relResult: '',
      idaStatus: null, idaBusy: false, idaOverview: null, idaError: '',
      decompiled: null,
      busy: false, message: '', error: '',
    };
  }

  function render() {
    const entry = entryNow();
    if (!entry || app().state.importState !== 'bound') {
      host().innerHTML = '<div class="sidebar-empty" style="padding:26px">导入 ELF 后，可在这里做 AWDP 字节级补丁与一键通防。</div>';
      return;
    }
    const cache = cacheOf(entry);
    const context = entry.context || {};
    host().innerHTML = `
      <div class="analysis-header"><div><h2>AWDP Patch</h2>
        <div class="analysis-path">${esc(context.working_binary || '')}</div></div>
        <div class="patch-arch-chips">
          <span class="chip">${esc(context.architecture || '未知架构')}</span>
          <span class="chip">${Number(context.bits || 0) || '?'} 位</span>
          <span class="chip">原始副本只读 · 补丁自动备份</span>
        </div></div>
      <div class="analysis-tabs" role="tablist" aria-label="AWDP 补丁内容">
        ${TABS.map(([key, label]) => `
          <button id="patch-tab-${key}" role="tab" data-tab="${key}" aria-controls="patch-panel-${key}"
            aria-selected="${cache.tab === key}">${label}</button>`).join('')}
      </div>
      ${cache.error ? `<div class="analysis-error" role="alert">${esc(cache.error)}</div>` : ''}
      ${cache.message ? `<div class="patch-message ok-text" role="status">${esc(cache.message)}</div>` : ''}
      <div id="patch-panel-manual" role="tabpanel" aria-labelledby="patch-tab-manual" ${cache.tab !== 'manual' ? 'hidden' : ''}></div>
      <div id="patch-panel-recipes" role="tabpanel" aria-labelledby="patch-tab-recipes" ${cache.tab !== 'recipes' ? 'hidden' : ''}></div>
      <div id="patch-panel-bytecode" role="tabpanel" aria-labelledby="patch-tab-bytecode" ${cache.tab !== 'bytecode' ? 'hidden' : ''}></div>
      <div id="patch-panel-manage" role="tabpanel" aria-labelledby="patch-tab-manage" ${cache.tab !== 'manage' ? 'hidden' : ''}></div>`;
    host().querySelectorAll('[data-tab]').forEach((button) => {
      button.onclick = () => { cache.tab = button.dataset.tab; render(); };
      button.tabIndex = button.dataset.tab === cache.tab ? 0 : -1;
      button.onkeydown = (event) => {
        if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
        event.preventDefault();
        const order = TABS.map(([key]) => key);
        const next = event.key === 'ArrowLeft'
          ? order[(order.indexOf(cache.tab) + order.length - 1) % order.length]
          : order[(order.indexOf(cache.tab) + 1) % order.length];
        cache.tab = next; render();
        query(`[data-tab="${next}"]`).focus();
      };
    });
    if (cache.tab === 'manual') renderManual(entry, cache);
    if (cache.tab === 'recipes') renderRecipes(entry, cache);
    if (cache.tab === 'bytecode') renderBytecode(entry, cache);
    if (cache.tab === 'manage') renderManage(entry, cache);
    if (!cache.functions && !cache.loading) ensureFunctions(entry);
    if (!cache.recipes) ensureRecipes(entry);
    if (cache.log === null) refreshLog(entry);
  }

  // ------------------------------------------------------------------
  // 共用：预览 / 应用
  async function previewPatch(entry, request, title) {
    const cache = cacheOf(entry);
    cache.previewError = ''; cache.preview = null; cache.previewTitle = title;
    cache.previewRequest = request; cache.busy = true; cache.message = ''; render();
    try {
      cache.preview = await window.pwncraft.request('patch_preview', { request });
    } catch (error) {
      cache.previewError = error.message || String(error);
    } finally {
      cache.busy = false;
      render();
    }
  }

  async function applyPreview(entry) {
    const cache = cacheOf(entry);
    if (!cache.previewRequest) return;
    cache.busy = true; cache.error = ''; cache.message = ''; render();
    try {
      const result = await window.pwncraft.request('patch_apply', { request: cache.previewRequest });
      cache.log = result.log || cache.log;
      const backupName = result.backup ? String(result.backup).split(/[\\/]/).pop() : '';
      cache.message = `已应用 ${result.applied.length} 条补丁${backupName ? `（备份 ${backupName}）` : ''}`;
      // Keypatch 反向联动：IDA 会话活跃时把补丁字节同步进 IDA 数据库（尽力而为）
      if (cache.idaStatus && cache.idaStatus.available) {
        try {
          for (const op of result.applied) {
            await window.pwncraft.request('ida_patch_bytes', {
              vaddr: `0x${Number(op.vaddr).toString(16)}`, hex: op.new_bytes });
          }
          cache.message += ' · 已同步 IDA';
        } catch (idaError) {
          cache.message += ` · IDA 同步失败（${String(idaError.message || idaError).slice(0, 60)}）`;
        }
      }
      cache.preview = null; cache.previewRequest = null;
      await refreshAfterMutation(entry);
    } catch (error) {
      cache.error = error.message || String(error);
    } finally {
      cache.busy = false;
      render();
    }
  }

  async function refreshAfterMutation(entry) {
    const cache = cacheOf(entry);
    cache.instructions = null;
    const functions = cache.functions || [];
    const fn = functions[cache.selectedFn];
    if (fn) await loadInstructions(entry, fn.name, false);
    try {
      const result = await window.pwncraft.request('patch_list', {});
      cache.log = result.ops;
      cache.logSummary = result.summary || null;
    } catch { /* 日志失败不阻塞补丁视图 */ }
  }

  function renderPreviewBox(entry, cache) {
    if (cache.previewError) {
      return `<div class="analysis-error" role="alert">预览失败：${esc(cache.previewError)}</div>`;
    }
    if (!cache.preview) return '';
    const ops = cache.preview.ops || [];
    return `
      <div class="patch-preview card">
        <div class="card-title">补丁预览 · ${esc(cache.previewTitle)}（${ops.length} 条等长替换）
          <span class="flex-spacer"></span>
          <button class="mini-btn primary" id="patch-preview-apply" ${cache.busy ? 'disabled' : ''}>${cache.busy ? '应用中…' : '应用补丁'}</button>
          <button class="mini-btn" id="patch-preview-cancel" ${cache.busy ? 'disabled' : ''}>放弃</button>
        </div>
        ${(cache.preview.warnings || []).map(w => `<div class="patch-warning">${esc(w)}</div>`).join('')}
        <table class="data-table mono"><thead><tr>
          <th>vaddr</th><th>file</th><th>长度</th><th>原字节</th><th>新字节</th><th>说明</th>
        </tr></thead><tbody>
          ${ops.map(op => `<tr>
            <td>0x${Number(op.vaddr).toString(16)}</td>
            <td>0x${Number(op.file_offset).toString(16)}</td>
            <td>${op.new_bytes.split(' ').length}</td>
            <td class="patch-bytes-old">${esc(op.original_bytes)}</td>
            <td class="patch-bytes-new">${esc(op.new_bytes)}</td>
            <td>${esc(op.note)}</td></tr>`).join('')}
        </tbody></table>
      </div>`;
  }

  function wirePreviewBox(entry, cache) {
    const apply = query('#patch-preview-apply');
    const cancel = query('#patch-preview-cancel');
    if (apply) apply.onclick = () => applyPreview(entry);
    if (cancel) cancel.onclick = () => { cache.preview = null; cache.previewRequest = null; cache.previewError = ''; render(); };
  }

  // ------------------------------------------------------------------
  // Tab 1: 手动 Patch
  async function ensureFunctions(entry) {
    const cache = cacheOf(entry);
    if (cache.loading || cache.functions) return;
    cache.loading = true; render();
    try {
      const result = await window.pwncraft.request('code_analysis', {
        path: entry.context.working_binary, include_assembly: true,
      });
      cache.functions = result.functions || [];
      cache.functionsError = result.assembly_error ? `汇编读取失败：${result.assembly_error}` : '';
      if (cache.selectedFn < 0 && cache.functions.length) cache.selectedFn = 0;
      const fn = cache.functions[cache.selectedFn];
      if (fn) loadInstructions(entry, fn.name, false);
    } catch (error) {
      cache.functionsError = error.message || String(error);
    } finally {
      cache.loading = false;
      if (entryNow() === entry && app().state.page === 'patch') render();
    }
  }

  async function loadInstructions(entry, functionName, rerender = true) {
    const cache = cacheOf(entry);
    cache.insnLoading = true; cache.instructionsError = '';
    if (rerender) render();
    try {
      cache.instructions = await window.pwncraft.request('patch_instructions', {
        function: functionName,
      });
    } catch (error) {
      cache.instructions = null;
      cache.instructionsError = error.message || String(error);
    } finally {
      cache.insnLoading = false;
      if (entryNow() === entry && app().state.page === 'patch') render();
    }
  }

  // ------------------------------------------------------------------
  // IDA 联动（IDA-CLI / idalib）：状态徽章 / pwn 体检 / 伪代码
  function idaBadgeText(cache) {
    if (cache.idaBusy) return 'IDA：检测中…';
    const status = cache.idaStatus;
    if (!status) return 'IDA：未检测';
    if (status.available) return `IDA：就绪（${status.backend && status.backend.idalib ? 'idalib' : 'backend'} · ${String(status.backend && (status.backend.ida_version || status.backend.version) || 'IDA 9.x')}）`;
    return 'IDA：不可用';
  }

  function renderIdaCards(cache) {
    if (cache.decompiled) {
      return `<details class="patch-decompile card" open><summary>IDA 伪代码 · ${esc(cache.decompiled.name || '')}</summary>
        <pre class="report-pre">${esc(cache.decompiled.pseudocode || '')}</pre></details>`;
    }
    const overview = cache.idaOverview;
    if (!overview) return '';
    const row = (label, items, render) => items && items.length
      ? `<div class="patch-ida-row"><span class="patch-ida-key">${label} (${items.length})</span>
          <span>${items.map(render).join('')}</span></div>` : '';
    return `
      <div class="card patch-ida-card">
        <div class="card-title">IDA pwn 体检</div>
        ${row('危险导入', overview.dangerous_imports, i =>
          `<span class="patch-ida-item mono">${esc(i.name)}</span>`)}
        ${row('可疑符号', overview.interesting_symbols, i =>
          `<span class="patch-ida-item mono">${esc(i.name)}@0x${Number(i.ea).toString(16)}<span class="hint-dim"> ${esc(i.reason || '')}</span></span>`)}
        ${row('命中字符串', overview.string_hits, i =>
          `<span class="patch-ida-item mono">${esc(String(i.value).slice(0, 40))}</span>`)}
        ${overview.mitigation_hints && Object.keys(overview.mitigation_hints).length
          ? `<div class="patch-ida-row"><span class="patch-ida-key">缓解提示</span><span class="hint-dim">${esc(Object.entries(overview.mitigation_hints).map(([k, v]) => `${k}=${v}`).join(' · '))}</span></div>` : ''}
      </div>`;
  }

  async function idaRefresh(entry, force = false) {
    const cache = cacheOf(entry);
    if (cache.idaBusy || (cache.idaStatus && !force)) return;
    cache.idaBusy = true; cache.idaError = '';
    renderManual(entry, cache);
    try {
      cache.idaStatus = await window.pwncraft.request('ida_status', {});
    } catch (error) {
      cache.idaStatus = { available: false };
      cache.idaError = error.message || String(error);
    } finally {
      cache.idaBusy = false;
      if (entryNow() === entry && app().state.page === 'patch') render();
    }
  }

  async function idaAnalyze(entry) {
    const cache = cacheOf(entry);
    cache.idaBusy = true; cache.idaError = ''; cache.idaOverview = null;
    renderManual(entry, cache);
    try {
      const result = await window.pwncraft.request('ida_analyze', {});
      cache.idaOverview = result.overview || {};
      cache.idaStatus = { available: true, backend: {} };
    } catch (error) {
      cache.idaError = `IDA 分析失败：${error.message || String(error)}`;
    } finally {
      cache.idaBusy = false;
      if (entryNow() === entry && app().state.page === 'patch') render();
    }
  }

  async function idaDecompile(entry, functionName) {
    const cache = cacheOf(entry);
    cache.idaBusy = true; cache.idaError = ''; cache.decompiled = null;
    renderManual(entry, cache);
    try {
      cache.decompiled = await window.pwncraft.request('ida_decompile', { function: functionName });
    } catch (error) {
      cache.idaError = `伪代码获取失败：${error.message || String(error)}`;
    } finally {
      cache.idaBusy = false;
      if (entryNow() === entry && app().state.page === 'patch') render();
    }
  }

  // ------------------------------------------------------------------
  // Keypatch 式汇编补丁对话框：输入汇编实时编译（keystone），剩余字节 NOP
  function openPatcherModal(entry, selected) {
    closePatcherModal();
    const overlay = document.createElement('div');
    overlay.className = 'patch-modal-overlay';
    overlay.id = 'patch-patcher-modal';
    overlay.innerHTML = `
      <div class="patch-modal card" role="dialog" aria-label="汇编补丁（Keypatch 式）">
        <div class="card-title">汇编补丁 · Keypatch 式
          <span class="flex-spacer"></span>
          <button class="mini-btn" id="patcher-close">关闭</button></div>
        <div class="patcher-origin mono">
          <div><span class="hint-dim">地址</span> ${esc(selected.address)}</div>
          <div><span class="hint-dim">原字节</span> ${esc(selected.bytes)}</div>
          <div><span class="hint-dim">原汇编</span> ${esc(selected.text)}（objdump AT&T，输入请用 Intel 语法）</div>
        </div>
        <input id="patcher-input" class="input mono" placeholder="新汇编（Intel 语法），如 mov edi, 0 / xor edx, edx / jmp 0x401234"
          aria-label="新汇编指令" autocomplete="off">
        <div id="patcher-encode" class="patcher-encode mono"></div>
        <label class="form-row"><input type="checkbox" id="patcher-nop-fill" checked>
          <span>剩余字节自动填 NOP（Keypatch 行为；新指令必须 ≤ 原 ${selected.size} 字节）</span></label>
        <div class="patcher-actions">
          <button class="mini-btn primary" id="patcher-apply" disabled>生成补丁预览</button>
          <span class="hint-dim">Ctrl+Enter 应用 · Esc 关闭</span>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    const input = overlay.querySelector('#patcher-input');
    const encodeBox = overlay.querySelector('#patcher-encode');
    const applyBtn = overlay.querySelector('#patcher-apply');
    let compiled = null;
    let timer = null;
    const compile = async () => {
      const text = input.value.trim();
      compiled = null;
      if (!text) {
        encodeBox.innerHTML = '<span class="hint-dim">输入汇编指令后实时显示机器码</span>';
        applyBtn.disabled = true;
        return;
      }
      try {
        const result = await window.pwncraft.request('patch_assemble', {
          text, vaddr: selected.address,
        });
        const tooLong = result.size > selected.size;
        compiled = tooLong ? null : result;
        applyBtn.disabled = tooLong;
        encodeBox.innerHTML = `
          <span class="${tooLong ? 'err-text' : 'ok-text'}">${esc(result.bytes)}</span>
          <span class="hint-dim">· ${result.size} 字节${tooLong
            ? `（超出原指令 ${selected.size} 字节，无法等长替换）`
            : result.size < selected.size
              ? `（差 ${selected.size - result.size} 字节，将按选项填充）` : '（恰好等长）'}</span>`;
      } catch (error) {
        compiled = null;
        applyBtn.disabled = true;
        encodeBox.innerHTML = `<span class="err-text">${esc(error.message || String(error))}</span>`;
      }
    };
    input.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(compile, 250);
    });
    const commit = () => {
      if (!compiled) return;
      const fill = overlay.querySelector('#patcher-nop-fill').checked;
      const pad = fill && compiled.size < selected.size
        ? ' ' + '90'.repeat(selected.size - compiled.size).replace(/(..)/g, '$1 ').trim() : '';
      const hex = compiled.bytes + pad;
      if (hex.replace(/ /g, '').length / 2 !== selected.size) {
        encodeBox.innerHTML = '<span class="err-text">长度不一致：请开启 NOP 填充或调整指令</span>';
        return;
      }
      closePatcherModal();
      previewPatch(entry, {
        kind: 'custom', vaddr: selected.address, hex, expected_size: selected.size,
      }, `汇编补丁 @${selected.address}（${input.value.trim()}）`);
    };
    applyBtn.addEventListener('click', commit);
    overlay.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closePatcherModal();
      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) commit();
    });
    overlay.querySelector('#patcher-close').addEventListener('click', closePatcherModal);
    input.focus();
  }

  function closePatcherModal() {
    document.getElementById('patch-patcher-modal')?.remove();
  }

  function renderManual(entry, cache) {
    const panel = query('#patch-panel-manual');
    const functions = cache.functions || [];
    const needle = cache.filter.toLowerCase().trim();
    const matches = functions.map((fn, index) => ({ fn, index }))
      .filter(({ fn }) => `${fn.name} ${fn.address}`.toLowerCase().includes(needle));
    if (!matches.some(item => item.index === cache.selectedFn)) cache.selectedFn = matches[0]?.index ?? -1;
    const fn = functions[cache.selectedFn];
    const instructions = cache.instructions && fn && cache.instructions.function === fn.name
      ? cache.instructions.instructions : null;
    panel.innerHTML = `
      ${cache.loading ? '<div class="analysis-hint" role="status">正在读取汇编函数…</div>' : ''}
      ${cache.functionsError ? `<div class="analysis-error">${esc(cache.functionsError)}</div>` : ''}
      <div class="analysis-layout"><aside class="analysis-function-sidebar">
        <input id="patch-filter" type="search" placeholder="搜索函数名 / 地址" aria-label="搜索函数" value="${esc(cache.filter)}">
        <div id="patch-fn-list" aria-label="函数列表">
          ${matches.map(({ fn: f, index }) => `
            <button class="analysis-function ${cache.selectedFn === index ? 'selected' : ''}" data-index="${index}" aria-pressed="${cache.selectedFn === index}">
              <span>${esc(f.name)}</span><code>${esc(f.address)}</code></button>`).join('') ||
            `<div class="analysis-empty">${cache.loading ? '读取中…' : needle ? '没有匹配的函数。' : '没有可展示的函数。'}</div>`}
        </div>
      </aside><div class="analysis-function-detail">
        <div class="patch-ida-bar">
          <span class="chip" id="patch-ida-badge">${idaBadgeText(cache)}</span>
          <button class="mini-btn" id="patch-ida-refresh" ${cache.idaBusy ? 'disabled' : ''}>检测 IDA</button>
          <button class="mini-btn" id="patch-ida-analyze" ${cache.idaBusy ? 'disabled' : ''}>IDA 分析</button>
          <button class="mini-btn" id="patch-ida-decompile" ${!fn || cache.idaBusy ? 'disabled' : ''}>查看伪代码</button>
        </div>
        ${cache.idaError ? `<div class="analysis-error">${esc(cache.idaError)}</div>` : ''}
        ${renderIdaCards(cache)}
        ${fn ? `
          <div class="analysis-function-heading"><strong>${esc(fn.name)}</strong><code>${esc(fn.address)}</code>
            <span>${esc(fn.section)} · ${fn.instruction_count} 条指令</span></div>
          <div class="patch-actions">
            <button class="mini-btn primary" id="patch-asm-open" ${cache.selectedInsn < 0 ? 'disabled' : ''} title="Keypatch 式：输入新汇编实时编译，剩余字节自动 NOP（Ctrl+P）">汇编补丁</button>
            <button class="mini-btn" id="patch-nop-insn" ${cache.selectedInsn < 0 ? 'disabled' : ''}>NOP 选中指令</button>
            <button class="mini-btn" id="patch-nop-tail" ${cache.selectedInsn < 0 ? 'disabled' : ''}>NOP 到函数尾</button>
            <button class="mini-btn" id="patch-jcc-invert" ${cache.selectedInsn < 0 ? 'disabled' : ''} title="jg↔jle / jl↔jge / je↔jne 等；off-by-one 边界修复的 1 字节手法">反转跳转条件</button>
            <button class="mini-btn" id="patch-ret-fn">函数 ret 化</button>
            <button class="mini-btn" id="patch-nop-fn">整函数 NOP</button>
            <span class="patch-hex-wrap">
              <input id="patch-hex" class="input mono" placeholder="自定义 hex（如 31 d2 或 b8 01 00 00 00）"
                value="${esc(cache.hex)}" aria-label="自定义补丁字节" ${cache.selectedInsn < 0 ? 'disabled' : ''}>
              <button class="mini-btn primary" id="patch-write-hex" ${cache.selectedInsn < 0 ? 'disabled' : ''}>写入选中地址</button>
            </span>
          </div>
          ${instructions ? `
            <div class="patch-insn-scroll">
              <table class="data-table mono patch-insn-table"><thead><tr>
                <th>地址</th><th>字节</th><th>汇编</th>
              </tr></thead><tbody>
                ${instructions.map((insn, index) => `<tr
                  class="patch-insn ${cache.selectedInsn === index ? 'selected' : ''}" data-index="${index}">
                  <td>${esc(insn.address)}</td><td>${esc(insn.bytes)}</td><td>${esc(insn.text)}</td></tr>`).join('')}
              </tbody></table>
            </div>` : `<div class="analysis-empty">${cache.insnLoading ? '读取指令…' : cache.instructionsError ? esc(cache.instructionsError) : '选择函数以查看指令。'}</div>`}
        ` : '<div class="analysis-empty">选择函数以查看指令。</div>'}
        ${renderPreviewBox(entry, cache)}
      </div></div>`;
    const filter = query('#patch-filter');
    if (filter) filter.oninput = (event) => { cache.filter = event.target.value; renderManual(entry, cache); };
    if (cache.idaStatus === null) idaRefresh(entry);
    panel.querySelectorAll('#patch-fn-list button').forEach((button) => {
      button.onclick = () => {
        cache.selectedFn = Number(button.dataset.index);
        cache.selectedInsn = -1;
        cache.instructions = null;
        render();
        const f = cache.functions[cache.selectedFn];
        if (f) loadInstructions(entry, f.name);
      };
    });
    panel.querySelectorAll('.patch-insn').forEach((row) => {
      row.onclick = () => {
        cache.selectedInsn = Number(row.dataset.index);
        renderManual(entry, cache);
      };
    });
    const selected = instructions?.[cache.selectedInsn];
    const fnEnd = fn && instructions?.length
      ? `0x${(parseInt(instructions[instructions.length - 1].address, 16)
        + instructions[instructions.length - 1].size).toString(16)}`
      : '';
    const bind = (id, handler) => { const el = query(id); if (el) el.onclick = handler; };
    bind('#patch-ida-refresh', () => idaRefresh(entry, true));
    bind('#patch-ida-analyze', () => idaAnalyze(entry));
    bind('#patch-ida-decompile', () => fn && idaDecompile(entry, fn.name));
    bind('#patch-asm-open', () => selected && openPatcherModal(entry, selected));
    bind('#patch-nop-insn', () => selected && previewPatch(entry, {
      kind: 'nop_range', start: selected.address,
      end: `0x${(parseInt(selected.address, 16) + selected.size).toString(16)}`,
    }, `NOP 0x${selected.address}（${selected.size} 字节）`));
    bind('#patch-nop-tail', () => selected && fnEnd && previewPatch(entry, {
      kind: 'nop_range', start: selected.address, end: fnEnd,
    }, `NOP 0x${selected.address} → 函数尾`));
    bind('#patch-jcc-invert', () => selected && previewPatch(entry, {
      kind: 'jcc_invert', vaddr: selected.address,
    }, `反转条件跳转 @${selected.address}`));
    bind('#patch-ret-fn', () => fn && previewPatch(entry, {
      kind: 'ret_function', function: fn.name,
    }, `${fn.name} ret 化`));
    bind('#patch-nop-fn', () => fn && previewPatch(entry, {
      kind: 'nop_function', function: fn.name,
    }, `${fn.name} 整函数 NOP`));
    const hex = query('#patch-hex');
    if (hex) hex.oninput = (event) => { cache.hex = event.target.value; };
    bind('#patch-write-hex', () => selected && previewPatch(entry, {
      kind: 'custom', vaddr: selected.address, hex: cache.hex, expected_size: selected.size,
    }, `自定义字节 @${selected.address}`));
    wirePreviewBox(entry, cache);
  }

  // ------------------------------------------------------------------
  // Tab 2: 一键通防
  async function ensureRecipes(entry) {
    const cache = cacheOf(entry);
    if (cache.recipes) return;
    try {
      cache.recipes = await window.pwncraft.request('patch_recipes', {});
    } catch (error) {
      cache.recipesError = error.message || String(error);
    } finally {
      if (entryNow() === entry && app().state.page === 'patch' && cache.tab === 'recipes') render();
    }
  }

  function formValue(cache, recipeId, key, fallback = '') {
    return (cache.forms[recipeId] ||= {})[key] ?? fallback;
  }

  function pltOptions(cache) {
    return (cache.functions || [])
      .filter(fn => String(fn.name).endsWith('@plt'))
      .map(fn => ({ value: fn.name.slice(0, -4), label: fn.name }));
  }

  function textOptions(cache) {
    return (cache.functions || [])
      .filter(fn => !String(fn.name).endsWith('@plt'))
      .map(fn => ({ value: fn.name, label: fn.name }));
  }

  function fieldControl(cache, recipe, field) {
    const value = esc(formValue(cache, recipe.id, field.key, field.default || ''));
    if (field.kind === 'select' && field.dynamic) {
      return `<select class="input" data-field="${esc(field.key)}" aria-label="${esc(field.label)}">
        ${field.options?.length
          ? field.options.map(o => `<option value="${esc(o.value)}" ${formValue(cache, recipe.id, field.key, field.default || o.value) === o.value ? 'selected' : ''}>${esc(o.label)}</option>`).join('')
          : `<option value="">（先等待函数列表）</option>`}
      </select>`;
    }
    if (field.kind === 'select') {
      return `<select class="input" data-field="${esc(field.key)}" aria-label="${esc(field.label)}">
        ${field.options.map(o => `<option value="${esc(o.value)}" ${formValue(cache, recipe.id, field.key, field.default || o.value) === o.value ? 'selected' : ''}>${esc(o.label)}</option>`).join('')}
      </select>`;
    }
    if (field.kind === 'policy') {
      return `<textarea class="input mono patch-policy" data-field="${esc(field.key)}" rows="3"
        placeholder="default kill&#10;allow read&#10;allow write&#10;kill execve" aria-label="${esc(field.label)}">${value}</textarea>`;
    }
    if (field.kind === 'number') {
      return `<input class="input mono" data-field="${esc(field.key)}" value="${value}" aria-label="${esc(field.label)}">`;
    }
    return `<input class="input" data-field="${esc(field.key)}" value="${value}" aria-label="${esc(field.label)}">`;
  }

  function buildRecipeRequest(cache, recipe) {
    const form = cache.forms[recipe.id] ||= {};
    if (recipe.id === 'seccomp') {
      const request = { kind: 'seccomp', preset: form.preset || 'blacklist_min' };
      if (request.preset === 'custom') request.policy = form.policy || '';
      return request;
    }
    if (recipe.id === 'plt_call' || recipe.id === 'plt_stub') {
      return { kind: recipe.id, source: form.source || '', target: form.target || '' };
    }
    if (recipe.id === 'readlen') {
      return { kind: 'readlen', function: form.function || '', callee: form.callee || 'read', size: form.size || '0x30' };
    }
    if (recipe.id === 'nop_function' || recipe.id === 'ret_function') {
      return { kind: recipe.id, function: form.function || '' };
    }
    return null;
  }

  function renderRecipes(entry, cache) {
    const panel = query('#patch-panel-recipes');
    const recipes = cache.recipes?.recipes || [];
    const presets = cache.recipes?.seccomp_presets || {};
    panel.innerHTML = `
      ${cache.recipesError ? `<div class="analysis-error">${esc(cache.recipesError)}</div>` : ''}
      <div class="patch-recipes">
        ${recipes.map(recipe => {
          const options = dynamicOptionsFor(cache, recipe);
          return `<article class="recipe-card card">
            <div class="card-title">${esc(recipe.name)}
              <span class="flex-spacer"></span>
              <button class="mini-btn primary patch-recipe-preview" data-recipe="${esc(recipe.id)}" ${cache.busy ? 'disabled' : ''}>预览补丁</button>
            </div>
            <div class="recipe-fields">
              ${recipe.fields.map(field => `
                <label class="form-row"><span class="k">${esc(field.label)}</span>
                  <span class="v">${fieldControl(cache, recipe, field, options)}</span></label>`).join('')}
            </div>
            ${(Array.isArray(recipe.warnings) ? recipe.warnings : []).map(w => `<div class="patch-warning">${esc(w)}</div>`).join('')}
          </article>`;
        }).join('')}
      </div>
      ${renderPreviewBox(entry, cache)}`;
    panel.querySelectorAll('[data-field]').forEach((control) => {
      const card = control.closest('.recipe-card');
      const recipeId = card?.querySelector('.patch-recipe-preview')?.dataset.recipe;
      control.oninput = control.onchange = () => {
        (cache.forms[recipeId] ||= {})[control.dataset.field] = control.value;
      };
    });
    panel.querySelectorAll('.patch-recipe-preview').forEach((button) => {
      button.onclick = () => {
        const recipe = recipes.find(r => r.id === button.dataset.recipe);
        if (!recipe) return;
        previewPatch(entry, buildRecipeRequest(cache, recipe), recipe.name);
      };
    });
    wirePreviewBox(entry, cache);
  }

  function dynamicOptionsFor(cache, recipe) {
    // 动态下拉的选项在渲染时注入（PLT / 函数列表来自 code_analysis 真值）
    if (recipe.id === 'seccomp') {
      const presets = cache.recipes?.seccomp_presets || {};
      const options = Object.entries(presets).map(([key, conf]) => ({ value: key, label: conf.name }));
      options.push({ value: 'custom', label: '自定义规则…' });
      recipe.fields.find(f => f.key === 'preset').options = options;
    }
    if (recipe.id === 'plt_call' || recipe.id === 'plt_stub') {
      const options = pltOptions(cache);
      recipe.fields.find(f => f.key === 'source').options = options;
      recipe.fields.find(f => f.key === 'target').options = options;
    }
    if (['readlen', 'nop_function', 'ret_function'].includes(recipe.id)) {
      const field = recipe.fields.find(f => f.key === 'function');
      if (field) field.options = textOptions(cache);
    }
    return undefined;
  }

  // ------------------------------------------------------------------
  // Tab 3: 字节码查询
  function renderBytecode(entry, cache) {
    const panel = query('#patch-panel-bytecode');
    const entries = cache.catalogData?.entries ?? [];
    panel.innerHTML = `
      <div class="patch-query-row">
        <input id="patch-catalog-query" class="input mono" placeholder="搜索助记符 / 字节 / 标签，如 nop、e9、跳转"
          value="${esc(cache.catalogQuery)}" aria-label="搜索字节码目录">
        <button class="mini-btn" id="patch-catalog-search">查询目录</button>
      </div>
      <div class="patch-insn-scroll">
        <table class="data-table mono"><thead><tr><th>指令</th><th>机器码</th><th>说明</th><th></th></tr></thead>
        <tbody>
          ${entries.map(e => `<tr><td>${esc(e.mnemonic)}</td><td class="ok-text">${esc(e.bytes)}</td>
            <td>${esc(e.note || e.tag)}</td>
            <td><button class="mini-btn patch-use-bytes" data-bytes="${esc(e.bytes)}">填入手动 Patch</button></td></tr>`).join('') ||
          `<tr><td colspan="4" class="hint-dim">${cache.catalogData ? '没有匹配条目。' : '输入关键词查询（如 nop、ret、jmp）。'}</td></tr>`}
        </tbody></table>
      </div>
      <div class="patch-disasm card">
        <div class="card-title">hex → 反汇编（Intel 语法）
          <span class="flex-spacer"></span>
          <button class="mini-btn" id="patch-disasm-run">反汇编</button></div>
        <input id="patch-disasm-input" class="input mono" placeholder="如 48 89 e5 或 4889e5" value="${esc(cache.disasmInput)}" aria-label="待反汇编字节">
        ${cache.disasmError ? `<div class="analysis-error">${esc(cache.disasmError)}</div>` : ''}
        ${cache.disasmData ? `<pre class="report-pre">${esc((cache.disasmData.instructions || []).map(i => `+0x${i.offset.toString(16).padStart(2, '0')}  ${i.text}`).join('\n')) || '（无指令）'}</pre>` : ''}
      </div>
      <div class="patch-disasm card">
        <div class="card-title">rel32 跳转计算器</div>
        <div class="patch-query-row">
          <input id="patch-rel-from" class="input mono" placeholder="指令地址 0x.." value="${esc(cache.relFrom)}" aria-label="跳转源地址">
          <input id="patch-rel-to" class="input mono" placeholder="目标地址 0x.." value="${esc(cache.relTo)}" aria-label="跳转目标地址">
          <button class="mini-btn" id="patch-rel-jmp">算 jmp rel32</button>
          <button class="mini-btn" id="patch-rel-call">算 call rel32</button>
        </div>
        ${cache.relResult ? `<pre class="report-pre">${esc(cache.relResult)}</pre>` : ''}
      </div>`;
    const search = query('#patch-catalog-query');
    const runSearch = async () => {
      cache.catalogData = await window.pwncraft.request('patch_bytecode_lookup', { query: cache.catalogQuery });
      renderBytecode(entry, cache);
    };
    if (search) {
      search.oninput = (event) => { cache.catalogQuery = event.target.value; };
      search.onkeydown = (event) => { if (event.key === 'Enter') runSearch(); };
    }
    const searchButton = query('#patch-catalog-search');
    if (searchButton) searchButton.onclick = runSearch;
    panel.querySelectorAll('.patch-use-bytes').forEach((button) => {
      button.onclick = () => {
        cache.hex = button.dataset.bytes;
        cache.tab = 'manual';
        cache.message = `已填入字节 ${button.dataset.bytes}；选中指令后点「写入选中地址」。`;
        render();
      };
    });
    const disasmInput = query('#patch-disasm-input');
    if (disasmInput) disasmInput.oninput = (event) => { cache.disasmInput = event.target.value; };
    const disasmRun = query('#patch-disasm-run');
    if (disasmRun) disasmRun.onclick = async () => {
      cache.disasmError = ''; cache.disasmData = null; renderBytecode(entry, cache);
      try {
        cache.disasmData = await window.pwncraft.request('patch_disasm_raw', { hex: cache.disasmInput });
      } catch (error) {
        cache.disasmError = error.message || String(error);
      }
      renderBytecode(entry, cache);
    };
    const relFrom = query('#patch-rel-from'), relTo = query('#patch-rel-to');
    if (relFrom) relFrom.oninput = (e) => { cache.relFrom = e.target.value; };
    if (relTo) relTo.oninput = (e) => { cache.relTo = e.target.value; };
    const runRel = async (kind) => {
      try {
        const result = await window.pwncraft.request('patch_encode', {
          kind, params: { origin: cache.relFrom, target: cache.relTo },
        });
        cache.relResult = `${result.note}\n${result.bytes}`;
      } catch (error) {
        cache.relResult = `错误：${error.message || String(error)}`;
      }
      renderBytecode(entry, cache);
    };
    query('#patch-rel-jmp').onclick = () => runRel('jmp_rel32');
    query('#patch-rel-call').onclick = () => runRel('call_rel32');
  }

  // ------------------------------------------------------------------
  // Tab 4: 补丁管理
  function renderManage(entry, cache) {
    const panel = query('#patch-panel-manage');
    const ops = cache.log;
    const summary = cache.logSummary || {
      total: ops?.length || 0,
      applied: (ops || []).filter(op => !op.state || op.state === 'applied').length,
      restored: (ops || []).filter(op => op.state === 'restored').length,
      conflict: (ops || []).filter(op => op.state === 'conflict').length,
    };
    const integrityUnknown = ops === null;
    const hasDrift = integrityUnknown || summary.restored > 0 || summary.conflict > 0;
    const batchCounts = new Map();
    (ops || []).forEach(op => {
      const key = op.batch_id || op.op_id;
      batchCounts.set(key, (batchCounts.get(key) || 0) + 1);
    });
    const batchHasDrift = new Map();
    (ops || []).forEach(op => {
      const key = op.batch_id || op.op_id;
      if (op.state && op.state !== 'applied') batchHasDrift.set(key, true);
    });
    const stateLabel = state => ({ applied: '已生效', restored: '已恢复', conflict: '有冲突' }[state] || '未检查');
    panel.innerHTML = `
      <div class="patch-integrity ${hasDrift ? 'has-drift' : ''}" role="status">
        <strong>${integrityUnknown ? (cache.logError ? '补丁完整性检查失败' : '正在检查补丁完整性…')
          : hasDrift ? '工作副本与补丁记录不一致' : '补丁完整性正常'}</strong>
        <span>${integrityUnknown ? esc(cache.logError || '')
          : `记录 ${summary.total} · 生效 ${summary.applied} · 已恢复 ${summary.restored} · 冲突 ${summary.conflict}`}</span>
      </div>
      <div class="patch-manage-bar">
        <button class="mini-btn" id="patch-refresh-log">重新检查</button>
        <button class="mini-btn" id="patch-reconcile" ${summary.restored === 0 ? 'disabled' : ''}>清理已恢复记录</button>
        <button class="mini-btn" id="patch-undo-all" ${(ops?.length ?? 0) === 0 || hasDrift ? 'disabled' : ''}>安全撤销全部</button>
        <span class="flex-spacer"></span>
        <button class="mini-btn primary" id="patch-export-script" ${(ops?.length ?? 0) === 0 || hasDrift ? 'disabled' : ''}>生成 patch.py</button>
        <button class="mini-btn primary" id="patch-export-elf" ${(ops?.length ?? 0) === 0 || hasDrift ? 'disabled' : ''}>导出补丁后 ELF</button>
        <button class="mini-btn" id="patch-export-diff" ${(ops?.length ?? 0) === 0 || hasDrift ? 'disabled' : ''}>导出 diff 文本</button>
      </div>
      ${ops === null ? `<div class="analysis-empty">${cache.logError ? esc(cache.logError) : '读取补丁记录…'}</div>` : ops.length === 0
        ? '<div class="analysis-empty">当前工作副本还没有已应用的补丁。</div>' : `
      <div class="patch-insn-scroll">
        <table class="data-table mono"><thead><tr>
          <th>#</th><th>状态</th><th>类型</th><th>vaddr</th><th>原字节</th><th>新字节</th><th>当前字节</th><th>说明</th><th></th>
        </tr></thead><tbody>
          ${ops.map((op, index) => `<tr>
            <td>${index + 1}</td>
            <td><span class="patch-state ${esc(op.state || 'unknown')}" title="${esc(op.issue || '')}">${stateLabel(op.state)}</span></td>
            <td>${esc(op.kind)}</td>
            <td>0x${Number(op.vaddr).toString(16)}</td>
            <td class="patch-bytes-old">${esc(op.original_bytes)}</td>
            <td class="patch-bytes-new">${esc(op.new_bytes)}</td>
            <td class="${op.state === 'conflict' ? 'patch-bytes-conflict' : 'patch-bytes-current'}">${op.state === 'applied' ? '—' : esc(op.current_bytes || '无法读取')}</td>
            <td>${esc(op.note)}</td>
            <td><button class="mini-btn patch-undo" data-op="${esc(op.op_id)}"
              ${(op.state && op.state !== 'applied') || batchHasDrift.get(op.batch_id || op.op_id) ? 'disabled' : ''}>
              ${batchCounts.get(op.batch_id || op.op_id) > 1 ? `撤销整组（${batchCounts.get(op.batch_id || op.op_id)}）` : '撤销'}</button></td></tr>`).join('')}
        </tbody></table>
      </div>`}
      ${(cache.exportPreviews || []).map(item => `
        <details class="patch-export-text card"><summary>导出内容预览（${esc(item.name)}）</summary>
          <pre class="report-pre">${esc(item.text)}</pre></details>`).join('')}`;
    query('#patch-refresh-log').onclick = () => refreshLog(entry, true);
    const reconcile = query('#patch-reconcile');
    if (reconcile) reconcile.onclick = async () => {
      try {
        const result = await window.pwncraft.request('patch_reconcile', {});
        cache.message = result.pending
          ? `已清理 ${result.count} 条记录；另有 ${result.pending} 条属于尚未完整恢复的补丁组，已保留。`
          : `已清理 ${result.count} 条已由外部恢复的补丁记录。`;
        await refreshAfterMutation(entry);
      } catch (error) {
        cache.error = error.message || String(error);
      }
      render();
    };
    const undoAll = query('#patch-undo-all');
    if (undoAll) undoAll.onclick = async () => {
      try {
        const result = await window.pwncraft.request('patch_clear', {});
        cache.message = `已安全撤销全部 ${result.count} 条补丁。`;
        await refreshAfterMutation(entry);
      } catch (error) {
        cache.error = error.message || String(error);
      }
      render();
    };
    panel.querySelectorAll('.patch-undo').forEach((button) => {
      button.onclick = async () => {
        try {
          const result = await window.pwncraft.request('patch_undo', { op_id: button.dataset.op });
          cache.message = result.count > 1 ? `已安全撤销整组 ${result.count} 条补丁。` : '已安全撤销一条补丁。';
          await refreshAfterMutation(entry);
        } catch (error) {
          cache.error = error.message || String(error);
        }
        render();
      };
    });
    const binaryName = (entry.context.working_binary || 'pwn').split(/[\\/]/).pop();
    query('#patch-export-script').onclick = () => exportArtifact(entry, 'script', `patch_${binaryName}.py`, 'py');
    query('#patch-export-diff').onclick = () => exportArtifact(entry, 'diff', `${binaryName}_patch.diff`, 'txt');
    query('#patch-export-elf').onclick = () => exportArtifact(entry, 'patched', `${binaryName}_patched`, 'bin');
  }

  async function exportArtifact(entry, kind, defaultName, dialogKind) {
    const cache = cacheOf(entry);
    const path = await window.pwncraft.pickSavePath(defaultName, dialogKind);
    if (!path) return;
    cache.busy = true; cache.error = ''; cache.message = ''; render();
    try {
      const result = await window.pwncraft.request('patch_export', { kind, dest: path });
      cache.message = kind === 'patched'
        ? `已导出补丁后 ELF → ${result.path}（${result.count} 条补丁，sha256 ${String(result.sha256).slice(0, 12)}…）`
        : `已生成${kind === 'script' ? ' patch.py 脚本' : ' diff 文本'} → ${result.path}`;
      if (result.text) {
        (cache.exportPreviews ||= []).push({
          name: String(path).split(/[\\/]/).pop(), text: result.text });
      }
    } catch (error) {
      cache.error = error.message || String(error);
    } finally {
      cache.busy = false;
      if (entryNow() === entry && app().state.page === 'patch') render();
    }
  }

  async function refreshLog(entry, rerender = false) {
    const cache = cacheOf(entry);
    try {
      const result = await window.pwncraft.request('patch_list', {});
      cache.log = result.ops;
      cache.logSummary = result.summary || null;
      cache.logError = '';
    } catch (error) {
      cache.logError = error.message || String(error);
    }
    if (rerender && entryNow() === entry && app().state.page === 'patch') render();
  }

  window.PwnPatch = { render };
})();
