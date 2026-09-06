/**
 * PwnCraft Electron Workbench — renderer shell (v0.31).
 *
 * Vanilla ES modules-free script: activity bar + tabs + pages over a bottom
 * panel, VS Code habits (Ctrl+` terminal, Ctrl+K/Ctrl+Shift+P palette,
 * Ctrl+O import, Ctrl+S save).  Pages live in pages.js / heap.js; terminals
 * are *instances* (WSL bash per project, one fresh pwndbg-mogai instance per
 * debug session).  All Pwn truth comes from the Python bridge.
 *
 * 每个 ELF 一个独立工作区：workspaces Map 按 ELF 路径保存各自的
 * context / facts / EXP 草稿；切换工作区通过 bridge 的 light import
 * 重新绑定单一真值，UI 不制造第二真值。
 */
(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const icon = (name) => window.lucideIcon ? window.lucideIcon(name) : '';
  const nowTime = () => new Date().toTimeString().slice(0, 8);
  const esc = (value) => String(value ?? '').replace(/[&<>"]/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;',
  }[c]));

  const state = {
    page: 'welcome',
    importState: 'empty',           // empty | importing | bound
    project: null,
    context: null,
    facts: null,
    staticReport: '',
    patchSummary: '',
    reports: null,                  // {checksec, file, ldd} — Binary 页三卡片
    reportsFor: '',
    reportsInFlight: false,
    terminalCwd: '',
    arch: 'amd64',
    bits: 64,
    expDirtyTimer: null,
    expHeapLineDecorationIds: [],
    expHeapLineItems: [],
    expHeapActiveLine: 0,
    expHeapLineHandler: null,
    workspaces: new Map(),          // elfPath -> workspace entry
    activePath: null,
  };

  // checksec 归一化值（bridge parse_checksec_output）→ 展示状态。
  // 旧实现判断 "enabled" 子串，对 ON/OFF 值域永远显示 ✗ —— 已修正。
  function secInfo(raw) {
    const value = String(raw || '').trim().toUpperCase();
    if (value === 'ON') return { cls: 'on', mark: '✓', text: '开启' };
    if (value === 'FULL') return { cls: 'on', mark: '✓', text: '全开' };
    if (value === 'PARTIAL') return { cls: 'partial', mark: '◐', text: '部分' };
    if (value === 'OFF') return { cls: 'off', mark: '✗', text: '关闭' };
    if (value === 'NONE') return { cls: 'off', mark: '✗', text: '无' };
    return { cls: 'unknown', mark: '?', text: '未知' };
  }
  const SEC_KEYS = ['PIE', 'NX', 'CANARY', 'RELRO', 'FORTIFY', 'STRIPPED'];

  // ------------------------------------------------------------------
  // Logging (bottom panel)

  const logStore = [];
  function log(message, level = 'info') {
    logStore.push({ time: nowTime(), level, message: String(message) });
    renderLogs();
  }
  function renderLogs() {
    const host = $('#logs-list');
    if (!host) return;
    const needle = $('#logs-filter').value.trim().toLowerCase();
    const rows = logStore
      .filter((row) => !needle || row.message.toLowerCase().includes(needle))
      .slice(-400);
    host.innerHTML = rows.map((row) => `
      <div class="log-row ${row.level}">
        <span class="log-time">${row.time}</span>
        <span class="log-msg"></span>
      </div>`).join('');
    const msgs = host.querySelectorAll('.log-msg');
    rows.forEach((row, index) => { msgs[index].textContent = row.message; });
    host.scrollTop = host.scrollHeight;
  }

  // ------------------------------------------------------------------
  // Dialogs

  function openDialog(title, bodyHtml, onOk, okLabel = '确定') {
    let overlay = $('#dialog-overlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.id = 'dialog-overlay';
      overlay.hidden = true;
      document.body.appendChild(overlay);
      overlay.addEventListener('mousedown', (event) => {
        if (event.target === overlay) closeDialog();
      });
    }
    overlay.innerHTML = `
      <div id="dialog">
        <div class="dialog-title">${title}</div>
        <div class="dialog-body">${bodyHtml}</div>
        <div class="dialog-actions">
          <button class="btn" id="dialog-cancel">取消</button>
          <button class="btn primary" id="dialog-ok">${okLabel}</button>
        </div>
      </div>`;
    overlay.hidden = false;
    $('#dialog-cancel').addEventListener('click', closeDialog);
    $('#dialog-ok').addEventListener('click', async () => {
      const host = $('#dialog-body-host') || overlay;
      const inputs = overlay.querySelectorAll('input, select, textarea');
      void inputs;
      try {
        if (onOk) await onOk();
        closeDialog();
      } catch (error) {
        log(`操作失败：${error.message}`, 'error');
      }
      void host;
    });
    const first = overlay.querySelector('input, select, textarea');
    if (first) first.focus();
  }
  function closeDialog() {
    const overlay = $('#dialog-overlay');
    if (overlay) overlay.hidden = true;
  }

  // ------------------------------------------------------------------
  // Tabs & pages

  // 顶部标签导览已移除：页面切换只走左侧活动栏（#activitybar）。
  // 保留 no-op 以兼容历史调用点。
  function renderTabs() { /* top tabbar removed */ }

  function switchPage(key) {
    state.page = key;
    for (const section of $$('.page')) section.hidden = true;
    const page = $(`#page-${key}`);
    if (page) page.hidden = false;
    if (key === 'binary') window.PwnPages.renderBinary();
    if (key === 'rop') window.PwnPages.renderRop();
    if (key === 'debug') window.PwnPages.renderDebug();
    if (key === 'format') window.PwnPages.renderFormat();
    if (key === 'syscall') window.PwnPages.renderSyscall();
    if (key === 'stack') window.PwnPages.renderStack();
    if (key === 'tools') window.PwnPages.renderTools();
    // 调试页聚焦模式：侧栏收起、EXP 从左滑入占 1/4、命令栏贴右
    document.getElementById('app').classList.toggle('debug-focus', key === 'debug');
    if (key === 'exp') {
      mountExpEditor('#monaco-host');
      setTimeout(() => monacoEditor && monacoEditor.layout(), 0);
    }
    if (key === 'debug') mountExpEditor('#debug-exp-slot');
    if (key === 'heap') {
      // Semantic Round Trip：堆页左栏源代码视图 = 同一个 EXP 编辑器实例
      mountExpEditor('#heap-exp-source-slot');
    }
    renderTabs();
  }

  // ------------------------------------------------------------------
  // Activity bar & sidebar

  const ACTIVITIES = [
    { key: 'welcome', title: '概览 / 导入 Target', icon: 'home' },
    { key: 'binary', title: 'Binary 概览', icon: 'box' },
    { key: 'exp', title: 'EXP 编辑器', icon: 'file-code' },
    { key: 'heap', title: 'Heap 物理堆画布', icon: 'cpu' },
    { key: 'rop', title: 'ROP / Gadget', icon: 'zap' },
    { key: 'debug', title: 'pwndbg-mogai 调试', icon: 'terminal' },
    { key: 'format', title: 'Format String', icon: 'command' },
    { key: 'syscall', title: 'Syscall / Seccomp', icon: 'shield' },
    { key: 'stack', title: 'Stack Offset / Leak', icon: 'import' },
    { key: 'tools', title: '工具箱', icon: 'folder-open' },
  ];

  function renderActivity() {
    const bar = $('#activitybar');
    bar.innerHTML = ACTIVITIES.map((item) => `
      <button class="activity-item" data-key="${item.key}" title="${item.title}">${icon(item.icon)}</button>
    `).join('');
    bar.querySelectorAll('.activity-item').forEach((button) => {
      button.addEventListener('click', () => switchPage(button.dataset.key));
    });
  }

  // 左侧 TARGET 侧栏已按需求移除：Target 详情在 Binary 页，入口走活动栏 / Ctrl+O / 命令面板。
  // 保留 no-op 以兼容既有调用点。
  function renderSidebar() { /* sidebar removed */ }

  async function startDebugFromSidebar() {
    switchPage('debug');
    const button = $('#debug-start');
    if (button) button.click();
  }

  // ------------------------------------------------------------------
  // Welcome page (概览：只保留大导入框 + 最近导入；Target 信息一律去 Binary 页看)

  function renderWelcome() {
    const host = $('#page-welcome');
    host.innerHTML = `
      <div class="welcome">
        <div class="welcome-brand">
          <div class="welcome-title">Pwn<span class="accent">Craft</span></div>
        </div>
        <div class="welcome-import">
          <div class="drop-square" id="drop-square" role="button" tabindex="0">
            ${icon('import')}
            <div class="drop-main">${state.importState === 'importing' ? '正在绑定 Target…' : '拖入 ELF 文件绑定 Target'}</div>
            <div class="drop-sub">或点击选择 · 绑定后所有工具自动继承同一 Target · Binary 页查看保护/架构详情</div>
          </div>
          <div class="welcome-hints" id="welcome-recent"></div>
        </div>
      </div>`;

    const drop = $('#drop-square');
    drop.addEventListener('click', pickAndImport);
    drop.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') pickAndImport();
    });
    renderRecent();
  }

  // 拖放监听只绑一次（document 级）：任何页面拖入 ELF 都能导入；
  // Electron 32+ 移除了 File.path，必须经 preload 的 webUtils.getPathForFile 取路径。
  function bindGlobalDragDrop() {
    if (document.documentElement.dataset.dropBound) return;
    document.documentElement.dataset.dropBound = '1';
    let overlay = null;
    const ensureOverlay = () => {
      if (overlay) return overlay;
      overlay = document.createElement('div');
      overlay.id = 'drop-overlay';
      overlay.hidden = true;
      overlay.innerHTML = `
        <div class="drop-overlay-box">
          ${icon('import')}
          <div class="drop-overlay-main">松开导入 ELF · 绑定为 Target</div>
          <div class="drop-overlay-sub">原始文件只读 · patch 仅作用于工作副本</div>
        </div>`;
      document.body.appendChild(overlay);
      return overlay;
    };
    let dragDepth = 0;
    document.addEventListener('dragenter', (event) => {
      event.preventDefault();
      dragDepth += 1;
      ensureOverlay().hidden = false;
    });
    document.addEventListener('dragover', (event) => {
      event.preventDefault();
      const drop = $('#drop-square');
      if (drop) drop.classList.add('dragover');
    });
    document.addEventListener('dragleave', (event) => {
      dragDepth = Math.max(0, dragDepth - 1);
      const drop = $('#drop-square');
      if (drop) drop.classList.remove('dragover');
      if (!dragDepth && overlay) overlay.hidden = true;
    });
    document.addEventListener('drop', (event) => {
      event.preventDefault();
      dragDepth = 0;
      if (overlay) overlay.hidden = true;
      const drop = $('#drop-square');
      if (drop) drop.classList.remove('dragover');
      const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
      if (!file) return;
      let path = '';
      if (window.pwnbao.filePathFor) path = window.pwnbao.filePathFor(file);
      else if (file.path) path = file.path;   // Electron ≤31 fallback
      if (!path) {
        log('无法获取拖入文件的路径（Electron 安全限制），请改用 Ctrl+O 选择文件。', 'error');
        return;
      }
      importElf(path);
    });
  }

  function recentPaths() {
    try { return JSON.parse(localStorage.getItem('pwnbao.recentPaths') || '[]'); }
    catch { return []; }
  }
  function pushRecentPath(path) {
    const list = recentPaths().filter((item) => item !== path);
    list.unshift(path);
    localStorage.setItem('pwnbao.recentPaths', JSON.stringify(list.slice(0, 5)));
  }

  function renderRecent() {
    const host = $('#welcome-recent');
    const list = recentPaths();
    if (!host) return;
    if (!list.length) { host.innerHTML = ''; return; }
    host.innerHTML = `
      <div class="sidebar-title">最近导入</div>
      ${list.map((path) => `<button class="recent-row" data-path="${esc(path)}">${icon('box')}<span class="recent-path"></span></button>`).join('')}`;
    host.querySelectorAll('.recent-row').forEach((button, index) => {
      button.querySelector('.recent-path').textContent = list[index];
      button.title = list[index];
      button.addEventListener('click', () => importElf(list[index]));
    });
  }

  async function pickAndImport() {
    const path = await window.pwnbao.pickElf();
    if (path) importElf(path);
  }

  async function importElf(path) {
    const existing = state.workspaces.get(path);
    if (existing) { await switchWorkspace(path); return; }
    if (state.importState === 'importing') {
      log('上一次导入仍在进行中，已忽略本次请求', 'warn');
      return;
    }
    state.importState = 'importing';
    renderSidebar();
    switchPage('welcome');
    renderWelcome();
    log(`正在绑定 Target: ${path}`);
    try {
      const result = await window.pwnbao.request('import_target', { path, light: true });
      const facts = Object.assign({}, result.facts, { path: result.context.working_binary });
      const binaryName = (result.context.working_binary || path).split(/[\\/]/).pop();
      const entry = {
        path,
        name: path.split(/[\\/]/).pop() || 'target',
        context: result.context,
        facts,
        project: result.project,
        staticReport: result.static_report || '',
        patchSummary: result.patch_summary || '',
        patchError: result.patch_error || '',
        reports: null,              // Binary 页三卡片：进入 Binary 页时按需拉取
        reportsFetched: false,
        arch: facts.architecture === 'i386' ? 'i386' : 'amd64',
        bits: Number(facts.bits) === 32 ? 32 : 64,
        exp: expTemplate(binaryName),
      };
      state.workspaces.set(path, entry);
      if (result.patch_summary) log('自动 Patch 工作副本完成（原始 ELF 保持只读）');
      pushRecentPath(path);
      await applyWorkspace(entry);
      switchPage('binary');
      log(`工作区已创建：${entry.name}`);
    } catch (error) {
      log(`导入失败：${error.message}`, 'error');
      // 导入失败不打断已打开的工作区
      const current = state.activePath ? state.workspaces.get(state.activePath) : null;
      if (current) await applyWorkspace(current);
      else {
        state.importState = 'empty';
        renderSidebar();
        renderWelcome();
      }
    }
  }

  // ------------------------------------------------------------------
  // Workspaces — 一个 ELF 一个工作区，互相分隔

  async function applyWorkspace(entry, options = {}) {
    state.importState = 'bound';
    state.context = entry.context;
    state.facts = entry.facts;
    state.project = entry.project;
    state.staticReport = entry.staticReport;
    state.patchSummary = entry.patchSummary;
    state.patchError = entry.patchError;
    state.reports = entry.reports || null;
    state.reportsFor = entry.reportsFetched ? entry.path : '';
    state.reportsInFlight = false;
    state.arch = entry.arch;
    state.bits = entry.bits;
    state.activePath = entry.path;
    setExpText(entry.exp);
    syncExpToBridge();
    renderSidebar();
    renderWelcome();
    renderWorkspaceBar();
    updateStatusLeft();
    if (options.restartTerminal !== false) {
      await restartShellTerminal(entry.project && entry.project.project_path || '');
    }
    // 数据页跟着新 Target 重渲染；Heap 画布是独立仿真沙盘，保持原状
    if (['binary', 'rop', 'debug', 'format', 'syscall', 'stack', 'tools'].includes(state.page)) {
      switchPage(state.page);
    }
  }

  async function switchWorkspace(path) {
    const entry = state.workspaces.get(path);
    if (!entry || state.activePath === path) return;
    const current = state.activePath ? state.workspaces.get(state.activePath) : null;
    if (current) current.exp = getExpText();
    log(`切换工作区：${entry.name}`);
    await applyWorkspace(entry);
  }

  async function closeWorkspace(path) {
    const entry = state.workspaces.get(path);
    if (!entry) return;
    state.workspaces.delete(path);
    log(`已关闭工作区：${entry.name}`);
    if (state.activePath !== path) { renderWorkspaceBar(); return; }
    const next = [...state.workspaces.values()].pop() || null;
    if (next) { await applyWorkspace(next); return; }
    state.activePath = null;
    state.importState = 'empty';
    state.context = null;
    state.facts = null;
    state.project = null;
    state.staticReport = '';
    state.patchSummary = '';
    state.patchError = '';
    state.reports = null;
    state.reportsFor = '';
    state.reportsInFlight = false;
    setExpText(expTemplate());
    syncExpToBridge();
    renderSidebar();
    renderWelcome();
    renderWorkspaceBar();
    updateStatusLeft();
    await restartShellTerminal('');
    switchPage('welcome');
  }

  function renderWorkspaceBar() {
    const bar = $('#workspace-bar');
    if (!bar) return;
    const entries = [...state.workspaces.values()];
    if (!entries.length) { bar.hidden = true; bar.innerHTML = ''; return; }
    bar.hidden = false;
    bar.innerHTML = '<span class="ws-label">工作区</span>' + entries.map((entry) => `
      <div class="workspace-tab ${entry.path === state.activePath ? 'active' : ''}" data-path="${esc(entry.path)}" title="${esc(entry.path)}">
        ${icon('box')}<span class="ws-name"></span>
        <span class="tab-close" data-close="1" title="关闭工作区">${icon('x')}</span>
      </div>`).join('');
    bar.querySelectorAll('.workspace-tab').forEach((node) => {
      const entry = state.workspaces.get(node.dataset.path);
      const nameSpan = node.querySelector('.ws-name');
      if (nameSpan) nameSpan.textContent = entry ? entry.name : node.dataset.path;
      node.addEventListener('click', (event) => {
        if (event.target.closest('[data-close]')) closeWorkspace(node.dataset.path);
        else switchWorkspace(node.dataset.path);
      });
    });
  }

  // ------------------------------------------------------------------
  // EXP editor (Monaco) + tools column

  const MONACO_BASE = '../node_modules/monaco-editor/min/vs';
  let monacoEditor = null;

  function expTemplate(binaryName) {
    const active = state.activePath ? state.workspaces.get(state.activePath) : null;
    const name = binaryName
      || (active && active.context && active.context.working_binary || '').split(/[\\/]/).pop()
      || 'pwn';
    const arch = state.arch || 'amd64';
    return [
      'from pwn import*',
      `context(arch='${arch === 'i386' ? 'i386' : 'amd64'}',os='linux',log_level='debug')`,
      "context.terminal=['cmd.exe','/c','wsl.exe','bash','-c']",
      '',
      `elf=ELF('./${name}')`,
      `libc = ELF('./libc.so.6')`,
      '',
      '',
    ].join('\n');
  }

  // EXP 编辑器是一个持久 DOM 节点：exp 页与调试页（左侧 1/4 面板）共用同一实例，
  // 切页时把节点搬去目标槽位（Monaco automaticLayout 会自行重排），不用第二个真值。
  let expEditorNode = null;
  function ensureExpEditorNode() {
    if (!expEditorNode) {
      expEditorNode = document.createElement('div');
      expEditorNode.id = 'exp-editor-inner';
      expEditorNode.style.width = '100%';
      expEditorNode.style.height = '100%';
    }
    return expEditorNode;
  }
  function mountExpEditor(slotSelector) {
    const node = ensureExpEditorNode();
    const slot = $(slotSelector);
    if (slot && node.parentElement !== slot) slot.appendChild(node);
    if (monacoEditor) {
      // 窄面板（堆页左栏/调试页左栏）开自动换行，长行尽量完整显示；
      // 主 EXP 编辑页保持单行 + 横向滚动
      const narrow = slotSelector !== '#monaco-host';
      setTimeout(() => {
        try {
          monacoEditor.updateOptions({ wordWrap: narrow ? 'on' : 'off' });
          monacoEditor.layout();
        } catch { /* editor not ready */ }
      }, 60);
    }
  }

  function initMonaco() {
    mountExpEditor('#monaco-host');
    if (typeof window.require === 'undefined' || !window.require.config) {
      log('Monaco 未找到（node_modules 不完整），EXP 编辑回退为纯文本框', 'warn');
      mountFallbackEditor();
      return;
    }
    const absoluteBase = new URL(MONACO_BASE, window.location.href).href;
    window.MonacoEnvironment = {
      getWorkerUrl: () => 'data:text/javascript;charset=utf-8,' + encodeURIComponent(`
        self.MonacoEnvironment = { baseUrl: '${absoluteBase}/' };
        importScripts('${absoluteBase}/base/worker/workerMain.js');`),
    };
    window.require.config({ paths: { vs: MONACO_BASE } });
    window.require(['vs/editor/editor.main'], () => {
      const monaco = window.monaco;
      monaco.editor.defineTheme('pwnbao-dark', {
        base: 'vs-dark', inherit: true,
        rules: [],
        colors: { 'editor.background': '#1f1f1f', 'editorGutter.background': '#1f1f1f' },
      });
      monacoEditor = monaco.editor.create(ensureExpEditorNode(), {
        value: expTemplate(),
        language: 'python',
        theme: 'pwnbao-dark',
        fontSize: 13,
        fontFamily: '"Cascadia Mono", Consolas, monospace',
        minimap: { enabled: false },
        automaticLayout: true,
        tabSize: 4,
        scrollBeyondLastLine: false,
      });
      monacoEditor.onDidChangeModelContent(() => {
        clearTimeout(state.expDirtyTimer);
        state.expDirtyTimer = setTimeout(syncExpToBridge, 600);
      });
      monacoEditor.onDidChangeCursorPosition((event) => {
        if (state.expHeapLineHandler) state.expHeapLineHandler(event.position.lineNumber);
      });
      // 不只依赖 cursor-position change：画布在别的 step 时，如果
      // 用户再点当前光标所在行，Monaco 不会发 cursor change，
      // 以前就表现为「行号有颜色但点了没用」。鼠标按下每次都按
      // 真实点击行重放，包括行号 gutter 和已经是光标行的情况。
      monacoEditor.onMouseDown((event) => {
        if (!state.expHeapLineHandler) return;
        const line = event.target && event.target.position
          ? event.target.position.lineNumber
          : event.target && event.target.range
            ? event.target.range.startLineNumber
            : 0;
        if (line) state.expHeapLineHandler(line);
      });
      updateExpHeapLineDecorations(state.expHeapLineItems, state.expHeapActiveLine);
      registerExpCompletions(monaco);
      if (window.PwnExpDnD) {
        window.PwnExpDnD.wireMonaco(monacoEditor);
        window.PwnExpDnD.mountPalette('#exp-chip-palette');
        window.PwnExpDnD.scan(document);
      }
      log('Monaco EXP 编辑器已就绪');
    }, (error) => {
      log(`Monaco 加载失败：${error}`, 'warn');
      mountFallbackEditor();
    });
  }

  // EXP 代码补全：pwntools 函数 / 常用对象成员 / exp 模板片段。
  // 数据在 exp_completions.js（社区 exp 高频 API，非自造函数）。
  function registerExpCompletions(monaco) {
    try {
      const data = window.PwnExpCompletions || { functions: [], members: {}, snippets: [] };
      const KIND = monaco.languages.CompletionItemKind;
      const RULE = monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet;
      const funcItems = data.functions.map((item) => ({
        label: item.label,
        kind: KIND.Function,
        detail: item.detail,
        documentation: { value: item.doc || '' },
        insertText: `${item.label}($0)`,
        insertTextRules: RULE,
        sortText: `2${item.label}`,
      }));
      const snippetItems = data.snippets.map((item) => ({
        label: item.label,
        kind: KIND.Snippet,
        detail: `模板 · ${item.detail}`,
        documentation: { value: ['```python', item.insert, '```'].join('\n') },
        insertText: item.insert,
        insertTextRules: RULE,
        sortText: `1${item.label}`,
      }));
      monaco.languages.registerCompletionItemProvider('python', {
        triggerCharacters: ['.', '_'],
        provideCompletionItems(model, position) {
          const before = model.getValueInRange({
            startLineNumber: position.lineNumber, startColumn: 1,
            endLineNumber: position.lineNumber, endColumn: position.column,
          });
          const word = model.getWordUntilPosition(position);
          const range = {
            startLineNumber: position.lineNumber, startColumn: word.startColumn,
            endLineNumber: position.lineNumber, endColumn: word.endColumn,
          };
          // 成员补全：elf. / libc. / p. / context. / rop. / frame. / log.
          const memberMatch = /\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*[A-Za-z0-9_]*$/.exec(before);
          if (memberMatch) {
            const receiver = memberMatch[1].toLowerCase();
            const entries = data.members[receiver];
            if (!entries) return { suggestions: [] };
            return {
              suggestions: entries.map((item) => ({
                label: item.label,
                kind: KIND.Property,
                detail: item.detail || `${receiver} 成员`,
                documentation: { value: item.doc || '' },
                insertText: item.label,
                range,
                sortText: `3${item.label}`,
              })),
            };
          }
          // 全局：函数 + 模板片段（按已输入前缀过滤交给 Monaco 模糊匹配）
          return { suggestions: [...snippetItems, ...funcItems] };
        },
      });
      log('EXP 代码补全已启用（pwntools 函数 / 成员 / exp 模板）');
    } catch (error) {
      log(`EXP 代码补全注册失败：${error.message}`, 'warn');
    }
  }

  function mountFallbackEditor() {
    const host = ensureExpEditorNode();
    host.innerHTML = '';
    const area = document.createElement('textarea');
    area.id = 'monaco-fallback';
    if (window.PwnExpDnD) window.PwnExpDnD.wireTextarea(area);
    area.value = expTemplate();
    area.style.width = '100%';
    area.style.height = '100%';
    area.addEventListener('input', () => {
      clearTimeout(state.expDirtyTimer);
      state.expDirtyTimer = setTimeout(syncExpToBridge, 600);
    });
    const notifyFallbackLine = () => {
      if (!state.expHeapLineHandler) return;
      const upto = area.value.slice(0, area.selectionStart || 0);
      state.expHeapLineHandler(upto.split(/\r?\n/).length);
    };
    area.addEventListener('click', notifyFallbackLine);
    area.addEventListener('keyup', notifyFallbackLine);
    host.appendChild(area);
    mountExpEditor('#monaco-host');
  }

  function setExpHeapLineHandler(handler) {
    state.expHeapLineHandler = typeof handler === 'function' ? handler : null;
  }

  function updateExpHeapLineDecorations(items = [], activeLine = 0) {
    state.expHeapLineItems = Array.isArray(items) ? items : [];
    state.expHeapActiveLine = Number(activeLine) || 0;
    if (!monacoEditor || !window.monaco) return;
    const monaco = window.monaco;
    const seen = new Map();
    for (const item of state.expHeapLineItems) {
      const line = Number(item.line) || 0;
      if (!line) continue;
      const prev = seen.get(line);
      if (!prev || Number(item.step) >= Number(prev.step)) seen.set(line, item);
    }
    const decorations = [...seen.values()].map((item) => {
      const line = Number(item.line);
      const kind = String(item.kind || 'heap').toLowerCase().replace(/[^a-z0-9_-]/g, '');
      const active = line === state.expHeapActiveLine;
      return {
        range: new monaco.Range(line, 1, line, 1),
        options: {
          isWholeLine: false,
          linesDecorationsClassName: `heap-exec-gutter heap-exec-${kind}${active ? ' active' : ''}`,
          lineNumberClassName: `heap-line-no heap-line-${kind}${active ? ' heap-line-active' : ''}`,
          stickiness: monaco.editor.TrackedRangeStickiness.NeverGrowsWhenTypingAtEdges,
        },
      };
    });
    state.expHeapLineDecorationIds = monacoEditor.deltaDecorations(
      state.expHeapLineDecorationIds || [], decorations,
    );
  }

  function getExpText() {
    if (monacoEditor) return monacoEditor.getValue();
    const area = $('#monaco-fallback');
    return area ? area.value : '';
  }

  function setExpText(text) {
    if (monacoEditor) monacoEditor.setValue(text);
    else {
      const area = $('#monaco-fallback');
      if (area) area.value = text;
    }
  }

  async function insertExpText(text) {
    const current = getExpText();
    const next = current && !current.endsWith('\n') ? `${current}\n${text}` : current + text;
    setExpText(next);
    switchPage('exp');
    log('已插入 EXP 片段（预览后可用 Ctrl+Z 撤销）');
    syncExpToBridge();
  }

  async function syncExpToBridge() {
    try {
      await window.pwnbao.request('exp_set', { text: getExpText() });
      // Semantic Round Trip：EXP 一变（停顿 600ms）自动重放识别 —— 画布实时上屏
      if (window.PwnHeap && window.PwnHeap.autoReplayFromExp) {
        window.PwnHeap.autoReplayFromExp();
      }
    } catch { /* bridge offline is fine */ }
  }

  async function saveExp() {
    const defaultName = (state.project && state.project.project_name || 'exp') + '.py';
    const path = await window.pwnbao.pickSavePath(defaultName, 'py');
    if (!path) return;
    try {
      await window.pwnbao.request('exp_save', { path, text: getExpText() });
      log(`已保存: ${path}`);
    } catch (error) {
      log(`保存失败：${error.message}`, 'error');
    }
  }

  // ------------------------------------------------------------------
  // Terminal instances

  const terminals = new Map();   // id -> {term, fitAddon, kind, name, host}
  let activeTerminalId = null;

  const TERM_THEME = {
    background: '#181818', foreground: '#cccccc', cursor: '#cccccc',
    selectionBackground: 'rgba(38, 79, 120, 0.99)',
    black: '#000000', red: '#cd3131', green: '#0dbc79', yellow: '#e5e510',
    blue: '#2472c8', magenta: '#bc3fbc', cyan: '#11a8cd', white: '#e5e5e5',
    brightBlack: '#666666', brightRed: '#f14c4c', brightGreen: '#23d18b',
    brightYellow: '#f5f543', brightBlue: '#3b8eea', brightMagenta: '#d670d6',
    brightCyan: '#29b8db', brightWhite: '#e5e5e5',
  };

  async function createTerminal(kind = 'shell') {
    const hosts = $('#terminal-hosts');
    const host = document.createElement('div');
    host.className = 'term-host';
    hosts.appendChild(host);
    const term = new window.Terminal({
      fontFamily: '"Cascadia Mono", Consolas, monospace',
      fontSize: 13,
      cursorBlink: true,
      allowProposedApi: true,
      theme: TERM_THEME,
    });
    const fitAddon = new window.FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(host);
    term.onData((data) => {
      if (activeTerminalId !== null) window.pwnbao.terminalInput(activeTerminalId, data);
    });
    const refit = () => {
      try {
        fitAddon.fit();
        const id = Number(host.dataset.termId);
        if (id) window.pwnbao.terminalResize(id, term.cols, term.rows);
      } catch { /* hidden */ }
    };
    new ResizeObserver(refit).observe(host);

    try {
      const started = await window.pwnbao.terminalStart({
        kind,
        cwd: state.terminalCwd || '',
        name: kind === 'debug' ? '' : undefined,
      });
      const id = started.id;
      host.dataset.termId = String(id);
      terminals.set(id, { term, fitAddon, kind, name: kind === 'debug' ? 'pwndbg-mogai' : 'WSL bash', host });
      term.clear();
      refit();
      renderTerminalTabs();
      activateTerminal(id);
      log(`终端实例已启动：${kind === 'debug' ? 'pwndbg-mogai 调试' : 'WSL bash'}（#${id}）`);
      return id;
    } catch (error) {
      host.remove();
      log(`终端启动失败：${error.message}`, 'error');
      return null;
    }
  }

  function renderTerminalTabs() {
    const bar = $('#terminal-tabs');
    bar.innerHTML = '';
    for (const [id, entry] of terminals) {
      if (entry.docked === 'page') continue;   // 调试终端挂调试页，不进底部面板
      const tab = document.createElement('button');
      tab.className = 'term-tab' + (id === activeTerminalId ? ' active' : '');
      tab.innerHTML = `<span class="term-dot ${entry.kind}"></span><span class="term-label">${entry.name} #${id}</span>`;
      tab.title = entry.kind === 'debug' ? 'pwndbg-mogai 调试实例' : 'WSL bash 实例';
      tab.addEventListener('click', () => activateTerminal(id));
      const close = document.createElement('span');
      close.className = 'tab-close';
      close.innerHTML = icon('x');
      close.title = '关闭终端';
      close.addEventListener('click', async (event) => {
        event.stopPropagation();
        await window.pwnbao.terminalKill(id);
        removeTerminal(id);
      });
      tab.appendChild(close);
      bar.appendChild(tab);
    }
  }

  function removeTerminal(id) {
    const entry = terminals.get(id);
    if (!entry) return;
    entry.host.remove();
    terminals.delete(id);
    if (entry.kind === 'debug') {
      // 调试实例退出：清空持久节点（连同补全弹层/手册），调试页显示占位
      if (debugTermNode) debugTermNode.innerHTML = '';
      if (state.page === 'debug') window.PwnPages.renderDebug();
      renderTerminalTabs();
      log(`pwndbg-mogai 调试终端已退出（exit 事件）。`, 'warn');
      return;
    }
    if (activeTerminalId === id) {
      activeTerminalId = null;
      const next = terminals.keys().next();
      if (!next.done) activateTerminal(next.value);
    }
    renderTerminalTabs();
  }

  function activateTerminal(id) {
    activeTerminalId = id;
    for (const [termId, entry] of terminals) {
      entry.host.classList.toggle('active', termId === id);
    }
    renderTerminalTabs();
    const entry = terminals.get(id);
    if (entry) {
      setTimeout(() => {
        try { entry.fitAddon.fit(); entry.term.focus(); } catch { /* hidden */ }
      }, 30);
    }
  }

  let shellRestartSeq = 0;
  async function restartShellTerminal(cwd) {
    const token = ++shellRestartSeq;
    state.terminalCwd = cwd || '';
    $('#panel-cwd').textContent = cwd || '~（未打开项目）';
    $('#panel-cwd').title = cwd || '未打开项目，bash 将在 ~ 启动';
    for (const [id, entry] of [...terminals]) {
      if (entry.kind === 'shell') {
        try { await window.pwnbao.terminalKill(id); } catch { /* gone */ }
        removeTerminal(id);
      }
    }
    if (token !== shellRestartSeq) return; // 已有更新的重启在跑，避免 kill/create 竞态
    await createTerminal('shell');
  }

  async function runInTerminal(command) {
    togglePanel('terminal');
    let shellId = null;
    for (const [id, entry] of terminals) {
      if (entry.kind === 'shell') { shellId = id; break; }
    }
    if (shellId === null) shellId = await createTerminal('shell');
    if (shellId === null) return;
    activateTerminal(shellId);
    await window.pwnbao.terminalInput(shellId, `${command}\r`);
    log(`已写入终端：${command}`);
  }

  async function sendToDebugTerminal(command) {
    let debugId = null;
    for (const [id, entry] of terminals) {
      if (entry.kind === 'debug') { debugId = id; break; }
    }
    if (debugId === null) {
      log('调试终端未开启：先在 pwndbg 页点「启动调试终端」。', 'warn');
      switchPage('debug');
      return;
    }
    activateTerminal(debugId);
    await window.pwnbao.terminalInput(debugId, `${command}\r`);
  }

  // 调试终端实例：不再进底部面板，直接挂调试页正中的槽位（持久 DOM 节点，
  // 切页重渲染后由 renderDebug 重新挂载，xterm 实例不重建）。
  let debugTermNode = null;
  function ensureDebugTermNode() {
    if (!debugTermNode) {
      debugTermNode = document.createElement('div');
      debugTermNode.id = 'debug-term-host';
    }
    return debugTermNode;
  }
  function hasDebugSession() {
    for (const [, entry] of terminals) {
      if (entry.kind === 'debug') return true;
    }
    return false;
  }
  function mountDebugTerminalNode() {
    const slot = $('#debug-term-slot');
    if (!slot) return;
    if (hasDebugSession()) {
      slot.innerHTML = '';
      slot.appendChild(ensureDebugTermNode());
      setTimeout(() => {
        for (const [, entry] of terminals) {
          if (entry.kind === 'debug') {
            try { entry.fitAddon.fit(); } catch { /* hidden */ }
          }
        }
      }, 60);
    }
  }
  // -------------------------------------------------------------------
  // pwndbg-mogai 中文补全层：输入前缀弹候选（Tab 采纳 / ↑↓ 选择 / Esc 关闭）
  // F1 打开中文命令手册；pwndbg 提示符首次出现时打印中文提示行。
  function attachDbgCompletion(entry) {
    const { term, host } = entry;
    entry.input = '';
    entry.matches = [];
    entry.sel = 0;
    entry.atPrompt = true;   // 启动初期 gdb 还没跑程序，按提示符处理

    const popup = document.createElement('div');
    popup.className = 'term-completion';
    popup.hidden = true;
    host.appendChild(popup);
    entry.popup = popup;

    const sheet = document.createElement('div');
    sheet.className = 'term-cheatsheet';
    sheet.hidden = true;
    host.appendChild(sheet);
    entry.sheet = sheet;

    const catalog = window.PwnDbgCommands || [];

    function hidePopup() {
      popup.hidden = true;
      entry.matches = [];
    }

    function renderPopup() {
      const matches = entry.matches;
      if (!matches.length) { popup.hidden = true; return; }
      popup.innerHTML = matches.map((m, i) => `
        <div class="tc-row ${i === entry.sel ? 'sel' : ''}" data-i="${i}">
          <span class="tc-name">${m.n}</span>
          <span class="tc-cn">${m.cn}</span>
        </div>`).join('');
      const row = popup.querySelector('.tc-row.sel');
      if (row) row.scrollIntoView({ block: 'nearest' });
      try {
        const dims = term._core._renderService.dimensions.css.cell;
        const x = Math.min(term.buffer.active.cursorX * dims.width,
          Math.max(8, host.clientWidth - 380));
        const y = Math.min((term.buffer.active.cursorY + 2) * dims.height,
          Math.max(8, host.clientHeight - 240));
        popup.style.left = `${Math.max(8, x)}px`;
        popup.style.top = `${Math.max(8, y)}px`;
      } catch { popup.style.left = '10px'; popup.style.top = '10px'; }
      popup.hidden = false;
    }

    function updatePopup() {
      const input = entry.input || '';
      if (!input || input.includes(' ') || entry.atPrompt === false) { hidePopup(); return; }
      const lower = input.toLowerCase();
      const starts = catalog.filter((c) => c.n.toLowerCase().startsWith(lower));
      const contains = catalog.filter((c) => !starts.includes(c) && c.n.toLowerCase().includes(lower));
      entry.matches = [...starts, ...contains].slice(0, 8);
      entry.sel = 0;
      renderPopup();
    }

    function acceptCompletion() {
      const m = entry.matches[entry.sel];
      if (!m) return;
      const rest = m.n.slice((entry.input || '').length);
      if (rest) {
        term.write(rest);
        window.pwnbao.terminalInput(entry.id, rest);
        entry.input = m.n;
      }
      hidePopup();
    }

    entry.toggleSheet = () => {
      sheet.hidden = !sheet.hidden;
      if (!sheet.hidden) {
        sheet.innerHTML = `
          <div class="tcs-head">
            <b>命令手册（中文）</b>
            <input class="input tcs-filter" placeholder="筛选：例如 heap / 断点 / 溢出…" />
            <span class="hint-dim">F1 或 Esc 关闭 · 点命令行写入终端</span>
          </div>
          <div class="tcs-list"></div>`;
        const list = sheet.querySelector('.tcs-list');
        const renderList = (needle) => {
          const n = String(needle || '').trim().toLowerCase();
          const items = catalog.filter((c) => !n
            || c.n.toLowerCase().includes(n)
            || (c.cn || '').toLowerCase().includes(n));
          list.innerHTML = items.map((c) => `
            <div class="tcs-row" data-n="${esc(c.n)}">
              <span class="tc-name mono">${esc(c.n)}</span>
              <span class="tc-cn">${esc(c.cn || '')}</span>
            </div>`).join('') || '<div class="hint-dim">没有匹配命令。</div>';
          list.querySelectorAll('.tcs-row').forEach((row) => {
            row.addEventListener('click', () => {
              sheet.hidden = true;
              const command = row.dataset.n.split(' ')[0];
              term.write(command);
              window.pwnbao.terminalInput(entry.id, command);
              entry.input = command;
              term.focus();
            });
          });
        };
        renderList('');
        sheet.querySelector('.tcs-filter').addEventListener('input', (event) => renderList(event.target.value));
        sheet.querySelector('.tcs-filter').focus();
      }
    };

    // 拦截层：返回 true 表示数据已由补全层消费（不转发 pty）
    entry.handleCompletionData = (data) => {
      if (data === '\x1bOP' || data === '\x1b[11~') { entry.toggleSheet(); return true; }   // F1
      if (!sheet.hidden) {
        if (data === '\x1b') { sheet.hidden = true; return true; }
        return true;   // 手册打开时输入都进筛选框（焦点在 input，这里只兜底）
      }
      if (data === '\t') {
        if (popup.hidden) updatePopup();
        else acceptCompletion();
        return true;   // Tab 永远本地消费，避免 gdb 自身补全打架
      }
      if (data === '\x1b[A' || data === '\x1b[B') {
        if (popup.hidden) return false;   // 无弹窗时放行：↑↓ 走 gdb 历史
        entry.sel = (entry.sel + (data === '\x1b[B' ? 1 : -1) + entry.matches.length) % entry.matches.length;
        renderPopup();
        return true;
      }
      if (data === '\x1b') { hidePopup(); return false; }
      if (data === '\n' || data === '\n') { entry.input = ''; hidePopup(); return false; }
      if (data === '\x03' || data === '\x04') { entry.input = ''; hidePopup(); return false; }
      if (data === '\x7f') { entry.input = (entry.input || '').slice(0, -1); updatePopup(); return false; }
      if (data.length === 1 && data >= ' ' && data <= '~') {
        entry.input = (entry.input || '') + data;
        updatePopup();
        return false;
      }
      hidePopup();
      return false;
    };
  }
  function attachDebugTerminal(id) {
    // main.js 已起好调试 pty；渲染层把它挂到调试页中央（不在底部面板）。
    const slot = $('#debug-term-slot');
    const host = ensureDebugTermNode();
    if (slot) {
      slot.innerHTML = '';
      slot.appendChild(host);
    }
    host.innerHTML = '';
    const term = new window.Terminal({
      fontFamily: '"Cascadia Mono", Consolas, monospace',
      fontSize: 13,
      cursorBlink: true,
      allowProposedApi: true,
      theme: TERM_THEME,
    });
    const fitAddon = new window.FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(host);
    const entry = { term, fitAddon, kind: 'debug', name: 'pwndbg-mogai', host, docked: 'page', id };
    attachDbgCompletion(entry);
    term.onData((data) => {
      // 中文补全层：返回 true = 数据已被消费（Tab/手册/弹窗导航），不转发 pty
      if (entry.handleCompletionData && entry.handleCompletionData(data)) return;
      window.pwnbao.terminalInput(id, data);
    });
    const refit = () => {
      try {
        fitAddon.fit();
        window.pwnbao.terminalResize(id, term.cols, term.rows);
      } catch { /* hidden */ }
    };
    new ResizeObserver(refit).observe(host);
    terminals.set(id, entry);
    refit();
    renderTerminalTabs();
    if (state.page === 'debug') {
      const start = $('#debug-start');
      const stop = $('#debug-stop');
      if (start) start.hidden = true;
      if (stop) stop.hidden = false;
    }
    log('pwndbg-mogai 调试终端已挂载到调试页（底部面板保留程序运行终端）。');
  }

  async function stopDebugSession() {
    for (const [id, entry] of [...terminals]) {
      if (entry.kind !== 'debug') continue;
      try { await window.pwnbao.terminalKill(id); } catch { /* gone */ }
      try { entry.term.dispose(); } catch { /* gone */ }
      terminals.delete(id);
    }
    if (debugTermNode) debugTermNode.innerHTML = '';
    if (state.page === 'debug') window.PwnPages.renderDebug();
    log('调试会话已结束。');
  }

  window.pwnbao.onTerminalData(({ id, data }) => {
    const entry = terminals.get(id);
    if (!entry) return;
    entry.term.write(data);
    window.__smokeTermBytes = (window.__smokeTermBytes || 0) + data.length;
    if (entry.kind === 'debug') {
      if (/Starting program|Continuing/.test(data)) entry.atPrompt = false;
      if (/pwndbg>|gdb>\)$|gdb>\s*$/.test(data) || /pwndbg>\s*$/.test(data)) entry.atPrompt = true;
      if (!entry.hintShown && /pwndbg>/.test(data)) {
        entry.hintShown = true;
        entry.term.write('\x1b[90m── PwnCraft 提示：输入前缀弹出中文补全（Tab 采纳 · ↑↓ 选择 · Esc 关闭） · F1 中文命令手册 · 底部终端 = 程序运行 ──\x1b[0m\r\n');
      }
    }
  });
  window.pwnbao.onTerminalExit(({ id, exitCode, kind }) => {
    if (!terminals.has(id)) return;
    removeTerminal(id);
    log(`${kind === 'debug' ? 'pwndbg-mogai 调试终端' : 'WSL bash'} 已退出（exit=${exitCode}）`, 'warn');
  });

  // ------------------------------------------------------------------
  // Bottom panel

  function togglePanel(which) {
    const panel = $('#panel');
    if (panel.hidden) panel.hidden = false;
    $$('.panel-tab').forEach((tab) => tab.classList.toggle('active', tab.dataset.panel === which));
    $('#terminal-page').hidden = which !== 'terminal';
    $('#logs-page').hidden = which !== 'logs';
    if (which === 'terminal' && activeTerminalId !== null) {
      setTimeout(() => {
        const entry = terminals.get(activeTerminalId);
        if (entry) { try { entry.fitAddon.fit(); entry.term.focus(); } catch { /* hidden */ } }
      }, 30);
    }
  }

  // ------------------------------------------------------------------
  // Command palette

  const COMMANDS = [
    { id: 'import', label: '导入 ELF 绑定 Target', key: 'Ctrl+O', icon: 'import', run: pickAndImport },
    { id: 'close-workspace', label: '关闭当前工作区', icon: 'x', run: () => { if (state.activePath) closeWorkspace(state.activePath); } },
    { id: 'terminal', label: '切换终端', key: 'Ctrl+`', icon: 'terminal', run: () => togglePanel('terminal') },
    { id: 'new-terminal', label: '新建 WSL bash 终端实例', icon: 'terminal', run: () => { togglePanel('terminal'); createTerminal('shell'); } },
    { id: 'debug-start', label: '启动 pwndbg-mogai 调试终端（自动加载 ELF）', icon: 'terminal', run: startDebugFromSidebar },
    { id: 'welcome', label: '转到概览', icon: 'home', run: () => switchPage('welcome') },
    { id: 'binary', label: '转到 Binary 概览', icon: 'box', run: () => switchPage('binary') },
    { id: 'exp', label: '转到 EXP 编辑器', icon: 'file-code', run: () => switchPage('exp') },
    { id: 'heap', label: '转到 Heap 物理堆画布', icon: 'cpu', run: () => switchPage('heap') },
    { id: 'rop', label: '转到 ROP / Gadget', icon: 'zap', run: () => switchPage('rop') },
    { id: 'format', label: '转到 Format String', icon: 'command', run: () => switchPage('format') },
    { id: 'syscall', label: '转到 Syscall / Seccomp', icon: 'shield', run: () => switchPage('syscall') },
    { id: 'stack', label: '转到 Stack / Leak', icon: 'import', run: () => switchPage('stack') },
    { id: 'tools', label: '转到工具箱', icon: 'folder-open', run: () => switchPage('tools') },
    { id: 'clib', label: 'C 函数速查（工具箱）', icon: 'scroll-text', run: () => {
      switchPage('tools');
      setTimeout(() => {
        const input = document.querySelector('#page-tools .clib-q');
        if (input) input.focus();
      }, 80);
    } },
    { id: 'heap-replay-exp', label: 'Heap：回放当前 exp.py（真实 allocator 仿真）', icon: 'cpu', run: () => {
      switchPage('heap');
      window.PwnHeap.replayExp();
    } },
    { id: 'ropgadget-terminal', label: 'ROP：在终端运行 ROPgadget（pop|ret）', icon: 'zap', run: () => {
      runInTerminal('ROPgadget --binary ./pwn --only "pop|ret"');
    } },
    { id: 'restart-terminal', label: '重启 WSL bash 终端（当前项目目录）', icon: 'rotate-cw', run: () => restartShellTerminal(state.terminalCwd || '') },
    { id: 'exp-template', label: 'EXP：初始化模板', icon: 'zap', run: () => {
      setExpText(expTemplate());
      switchPage('exp');
    } },
    { id: 'save', label: '保存 EXP', key: 'Ctrl+S', icon: 'save', run: saveExp },
  ];

  let paletteSelection = 0;

  function openPalette() {
    $('#palette-overlay').hidden = false;
    const input = $('#palette-input');
    input.value = '';
    paletteSelection = 0;
    renderPalette('');
    input.focus();
  }
  function closePalette() { $('#palette-overlay').hidden = true; }

  function renderPalette(query) {
    const list = $('#palette-list');
    const needle = query.trim().toLowerCase();
    const visible = COMMANDS.filter((command) => !needle || command.label.toLowerCase().includes(needle));
    if (!visible.length) {
      list.innerHTML = '<div class="palette-empty">没有匹配的命令</div>';
      return;
    }
    paletteSelection = Math.min(paletteSelection, visible.length - 1);
    list.innerHTML = visible.map((command, index) => `
      <div class="palette-item ${index === paletteSelection ? 'selected' : ''}" data-id="${command.id}">
        ${icon(command.icon)}<span class="palette-label"></span>
        ${command.key ? `<span class="palette-key">${command.key}</span>` : ''}
      </div>`).join('');
    list.querySelectorAll('.palette-label').forEach((span, index) => {
      span.textContent = visible[index].label;
    });
    list.querySelectorAll('.palette-item').forEach((item, index) => {
      item.addEventListener('click', () => runCommand(visible[index]));
      item.addEventListener('mousemove', () => {
        if (paletteSelection !== index) {
          paletteSelection = index;
          list.querySelectorAll('.palette-item').forEach((node, nodeIndex) => {
            node.classList.toggle('selected', nodeIndex === paletteSelection);
          });
        }
      });
    });
    list.__visible = visible;
  }

  function runCommand(command) {
    closePalette();
    log(`命令：${command.label}`);
    command.run();
  }

  // ------------------------------------------------------------------
  // Global wiring

  function bindGlobalKeys() {
    window.addEventListener('keydown', (event) => {
      const control = event.ctrlKey && !event.altKey && !event.metaKey;
      if (control && event.shiftKey && event.key.toLowerCase() === 'p') {
        event.preventDefault();
        openPalette();
      } else if (control && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        openPalette();
      } else if (control && event.key.toLowerCase() === 'o') {
        event.preventDefault();
        pickAndImport();
      } else if (control && event.key === '`') {
        event.preventDefault();
        const panel = $('#panel');
        if (panel.hidden) {
          togglePanel('terminal');
        } else if ($('#terminal-page').hidden) {
          togglePanel('terminal');
        } else {
          panel.hidden = true;
        }
      } else if (control && event.key.toLowerCase() === 's') {
        event.preventDefault();
        saveExp();
      } else if (event.key === 'Escape' && !$('#palette-overlay').hidden) {
        closePalette();
      } else if (event.key === 'Escape' && $('#dialog-overlay') && !$('#dialog-overlay').hidden) {
        closeDialog();
      }
    });
    $('#palette-input').addEventListener('keydown', (event) => {
      const list = $('#palette-list');
      const visible = list.__visible || [];
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        paletteSelection = Math.min(paletteSelection + 1, visible.length - 1);
        renderPalette($('#palette-input').value);
      } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        paletteSelection = Math.max(paletteSelection - 1, 0);
        renderPalette($('#palette-input').value);
      } else if (event.key === 'Enter') {
        event.preventDefault();
        if (visible[paletteSelection]) runCommand(visible[paletteSelection]);
      }
    });
    $('#palette-overlay').addEventListener('mousedown', (event) => {
      if (event.target === $('#palette-overlay')) closePalette();
    });
    $('#palette-input').addEventListener('input', (event) => {
      paletteSelection = 0;
      renderPalette(event.target.value);
    });

    document.querySelectorAll('.panel-tab').forEach((tab) => {
      tab.addEventListener('click', () => togglePanel(tab.dataset.panel));
    });
    $('#logs-filter').addEventListener('input', renderLogs);
    $('#logs-clear').addEventListener('click', () => { logStore.length = 0; renderLogs(); });
    $('#exp-save').addEventListener('click', saveExp);
    $('#exp-copy').addEventListener('click', async () => {
      await navigator.clipboard.writeText(getExpText());
      log('已复制全部 EXP 代码到剪贴板');
    });
    $('#exp-template').addEventListener('click', () => {
      setExpText(expTemplate());
      log('已初始化 EXP 模板');
    });
  }

  function bindBridgeEvents() {
    window.pwnbao.onBridgeEvent((payload) => {
      if (payload.event === 'log') log(payload.message);
      else if (payload.event === 'hello') {
        log(`Python 桥已连接 · ${payload.app} ${payload.version}`);
        $('#status-right').textContent = `WSL · ${payload.version} · Electron`;
      } else if (payload.event === 'bridge_exit') {
        log(`Python 桥已退出（code=${payload.code}）${payload.stderr ? ' · ' + payload.stderr : ''}`, 'error');
      }
    });
  }

  function updateStatusLeft() {
    const projectName = state.project && state.project.project_name;
    $('#status-left').textContent = projectName
      ? `PwnCraft v0.32.0 · Electron Workbench · ${projectName}`
      : 'PwnCraft v0.32.0 · Electron Workbench · 尚未绑定 Target';
  }

  // ------------------------------------------------------------------
  // Boot

  async function boot() {
    renderActivity();
    renderWelcome();
    renderTabs();
    renderWorkspaceBar();
    switchPage('welcome');
    bindGlobalKeys();
    bindGlobalDragDrop();
    bindBridgeEvents();
    renderLogs();
    log('PwnCraft Electron Workbench 已启动。拖入 ELF 或按 Ctrl+O 绑定 Target。');
    initMonaco();
    window.PwnPages.renderExpTools();
    await window.PwnHeap.boot();
    await createTerminal('shell');
    updateStatusLeft();
    try {
      const pong = await window.pwnbao.request('ping');
      log(`Python 桥 ping 成功 · ${pong.app} ${pong.version}`);
    } catch (error) {
      log(`Python 桥不可用：${error.message}`, 'error');
    }
  }

  document.addEventListener('DOMContentLoaded', boot);

  // Public surface for pages.js / heap.js
  // arch/bits 用 getter：heap/IOFILE 必须跟随当前工作区的真实架构
  // （此前 heap.js 读 PwnApp.arch 恒为 undefined，32 位目标被按 amd64 仿真）
  window.PwnApp = {
    state,
    get arch() { return state.arch; },
    get bits() { return state.bits; },
    log,
    openDialog,
    switchPage,
    getExpText,
    insertExpText,
    runInTerminal,
    sendToDebugTerminal,
    attachDebugTerminal,
    mountDebugTerminalNode,
    mountExpEditor,
    setExpHeapLineHandler,
    updateExpHeapLineDecorations,
    hasDebugSession,
    stopDebugSession,
    debugSheetToggle: () => {
      for (const [, entry] of terminals) {
        if (entry.kind === 'debug' && entry.toggleSheet) {
          entry.toggleSheet();
          return true;
        }
      }
      return false;
    },
    secInfo,
    SEC_KEYS,
  };

  // Dev/test hook: main.js drives import + page switches for screenshots.
  window.__pwnbaoDebug = {
    importElf,
    switchPage,
    openPalette,
    heapAdvance: (n) => window.PwnHeapDebugAdvance && window.PwnHeapDebugAdvance(n),
    state,
  };
})();
