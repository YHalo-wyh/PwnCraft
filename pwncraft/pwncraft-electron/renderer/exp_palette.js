// EXP 代码块面板 (VNext.3 UI): Auditor Quick Fix / 常用片段的可拖拽来源。
// 数据驱动: setQuickFixes(diagnostics) 渲染 Auditor 诊断的 suggested_fix;
// 也可直接静态声明片段。所有块经 PwnExpDnD.register 可拖入编辑器。
(function () {
  'use strict';

  let container = null;

  const BUILTIN_BLOCKS = [
    { label: 'u64 ljust 补齐', code: "u64(leak.ljust(8, b'\\x00'))",
      hint: 'EXP_LEAK_001 · 6 字节泄露补齐 8 字节' },
    { label: 'p64 打包', code: 'p64(target_addr)',
      hint: 'amd64 地址打包' },
    { label: 'recvuntil 菜单同步', code: 'io.recvuntil(b"Choice:")',
      hint: 'PROMPT_SYNC' },
  ];

  function chip(block) {
    const el = document.createElement('div');
    el.className = 'pwncraft-code-chip';
    el.setAttribute('data-pwncraft-code', block.code);
    const label = document.createElement('div');
    label.className = 'pwncraft-chip-label';
    label.textContent = block.label;
    const code = document.createElement('pre');
    code.className = 'pwncraft-chip-code';
    code.textContent = block.code;
    const hint = document.createElement('div');
    hint.className = 'pwncraft-chip-hint';
    hint.textContent = block.hint || '';
    el.append(label, code);
    if (block.hint) el.append(hint);
    window.PwnExpDnD.register(el, block.code);
    return el;
  }

  function render() {
    if (!container) return;
    container.innerHTML = '';
    const title = document.createElement('div');
    title.className = 'pwncraft-chip-title';
    title.textContent = '代码块 · 拖入编辑器';
    container.append(title);
    for (const block of BUILTIN_BLOCKS) container.append(chip(block));
    for (const block of window.PwnExpDnD.quickFixes || []) container.append(chip(block));
    window.PwnExpDnD.scan(container);
  }

  window.PwnExpDnD.setQuickFixes = function (fixes) {
    // Auditor 诊断入口: [{label, code, hint}]
    window.PwnExpDnD.quickFixes = Array.isArray(fixes) ? fixes : [];
    render();
  };

  window.PwnExpDnD.mountPalette = function (selector) {
    container = document.querySelector(selector);
    if (container) render();
  };
})();
