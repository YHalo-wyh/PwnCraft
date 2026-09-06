// EXP DnD — 拖代码块入编辑器 (VNext.3 UI 层)
//
// 交互契约:
//   * 任何带 [data-pwncraft-code] 的元素都是可拖代码块, 属性值即插入文本;
//     或用 PwnExpDnD.register(el, code) 动态注册 (Auditor 诊断卡/Quick Fix
//     /模板面板统一走这条路)。
//   * 拖放载荷: text/pwncraft-code (主) + text/plain (兜底)。
//   * 落点: Monaco 编辑器按鼠标位置换算行列后 executeEdits (单次 undo),
//     textarea 回退编辑器按 selectionStart 插入。
//   * 多行插入时按落点行的缩进对齐。
//   * ELF 文件拖入由 app.js 的全局 drop 处理, 这里只在载荷是代码块时接管。
(function () {
  'use strict';

  const MIME = 'text/pwncraft-code';
  const state = { editor: null };   // 由 app.js 在 Monaco ready 后注入

  function setEditor(editor) { state.editor = editor; }

  // ---------- 拖拽源 ----------
  function enableDragSource(el, code) {
    if (!el || el.__pwncraftDnd) return el;
    const payload = code !== undefined ? String(code)
      : el.getAttribute('data-pwncraft-code') || el.textContent || '';
    el.__pwncraftDnd = payload;
    el.setAttribute('draggable', 'true');
    el.classList.add('pwncraft-draggable');
    el.addEventListener('dragstart', (event) => {
      event.dataTransfer.setData(MIME, payload);
      event.dataTransfer.setData('text/plain', payload);
      event.dataTransfer.effectAllowed = 'copy';
      el.classList.add('pwncraft-dragging');
    });
    el.addEventListener('dragend', () => el.classList.remove('pwncraft-dragging'));
    return el;
  }

  // 面板渲染后扫一遍, 声明式代码块自动可拖
  function scan(root) {
    (root || document).querySelectorAll('[data-pwncraft-code]').forEach((el) => {
      enableDragSource(el, el.getAttribute('data-pwncraft-code'));
    });
  }

  // ---------- 插入 ----------
  function indentFor(text, baseIndent) {
    if (!baseIndent) return text;
    return text.split('\n').map((line, i) => (i === 0 || !line) ? line : baseIndent + line).join('\n');
  }

  function insertIntoMonaco(editor, text, mouseX, mouseY) {
    let position = null;
    try {
      const target = editor.getTargetAtClientPoint(mouseX, mouseY);
      position = target && target.position ? target.position : null;
    } catch { /* 鼠标不在编辑器上 */ }
    if (!position) position = editor.getPosition() || editor.getModel().getPositionAt(0);
    const model = editor.getModel();
    const lineText = model.getLineContent(position.lineNumber);
    const baseIndent = (lineText.match(/^\s*/) || [''])[0];
    const range = new monaco.Range(position.lineNumber, position.column,
                                   position.lineNumber, position.column);
    editor.executeEdits('pwnbao-dnd', [{ range, text: indentFor(text, baseIndent) }]);
    editor.pushUndoStop();
    editor.setPosition({ lineNumber: position.lineNumber, column: position.column });
    editor.focus();
  }

  function insertIntoTextarea(textarea, text) {
    const start = textarea.selectionStart || textarea.value.length;
    const before = textarea.value.slice(0, start);
    const baseIndent = (before.slice(before.lastIndexOf('\n') + 1).match(/^\s*/) || [''])[0];
    const next = before + indentFor(text, baseIndent) + textarea.value.slice(start);
    textarea.value = next;
    textarea.dispatchEvent(new Event('input', { bubbles: true }));
    textarea.focus();
  }

  function payloadFrom(event) {
    if (event.dataTransfer.getData(MIME)) return event.dataTransfer.getData(MIME);
    const plain = event.dataTransfer.getData('text/plain') || '';
    // 只接管显式标记的代码载荷, 不与 ELF 文件拖入冲突
    return event.dataTransfer.types.includes(MIME) ? plain : '';
  }

  function wireMonaco(editor) {
    setEditor(editor);
    const node = editor.getDomNode();
    if (!node) return;
    node.addEventListener('dragover', (event) => {
      if (!event.dataTransfer.types.includes(MIME)) return; // ELF 等交给全局
      event.preventDefault();
      event.dataTransfer.dropEffect = 'copy';
      node.classList.add('pwncraft-drop-target');
    });
    node.addEventListener('dragleave', () => node.classList.remove('pwncraft-drop-target'));
    node.addEventListener('drop', (event) => {
      const text = payloadFrom(event);
      if (!text) return;              // 非代码载荷: 交给全局 ELF 处理
      event.preventDefault();
      event.stopPropagation();        // 阻断全局 ELF drop
      node.classList.remove('pwncraft-drop-target');
      insertIntoMonaco(editor, text, event.clientX, event.clientY);
    });
  }

  function wireTextarea(textarea) {
    if (!textarea) return;
    textarea.addEventListener('dragover', (event) => {
      if (!event.dataTransfer.types.includes(MIME)) return;
      event.preventDefault();
    });
    textarea.addEventListener('drop', (event) => {
      const text = payloadFrom(event);
      if (!text) return;
      event.preventDefault();
      event.stopPropagation();
      insertIntoTextarea(textarea, text);
    });
  }

  // ---------- 暴露 API ----------
  window.PwnExpDnD = {
    register: enableDragSource,
    scan,
    wireMonaco,
    wireTextarea,
    setEditor,
    get editor() { return state.editor; },
  };
})();
