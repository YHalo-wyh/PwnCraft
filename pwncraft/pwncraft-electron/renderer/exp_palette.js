// EXP 快速修复数据源 (VNext.4): 渲染已并入 EXP 工具列「代码块」分组目录
// (pages.js renderBlockCatalog)。这里只保留数据通道：Auditor 诊断把
// suggested_fix 塞进来，下次「代码块」tab 渲染时以「审计快速修复」分组出现。
(function () {
  'use strict';
  if (!window.PwnExpDnD) return;
  window.PwnExpDnD.quickFixes = [];
  window.PwnExpDnD.setQuickFixes = function (fixes) {
    // [{label, code, hint}]
    window.PwnExpDnD.quickFixes = Array.isArray(fixes) ? fixes : [];
    document.dispatchEvent(new CustomEvent('pwncraft:quickfixes'));
  };
})();
