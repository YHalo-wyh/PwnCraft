#!/usr/bin/env node
/**
 * Headless RendererPlan exporter (INFRA-CLOSURE-1 P0-5).
 *
 * Evaluates the REAL renderer sources (physics.js + heap.js IIFE) in a
 * stubbed DOM-free environment and calls PwnHeap.rebuildAndPlan(steps, i) —
 * the plan therefore reuses the actual chunkLayout / chunkSizeTriple /
 * cachedChunkGrid / coverageSpansFor / bodiesByChunk pipeline. No geometry is
 * reimplemented here.
 *
 * Usage: node renderer_plan_export.mjs <generated_dir> [stepIndices...]
 * Reads  : <generated_dir>/bridge_steps.json + run_manifest.json
 * Writes : <generated_dir>/renderer_plan.json  {run_id, steps:[plan...]}
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import vm from 'node:vm';

const dir = process.argv[2];
if (!dir) {
  console.error('usage: node renderer_plan_export.mjs <generated_dir> [stepIndices...]');
  process.exit(2);
}
const genDir = path.resolve(dir);
const bridge = JSON.parse(readFileSync(path.join(genDir, 'bridge_steps.json'), 'utf-8'));
const manifest = JSON.parse(readFileSync(path.join(genDir, 'run_manifest.json'), 'utf-8'));

// ---- DOM-free stub environment
const listeners = {};
const windowStub = {
  addEventListener: () => {},
  removeEventListener: () => {},
  PwnApp: null,
};
const documentStub = {
  getElementById: () => null,
  querySelector: () => null,
  querySelectorAll: () => [],
  createElement: () => ({ getContext: () => null, style: {} }),
  addEventListener: () => {},
  body: { appendChild: () => {}, classList: { add: () => {}, remove: () => {} } },
};
const sandbox = {
  window: windowStub,
  document: documentStub,
  navigator: { userAgent: 'node-harness' },
  requestAnimationFrame: () => 0,
  cancelAnimationFrame: () => {},
  setTimeout, clearTimeout, setInterval, clearInterval,
  console,
  performance: { now: () => Date.now() },
  BigInt, Math, JSON, Map, Set, WeakMap, WeakSet, Promise,
};
windowStub.window = windowStub;
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

const rendererRoot = path.resolve(import.meta.dirname, '..', 'pwn宝', 'pwnbao-electron', 'renderer');
function loadScript(rel) {
  const src = readFileSync(path.join(rendererRoot, rel), 'utf-8');
  vm.runInContext(src, sandbox, { filename: rel });
}
loadScript('physics.js');
loadScript('heap.js');

const PwnHeap = sandbox.window.PwnHeap;
if (!PwnHeap || typeof PwnHeap.rebuildAndPlan !== 'function') {
  console.error('PwnHeap.rebuildAndPlan unavailable');
  process.exit(1);
}
// allocator word size comes from state (archWord reads state.allocator.bits)
PwnHeap.state.allocator = PwnHeap.state.allocator || {};
if (!PwnHeap.state.allocator.bits) PwnHeap.state.allocator.bits = 64;
PwnHeap.state.snapshotId = bridge.snapshot_id || '';
PwnHeap.state.memoryRevision = bridge.memory_revision || '';

const steps = bridge.steps || [];
let picks = process.argv.slice(3).map((x) => Number(x));
if (picks.length === 0) {
  picks = [1, Math.floor(steps.length / 2), steps.length - 1].filter((i) => i >= 0 && i < steps.length);
  picks = [...new Set(picks)];
}
const plans = [];
for (const i of picks) {
  const plan = PwnHeap.rebuildAndPlan(steps, i);
  plans.push(plan);
}
const out = {
  run_id: bridge.run_id || manifest.run_id,
  source: 'pwnbao-electron/renderer/heap.js exportRendererPlan (real geometry pipeline, node headless)',
  snapshot_id: bridge.snapshot_id,
  memory_revision: bridge.memory_revision,
  exported_steps: picks,
  steps: plans,
};
writeFileSync(path.join(genDir, 'renderer_plan.json'), JSON.stringify(out, null, 2));
console.log(`[renderer-plan] run_id=${out.run_id} steps=${picks.join(',')} cards=${plans.map((p) => p.cards.length).join('/')} -> renderer_plan.json`);
