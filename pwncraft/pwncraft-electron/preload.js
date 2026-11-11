/**
 * PwnCraft preload — the only bridge between the renderer and the host.
 * Everything the UI can do is enumerated here; no node access leaks.
 */
const { contextBridge, ipcRenderer, webUtils } = require('electron');
const { Worker } = require('worker_threads');
const path = require('path');
const { probeFile } = require('./parallel/parallel_file_analysis');

function parallelAnalyze(filePath, options = {}) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(path.join(__dirname, 'parallel', 'worker.js'), {
      workerData: { filePath: String(filePath || ''), options },
    });
    const timer = setTimeout(() => {
      worker.terminate().catch(() => {});
      reject(new Error('并行文件分析超时（60s）'));
    }, 60000);
    worker.once('message', (message) => {
      clearTimeout(timer);
      worker.terminate().catch(() => {});
      if (message && message.ok) resolve(message.result);
      else reject(new Error((message && message.error) || '并行文件分析失败'));
    });
    worker.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    worker.once('exit', (code) => {
      if (code !== 0) clearTimeout(timer);
    });
  });
}

contextBridge.exposeInMainWorld('pwncraft', {
  // Python truth bridge
  request: (method, params) => ipcRenderer.invoke('bridge:request', method, params),
  onBridgeEvent: (callback) => {
    ipcRenderer.on('bridge:event', (_event, payload) => callback(payload));
  },
  // Terminal instances (node-pty): kind 'shell' | 'debug'
  terminalStart: (options) => ipcRenderer.invoke('terminal:start', options || {}),
  terminalKill: (id) => ipcRenderer.invoke('terminal:kill', id),
  terminalInput: (id, data) => ipcRenderer.invoke('terminal:input', { id, data }),
  terminalResize: (id, cols, rows) => ipcRenderer.invoke('terminal:resize', { id, cols, rows }),
  onTerminalData: (callback) => {
    ipcRenderer.on('terminal:data', (_event, payload) => callback(payload));
  },
  onTerminalExit: (callback) => {
    ipcRenderer.on('terminal:exit', (_event, payload) => callback(payload));
  },
  // dialogs
  pickElf: () => ipcRenderer.invoke('dialog:openElf'),
  pickSavePath: (defaultName, kind) => ipcRenderer.invoke('dialog:saveFile', defaultName, kind),
  pickOpenPath: (kind) => ipcRenderer.invoke('dialog:openFile', kind),
  // Non-AI sidecar: bounded, read-only worker. Pwn stays on the Python truth bridge.
  parallelAnalyze,
  probeFile: (filePath) => probeFile(filePath),
  // drag & drop: Electron 32+ removed File.path — webUtils 是唯一官方取路径方式
  filePathFor: (file) => {
    try { return webUtils.getPathForFile(file) || ''; }
    catch { return ''; }
  },
});
