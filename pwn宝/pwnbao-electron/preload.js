/**
 * PwnCraft preload — the only bridge between the renderer and the host.
 * Everything the UI can do is enumerated here; no node access leaks.
 */
const { contextBridge, ipcRenderer, webUtils } = require('electron');

contextBridge.exposeInMainWorld('pwnbao', {
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
  // drag & drop: Electron 32+ removed File.path — webUtils 是唯一官方取路径方式
  filePathFor: (file) => {
    try { return webUtils.getPathForFile(file) || ''; }
    catch { return ''; }
  },
});
