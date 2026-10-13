'use strict';

const { contextBridge, ipcRenderer, webUtils } = require('electron');

contextBridge.exposeInMainWorld('mailview', {
  openDialog: () => ipcRenderer.invoke('open-dialog'),
  openFile: (file) => ipcRenderer.invoke('open-path', webUtils.getPathForFile(file)),
  enableRemote: () => ipcRenderer.invoke('enable-remote'),
  loadAttachments: () => ipcRenderer.invoke('load-attachments'),
  attachmentText: (id) => ipcRenderer.invoke('attachment-text', id),
  saveAttachment: (id) => ipcRenderer.invoke('save-attachment', id),
  openAttachmentMessage: (id) => ipcRenderer.invoke('open-attachment-message', id),
  copyText: (text) => ipcRenderer.invoke('copy-text', text),
  about: () => ipcRenderer.invoke('get-about'),
  onMessage: (cb) => ipcRenderer.on('message-loaded', (_e, payload) => cb(payload)),
  onError: (cb) => ipcRenderer.on('message-error', (_e, payload) => cb(payload)),
  onAbout: (cb) => ipcRenderer.on('show-about', (_e, info) => cb(info)),
});
