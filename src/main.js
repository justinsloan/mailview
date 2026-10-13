'use strict';

const fs = require('fs');
const path = require('path');
const { pathToFileURL, fileURLToPath } = require('url');
const { app, BrowserWindow, Menu, clipboard, dialog, ipcMain, session } = require('electron');
const { parseMessage } = require('./parser');
const { analyzeMessage } = require('./analysis');

const APP_ROOT = path.resolve(__dirname, '..');
const INDEX_URL = pathToFileURL(path.join(__dirname, 'renderer', 'index.html')).href;
const PARTITION = 'mailview'; // no "persist:" prefix => in-memory only, nothing cached to disk
const MAX_INLINE_IMAGE = 10 * 1024 * 1024;
const MAX_TEXT_PREVIEW = 512 * 1024;
const INLINE_IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp', 'image/bmp']);

// webContents.id -> { msg, remoteAllowed }
const windowState = new Map();

app.enableSandbox();

// --- Network gate ---------------------------------------------------------
// Every request from the viewer goes through here. Remote requests are
// refused unless the user enabled remote images for that window, and even
// then only image requests are let through. file:// is limited to the app's
// own files so email content can't reach local or UNC (\\host\share) paths.

function isInsideApp(fileUrl) {
  try {
    const p = path.resolve(fileURLToPath(fileUrl));
    return p === APP_ROOT || p.startsWith(APP_ROOT + path.sep);
  } catch {
    return false;
  }
}

function installNetworkGate(ses) {
  ses.webRequest.onBeforeRequest((details, cb) => {
    const callback = !process.env.MAILVIEW_LOG_REQUESTS ? cb : (result) => {
      console.log(`[net] ${result.cancel ? 'BLOCK' : 'allow'} ${details.resourceType} ${details.url.slice(0, 120)}`);
      cb(result);
    };
    let url;
    try {
      url = new URL(details.url);
    } catch {
      return callback({ cancel: true });
    }
    switch (url.protocol) {
      case 'file:':
        return callback({ cancel: !(isInsideApp(details.url) && !url.host) });
      case 'data:':
      case 'blob:':
      case 'about:':
      case 'devtools:':
        return callback({ cancel: false });
      case 'http:':
      case 'https:': {
        const state = windowState.get(details.webContentsId);
        const allowed = !!(state && state.remoteAllowed && details.resourceType === 'image');
        return callback({ cancel: !allowed });
      }
      default:
        return callback({ cancel: true });
    }
  });

  // Don't leak where the request came from, or carry any cookies.
  ses.webRequest.onBeforeSendHeaders((details, callback) => {
    const headers = { ...details.requestHeaders };
    for (const k of Object.keys(headers)) {
      if (/^(referer|cookie|origin)$/i.test(k)) delete headers[k];
    }
    callback({ requestHeaders: headers });
  });
  ses.webRequest.onHeadersReceived((details, callback) => {
    const headers = { ...details.responseHeaders };
    for (const k of Object.keys(headers)) {
      if (/^set-cookie$/i.test(k)) delete headers[k];
    }
    callback({ responseHeaders: headers });
  });

  ses.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  ses.setPermissionCheckHandler(() => false);
  ses.on('will-download', (event) => event.preventDefault());
}

// Defense in depth for every webContents the app ever creates.
app.on('web-contents-created', (_event, contents) => {
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
  contents.on('will-navigate', (event, url) => {
    if (url !== INDEX_URL) event.preventDefault();
  });
  contents.on('will-frame-navigate', (event) => {
    if (!event.isMainFrame && event.url !== 'about:srcdoc') event.preventDefault();
  });
  contents.on('will-redirect', (event) => event.preventDefault());
  contents.on('will-attach-webview', (event) => event.preventDefault());
});

// --- Windows and message loading ------------------------------------------

function publicMessage(msg) {
  // Everything except attachment bytes. The renderer gets those only on request.
  const { attachments, ...rest } = msg;
  return { ...rest, attachmentCount: attachments.length };
}

function attachmentMeta(a) {
  return {
    id: a.id,
    filename: a.filename,
    contentType: a.contentType,
    contentId: a.contentId,
    inline: a.inline,
    size: a.size,
    sha256: a.sha256,
  };
}

async function loadInto(win, source) {
  const wc = win.webContents;
  const pending = windowState.get(wc.id);
  if (pending) pending.loading = true;
  try {
    const buf = source.buffer || (await fs.promises.readFile(source.path));
    const name = source.name || path.basename(source.path);
    const msg = await parseMessage(buf, name);
    const analysis = analyzeMessage(msg);
    windowState.set(wc.id, { msg, remoteAllowed: false });
    win.setTitle(`${msg.subject || '(no subject)'} | ${name} | MailView`);
    wc.send('message-loaded', { message: publicMessage(msg), analysis });
  } catch (err) {
    windowState.set(wc.id, { msg: null, remoteAllowed: false });
    wc.send('message-error', { file: source.name || source.path, error: err.message });
  }
}

function createWindow(source) {
  const win = new BrowserWindow({
    width: 1200,
    height: 900,
    title: 'MailView',
    backgroundColor: '#1b1d22',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      partition: PARTITION,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      nodeIntegrationInSubFrames: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      spellcheck: false,
      navigateOnDragDrop: false,
      safeDialogs: true,
    },
  });
  const id = win.webContents.id;
  windowState.set(id, { msg: null, remoteAllowed: false });
  win.on('closed', () => windowState.delete(id));
  win.webContents.on('did-finish-load', () => {
    const state = windowState.get(id);
    if (state && state.msg) {
      // Reload: re-render from scratch with remote content blocked again.
      state.remoteAllowed = false;
      win.webContents.send('message-loaded', { message: publicMessage(state.msg), analysis: analyzeMessage(state.msg) });
    } else if (source) {
      loadInto(win, source);
      source = null;
    }
  });
  win.loadURL(INDEX_URL);
  return win;
}

async function openFileDialog(win) {
  const result = await dialog.showOpenDialog(win, {
    title: 'Open email message',
    properties: ['openFile', 'multiSelections'],
    filters: [
      { name: 'Email messages', extensions: ['eml', 'emlx', 'msg', 'mht', 'mhtml'] },
      { name: 'All files', extensions: ['*'] },
    ],
  });
  if (result.canceled) return;
  result.filePaths.forEach((p, i) => {
    const state = win && windowState.get(win.webContents.id);
    if (i === 0 && win && state && !state.msg && !state.loading) loadInto(win, { path: p });
    else createWindow({ path: p });
  });
}

// --- IPC ------------------------------------------------------------------

function handle(channel, fn) {
  ipcMain.handle(channel, (event, ...args) => {
    if (!event.senderFrame || event.senderFrame.url !== INDEX_URL) throw new Error('Untrusted sender');
    const win = BrowserWindow.fromWebContents(event.sender);
    const state = windowState.get(event.sender.id);
    return fn({ win, state }, ...args);
  });
}

function getAttachment(state, id) {
  const att = state && state.msg && state.msg.attachments[id];
  if (!att) throw new Error('No such attachment');
  return att;
}

function safeFileName(name) {
  const cleaned = (name || 'attachment')
    .replace(/[\u0000-\u001f\u007f‪-‮⁦-⁩]/g, '')
    .replace(/[\\/:*?"<>|]/g, '_')
    .trim();
  return cleaned || 'attachment';
}

handle('open-dialog', ({ win }) => openFileDialog(win));

handle('open-path', async ({ win, state }, filePath) => {
  if (typeof filePath !== 'string' || !filePath) return;
  const stat = await fs.promises.stat(filePath);
  if (!stat.isFile()) throw new Error('Not a file');
  if (state && !state.msg && !state.loading) loadInto(win, { path: filePath });
  else createWindow({ path: filePath });
});

handle('enable-remote', ({ state }) => {
  if (state) state.remoteAllowed = true;
});

handle('load-attachments', ({ state }) => {
  if (!state || !state.msg) return [];
  return state.msg.attachments.map((a) => {
    const meta = attachmentMeta(a);
    if (INLINE_IMAGE_TYPES.has(a.contentType) && a.size <= MAX_INLINE_IMAGE) {
      meta.dataUrl = `data:${a.contentType};base64,${a.content.toString('base64')}`;
    }
    return meta;
  });
});

handle('attachment-text', ({ state }, id) => {
  const att = getAttachment(state, id);
  const slice = att.content.subarray(0, MAX_TEXT_PREVIEW);
  return { text: slice.toString('utf8'), truncated: att.content.length > MAX_TEXT_PREVIEW };
});

handle('save-attachment', async ({ win, state }, id) => {
  const att = getAttachment(state, id);
  const result = await dialog.showSaveDialog(win, {
    title: 'Save attachment (do not open it on this machine)',
    defaultPath: path.join(app.getPath('downloads'), safeFileName(att.filename)),
  });
  if (result.canceled || !result.filePath) return false;
  await fs.promises.writeFile(result.filePath, att.content, { mode: 0o600 });
  return true;
});

handle('open-attachment-message', ({ state }, id) => {
  const att = getAttachment(state, id);
  createWindow({ buffer: att.content, name: safeFileName(att.filename || 'attached-message.eml') });
});

handle('copy-text', (_ctx, text) => {
  if (typeof text === 'string') clipboard.writeText(text);
});

// --- About ------------------------------------------------------------------

let licenseText = null;
function aboutInfo() {
  if (licenseText === null) {
    try {
      licenseText = fs.readFileSync(path.join(APP_ROOT, 'LICENSE'), 'utf8');
    } catch {
      licenseText = '';
    }
  }
  return {
    name: 'MailView',
    version: require('../package.json').version,
    copyright: 'Copyright © 2026 Justin Sloan',
    license: 'MIT',
    licenseText,
    versions: { electron: process.versions.electron, chrome: process.versions.chrome, node: process.versions.node },
  };
}

handle('get-about', () => aboutInfo());

function showAbout(win) {
  const target = win || BrowserWindow.getFocusedWindow() || BrowserWindow.getAllWindows()[0] || createWindow();
  const send = () => target.webContents.send('show-about', aboutInfo());
  if (target.webContents.isLoading()) target.webContents.once('did-finish-load', send);
  else send();
}

// --- App lifecycle ----------------------------------------------------------

function buildMenu() {
  const aboutItem = { label: 'About MailView', click: (_item, win) => showAbout(win) };
  const template = [
    ...(process.platform === 'darwin'
      ? [{ label: 'MailView', submenu: [aboutItem, { type: 'separator' }, { role: 'hide' }, { role: 'hideOthers' }, { type: 'separator' }, { role: 'quit' }] }]
      : []),
    {
      label: 'File',
      submenu: [
        { label: 'Open…', accelerator: 'CmdOrCtrl+O', click: (_item, win) => openFileDialog(win) },
        { label: 'New Window', accelerator: 'CmdOrCtrl+N', click: () => createWindow() },
        { type: 'separator' },
        { role: 'close' },
        { role: 'quit' },
      ],
    },
    { role: 'editMenu' },
    {
      label: 'View',
      submenu: [
        { role: 'reload', label: 'Reset view (re-block remote content)' },
        ...(app.isPackaged ? [] : [{ role: 'toggleDevTools' }]),
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
      ],
    },
    ...(process.platform === 'darwin' ? [] : [{ label: 'Help', submenu: [aboutItem] }]),
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

const pendingOpenFiles = [];
app.on('open-file', (event, filePath) => {
  // macOS "Open With" / dock drop.
  event.preventDefault();
  if (app.isReady()) createWindow({ path: filePath });
  else pendingOpenFiles.push(filePath);
});

app.whenReady().then(() => {
  installNetworkGate(session.fromPartition(PARTITION));
  buildMenu();

  const args = process.argv.slice(app.isPackaged ? 1 : 2).filter((a) => !a.startsWith('-') && a !== '.');
  const files = [...pendingOpenFiles, ...args.map((a) => path.resolve(a))];
  if (files.length) files.forEach((f) => createWindow({ path: f }));
  else createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
