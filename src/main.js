'use strict';

const fs = require('fs');
const path = require('path');
const { pathToFileURL, fileURLToPath } = require('url');
const { app, BrowserWindow, Menu, clipboard, dialog, ipcMain, session } = require('electron');
const { parseMessage } = require('./parser');
const { analyzeMessage } = require('./analysis');
const { markAsDownloaded } = require('./quarantine');

const APP_ROOT = path.resolve(__dirname, '..');
const INDEX_URL = pathToFileURL(path.join(__dirname, 'renderer', 'index.html')).href;
const PARTITION = 'mailview'; // no "persist:" prefix => in-memory only, nothing cached to disk
const MAX_INLINE_IMAGE = 10 * 1024 * 1024;
const MAX_TEXT_PREVIEW = 512 * 1024;
const INLINE_IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp', 'image/bmp']);

// webContents.id -> { msg, remoteAllowed }
const windowState = new Map();

// Chromium's OS-level sandbox is what contains a renderer exploit triggered by
// a malicious message. Refuse to run if it has been switched off, for example
// by the AppImage launcher on systems that block unprivileged user namespaces.
// This must run before app.enableSandbox(), which hides --no-sandbox from
// app.commandLine without actually re-enabling the sandbox. The raw argv is
// checked too (Chromium accepts "--name", "-name" and "--name=value").
const SANDBOX_DISABLING_SWITCHES = ['no-sandbox', 'disable-seccomp-filter-sandbox', 'disable-namespace-sandbox', 'disable-setuid-sandbox'];
const argvSwitches = new Set();
for (const arg of process.argv.slice(1)) {
  if (arg === '--') break;
  const m = /^--?([^=]+)/.exec(arg);
  if (m) argvSwitches.add(m[1].toLowerCase());
}
const sandboxDisabledBy = SANDBOX_DISABLING_SWITCHES.filter((name) => app.commandLine.hasSwitch(name) || argvSwitches.has(name));

app.enableSandbox();

// Windows: match the installer's AppUserModelID so the taskbar groups windows
// under the pinned/Start menu shortcut.
if (process.platform === 'win32') app.setAppUserModelId('local.mailview.viewer');

function refuseUnsandboxed() {
  const message =
    `MailView won't run with Chromium's sandbox disabled (--${sandboxDisabledBy.join(', --')}).\n\n` +
    'The sandbox contains a malicious message if it exploits a browser bug, so MailView never runs without it.' +
    (process.platform === 'linux'
      ? "\n\nOn Ubuntu 24.04 and later the AppImage can't use the sandbox. Install the .deb or .rpm package instead; " +
        'it includes the AppArmor profile the sandbox needs.'
      : '\n\nRemove the flag from the shortcut or command line that started MailView.');
  console.error(message);
  dialog.showErrorBox('Sandbox disabled', message);
  app.exit(1);
}

// --- Network gate ---------------------------------------------------------
// Every request from the viewer goes through here. Remote requests are
// refused unless the user enabled remote images for that window, and even
// then only image requests are let through. file:// is limited to the app's
// own files so email content can't reach local or UNC (\\host\share) paths.

// Windows paths are case-insensitive, so compare them that way there.
const foldCase = process.platform === 'win32' ? (p) => p.toLowerCase() : (p) => p;
const APP_ROOT_KEY = foldCase(APP_ROOT);

function isInsideApp(fileUrl) {
  try {
    const p = foldCase(path.resolve(fileURLToPath(fileUrl)));
    return p === APP_ROOT_KEY || p.startsWith(APP_ROOT_KEY + path.sep);
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

  // Never send Windows (NTLM/Kerberos) credentials automatically. By default
  // Chromium does so for any host Windows puts in the Local Intranet zone,
  // such as a dotless name in an opted-in remote image URL. An allowlist that
  // matches no real host turns that off.
  ses.allowNTLMCredentialsForDomains('mailview.invalid');

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

// Launch arguments arrive as plain paths (terminal) or as URLs (file managers,
// via the desktop entry's %U). Only local files are accepted: a URL is never
// fetched, and a file:// URL with a host names a network share (on Windows,
// opening one makes an SMB connection that can leak the user's credentials).
function launchArgToSource(arg) {
  // Require "scheme://" (or "file:") so names like "RE: Invoice.eml" stay paths.
  if (!/^[a-z][a-z0-9+.-]+:\/\//i.test(arg) && !/^file:/i.test(arg)) return { path: path.resolve(arg) };
  let url;
  try {
    url = new URL(arg);
  } catch {
    return { error: 'Not a valid URL.', label: arg };
  }
  if (url.protocol !== 'file:') {
    return { error: `Only local files can be opened, not ${url.protocol} URLs.`, label: arg };
  }
  if (url.hostname && url.hostname.toLowerCase() !== 'localhost') {
    return { error: `Refusing to open a file on a network host (${url.hostname}).`, label: arg };
  }
  try {
    return { path: fileURLToPath(url) };
  } catch (err) {
    return { error: err.message, label: arg };
  }
}

async function loadInto(win, source) {
  const wc = win.webContents;
  const pending = windowState.get(wc.id);
  if (pending) pending.loading = true;
  try {
    if (source.error) throw new Error(source.error);
    let buf = source.buffer;
    if (!buf) {
      // Directories, FIFOs and device files are refused (a FIFO would hang the read).
      const stat = await fs.promises.stat(source.path);
      if (!stat.isFile()) throw new Error('Not a regular file.');
      buf = await fs.promises.readFile(source.path);
    }
    const name = source.name || path.basename(source.path);
    const msg = await parseMessage(buf, name);
    const analysis = analyzeMessage(msg);
    windowState.set(wc.id, { msg, remoteAllowed: false });
    win.setTitle(`${msg.subject || '(no subject)'} | ${name} | MailView`);
    wc.send('message-loaded', { message: publicMessage(msg), analysis });
  } catch (err) {
    windowState.set(wc.id, { msg: null, remoteAllowed: false });
    wc.send('message-error', { file: source.label || source.name || source.path, error: err.message });
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
    .trim()
    // Windows silently strips trailing dots and spaces; drop them so the save dialog shows the real name.
    .replace(/[. ]+$/, '');
  if (!cleaned) return 'attachment';
  // Reserved device names (CON, NUL, COM1...) can't be used as file names on Windows.
  return /^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\.|$)/i.test(cleaned) ? `_${cleaned}` : cleaned;
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
  await markAsDownloaded(result.filePath);
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
  if (sandboxDisabledBy.length) {
    refuseUnsandboxed();
    return;
  }
  installNetworkGate(session.fromPartition(PARTITION));
  buildMenu();

  const args = process.argv.slice(app.isPackaged ? 1 : 2).filter((a) => !a.startsWith('-') && a !== '.');
  const sources = [...pendingOpenFiles.map((f) => ({ path: f })), ...args.map(launchArgToSource)];
  if (sources.length) sources.forEach((source) => createWindow(source));
  else createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
