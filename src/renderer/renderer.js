'use strict';

/* global MailSanitizer */

const api = window.mailview;
const $ = (id) => document.getElementById(id);

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'rb.gy', 'cutt.ly', 'buff.ly', 'rebrand.ly',
  'shorturl.at', 'tiny.cc', 'bl.ink', 's.id', 'v.gd', 'lnkd.in', 't.ly', 'qrco.de',
]);
const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'co.kr',
  'com.br', 'com.cn', 'com.mx', 'co.in', 'co.za', 'com.sg', 'com.tr', 'com.hk',
]);
const TEXT_PREVIEW_TYPES = /^(text\/|application\/(json|xml|javascript|x-javascript|x-sh|ecmascript)|image\/svg|message\/)/;
const TEXT_PREVIEW_EXT = /\.(html?|shtml|xhtml|txt|csv|js|jse|vbs|vbe|ps1|bat|cmd|hta|svg|xml|json|eml|url|wsf|sh|py|rtf|ics)$/i;

let state = null;

// --- Small DOM helpers (never use innerHTML with message data) ------------

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function formatSize(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function orgDomain(host) {
  const labels = (host || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  return MULTI_PART_SUFFIXES.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

function defang(url) {
  return url
    .replace(/^http/i, 'hxxp')
    .replace(/^(hxxps?):\/\//i, '$1[://]')
    .replace(/^([^/]*\[:\/\/\])?([^/?#]*)/, (whole, scheme, host) => (scheme || '') + host.replace(/\./g, '[.]'));
}

function formatAddress(a) {
  if (!a) return '';
  return a.name ? `${a.name} <${a.address}>` : a.address;
}

// --- Link analysis ----------------------------------------------------------

function analyzeLink(link) {
  const flags = [];
  let url = null;
  try {
    url = new URL(link.href);
  } catch {
    if (link.href && !link.href.startsWith('#')) flags.push({ level: 'medium', text: 'Unparseable or relative URL' });
    return { ...link, host: '', flags };
  }
  const scheme = url.protocol.replace(':', '').toLowerCase();
  const host = url.hostname.toLowerCase();

  if (/^(javascript|vbscript|data|file|blob)$/.test(scheme)) flags.push({ level: 'high', text: `${scheme}: URL` });
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) flags.push({ level: 'high', text: 'IP address instead of a domain name' });
  if (/(^|\.)xn--/.test(host)) flags.push({ level: 'medium', text: 'Punycode (lookalike) domain' });
  if (url.username || url.password) flags.push({ level: 'high', text: 'Credentials/"@" trick in URL' });
  if (SHORTENERS.has(host)) flags.push({ level: 'info', text: 'URL shortener hides the real destination' });
  if (scheme === 'http') flags.push({ level: 'info', text: 'Unencrypted http' });

  // Visible text that looks like a URL/domain but points somewhere else.
  const shown = /(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|\s|$)/i.exec(link.text || '');
  if (shown && host && (scheme === 'http' || scheme === 'https')) {
    const shownDomain = orgDomain(shown[1]);
    if (shownDomain && shownDomain !== orgDomain(host)) {
      flags.push({ level: 'high', text: `Text shows ${shown[1]} but link goes to ${host}` });
    }
  }
  return { ...link, host, flags };
}

// --- Rendering ---------------------------------------------------------------

// Replacing srcdoc while the panel is display:none can leave the out-of-process
// frame unpainted when it is shown again, so defer it until it is visible.
let pendingSrcdoc = null;
function setFrame(srcdoc) {
  if (document.querySelector('[data-panel="rendered"]').classList.contains('active')) {
    $('frame').srcdoc = srcdoc;
    pendingSrcdoc = null;
  } else {
    pendingSrcdoc = srcdoc;
  }
}

function renderBody() {
  const msg = state.message;
  const html = msg.html || MailSanitizer.textToHtml(msg.text || '');
  const result = MailSanitizer.build(html, { allowRemote: state.remoteAllowed, cidMap: state.cidMap });
  setFrame(result.srcdoc);

  state.links = result.links.map(analyzeLink);
  state.remoteCount = result.remoteCount;

  const notice = $('blocked-notice');
  const parts = [];
  if (!state.remoteAllowed && result.remoteCount) parts.push(`${result.remoteCount} remote image${result.remoteCount === 1 ? '' : 's'} blocked`);
  if (!state.cidMap && result.cidCount) parts.push(`${result.cidCount} inline image${result.cidCount === 1 ? '' : 's'} hidden (attachments not loaded)`);
  if (result.otherBlocked) parts.push(`${result.otherBlocked} image${result.otherBlocked === 1 ? '' : 's'} with disallowed URLs (e.g. file://) blocked`);
  notice.hidden = parts.length === 0;
  notice.textContent = parts.length ? parts.join(' · ') + '. Links are disabled; hover to see their destination.' : '';

  renderToolbar();
  renderLinks();
  renderFindings();
}

function renderToolbar() {
  const msg = state.message;
  $('file-info').textContent = `${msg.fileName || 'message'} · ${msg.format.toUpperCase()} · ${formatSize(msg.fileSize)}`;
  $('file-info').title = `SHA-256: ${msg.fileSha256}`;

  const chip = $('remote-state');
  chip.hidden = false;
  chip.textContent = state.remoteAllowed ? 'Remote content: LOADED' : 'Remote content: blocked';
  chip.className = 'chip ' + (state.remoteAllowed ? 'chip-warn' : 'chip-ok');

  const rb = $('btn-remote');
  rb.hidden = false;
  rb.disabled = state.remoteAllowed || state.remoteCount === 0;
  rb.textContent = state.remoteAllowed ? 'Remote images loaded' : state.remoteCount ? `Load remote images (${state.remoteCount})` : 'No remote images';

  const ab = $('btn-attachments');
  ab.hidden = false;
  ab.disabled = !!state.attachments || msg.attachmentCount === 0;
  ab.textContent = state.attachments ? 'Attachments loaded' : msg.attachmentCount ? `Load attachments (${msg.attachmentCount})` : 'No attachments';
}

function renderSummary() {
  const msg = state.message;
  $('subject').textContent = msg.subject || '(no subject)';

  const dl = $('summary-fields');
  dl.replaceChildren();
  const row = (label, list, opts = {}) => {
    if (!list || !list.length) return;
    dl.append(el('dt', null, label));
    dl.append(el('dd', { class: opts.cls }, list.map((a, i) => [
      i ? ', ' : '',
      a.name ? el('span', { class: 'addr-name' }, a.name, ' ') : null,
      el('span', { class: 'addr' }, `<${a.address || '?'}>`),
    ])));
  };
  row('From', msg.from);
  row('Reply-To', msg.replyTo);
  row('Sender', msg.sender);
  row('Return-Path', msg.returnPath);
  row('To', msg.to);
  row('Cc', msg.cc);
  row('Bcc', msg.bcc);
  if (msg.date) {
    dl.append(el('dt', null, 'Date'));
    const d = new Date(msg.date);
    dl.append(el('dd', null, isNaN(d) ? msg.date : `${d.toLocaleString()} (${d.toISOString()})`));
  }

  const auth = $('auth');
  auth.replaceChildren();
  for (const mech of ['spf', 'dkim', 'dmarc']) {
    const r = state.analysis.auth[mech];
    const cls = !r ? 'chip-muted' : r === 'pass' ? 'chip-ok' : /fail|error/.test(r) ? 'chip-bad' : 'chip-muted';
    auth.append(el('span', { class: 'chip ' + cls }, `${mech.toUpperCase()}: ${r || 'n/a'}`));
  }
}

function renderLinks() {
  const box = $('links');
  box.replaceChildren();
  $('count-links').textContent = state.links.length || '';
  if (!state.links.length) {
    box.append(el('p', { class: 'muted' }, 'No links in this message.'));
    return;
  }
  const uniqueDefanged = [...new Set(state.links.map((l) => defang(l.href)))].join('\n');
  box.append(el('div', { class: 'panel-actions' },
    el('button', { class: 'btn', onclick: () => api.copyText(uniqueDefanged) }, 'Copy all (defanged)'),
    el('span', { class: 'muted' }, 'Links are never opened by this app.')));

  const table = el('table', { class: 'grid' },
    el('thead', null, el('tr', null, el('th', null, 'Shown text'), el('th', null, 'Actual destination'), el('th', null, 'Flags'), el('th', null, ''))));
  const tbody = el('tbody');
  for (const l of state.links) {
    tbody.append(el('tr', null,
      el('td', { class: 'link-text' }, l.text || el('span', { class: 'muted' }, '(no text / image)')),
      el('td', { class: 'mono break' }, l.host ? el('strong', null, l.host) : null, l.host ? el('br') : null, l.href),
      el('td', null, l.flags.map((f) => el('div', { class: 'flag flag-' + f.level }, f.text))),
      el('td', null, el('button', { class: 'btn btn-small', onclick: () => api.copyText(defang(l.href)), title: 'Copy defanged URL' }, 'Copy'))));
  }
  table.append(tbody);
  box.append(table);
}

function renderAttachments() {
  const box = $('attachments');
  box.replaceChildren();
  const count = state.message.attachmentCount;
  $('count-attachments').textContent = count || '';

  if (!count) {
    box.append(el('p', { class: 'muted' }, 'This message has no attachments.'));
    return;
  }
  if (!state.attachments) {
    box.append(el('div', { class: 'locked' },
      el('p', null, `${count} attachment${count === 1 ? ' is' : 's are'} hidden.`),
      el('p', { class: 'muted' }, 'Attachment names, hashes and inline images are not loaded until you ask. Loading them never opens or runs a file.'),
      el('button', { class: 'btn btn-warn', onclick: loadAttachments }, 'Load attachments')));
    return;
  }

  const table = el('table', { class: 'grid' },
    el('thead', null, el('tr', null, el('th', null, 'Name'), el('th', null, 'Type'), el('th', null, 'Size'), el('th', null, 'SHA-256'), el('th', null, 'Flags'), el('th', null, ''))));
  const tbody = el('tbody');
  for (const a of state.attachments) {
    const flags = state.analysis.findings.filter((f) => f.detail && a.filename && f.detail.includes(a.filename));
    const isMessage = a.contentType === 'message/rfc822' || a.contentType === 'application/vnd.ms-outlook' || /\.(eml|msg)$/i.test(a.filename);
    const isText = TEXT_PREVIEW_TYPES.test(a.contentType) || TEXT_PREVIEW_EXT.test(a.filename);
    tbody.append(el('tr', null,
      el('td', { class: 'break-word' }, a.filename || el('span', { class: 'muted' }, '(unnamed)'),
        a.inline ? el('span', { class: 'chip chip-muted chip-small' }, 'inline') : null,
        a.contentId ? el('div', { class: 'muted mono small' }, `cid:${a.contentId}`) : null),
      el('td', { class: 'mono small' }, a.contentType),
      el('td', { class: 'nowrap' }, formatSize(a.size)),
      el('td', { class: 'mono small break' }, a.sha256, ' ',
        el('button', { class: 'btn btn-small', onclick: () => api.copyText(a.sha256) }, 'Copy')),
      el('td', null, flags.map((f) => el('div', { class: 'flag flag-' + f.level }, f.title))),
      el('td', null, el('div', { class: 'actions' },
        isMessage ? el('button', { class: 'btn btn-small', onclick: () => api.openAttachmentMessage(a.id) }, 'Open as message') : null,
        el('button', { class: 'btn btn-small', onclick: () => showAttachmentText(a), title: isText ? '' : 'Binary file: will show as garbled text' }, 'View as text'),
        el('button', { class: 'btn btn-small', onclick: () => api.saveAttachment(a.id) }, 'Save…')))));
  }
  table.append(tbody);
  box.append(table);
}

const RELATION_CLASS = { 'same address': 'chip-ok', 'same domain': 'chip-ok', 'different address, same domain': 'chip-warn', 'different domain': 'chip-bad' };
const ENVELOPE_LABEL = { high: 'DIFFERENT', medium: 'DIFFERENT', ok: 'MATCH', info: 'N/A' };

function renderEnvelopeCheck(box) {
  const env = state.analysis.envelope;
  box.append(el('h3', null, 'Envelope-from vs Reply-To'));
  const rows = el('dl', { class: 'envelope-rows' },
    el('dt', null, 'Envelope-from'),
    el('dd', null, env.envelopeFrom
      ? [el('span', { class: 'addr' }, env.envelopeFrom.address ? env.envelopeFrom.address : '<> (null sender)'),
        el('span', { class: 'muted small' }, ` from ${env.envelopeFrom.source}`)]
      : el('span', { class: 'muted' }, 'not found')),
    el('dt', null, 'Reply-To'),
    el('dd', null, env.replyTo.length
      ? env.replyTo.map((r) => el('div', null,
        el('span', { class: 'addr' }, r.address), ' ',
        el('span', { class: 'chip chip-small ' + RELATION_CLASS[r.relation] }, r.relation)))
      : replyToFallback(env)));
  box.append(el('div', { class: 'finding envelope finding-' + env.level },
    el('span', { class: 'finding-level' }, ENVELOPE_LABEL[env.level]),
    el('div', null, rows, el('div', { class: 'finding-detail' }, env.summary))));
}

function replyToFallback(env) {
  const replyTo = state.message.replyTo.filter((a) => a.address);
  if (replyTo.length) return replyTo.map((a) => el('div', null, el('span', { class: 'addr' }, a.address)));
  return el('span', { class: 'muted' }, env.fromAddress ? `not set (replies go to From: ${env.fromAddress})` : 'not set');
}

function renderHeaders() {
  const box = $('headers');
  box.replaceChildren();
  const msg = state.message;
  renderEnvelopeCheck(box);
  const hops = state.analysis.received;
  if (hops.length) {
    box.append(el('h3', null, `Delivery path (${hops.length} hops, origin first)`));
    const tbody = el('tbody');
    hops.forEach((h, i) => tbody.append(el('tr', null,
      el('td', null, String(i + 1)), el('td', { class: 'mono small break' }, h.from), el('td', { class: 'mono small break' }, h.by), el('td', { class: 'small nowrap' }, h.date))));
    box.append(el('table', { class: 'grid' },
      el('thead', null, el('tr', null, el('th', null, '#'), el('th', null, 'From'), el('th', null, 'By'), el('th', null, 'Date'))), tbody));
  }
  box.append(el('div', { class: 'panel-actions' },
    el('h3', null, 'Raw headers'),
    el('button', { class: 'btn btn-small', onclick: () => api.copyText(msg.rawHeaders) }, 'Copy')));
  box.append(el('pre', { class: 'mono pre-wrap raw' }, msg.rawHeaders || '(no transport headers in this file)'));
  box.append(el('p', { class: 'muted small' }, `File SHA-256: ${msg.fileSha256}`));
}

function renderFindings() {
  const box = $('findings');
  box.replaceChildren();
  const all = [...state.analysis.findings];
  for (const l of state.links) {
    for (const f of l.flags) {
      if (f.level !== 'info') all.push({ level: f.level, title: `Link: ${f.text}`, detail: l.href });
    }
  }
  const order = { high: 0, medium: 1, info: 2 };
  all.sort((a, b) => order[a.level] - order[b.level]);

  const serious = all.filter((f) => f.level !== 'info').length;
  $('count-findings').textContent = serious || '';
  $('count-findings').className = 'count' + (all.some((f) => f.level === 'high') ? ' count-bad' : serious ? ' count-warn' : '');

  if (!all.length) {
    box.append(el('p', { class: 'muted' }, 'No automated indicators found. That does not mean the message is safe.'));
    return;
  }
  for (const f of all) {
    box.append(el('div', { class: 'finding finding-' + f.level },
      el('span', { class: 'finding-level' }, f.level.toUpperCase()),
      el('div', null, el('div', { class: 'finding-title' }, f.title), f.detail ? el('div', { class: 'finding-detail mono small break' }, f.detail) : null)));
  }
  box.append(el('p', { class: 'muted small' }, 'Heuristic checks only. Domain comparison uses a simplified registrable-domain rule.'));
}

function render() {
  $('empty').hidden = true;
  $('viewer').hidden = false;
  $('error').hidden = true;
  renderSummary();
  $('plain').textContent = state.message.text || '(no plain-text part)';
  renderBody();
  renderAttachments();
  renderHeaders();
}

// --- Actions -----------------------------------------------------------------

async function loadAttachments() {
  state.attachments = await api.loadAttachments();
  state.cidMap = {};
  for (const a of state.attachments) {
    if (a.contentId && a.dataUrl) state.cidMap[a.contentId.toLowerCase()] = a.dataUrl;
  }
  renderAttachments();
  renderBody();
}

async function showAttachmentText(a) {
  const { text, truncated } = await api.attachmentText(a.id);
  $('text-dialog-title').textContent = `${a.filename || 'attachment'}${truncated ? ' (first 512 KB)' : ''}`;
  $('text-dialog-body').textContent = text;
  $('text-dialog').showModal();
}

function selectTab(name) {
  for (const t of document.querySelectorAll('.tab')) t.classList.toggle('active', t.dataset.tab === name);
  for (const p of document.querySelectorAll('.panel')) p.classList.toggle('active', p.dataset.panel === name);
  if (name === 'rendered' && pendingSrcdoc !== null) setFrame(pendingSrcdoc);
}

function showError(text) {
  const box = $('error');
  box.textContent = text;
  box.hidden = false;
}

function showAbout(info) {
  $('about-name').textContent = info.name;
  $('about-version').textContent = `Version ${info.version}`;
  $('about-copyright').textContent = info.copyright;
  $('about-license-line').textContent = `Released under the ${info.license} License.`;
  // Reflow the hard-wrapped license so it reads well at dialog width.
  const reflowed = (info.licenseText || `${info.license} License`).trim().split(/\n\s*\n/).map((p) => p.replace(/\s*\n\s*/g, ' ')).join('\n\n');
  $('about-license-text').textContent = reflowed;
  $('about-runtime').textContent = `Electron ${info.versions.electron} · Chromium ${info.versions.chrome} · Node ${info.versions.node}`;
  if (!$('about-dialog').open) $('about-dialog').showModal();
}

// --- Wiring ------------------------------------------------------------------

api.onMessage(({ message, analysis }) => {
  state = { message, analysis, remoteAllowed: false, cidMap: null, attachments: null, links: [], remoteCount: 0 };
  selectTab('rendered');
  render();
});
api.onError(({ file, error }) => showError(`Could not open ${file}: ${error}`));

$('btn-open').addEventListener('click', () => api.openDialog());
$('btn-open-empty').addEventListener('click', () => api.openDialog());
$('btn-attachments').addEventListener('click', () => {
  selectTab('attachments');
  loadAttachments();
});
$('btn-remote').addEventListener('click', () => $('remote-dialog').showModal());
$('remote-cancel').addEventListener('click', () => $('remote-dialog').close());
$('remote-confirm').addEventListener('click', async () => {
  $('remote-dialog').close();
  await api.enableRemote();
  state.remoteAllowed = true;
  renderBody();
});
$('text-dialog-close').addEventListener('click', () => $('text-dialog').close());
$('about-close').addEventListener('click', () => $('about-dialog').close());
$('btn-about-empty').addEventListener('click', async () => showAbout(await api.about()));
api.onAbout(showAbout);
for (const t of document.querySelectorAll('.tab')) t.addEventListener('click', () => selectTab(t.dataset.tab));

// Drag and drop. Only the path is handed to the main process, which reads the file.
let dragDepth = 0;
window.addEventListener('dragenter', (e) => { e.preventDefault(); dragDepth++; $('drop-overlay').hidden = false; });
window.addEventListener('dragleave', (e) => { e.preventDefault(); if (--dragDepth <= 0) { dragDepth = 0; $('drop-overlay').hidden = true; } });
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => {
  e.preventDefault();
  dragDepth = 0;
  $('drop-overlay').hidden = true;
  for (const file of e.dataTransfer.files) {
    api.openFile(file).catch((err) => showError(`Could not open ${file.name}: ${err.message}`));
  }
});
