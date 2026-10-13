'use strict';
// End-to-end smoke test: opens a message, checks that nothing remote loads,
// then loads attachments and remote images and takes screenshots.
// Usage: MAILVIEW_LOG_REQUESTS=1 npx electron scripts/smoke-test.js <file> <outdir>

const fs = require('fs');
const path = require('path');
const { app, BrowserWindow } = require('electron');

const [file, outDir] = process.argv.slice(-2);
process.argv = [process.argv[0], '.', file];
require('../src/main.js');

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function shot(win, name) {
  const img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(outDir, name), img.toPNG());
}

app.whenReady().then(async () => {
  await wait(2500);
  const win = BrowserWindow.getAllWindows()[0];
  const js = (code) => win.webContents.executeJavaScript(code);
  const results = {};

  const srcdoc = await js('document.getElementById("frame").srcdoc');
  results.blockedNotice = await js('document.getElementById("blocked-notice").textContent');
  results.srcdocHas = Object.fromEntries(['<script', 'onload', ' href=', '<form', '<input', '<iframe', '<svg', '<base', 'http-equiv="refresh"', 'src="https://', 'src="cid:', 'background="'].map((s) => [s, srcdoc.includes(s)]));
  results.frameTitleAfterLoad = await js('document.title');
  await shot(win, '1-blocked.png');

  await js('document.querySelector(\'[data-tab="findings"]\').click()');
  await wait(200);
  await shot(win, '2-findings.png');
  await js('document.querySelector(\'[data-tab="links"]\').click()');
  await wait(200);
  await shot(win, '3-links.png');

  console.log('--- loading attachments');
  await js('document.getElementById("btn-attachments").click()');
  await wait(800);
  await shot(win, '4-attachments.png');
  await js('document.querySelector(\'[data-tab="rendered"]\').click()');
  await wait(300);
  results.cidResolved = (await js('document.getElementById("frame").srcdoc')).includes('src="data:image/png');

  console.log('--- enabling remote images');
  await js('document.getElementById("btn-remote").click()');
  await wait(300);
  await shot(win, '5-confirm.png');
  await js('document.getElementById("remote-confirm").click()');
  await js('document.querySelector(\'[data-tab="rendered"]\').click()');
  await wait(4000);
  await shot(win, '6-remote.png');
  const remoteDoc = await js('document.getElementById("frame").srcdoc');
  results.remoteDocCss = remoteDoc.match(/url\([^)]*\)|background="[^"]*"/g);

  console.log(JSON.stringify(results, null, 2));
  app.exit(0);
});
