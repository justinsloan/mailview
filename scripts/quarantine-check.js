'use strict';
// Checks that saved attachments are marked as downloaded from the internet
// (Windows Mark of the Web, macOS quarantine). Usage: node scripts/quarantine-check.js

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { markAsDownloaded } = require('../src/quarantine');

(async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'mailview-')), 'invoice.pdf.exe');
  fs.writeFileSync(file, 'test');
  await markAsDownloaded(file);
  let mark = null;
  if (process.platform === 'win32') {
    mark = fs.readFileSync(`${file}:Zone.Identifier`, 'utf8');
  } else if (process.platform === 'darwin') {
    mark = execFileSync('/usr/bin/xattr', ['-p', 'com.apple.quarantine', file], { encoding: 'utf8' });
  } else {
    console.log(`No download mark on ${process.platform}; nothing to check.`);
    return;
  }
  console.log(mark.trim());
  if (!/ZoneId=3|^0081;/m.test(mark)) {
    console.error('FAILED: unexpected download mark');
    process.exit(1);
  }
})().catch((err) => {
  console.error(`FAILED: ${err.message}`);
  process.exit(1);
});
