'use strict';

// Mark a saved attachment as downloaded from the internet, so the OS treats it
// as untrusted: Windows gets the "Mark of the Web" (SmartScreen, Office
// Protected View) and macOS the quarantine flag (Gatekeeper). Best effort:
// drives without alternate data streams or extended attributes are skipped.

const fs = require('fs');
const { execFile } = require('child_process');

async function markAsDownloaded(filePath) {
  try {
    if (process.platform === 'win32') {
      await fs.promises.writeFile(`${filePath}:Zone.Identifier`, '[ZoneTransfer]\r\nZoneId=3\r\n');
    } else if (process.platform === 'darwin') {
      // Same flags browsers use for downloads; the timestamp is hex seconds.
      const value = `0081;${Math.floor(Date.now() / 1000).toString(16)};MailView;`;
      await new Promise((resolve, reject) =>
        execFile('/usr/bin/xattr', ['-w', 'com.apple.quarantine', value, filePath], (err) => (err ? reject(err) : resolve())),
      );
    }
  } catch {}
}

module.exports = { markAsDownloaded };
