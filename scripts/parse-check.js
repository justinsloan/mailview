'use strict';
// Parses a message outside Electron and prints the summary + findings.
// Usage: node scripts/parse-check.js <file>
const fs = require('fs');
const { parseMessage } = require('../src/parser');
const { analyzeMessage } = require('../src/analysis');

(async () => {
  const file = process.argv[2];
  if (!file) { console.error('usage: node scripts/parse-check.js <file>'); process.exit(2); }
  const msg = await parseMessage(fs.readFileSync(file), file);
  const { findings, auth, received } = analyzeMessage(msg);
  console.log(JSON.stringify({
    format: msg.format, subject: msg.subject, from: msg.from, replyTo: msg.replyTo, returnPath: msg.returnPath,
    to: msg.to, date: msg.date, htmlLength: msg.html && msg.html.length, textLength: msg.text && msg.text.length,
    htmlHasCid: !!(msg.html && msg.html.includes('cid:')),
    attachments: msg.attachments.map((a) => ({ filename: a.filename, contentType: a.contentType, contentId: a.contentId, inline: a.inline, size: a.size })),
    auth, hops: received.length, findings: findings.map((f) => `[${f.level}] ${f.title}`),
  }, null, 2));
})().catch((e) => { console.error(e); process.exit(1); });
