'use strict';

// Parses single-message email files (.eml, .emlx, .msg, .mht/.mhtml) into a
// normalized structure. Runs only in the main process. Nothing here fetches
// anything over the network; mailparser is configured to leave cid: links
// untouched so inline images stay hidden until the user asks for them.

const crypto = require('crypto');
const path = require('path');
const { simpleParser } = require('mailparser');
const MsgReaderModule = require('@kenjiuno/msgreader');
const { decompressRTF } = require('@kenjiuno/decompressrtf');
const { deEncapsulateSync } = require('rtf-stream-parser');
const iconv = require('iconv-lite');

const MsgReader = MsgReaderModule.default || MsgReaderModule;

const MAX_FILE_SIZE = 150 * 1024 * 1024;
const OLE_MAGIC = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);

const SIMPLE_PARSER_OPTIONS = {
  keepCidLinks: true, // do NOT inline cid: images as data: URIs
  skipHtmlToText: false,
  skipTextToHtml: true,
  skipTextLinks: true,
  skipImageLinks: true,
};

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function detectFormat(buf, fileName) {
  const ext = path.extname(fileName || '').toLowerCase();
  if (buf.length >= 8 && buf.subarray(0, 8).equals(OLE_MAGIC)) return 'msg';
  if (ext === '.emlx' && /^\s*\d+\s*\r?\n/.test(buf.subarray(0, 32).toString('latin1'))) return 'emlx';
  if (ext === '.mht' || ext === '.mhtml') return 'mht';
  return 'eml';
}

// --- Header helpers -------------------------------------------------------

function splitHeaderBlock(buf) {
  const s = buf.toString('latin1');
  const m = /\r?\n\r?\n/.exec(s);
  return m ? s.slice(0, m.index) : s;
}

// Unfold a raw RFC 5322 header block into [{ name, value }] preserving order.
function parseHeaderBlock(text) {
  const out = [];
  if (!text) return out;
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  for (const line of lines) {
    if (/^[ \t]/.test(line) && out.length) {
      out[out.length - 1].value += ' ' + line.trim();
    } else {
      const idx = line.indexOf(':');
      if (idx > 0) out.push({ name: line.slice(0, idx).trim(), value: line.slice(idx + 1).trim() });
    }
  }
  return out;
}

function decodeMimeWords(value) {
  // Decode RFC 2047 encoded-words for display (=?utf-8?B?...?=).
  return value.replace(/=\?([^?]+)\?([bqBQ])\?([^?]*)\?=/g, (whole, charset, enc, data) => {
    try {
      let bytes;
      if (enc.toUpperCase() === 'B') bytes = Buffer.from(data, 'base64');
      else {
        bytes = Buffer.from(
          data.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))),
          'latin1'
        );
      }
      return iconv.encodingExists(charset) ? iconv.decode(bytes, charset) : whole;
    } catch {
      return whole;
    }
  }).replace(/\?=\s+=\?/g, '?==?');
}

function addressList(field) {
  if (!field) return [];
  const groups = Array.isArray(field) ? field : [field];
  const out = [];
  for (const g of groups) {
    for (const v of g.value || []) {
      if (v.group) {
        for (const m of v.group) out.push({ name: m.name || '', address: m.address || '' });
      } else {
        out.push({ name: v.name || '', address: v.address || '' });
      }
    }
  }
  return out;
}

// --- MIME (.eml / .emlx / .mht) ------------------------------------------

async function parseMime(buf, format) {
  const parsed = await simpleParser(buf, SIMPLE_PARSER_OPTIONS);
  const rawHeaders = splitHeaderBlock(buf);

  const attachments = (parsed.attachments || []).map((a) => ({
    filename: a.filename || '',
    contentType: (a.contentType || 'application/octet-stream').toLowerCase(),
    contentId: a.contentId ? a.contentId.replace(/^<|>$/g, '') : '',
    inline: a.contentDisposition === 'inline' || !!a.related,
    content: a.content,
  }));

  const returnPath = parsed.headers.get('return-path');

  return {
    format,
    subject: parsed.subject || '',
    date: parsed.date ? parsed.date.toISOString() : '',
    from: addressList(parsed.from),
    to: addressList(parsed.to),
    cc: addressList(parsed.cc),
    bcc: addressList(parsed.bcc),
    replyTo: addressList(parsed.replyTo),
    sender: addressList(parsed.headers.get('sender')),
    returnPath: returnPath ? addressList(returnPath) : [],
    messageId: parsed.messageId || '',
    rawHeaders,
    headers: parseHeaderBlock(rawHeaders),
    html: typeof parsed.html === 'string' ? parsed.html : null,
    text: parsed.text || null,
    attachments,
  };
}

function parseEmlx(buf) {
  // .emlx = "<byte count>\n" + RFC 822 message + Apple plist trailer.
  const nl = buf.indexOf(0x0a);
  const count = parseInt(buf.subarray(0, nl).toString('ascii').trim(), 10);
  if (nl < 0 || !Number.isFinite(count)) return parseMime(buf, 'emlx');
  const start = nl + 1;
  return parseMime(buf.subarray(start, Math.min(buf.length, start + count)), 'emlx');
}

// --- Outlook .msg ---------------------------------------------------------

function decodeBytes(bytes, codepage) {
  const buf = Buffer.from(bytes);
  const head = buf.subarray(0, 2048).toString('latin1');
  const meta = /<meta[^>]+charset=["']?([\w-]+)/i.exec(head);
  const candidates = [meta && meta[1], codepage === 65001 ? 'utf8' : codepage ? 'cp' + codepage : null, 'utf8'];
  for (const enc of candidates) {
    if (enc && iconv.encodingExists(enc)) return iconv.decode(buf, enc);
  }
  return buf.toString('utf8');
}

function rtfToHtml(compressed) {
  try {
    const rtf = Buffer.from(decompressRTF(Array.from(compressed)));
    const result = deEncapsulateSync(rtf, { mode: 'either', decode: iconv.decode });
    return { mode: result.mode, text: String(result.text) };
  } catch {
    return null;
  }
}

function msgRecipients(recipients, type) {
  return (recipients || [])
    .filter((r) => (r.recipType || 'to') === type)
    .map((r) => ({ name: r.name || '', address: r.smtpAddress || r.email || '' }));
}

async function parseMsg(buf) {
  const reader = new MsgReader(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
  const data = reader.getFileData();
  if (data.error) throw new Error('Not a valid Outlook message: ' + data.error);

  const rawHeaders = data.headers || '';
  let structured = null;
  if (rawHeaders.trim()) {
    // Reuse mailparser to get structured addresses from the transport headers.
    structured = await simpleParser(Buffer.from(rawHeaders.replace(/\s*$/, '') + '\r\n\r\n', 'utf8'), SIMPLE_PARSER_OPTIONS);
  }

  let html = null;
  let text = data.body || null;
  if (data.bodyHtml) html = data.bodyHtml;
  else if (data.html && data.html.length) html = decodeBytes(data.html, data.internetCodepage);
  else if (data.compressedRtf && data.compressedRtf.length) {
    const r = rtfToHtml(data.compressedRtf);
    if (r && r.mode === 'html') html = r.text;
    else if (r && !text) text = r.text;
  }

  const attachments = [];
  for (const att of data.attachments || []) {
    try {
      const file = reader.getAttachment(att);
      const name = file.fileName || att.fileName || att.name || 'attachment';
      attachments.push({
        filename: att.innerMsgContent && !/\.msg$/i.test(name) ? name + '.msg' : name,
        contentType: (att.attachMimeTag || (att.innerMsgContent ? 'application/vnd.ms-outlook' : 'application/octet-stream')).toLowerCase(),
        contentId: att.pidContentId ? att.pidContentId.replace(/^<|>$/g, '') : '',
        inline: !!att.attachmentHidden,
        content: Buffer.from(file.content),
      });
    } catch (err) {
      attachments.push({
        filename: (att.fileName || att.name || 'attachment') + ' (unreadable)',
        contentType: 'application/octet-stream',
        contentId: '',
        inline: false,
        content: Buffer.alloc(0),
      });
    }
  }

  const from = structured && structured.from
    ? addressList(structured.from)
    : [{ name: data.senderName || '', address: data.senderSmtpAddress || data.senderEmail || '' }];

  return {
    format: 'msg',
    subject: data.subject || (structured && structured.subject) || '',
    date: (structured && structured.date && structured.date.toISOString()) || data.clientSubmitTime || data.messageDeliveryTime || '',
    from,
    to: structured ? addressList(structured.to) : msgRecipients(data.recipients, 'to'),
    cc: structured ? addressList(structured.cc) : msgRecipients(data.recipients, 'cc'),
    bcc: msgRecipients(data.recipients, 'bcc'),
    replyTo: structured ? addressList(structured.replyTo) : [],
    sender: structured ? addressList(structured.headers.get('sender')) : [],
    returnPath: structured && structured.headers.get('return-path') ? addressList(structured.headers.get('return-path')) : [],
    messageId: (structured && structured.messageId) || '',
    rawHeaders,
    headers: parseHeaderBlock(rawHeaders),
    html,
    text,
    attachments,
  };
}

// --- Entry point ----------------------------------------------------------

async function parseMessage(buf, fileName) {
  if (buf.length > MAX_FILE_SIZE) throw new Error('File is larger than 150 MB; refusing to parse.');
  const format = detectFormat(buf, fileName);
  let msg;
  if (format === 'msg') msg = await parseMsg(buf);
  else if (format === 'emlx') msg = await parseEmlx(buf);
  else msg = await parseMime(buf, format);

  for (const field of ['from', 'to', 'cc', 'bcc', 'replyTo', 'sender', 'returnPath']) {
    msg[field] = (msg[field] || []).filter((a) => a.name || a.address);
  }
  msg.fileName = fileName ? path.basename(fileName) : '';
  msg.fileSize = buf.length;
  msg.fileSha256 = sha256(buf);
  msg.headers = msg.headers.map((h) => ({ name: h.name, value: decodeMimeWords(h.value) }));
  msg.attachments = msg.attachments.map((a, i) => ({
    ...a,
    id: i,
    size: a.content.length,
    sha256: sha256(a.content),
  }));
  return msg;
}

module.exports = { parseMessage, parseHeaderBlock };
