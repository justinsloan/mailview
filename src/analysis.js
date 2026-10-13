'use strict';

// Heuristic phishing indicators derived from headers and attachment metadata.
// Link indicators are computed in the renderer after the HTML is sanitized.

const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'co.kr',
  'com.br', 'com.cn', 'com.mx', 'co.in', 'co.za', 'com.sg', 'com.tr', 'com.hk',
]);

const RISKY_EXTENSIONS = new Set([
  'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta',
  'msi', 'msix', 'appx', 'dll', 'cpl', 'jar', 'lnk', 'url', 'iso', 'img', 'vhd', 'vhdx', 'one', 'onepkg',
  'html', 'htm', 'shtml', 'xhtml', 'svg', 'chm', 'reg', 'xll', 'docm', 'xlsm', 'pptm', 'dotm', 'xlam',
  'library-ms', 'search-ms', 'settingcontent-ms', 'application', 'gadget', 'scf', 'inf', 'msc', 'sh', 'py',
]);
const ARCHIVE_EXTENSIONS = new Set(['zip', '7z', 'rar', 'gz', 'tgz', 'bz2', 'xz', 'cab', 'ace', 'arj', 'tar', 'z']);

function domainOf(address) {
  const m = /@([^@>\s]+)$/.exec((address || '').trim().toLowerCase());
  return m ? m[1].replace(/\.$/, '') : '';
}

// Rough "organizational domain" (last two labels, or three for common ccSLDs).
function orgDomain(domain) {
  const labels = (domain || '').toLowerCase().split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  return MULTI_PART_SUFFIXES.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

function headerValues(headers, name) {
  const n = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === n).map((h) => h.value);
}

function parseAuthResults(headers) {
  const results = { spf: null, dkim: null, dmarc: null, arc: null };
  // The top-most Authentication-Results header is the one added by the receiving server.
  const values = headerValues(headers, 'authentication-results');
  for (const value of values.length ? [values[0]] : []) {
    for (const mech of Object.keys(results)) {
      const m = new RegExp('\\b' + mech + '\\s*=\\s*([a-z]+)', 'i').exec(value);
      if (m && !results[mech]) results[mech] = m[1].toLowerCase();
    }
  }
  if (!results.spf) {
    const spf = headerValues(headers, 'received-spf')[0];
    if (spf) results.spf = (/^\s*([a-z]+)/i.exec(spf) || [])[1]?.toLowerCase() || null;
  }
  return results;
}

function parseReceived(headers) {
  // Received headers are prepended by each hop, so reverse to get origin first.
  return headerValues(headers, 'received')
    .reverse()
    .map((value) => {
      const [route, date] = value.split(/;(?=[^;]*$)/);
      const from = (/\bfrom\s+(.+?)(?=\s+by\s|\s+with\s|\s+id\s|$)/i.exec(route) || [])[1] || '';
      const by = (/\bby\s+(.+?)(?=\s+with\s|\s+id\s|\s+for\s|$)/i.exec(route) || [])[1] || '';
      return { from: from.trim(), by: by.trim(), date: (date || '').trim(), raw: value };
    });
}

// Envelope-from (SMTP MAIL FROM) as recorded by the receiving server. Prefer the
// Return-Path header; fall back to what SPF evaluated.
function envelopeFrom(headers) {
  const rp = headerValues(headers, 'return-path')[0];
  if (rp !== undefined) {
    const m = /<([^>]*)>/.exec(rp);
    return { address: (m ? m[1] : rp).trim(), source: 'Return-Path header' };
  }
  const ar = headerValues(headers, 'authentication-results')[0];
  const mailfrom = ar && /smtp\.mailfrom=("?)([^\s;"]+)\1/i.exec(ar);
  if (mailfrom) return { address: mailfrom[2], source: 'Authentication-Results (smtp.mailfrom)' };
  const spf = headerValues(headers, 'received-spf')[0];
  const envFrom = spf && /envelope-from=("?)([^\s;"]+)\1/i.exec(spf);
  if (envFrom) return { address: envFrom[2], source: 'Received-SPF (envelope-from)' };
  return null;
}

// smtp.mailfrom is sometimes just a domain, so accept either form.
function domainOfAny(value) {
  return value.includes('@') ? domainOf(value) : value.toLowerCase().replace(/\.$/, '');
}

function compareEnvelopeReplyTo(msg) {
  const env = envelopeFrom(msg.headers);
  const replyTo = msg.replyTo.map((a) => a.address).filter(Boolean);
  const fromAddress = (msg.from[0] && msg.from[0].address) || '';
  const result = { envelopeFrom: env, replyTo: [], fromAddress };

  if (!env) {
    return { ...result, status: 'unknown', level: 'info', summary: 'No envelope-from found (no Return-Path, smtp.mailfrom or Received-SPF header), so it can\'t be compared.' };
  }
  if (!env.address) {
    return { ...result, status: 'null-sender', level: 'info', summary: 'Null envelope sender (<>). This is normal for bounces and auto-replies, so there\'s nothing to compare.' };
  }
  if (!replyTo.length) {
    return { ...result, status: 'no-reply-to', level: 'info', summary: `No Reply-To header, so replies go to the From address${fromAddress ? ` (${fromAddress})` : ''}.` };
  }

  const envDomain = orgDomain(domainOfAny(env.address));
  const envIsDomainOnly = !env.address.includes('@');
  result.replyTo = replyTo.map((address) => {
    let relation;
    if (!envIsDomainOnly && address.toLowerCase() === env.address.toLowerCase()) relation = 'same address';
    else if (orgDomain(domainOf(address)) === envDomain) relation = envIsDomainOnly ? 'same domain' : 'different address, same domain';
    else relation = 'different domain';
    return { address, relation };
  });

  if (result.replyTo.some((r) => r.relation === 'different domain')) {
    return { ...result, status: 'different-domain', level: 'high', summary: 'Reply-To is on a different domain from the envelope sender. Replies would go to a domain that didn\'t send this message, which is a common tactic in reply-based fraud (BEC).' };
  }
  if (result.replyTo.some((r) => r.relation === 'different address, same domain')) {
    return { ...result, status: 'different-address', level: 'medium', summary: 'Reply-To is a different address on the same domain as the envelope sender. This is often legitimate (e.g. bounce@ vs support@), but check it.' };
  }
  return { ...result, status: 'match', level: 'ok', summary: 'Reply-To matches the envelope sender.' };
}

function analyzeAttachment(att) {
  const findings = [];
  const name = (att.filename || '').toLowerCase().trim();
  const parts = name.split('.');
  const ext = parts.length > 1 ? parts[parts.length - 1] : '';
  const prev = parts.length > 2 ? parts[parts.length - 2] : '';

  if (RISKY_EXTENSIONS.has(ext)) {
    findings.push({ level: 'high', title: `Risky attachment type: .${ext}`, detail: att.filename });
  } else if (ARCHIVE_EXTENSIONS.has(ext)) {
    findings.push({ level: 'medium', title: `Archive attachment: .${ext}`, detail: `${att.filename}. Archives are often used to smuggle executables past filters.` });
  }
  if (prev && /^(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|rtf)$/.test(prev) && ext && ext !== prev) {
    findings.push({ level: 'high', title: 'Double file extension', detail: att.filename });
  }
  if (/[‪-‮⁦-⁩]/.test(att.filename || '')) {
    findings.push({ level: 'high', title: 'Right-to-left override in filename', detail: JSON.stringify(att.filename) });
  }
  if (/\s{5,}/.test(att.filename || '')) {
    findings.push({ level: 'medium', title: 'Filename padded with whitespace', detail: JSON.stringify(att.filename) });
  }
  if (att.contentType === 'message/rfc822' || ext === 'eml' || ext === 'msg') {
    findings.push({ level: 'info', title: 'Embedded email message', detail: `${att.filename || 'message'}: open it from the Attachments tab to inspect it.` });
  }
  return findings;
}

function analyzeMessage(msg) {
  const findings = [];
  const from = msg.from[0] || { name: '', address: '' };
  const fromDomain = domainOf(from.address);
  const fromOrg = orgDomain(fromDomain);

  // Display name spoofing: "PayPal <random@evil.example>" or "support@bank.com <x@evil>".
  const embedded = /[\w.+-]+@[\w-]+(\.[\w-]+)+/.exec(from.name || '');
  if (embedded && orgDomain(domainOf(embedded[0])) !== fromOrg) {
    findings.push({
      level: 'high',
      title: 'Display name contains a different email address',
      detail: `Display name "${from.name}" but actual sender is ${from.address}.`,
    });
  }

  for (const r of msg.replyTo) {
    if (fromOrg && domainOf(r.address) && orgDomain(domainOf(r.address)) !== fromOrg) {
      findings.push({ level: 'high', title: 'Reply-To domain differs from From', detail: `Replies go to ${r.address}, not ${from.address}.` });
    }
  }
  for (const r of msg.returnPath) {
    if (fromOrg && domainOf(r.address) && orgDomain(domainOf(r.address)) !== fromOrg) {
      findings.push({ level: 'medium', title: 'Return-Path (envelope sender) domain differs from From', detail: `${r.address} vs ${from.address}` });
    }
  }
  for (const s of msg.sender) {
    if (fromOrg && domainOf(s.address) && orgDomain(domainOf(s.address)) !== fromOrg) {
      findings.push({ level: 'medium', title: 'Sender header domain differs from From', detail: `${s.address} vs ${from.address}` });
    }
  }
  if (fromDomain && /(^|\.)xn--/.test(fromDomain)) {
    findings.push({ level: 'high', title: 'Punycode (internationalized) sender domain', detail: fromDomain });
  }
  const midDomain = (/@([^>]+)>?$/.exec(msg.messageId || '') || [])[1];
  if (midDomain && fromOrg && orgDomain(midDomain.toLowerCase()) !== fromOrg) {
    findings.push({ level: 'info', title: 'Message-ID domain differs from From', detail: `${msg.messageId}. This is common for bulk mail services but worth noting.` });
  }

  const auth = parseAuthResults(msg.headers);
  for (const mech of ['spf', 'dkim', 'dmarc']) {
    const r = auth[mech];
    if (r && /fail|softfail|permerror|temperror/.test(r)) {
      findings.push({ level: mech === 'dmarc' || r === 'fail' ? 'high' : 'medium', title: `${mech.toUpperCase()} ${r}`, detail: 'From the receiving server\'s Authentication-Results header.' });
    }
  }
  if (!msg.headers.length) {
    findings.push({ level: 'info', title: 'No transport headers', detail: 'This file has no Internet headers (common for Outlook drafts or saved copies), so sender authentication cannot be checked.' });
  } else if (!auth.spf && !auth.dkim && !auth.dmarc) {
    findings.push({ level: 'info', title: 'No authentication results', detail: 'No Authentication-Results or Received-SPF header found.' });
  }

  for (const att of msg.attachments) findings.push(...analyzeAttachment(att));

  return { findings, auth, received: parseReceived(msg.headers), envelope: compareEnvelopeReplyTo(msg) };
}

module.exports = { analyzeMessage, orgDomain };
