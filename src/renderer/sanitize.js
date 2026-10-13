'use strict';

// Turns untrusted email HTML into a srcdoc for a sandboxed iframe.
//
// Layers, from the inside out:
//   1. DOMPurify (parsing happens in an inert document, so nothing loads)
//      strips scripts, forms, embeds, event handlers, etc.
//   2. Hooks below disable every link and swap remote/cid/other image sources
//      for a placeholder unless the user has opted in.
//   3. A CSP <meta> inside the srcdoc forbids scripts and limits images to
//      data: (plus http/https after opt-in).
//   4. The iframe has sandbox="" and the main process blocks the request
//      anyway unless remote images were enabled for the window.

/* global DOMPurify */

const MailSanitizer = (() => {
  const PLACEHOLDER = 'data:image/svg+xml,' + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48">' +
    '<rect width="48" height="48" fill="#eceff3"/><rect x="0.5" y="0.5" width="47" height="47" fill="none" stroke="#a7afba" stroke-dasharray="3 2"/>' +
    '<path d="M14 32l7-9 5 6 4-4 6 7z" fill="#a7afba"/><circle cx="31" cy="17" r="3" fill="#a7afba"/>' +
    '<path d="M10 10l28 28" stroke="#c0392b" stroke-width="2.5"/></svg>'
  );

  const FORBID_TAGS = [
    'script', 'noscript', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet', 'base', 'link', 'meta',
    'form', 'input', 'button', 'textarea', 'select', 'option', 'optgroup', 'datalist', 'output', 'keygen',
    'svg', 'math', 'video', 'audio', 'source', 'track', 'picture', 'portal', 'dialog', 'template', 'slot',
  ];
  const FORBID_ATTR = ['ping', 'srcset', 'lowsrc', 'dynsrc', 'action', 'formaction', 'target', 'autofocus', 'popover', 'download'];

  const REMOTE_CSS_URL = /url\(\s*(['"]?)\s*((?:https?:)?\/\/[^'")]*)\1\s*\)/gi;
  const REMOTE_IMPORT = /@import\s+(?:url\()?\s*['"]?\s*(?:https?:)?\/\/[^;]*;?/gi;
  const CID_CSS_URL = /url\(\s*(['"]?)\s*cid:([^'")]*)\1\s*\)/gi;

  function classify(url) {
    const s = (url || '').trim();
    if (!s) return 'empty';
    if (/^data:image\//i.test(s)) return 'data';
    if (/^cid:/i.test(s)) return 'cid';
    if (/^https?:\/\//i.test(s) || s.startsWith('//')) return 'remote';
    return 'other';
  }

  function cidKey(url) {
    let v = url.trim().replace(/^cid:/i, '').replace(/^<|>$/g, '');
    try { v = decodeURIComponent(v); } catch { /* keep raw */ }
    return v.toLowerCase();
  }

  function normalizeRemote(url) {
    const s = url.trim();
    return s.startsWith('//') ? 'https:' + s : s;
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function textToHtml(text) {
    return '<pre style="white-space:pre-wrap;word-wrap:break-word;font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;margin:0">' +
      escapeHtml(text || '') + '</pre>';
  }

  /**
   * @param {string} html            untrusted message HTML
   * @param {object} opts
   * @param {boolean} opts.allowRemote   let http(s) images through
   * @param {Object<string,string>} opts.cidMap  lowercased content-id -> data: URL (after attachments are loaded)
   */
  function build(html, { allowRemote = false, cidMap = null } = {}) {
    const links = [];
    const stats = { remote: 0, cid: 0, other: 0, cssRemote: 0 };

    function resolveImage(src) {
      const kind = classify(src);
      if (kind === 'data') return { src };
      if (kind === 'remote') {
        stats.remote++;
        return allowRemote ? { src: normalizeRemote(src) } : { blocked: 'remote image' };
      }
      if (kind === 'cid') {
        stats.cid++;
        const data = cidMap && cidMap[cidKey(src)];
        return data ? { src: data } : { blocked: 'inline image (attachment)' };
      }
      if (kind === 'other') {
        stats.other++;
        return { blocked: 'image with disallowed URL' };
      }
      return { src: null };
    }

    DOMPurify.removeAllHooks();
    DOMPurify.addHook('beforeSanitizeAttributes', (node) => {
      if (node.nodeType !== 1) return;
      const tag = node.nodeName.toLowerCase();

      if ((tag === 'a' || tag === 'area') && node.hasAttribute('href')) {
        const href = node.getAttribute('href').trim();
        const text = (node.textContent || '').replace(/\s+/g, ' ').trim();
        const index = links.push({ href, text }) - 1;
        node.removeAttribute('href');
        node.setAttribute('data-mv-link', String(index));
        node.setAttribute('title', 'Link disabled. Destination: ' + href);
      }

      if (tag === 'img') {
        let src = node.getAttribute('src') || '';
        if (!src && node.getAttribute('srcset')) src = node.getAttribute('srcset').trim().split(/\s+/)[0];
        const r = resolveImage(src);
        if (r.blocked) {
          node.setAttribute('src', PLACEHOLDER);
          node.setAttribute('data-mv-blocked', '');
          node.setAttribute('title', `Blocked ${r.blocked}: ${src.slice(0, 500)}`);
          if (!node.getAttribute('alt')) node.setAttribute('alt', 'blocked image');
        } else if (r.src) {
          node.setAttribute('src', r.src);
        } else {
          node.removeAttribute('src');
        }
      }

      if (node.hasAttribute('background')) {
        const r = resolveImage(node.getAttribute('background'));
        if (r.src) node.setAttribute('background', r.src);
        else node.removeAttribute('background');
      }
    });

    const sanitized = DOMPurify.sanitize(html || '', {
      WHOLE_DOCUMENT: true,
      ADD_TAGS: ['style'],
      FORBID_TAGS,
      FORBID_ATTR,
      ALLOW_UNKNOWN_PROTOCOLS: false,
    });
    DOMPurify.removeAllHooks();

    const doc = new DOMParser().parseFromString(sanitized, 'text/html');

    // CSS url(...) references: count them, and strip them unless allowed.
    const rewriteCss = (css) => css
      .replace(REMOTE_IMPORT, () => { stats.cssRemote++; return ''; })
      .replace(REMOTE_CSS_URL, (whole, _q, url) => {
        stats.cssRemote++;
        return allowRemote ? `url("${normalizeRemote(url).replace(/"/g, '%22')}")` : 'none';
      })
      .replace(CID_CSS_URL, (whole, _q, id) => {
        stats.cid++;
        const data = cidMap && cidMap[cidKey(id)];
        return data ? `url("${data}")` : 'none';
      });
    for (const el of doc.querySelectorAll('[style]')) el.setAttribute('style', rewriteCss(el.getAttribute('style')));
    for (const el of doc.querySelectorAll('style')) el.textContent = rewriteCss(el.textContent);

    const csp = [
      "default-src 'none'",
      `img-src data:${allowRemote ? ' https: http:' : ''}`,
      "style-src 'unsafe-inline'",
      'font-src data:',
      "script-src 'none'",
      "object-src 'none'",
      "media-src 'none'",
      "frame-src 'none'",
      "form-action 'none'",
      "base-uri 'none'",
    ].join('; ');

    const head = doc.head || doc.documentElement.insertBefore(doc.createElement('head'), doc.body);
    const meta = doc.createElement('meta');
    meta.setAttribute('http-equiv', 'Content-Security-Policy');
    meta.setAttribute('content', csp);
    const charset = doc.createElement('meta');
    charset.setAttribute('charset', 'utf-8');
    const style = doc.createElement('style');
    style.textContent =
      'html{background:#fff;color:#111}' +
      'body{margin:16px;font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;word-wrap:break-word}' +
      '[data-mv-link]{color:#1a5fb4;text-decoration:underline dotted;cursor:help}' +
      '[data-mv-blocked]{outline:1px dashed #c0392b;min-width:24px;min-height:24px;object-fit:none;background:#eceff3}';
    head.prepend(meta, charset, style);

    return {
      srcdoc: '<!doctype html>\n' + doc.documentElement.outerHTML,
      links,
      remoteCount: stats.remote + stats.cssRemote,
      cidCount: stats.cid,
      otherBlocked: stats.other,
    };
  }

  return { build, textToHtml };
})();
