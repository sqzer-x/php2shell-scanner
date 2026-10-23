#!/usr/bin/env node
// Serve the assembled site in _site/ at http://127.0.0.1:8790 for a local
// preview. No dependencies. Run `node tools/build-site.mjs` first, or use
// `npm run serve`, which does both. Set PORT to use another port.
//
// It answers GET and HEAD only, serves index.html for a directory, and
// redirects a directory without a trailing slash, so relative links on /kr/
// work as on GitHub Pages. A path is served only if its real path, with
// symlinks resolved, is that same file inside _site/, so nothing outside
// _site/ can be read. Where the file system reports the true case (Windows),
// a wrong-case link fails here as it would on GitHub Pages. Downloads (.php,
// .sh) are sent as plain text.

import { createServer } from 'node:http';
import { createReadStream } from 'node:fs';
import { realpath, stat } from 'node:fs/promises';
import { extname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT) || 8790;
const ROOT = fileURLToPath(new URL('../_site/', import.meta.url));

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.php': 'text/plain; charset=utf-8',
  '.sh': 'text/plain; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '': 'text/plain; charset=utf-8', // SHA256SUMS
};

// The request target as a URL. A path such as //kr stays a path; it is not read as a host.
function parseTarget(target) {
  try {
    return target.startsWith('/') ? new URL(`http://${HOST}${target}`) : new URL(target);
  } catch {
    return null;
  }
}

// The decoded path segments, or null if one could step outside _site/ or is
// not a plain file name (separators, a drive or stream colon, NUL).
function segmentsOf(pathname) {
  const out = [];
  for (const raw of pathname.split('/')) {
    if (raw === '') continue;
    let s;
    try {
      s = decodeURIComponent(raw);
    } catch {
      return null;
    }
    if (s === '.' || s === '..' || /[\\/:\0]/.test(s)) return null;
    out.push(s);
  }
  return out;
}

// The real path of file relative to the real _site/ (symlinks resolved, true case).
async function realRelative(file) {
  const [root, real] = await Promise.all([realpath(ROOT), realpath(file)]);
  return relative(root, real);
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(res.req.method === 'HEAD' ? undefined : body + '\n');
}

async function handle(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed', { allow: 'GET, HEAD' });

  const url = parseTarget(req.url || '/');
  const segments = url && segmentsOf(url.pathname);
  if (!segments) return send(res, 400, 'Bad request');

  let info = await stat(join(ROOT, ...segments)).catch(() => null);
  if (info?.isDirectory()) {
    if (!url.pathname.endsWith('/')) {
      const location = ['', ...segments.map(encodeURIComponent), ''].join('/') + url.search;
      return send(res, 301, 'Moved', { location });
    }
    segments.push('index.html');
    info = await stat(join(ROOT, ...segments)).catch(() => null);
  }
  const file = join(ROOT, ...segments);
  if (!info?.isFile() || (await realRelative(file)) !== join(...segments)) return send(res, 404, 'Not found');

  res.writeHead(200, {
    'content-type': TYPES[extname(file).toLowerCase()] || 'application/octet-stream',
    'content-length': info.size,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  if (req.method === 'HEAD') return res.end();
  createReadStream(file).on('error', () => res.destroy()).pipe(res);
}

const server = createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error(err);
    if (!res.headersSent) send(res, 500, 'Internal error');
    else res.destroy();
  });
});

server.on('error', (err) => {
  console.error(err.code === 'EADDRINUSE' ? `Port ${PORT} on ${HOST} is already in use. Set PORT to use another one.` : err.message);
  process.exit(1);
});

stat(join(ROOT, 'index.html')).then(
  () => server.listen(PORT, HOST, () => console.log(`Serving _site/ at http://${HOST}:${PORT}/ (Ctrl+C to stop)`)),
  () => {
    console.error('_site/index.html not found. Run `node tools/build-site.mjs` first, or `npm run serve`.');
    process.exit(1);
  },
);
