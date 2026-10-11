// Loopback-only build cache for the official public Cargo index and crate archives.
// Cargo still verifies each archive against the official index checksum.
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const cache = path.resolve(__dirname, '../../.toolchain/registry-bridge');
fs.mkdirSync(cache, {recursive: true});
const pending = new Map();
let completed = 0;
let requests = 0;
function indexPath(name) {
  return name.length === 1 ? `1/${name}` : name.length === 2 ? `2/${name}` : name.length === 3 ? `3/${name[0]}/${name}` : `${name.slice(0, 2)}/${name.slice(2, 4)}/${name}`;
}

function fetch(url) {
  return new Promise((resolve, reject) => {
    const request = https.get(url, {headers: {'Accept-Encoding': 'gzip', 'User-Agent': 'CargoBuildCache'}}, response => {
      if (response.statusCode !== 200) { response.resume(); reject(new Error(`upstream HTTP ${response.statusCode}`)); return; }
      const total = Number(response.headers['content-length']);
      if (url.startsWith('https://static.crates.io/') && total > 256 * 1024 && !response.headers['content-encoding']) {
        response.destroy();
        fetchRanges(url, total).then(resolve, reject);
        return;
      }
      const pieces = []; let size = 0;
      response.on('data', data => {
        size += data.length;
        if (size > 100 * 1024 * 1024) { response.destroy(new Error('build artifact size limit')); return; }
        pieces.push(data);
      });
      response.on('error', reject);
      response.on('end', () => {
        const data = Buffer.concat(pieces);
        if (response.headers['content-encoding'] === 'gzip') {
          zlib.gunzip(data, (error, result) => error ? reject(error) : resolve(result));
        } else resolve(data);
      });
    });
    request.setTimeout(45000, () => request.destroy(new Error('build download timeout')));
    request.on('error', reject);
  });
}

async function fetchRanges(url, size) {
  const block = 128 * 1024;
  const count = Math.ceil(size / block), parts = Array(count);
  let cursor = 0;
  await Promise.all(Array.from({length: Math.min(32, count)}, async () => {
    for (;;) {
      const index = cursor++; if (index >= count) return;
      const start = index * block, end = Math.min(size - 1, start + block - 1);
      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          parts[index] = await new Promise((resolve, reject) => {
            const request = https.get(url, {headers: {Range: `bytes=${start}-${end}`}}, response => {
              if (response.statusCode !== 206) { response.resume(); reject(new Error('build range rejected')); return; }
              const pieces = []; response.on('data', data => pieces.push(data)); response.on('error', reject);
              response.on('end', () => {
                const result = Buffer.concat(pieces);
                result.length === end - start + 1 ? resolve(result) : reject(new Error('incomplete build range'));
              });
            });
            request.setTimeout(45000, () => request.destroy(new Error('build range timeout')));
            request.on('error', reject);
          });
          break;
        } catch (error) { if (attempt === 4) throw error; }
      }
    }
  }));
  return Buffer.concat(parts);
}

async function cached(key, url) {
  const file = path.join(cache, key.replaceAll('/', '_'));
  if (fs.existsSync(file)) return fs.readFileSync(file);
  if (!pending.has(key)) {
    pending.set(key, (async () => {
      try {
        let bytes;
        for (let attempt = 0; attempt < 5; attempt++) {
          try { bytes = await fetch(url); break; }
          catch (error) { if (attempt === 4 || error.message === 'upstream HTTP 404') throw error; }
        }
        fs.writeFileSync(file, bytes); completed++; return bytes;
      } finally { pending.delete(key); }
    })());
  }
  return pending.get(key);
}

const server = http.createServer(async (request, response) => {
  requests++;
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname;
  try {
    let data;
    if (pathname === '/index/config.json') {
      data = Buffer.from(JSON.stringify({dl: `http://127.0.0.1:${server.address().port}/crates/{crate}/{version}/download`}));
    } else if (/^\/index\/[a-z0-9_\/-]+$/.test(pathname)) {
      const indexPath = pathname.slice('/index/'.length);
      data = await cached(`index/${indexPath}`, `https://index.crates.io/${indexPath}`);
    } else {
      const match = pathname.match(/^\/crates\/([a-zA-Z0-9_-]+)\/([a-zA-Z0-9.+_-]+)\/download$/);
      if (!match) { response.writeHead(404); response.end(); return; }
      const [, crate, version] = match;
      data = await cached(`crates/${crate}-${version}`, `https://static.crates.io/crates/${crate}/${crate}-${version}.crate`);
    }
    response.writeHead(200, {'Content-Length': data.length}); response.end(data);
  } catch (error) {
    response.writeHead(502); response.end('Public build dependency download failed');
  }
});
server.listen(Number(process.env.CODEX_BUILD_CACHE_PORT || 0), '127.0.0.1', () => {
  const endpoint = `sparse+http://127.0.0.1:${server.address().port}/index/`;
  fs.writeFileSync(path.join(cache, 'endpoint.txt'), endpoint);
  console.log(`Official Cargo build cache ready on loopback port ${server.address().port}`);
  const lock = fs.readFileSync(path.resolve(__dirname, '../codex-rs/Cargo.lock'), 'utf8');
  const names = new Set(['rpassword', 'rtoolbox']);
  for (const block of lock.split('[[package]]')) {
    if (block.includes('source = "registry+')) names.add(block.match(/name = "([^"]+)"/)?.[1]);
  }
  const queue = Array.from(names).filter(Boolean);
  let cursor = 0;
  for (let worker = 0; worker < 32; worker++) {
    (async () => {
      for (;;) {
        const name = queue[cursor++]; if (!name) return;
        const pathname = indexPath(name);
        try { await cached(`index/${pathname}`, `https://index.crates.io/${pathname}`); }
        catch (_) { /* Cargo receives a bounded generic error if it needs an unavailable entry. */ }
      }
    })();
  }
  const packages = lock.split('[[package]]').map(block => ({
    name: block.match(/^name = "([^"]+)"/m)?.[1],
    version: block.match(/^version = "([^"]+)"/m)?.[1],
    registry: block.includes('source = "registry+'),
    dependencies: Array.from((block.match(/dependencies = \[([\s\S]*?)\]/)?.[1] || '').matchAll(/"([^\"]+)"/g), match => match[1])
  }));
  const selected = new Set(), visit = ['codex-cli'];
  while (visit.length) {
    const dependency = visit.pop(), parts = dependency.split(' ');
    for (const entry of packages.filter(entry => entry.name === parts[0] && (!parts[1] || entry.version === parts[1]))) {
      const key = `${entry.name}@${entry.version}`;
      if (selected.has(key)) continue;
      selected.add(key); visit.push(...entry.dependencies);
    }
  }
  const archives = packages.filter(entry => entry.registry && selected.has(`${entry.name}@${entry.version}`));
  let archiveCursor = 0;
  for (let worker = 0; worker < 24; worker++) {
    (async () => {
      for (;;) {
        const entry = archives[archiveCursor++]; if (!entry) return;
        try { await cached(`crates/${entry.name}-${entry.version}`, `https://static.crates.io/crates/${entry.name}/${entry.name}-${entry.version}.crate`); }
        catch (_) { /* Cargo reports any dependency it needs that remains unavailable. */ }
      }
    })();
  }
});
setInterval(() => console.log(`Cached public build artifacts: ${completed}; pending: ${pending.size}; local requests: ${requests}; pending keys: ${Array.from(pending.keys()).slice(0, 4).join(', ')}`), 30000);
