// Download Rust artifacts in verified ranges when the local network stalls on large transfers.
// Every result must match the SHA-256 in the official Rust release manifest.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const https = require('node:https');

const root = path.resolve(__dirname, '../../.toolchain');
const manifest = fs.readFileSync(path.join(root, 'channel-rust-1.95.0.toml'), 'utf8');
const digest = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

function request(url, start, end) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { Range: `bytes=${start}-${end}` } }, res => {
      if ([301, 302, 307, 308].includes(res.statusCode)) {
        res.resume();
        request(new URL(res.headers.location, url).href, start, end).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 206) { res.resume(); reject(new Error(`range HTTP ${res.statusCode}`)); return; }
      const buffers = [];
      let length = 0;
      res.on('data', data => { buffers.push(data); length += data.length; });
      res.on('end', () => length === end - start + 1 ? resolve(Buffer.concat(buffers)) : reject(new Error('incomplete range')));
      res.on('error', reject);
    });
    req.setTimeout(45000, () => req.destroy(new Error('range timeout')));
    req.on('error', reject);
  });
}

async function component(name, target) {
  const escaped = target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const section = manifest.match(new RegExp(`^\\[pkg\\.${name}\\.target\\."?${escaped}"?\\]\\r?\\n([\\s\\S]*?)(?=^\\[|$(?![\\s\\S]))`, 'm'))?.[1];
  if (!section) throw new Error(`missing official manifest section ${name}`);
  const url = section.match(/xz_url = "([^"]+)"/)[1];
  const hash = section.match(/xz_hash = "([^"]+)"/)[1];
  const cache = path.join(root, 'rustup/downloads', hash);
  if (fs.existsSync(cache) && digest(cache) === hash) { console.log(`Cached and verified: ${name}`); return; }
  let sizeResponse;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      sizeResponse = await new Promise((resolve, reject) => {
        const req = https.request(url, {method: 'HEAD'}, resolve);
        req.setTimeout(45000, () => req.destroy(new Error('artifact HEAD timeout')));
        req.on('error', reject); req.end();
      });
      break;
    } catch (error) { if (attempt === 4) throw error; }
  }
  const size = Number(sizeResponse.headers['content-length']); sizeResponse.resume();
  if (!size) throw new Error(`missing artifact size ${name}`);
  const parts = path.join(root, `ranges-${name}`); fs.mkdirSync(parts, {recursive: true});
  const block = 256 * 1024;
  const count = Math.ceil(size / block);
  let cursor = 0, done = 0;
  const progress = setInterval(() => console.log(`${name}: ${done}/${count} verified-length ranges`), 30000);
  try {
    await Promise.all(Array.from({length: 32}, async () => {
      for (;;) {
        const index = cursor++; if (index >= count) return;
        const start = index * block, end = Math.min(size - 1, start + block - 1);
        const file = path.join(parts, `${index}.part`);
        if (!fs.existsSync(file) || fs.statSync(file).size !== end - start + 1) {
          let data;
          for (let attempt = 0; attempt < 4; attempt++) {
            try { data = await request(url, start, end); break; }
            catch (error) { if (attempt === 3) throw error; }
          }
          fs.writeFileSync(file, data);
        }
        done++;
      }
    }));
    const output = path.join(root, `${name}-verified.tar.xz`);
    const descriptor = fs.openSync(output, 'w');
    try { for (let index = 0; index < count; index++) fs.writeSync(descriptor, fs.readFileSync(path.join(parts, `${index}.part`))); }
    finally { fs.closeSync(descriptor); }
    if (digest(output) !== hash) throw new Error(`official checksum mismatch: ${name}`);
    fs.copyFileSync(output, cache);
    console.log(`Official checksum verified: ${name}`);
  } finally { clearInterval(progress); }
}

(async () => {
  for (const name of ['rustc', 'rust-std', 'rust-src', 'cargo', 'clippy-preview', 'rustfmt-preview', 'rust-docs']) {
    await component(name, name === 'rust-src' ? '*' : 'x86_64-pc-windows-msvc');
  }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
