// Extract only build headers and x64 linker libraries from Microsoft's official SDK NuGet ZIPs.
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const http = require('node:http');
const tls = require('node:tls');
const zlib = require('node:zlib');
const root = path.resolve(__dirname, '../../.toolchain/windows-sdk');
fs.mkdirSync(root, {recursive: true});
const agent = new https.Agent({keepAlive: true, maxSockets: 32});
agent.createConnection = (options, callback) => {
  const request = http.request({host: '127.0.0.1', port: 7897, method: 'CONNECT', path: `${options.host}:443`});
  request.once('connect', (response, socket) => {
    if (response.statusCode !== 200) { socket.destroy(); callback(new Error('existing build network tunnel failed')); return; }
    callback(null, tls.connect({socket, servername: options.host}));
  });
  request.once('error', callback); request.end();
};

async function range(url, start, end) {
  if (end - start + 1 > 256 * 1024) {
    const pieces = [];
    for (let position = start; position <= end; position += 128 * 1024) pieces.push([position, Math.min(end, position + 128 * 1024 - 1)]);
    return Buffer.concat(await Promise.all(pieces.map(([first, last]) => range(url, first, last))));
  }
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      return await new Promise((resolve, reject) => {
        const request = https.get(url, {agent, headers: {Range: `bytes=${start}-${end}`}}, response => {
          if (response.statusCode !== 206) { response.resume(); reject(new Error(`SDK range HTTP ${response.statusCode}`)); return; }
          const pieces = []; response.on('data', data => pieces.push(data)); response.on('error', reject);
          response.on('end', () => {
            const data = Buffer.concat(pieces);
            data.length === end - start + 1 ? resolve(data) : reject(new Error('incomplete SDK range'));
          });
        });
        request.setTimeout(45000, () => request.destroy(new Error('SDK range timeout'))); request.on('error', reject);
      });
    } catch (error) { if (attempt === 4) throw error; }
  }
}

const pendingBlocks = new Map();
async function archiveRange(name, url, size, start, end) {
  const block = 128 * 1024, pieces = [];
  const directory = path.join(root, '.ranges', name); fs.mkdirSync(directory, {recursive: true});
  for (let index = Math.floor(start / block); index <= Math.floor(end / block); index++) {
    pieces.push((async () => {
      const key = `${name}/${index}`, file = path.join(directory, `${index}.part`);
      const first = index * block, last = Math.min(size - 1, first + block - 1);
      if (!fs.existsSync(file) || fs.statSync(file).size !== last - first + 1) {
        if (!pendingBlocks.has(key)) pendingBlocks.set(key, range(url, first, last).then(bytes => { fs.writeFileSync(file, bytes); }).finally(() => pendingBlocks.delete(key)));
        await pendingBlocks.get(key);
      }
      return fs.readFileSync(file).subarray(Math.max(0, start - first), Math.min(last + 1, end + 1) - first);
    })());
  }
  return Buffer.concat(await Promise.all(pieces));
}

const table = Array.from({length: 256}, (_, byte) => {
  for (let bit = 0; bit < 8; bit++) byte = byte & 1 ? 0xedb88320 ^ (byte >>> 1) : byte >>> 1;
  return byte >>> 0;
});
function crc32(data) { let value = 0xffffffff; for (const byte of data) value = table[(value ^ byte) & 255] ^ (value >>> 8); return (value ^ 0xffffffff) >>> 0; }
const libraries = new Set('kernel32 ntdll userenv ws2_32 dbghelp bcrypt crypt32 secur32 advapi32 shell32 ole32 oleaut32 uuid shlwapi winhttp iphlpapi user32 gdi32 comdlg32 mswsock mpr winmm powrprof version wtsapi32 psapi runtimeobject propsys wbemuuid wintrust winspool netapi32 ntdsapi cryptui setupapi cfgmgr32 comctl32 synchronization windowsapp fwpuclnt msimg32 opengl32 rpcrt4 ktmw32 avrt dwmapi'.split(' ').map(value => value + '.lib'));

async function extract(name, size) {
  const version = '10.0.26100.9169';
  const url = `https://api.nuget.org/v3-flatcontainer/${name}/${version}/${name}.${version}.nupkg`;
  const tail = await range(url, size - 65536, size - 1);
  let eocd = tail.length - 22;
  while (eocd >= 0 && tail.readUInt32LE(eocd) !== 0x06054b50) eocd--;
  if (eocd < 0) throw new Error('SDK ZIP directory missing');
  const length = tail.readUInt32LE(eocd + 12), offset = tail.readUInt32LE(eocd + 16);
  const directory = await range(url, offset, offset + length - 1);
  const entries = [];
  const sampleNames = [];
  for (let position = 0; position < directory.length;) {
    if (directory.readUInt32LE(position) !== 0x02014b50) throw new Error('Invalid SDK ZIP directory');
    const nameLength = directory.readUInt16LE(position + 28), extra = directory.readUInt16LE(position + 30), comment = directory.readUInt16LE(position + 32);
    const file = directory.toString('utf8', position + 46, position + 46 + nameLength).replaceAll('\\', '/');
    const lower = file.toLowerCase();
    if (sampleNames.length < 12) sampleNames.push(file);
    const header = /(^|\/)(um|shared|ucrt|winrt)\/.+\.(h|hpp|inl)$/.test(lower);
    const library = /(^|\/)(um|ucrt)\/x64\//.test(lower) && lower.endsWith('.lib') && (lower.includes('/ucrt/') || libraries.has(path.posix.basename(lower)));
    const windowsSdkTool = /(^|\/)bin\/(?:[^/]+\/)?x64\/[^/]+$/.test(lower);
    if (header || library || windowsSdkTool) entries.push({file, method: directory.readUInt16LE(position + 10), crc: directory.readUInt32LE(position + 16), compressed: directory.readUInt32LE(position + 20), size: directory.readUInt32LE(position + 24), offset: directory.readUInt32LE(position + 42)});
    position += 46 + nameLength + extra + comment;
  }
  if (!entries.length) throw new Error(`No matching official SDK build files: ${sampleNames.join(', ')}`);
  const score = entry => /\/ucrt\//i.test(entry.file) ? 0 : /\/shared\//i.test(entry.file) ? 1 : /\/(Windows|winnt|winbase|winuser|minwinbase|wincrypt)\.h$/i.test(entry.file) ? 2 : 3;
  entries.sort((left, right) => score(left) - score(right));
  console.log(`${name}: ${entries.length} required build files`);
  console.log(`Official SDK layout example: ${entries[0].file}`);
  let cursor = 0, done = 0;
  const timer = setInterval(() => console.log(`${name}: ${done}/${entries.length} CRC-verified files`), 30000);
  try {
    await Promise.all(Array.from({length: 32}, async () => {
      for (;;) {
        const entry = entries[cursor++]; if (!entry) return;
        const output = path.resolve(root, entry.file);
        if (!output.startsWith(root + path.sep)) throw new Error('Unsafe SDK archive path');
        if (fs.existsSync(output) && crc32(fs.readFileSync(output)) === entry.crc) { done++; continue; }
        const header = await archiveRange(name, url, size, entry.offset, entry.offset + 29);
        if (header.readUInt32LE(0) !== 0x04034b50) throw new Error('Invalid SDK local ZIP header');
        const start = entry.offset + 30 + header.readUInt16LE(26) + header.readUInt16LE(28);
        const compressed = await archiveRange(name, url, size, start, start + entry.compressed - 1);
        const bytes = entry.method === 0 ? compressed : entry.method === 8 ? zlib.inflateRawSync(compressed) : null;
        if (!bytes || bytes.length !== entry.size || crc32(bytes) !== entry.crc) throw new Error('SDK ZIP integrity failure');
        fs.mkdirSync(path.dirname(output), {recursive: true}); fs.writeFileSync(output, bytes); done++;
      }
    }));
  } finally { clearInterval(timer); }
}
(async () => {
  if (!process.argv.includes('--headers')) await extract('microsoft.windows.sdk.cpp.x64', 53001499);
  await extract('microsoft.windows.sdk.cpp', 160512239);
})().catch(error => { console.error(error.message); process.exitCode = 1; });
