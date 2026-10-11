import { build } from 'vite';
import { readFile, writeFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';

await build();

const dist = resolve('dist');
const index = resolve(dist, 'index.html');
let html = await readFile(index, 'utf8');
const scriptTag = html.match(/<script\b[^>]*type="module"[^>]*src="\.\/([^"]+)"[^>]*><\/script>/);
const cssTag = html.match(/<link\b[^>]*rel="stylesheet"[^>]*href="\.\/([^"]+)"[^>]*>/);
if (!scriptTag || !cssTag) throw new Error('Vite output did not contain the expected JavaScript and CSS assets.');

const [js, css] = await Promise.all([
  readFile(resolve(dist, scriptTag[1]), 'utf8'),
  readFile(resolve(dist, cssTag[1]), 'utf8'),
]);
html = html.replace(cssTag[0], () => `<style>${css.replace(/<\/style/gi, '<\\/style')}</style>`);
html = html.replace(scriptTag[0], () => `<script type="module">${js.replace(/<\/script/gi, '<\\/script')}</script>`);
await writeFile(index, html, 'utf8');
const output = await stat(index);
console.log(`Self-contained browser preview: ${index} (${(output.size / 1024).toFixed(1)} KiB)`);
