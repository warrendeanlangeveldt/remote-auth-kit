// Copies shared files into the two places that can't import from outside
// their own folder: the unpacked extension and the static phone page.
//   node scripts/build.mjs           write the copies
//   node scripts/build.mjs --check   fail if a copy is out of date
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const copies = [
  ['extension/lib/relay-crypto.js', 'phone/relay-crypto.js'],
  ['node_modules/qrcode-generator/dist/qrcode.mjs', 'extension/vendor/qrcode.mjs'],
];
const check = process.argv.includes('--check');
let stale = 0;
for (const [from, to] of copies) {
  const src = join(root, from), dst = join(root, to);
  if (!existsSync(src)) {
    if (check && existsSync(dst)) continue; // dev dependency not installed; the committed copy stands
    throw new Error(`missing ${from} (run npm install)`);
  }
  const body = readFileSync(src);
  if (existsSync(dst) && readFileSync(dst).equals(body)) continue;
  if (check) { console.error(`${to} is out of date: run npm run build`); stale++; continue; }
  mkdirSync(dirname(dst), { recursive: true });
  writeFileSync(dst, body);
  console.log(`${from} -> ${to}`);
}
if (stale) process.exit(1);
