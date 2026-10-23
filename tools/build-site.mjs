#!/usr/bin/env node
// Assemble the deployable site into _site/: the static page from site/, the
// two server-side files under downloads/ with a SHA256SUMS file, and
// config.json pointing at the source repository. The deploy workflow and
// `npm run serve` both use this, so a local preview matches production.

import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const ROOT = new URL('..', import.meta.url);
const OUT = new URL('_site/', ROOT);
const DOWNLOADS = [
  ['check/php2shell-selfcheck.php', 'php2shell-selfcheck.php'],
  ['scripts/php2shell-server-check.sh', 'php2shell-server-check.sh'],
];

const server = process.env.GITHUB_SERVER_URL || 'https://github.com';
const repository = process.env.GITHUB_REPOSITORY || 'sqzer-x/php2shell-scanner';

await rm(OUT, { recursive: true, force: true });
await cp(new URL('site/', ROOT), OUT, { recursive: true });
await mkdir(new URL('downloads/', OUT), { recursive: true });

const sums = [];
for (const [from, name] of DOWNLOADS) {
  const data = await readFile(new URL(from, ROOT));
  await writeFile(new URL(`downloads/${name}`, OUT), data);
  sums.push(`${createHash('sha256').update(data).digest('hex')}  ${name}`);
}
await writeFile(new URL('downloads/SHA256SUMS', OUT), sums.join('\n') + '\n');
await writeFile(new URL('config.json', OUT), JSON.stringify({ repository: `${server}/${repository}` }) + '\n');

console.log(`Built _site/ (${DOWNLOADS.length} downloads, repository ${server}/${repository})`);
