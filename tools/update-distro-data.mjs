#!/usr/bin/env node
// Fetches distribution security data and writes it to site/data/distro.json.
//
// Sources
//   - OSV: fixed versions per package for Debian and Ubuntu (https://osv.dev)
//   - Red Hat Security Data API: RHEL advisories (RHSA) and package states
//   - php-src GitHub security advisories: checks that the fixed versions match upstream.json
//
// - distro.json is rewritten only when its content changes (commit history = data change history).
// - status.json is written on every run (last check time, success per source). It is not committed.
// - If one source fails, its previous data is kept as is and the failure is recorded.
// - A 404 means "no record yet", which is normal before a distribution publishes anything.
//   But if the previous distro.json has entries for that CVE, a 404 is treated as a fault
//   on the source side: the previous entries for that CVE are kept, and the source is
//   recorded as failed in status.json with the CVEs in kept_previous. To accept a record
//   that really was withdrawn, delete its entries from distro.json by hand.
// - If the fixed versions in the official advisories differ from upstream.json, exit with code 1 (a person must check).

import { readFile, writeFile } from 'node:fs/promises';

const ROOT = new URL('..', import.meta.url);
const UPSTREAM_FILE = new URL('site/data/upstream.json', ROOT);
const DISTRO_FILE = new URL('site/data/distro.json', ROOT);
const STATUS_FILE = new URL('site/data/status.json', ROOT);

const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';

// Print a warning, and in GitHub Actions also an annotation on the run.
function warn(message) {
  console.error(message);
  if (process.env.GITHUB_ACTIONS === 'true') console.log(`::warning::${message.replace(/\s+/g, ' ')}`);
}

// Returns null on 404 (no record).
async function getJson(url, headers = {}) {
  const res = await fetch(url, {
    headers: { accept: 'application/json', 'user-agent': 'php2shell-scanner-data-updater', ...headers },
    signal: AbortSignal.timeout(30_000),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

async function readJson(file, fallback) {
  try {
    return JSON.parse(await readFile(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function purlCodename(purl) {
  const query = String(purl || '').split('?')[1] || '';
  const distro = new URLSearchParams(query).get('distro') || '';
  return distro.split('/').pop() || null;
}

function addOsv(target, family, cve, record) {
  const prefix = family === 'debian' ? 'Debian' : 'Ubuntu';
  for (const a of record?.affected || []) {
    const parts = String(a.package?.ecosystem || '').split(':');
    if (parts[0] !== prefix) continue;
    const pro = parts[1] === 'Pro';
    const release = pro ? parts[2] : parts[1];
    if (!release || !a.package?.name) continue;
    const codename = purlCodename(a.package.purl);
    const rel = (target[release] ||= { codename, packages: {} });
    if (!rel.codename && codename) rel.codename = codename;
    const pkg = (rel.packages[a.package.name] ||= { pro, fixed: {} });
    pkg.pro = pkg.pro && pro;
    const fixed = (a.ranges || []).flatMap((range) => range.events || []).find((e) => e.fixed);
    pkg.fixed[cve] = fixed ? fixed.fixed : null;
  }
}

// The record for cve returned 404. Copy that CVE's entries from the previous data
// into target. Returns true if there were any, that is, the record existed before.
function keepOsv(target, previous, cve) {
  let found = false;
  for (const [release, prevRel] of Object.entries(previous || {})) {
    for (const [name, prevPkg] of Object.entries(prevRel?.packages || {})) {
      if (!Object.hasOwn(prevPkg?.fixed || {}, cve)) continue;
      found = true;
      const rel = (target[release] ||= { codename: prevRel.codename ?? null, packages: {} });
      if (!rel.codename && prevRel.codename) rel.codename = prevRel.codename;
      const pkg = (rel.packages[name] ||= { pro: prevPkg.pro === true, fixed: {} });
      pkg.pro = pkg.pro && prevPkg.pro === true;
      pkg.fixed[cve] = prevPkg.fixed[cve];
    }
  }
  return found;
}

async function fetchOsv(family, list, previous, kept) {
  const out = {};
  for (const c of list) {
    const record = await getJson(`https://api.osv.dev/v1/vulns/${family.toUpperCase()}-${c.id}`);
    if (record) addOsv(out, family, c.id, record);
    else if (keepOsv(out, previous, c.id)) kept.push(c.id);
  }
  return out;
}

function addRedhat(target, notes, cve, record) {
  if (!record) return;
  notes[cve] = {
    severity: record.threat_severity || null,
    cvss3: record.cvss3?.cvss3_base_score || null,
    statement: record.statement || null,
  };
  const relOf = (cpe) => /enterprise_linux:(\d+)/.exec(cpe || '')?.[1];
  for (const a of record.affected_release || []) {
    const rel = relOf(a.cpe);
    if (!rel) continue;
    (target[rel] ||= { advisories: [], states: [] }).advisories.push({ cve, advisory: a.advisory, package: a.package });
  }
  for (const s of record.package_state || []) {
    const rel = relOf(s.cpe);
    if (!rel) continue;
    (target[rel] ||= { advisories: [], states: [] }).states.push({ cve, package: s.package_name, state: s.fix_state });
  }
}

// Same as keepOsv, for the Red Hat releases and notes.
function keepRedhat(releases, notes, previous, previousNotes, cve) {
  let found = false;
  if (previousNotes && Object.hasOwn(previousNotes, cve)) {
    notes[cve] = previousNotes[cve];
    found = true;
  }
  for (const [rel, prev] of Object.entries(previous || {})) {
    const advisories = (prev?.advisories || []).filter((a) => a.cve === cve);
    const states = (prev?.states || []).filter((s) => s.cve === cve);
    if (!advisories.length && !states.length) continue;
    found = true;
    const target = (releases[rel] ||= { advisories: [], states: [] });
    target.advisories.push(...advisories);
    target.states.push(...states);
  }
  return found;
}

// fn(kept) returns the source's data, and pushes onto kept every CVE whose record
// returned 404 although the previous data had entries for it. Such a source still
// counts as failed: part of its data is not current.
async function fetchSource(name, fn) {
  const kept = [];
  try {
    const data = await fn(kept);
    if (!kept.length) return { ok: true, data };
    const error = `no record any more for ${kept.join(', ')} (HTTP 404); the previous entries were kept`;
    warn(`[${name}] ${error}`);
    return { ok: false, data, error, kept };
  } catch (err) {
    warn(`[${name}] failed: ${err.message}`);
    return { ok: false, error: err.message };
  }
}

function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortDeep(value[k])]));
  }
  return value;
}

const byKey = (...keys) => (a, b) => {
  for (const k of keys) {
    const c = String(a[k]).localeCompare(String(b[k]));
    if (c) return c;
  }
  return 0;
};

async function main() {
  const upstream = JSON.parse(await readFile(UPSTREAM_FILE, 'utf8'));
  const previous = await readJson(DISTRO_FILE, {});
  const cves = upstream.cves;

  const sources = {
    'osv-debian': await fetchSource('osv-debian', (kept) => fetchOsv('debian', cves, previous.debian, kept)),
    'osv-ubuntu': await fetchSource('osv-ubuntu', (kept) => fetchOsv('ubuntu', cves, previous.ubuntu, kept)),
    redhat: await fetchSource('redhat', async (kept) => {
      const releases = {};
      const notes = {};
      for (const c of cves) {
        const record = await getJson(`https://access.redhat.com/hydra/rest/securitydata/cve/${c.id}.json`);
        if (record) addRedhat(releases, notes, c.id, record);
        else if (keepRedhat(releases, notes, previous.redhat, previous.redhat_notes, c.id)) kept.push(c.id);
      }
      for (const rel of Object.values(releases)) {
        rel.advisories.sort(byKey('cve', 'advisory', 'package'));
        rel.states.sort(byKey('cve', 'package'));
      }
      return { releases, notes };
    }),
    ghsa: await fetchSource('ghsa', async () => {
      const out = {};
      const auth = GITHUB_TOKEN ? { authorization: `Bearer ${GITHUB_TOKEN}` } : {};
      for (const c of cves) {
        const g = await getJson(`https://api.github.com/repos/php/php-src/security-advisories/${c.ghsa}`, auth);
        if (!g) throw new Error(`advisory ${c.ghsa} not found`);
        out[c.id] = {};
        for (const v of g.vulnerabilities || []) {
          const branch = /^(\d+\.\d+)\./.exec(v.patched_versions || '')?.[1];
          if (branch) out[c.id][branch] = v.patched_versions;
        }
      }
      return out;
    }),
  };

  // A source with data (fully fresh, or fresh with some CVEs kept from before) replaces the
  // previous data. A source that failed outright leaves the previous data as it was.
  const pick = (name, fresh, old) => (sources[name].data !== undefined ? fresh : old);
  const content = sortDeep({
    schema: 1,
    debian: pick('osv-debian', sources['osv-debian'].data, previous.debian || {}),
    ubuntu: pick('osv-ubuntu', sources['osv-ubuntu'].data, previous.ubuntu || {}),
    redhat: pick('redhat', sources.redhat.data?.releases, previous.redhat || {}),
    redhat_notes: pick('redhat', sources.redhat.data?.notes, previous.redhat_notes || {}),
  });

  const { updated_at: _ignored, ...previousContent } = previous;
  const changed = JSON.stringify(sortDeep(previousContent)) !== JSON.stringify(content);
  const now = new Date().toISOString();
  if (changed) {
    await writeFile(DISTRO_FILE, JSON.stringify({ updated_at: now, ...content }, null, 2) + '\n');
    console.log('distro.json updated');
  } else {
    console.log('distro.json unchanged');
  }

  let exitCode = 0;
  const mismatches = [];
  if (sources.ghsa.ok) {
    for (const [cve, fixed] of Object.entries(sources.ghsa.data)) {
      const branches = new Set([...Object.keys(fixed), ...Object.keys(upstream.fixed)]);
      for (const b of branches) {
        if (fixed[b] !== upstream.fixed[b]) mismatches.push(`${cve} ${b}: official advisory ${fixed[b] ?? 'none'} / upstream.json ${upstream.fixed[b] ?? 'none'}`);
      }
    }
  }
  if (mismatches.length) {
    console.error('The fixed versions in the official advisories differ from upstream.json. Check upstream.json:\n  ' + mismatches.join('\n  '));
    exitCode = 1;
  }

  const status = {
    checked_at: now,
    data_updated_at: changed ? now : previous.updated_at || null,
    upstream_matches_advisory: sources.ghsa.ok ? mismatches.length === 0 : null,
    sources: Object.fromEntries(Object.entries(sources).map(([k, v]) => [
      k,
      v.ok ? { ok: true } : { ok: false, error: v.error, ...(v.kept ? { kept_previous: v.kept } : {}) },
    ])),
  };
  await writeFile(STATUS_FILE, JSON.stringify(status, null, 2) + '\n');

  const failed = Object.entries(sources).filter(([, v]) => v.data === undefined).map(([k]) => k);
  if (failed.length === Object.keys(sources).length) {
    console.error('No data could be fetched from any source.');
    exitCode = 1;
  }
  process.exitCode = exitCode;
}

await main();
