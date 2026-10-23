import { parseInput } from './lib/parse.js';
import * as engine from './lib/judge.js';
import { UI } from './i18n.js';

// The Korean page lives at kr/ and points data-root at the site root, so data,
// downloads and config resolve the same from either page.
const ROOT = new URL(document.documentElement.dataset.root || './', location.href);
const LANG = document.documentElement.lang.startsWith('ko') ? 'ko' : 'en';
const T = UI[LANG];
const at = (path) => new URL(path, ROOT).href;

const state = {
  upstream: null,
  distro: {},
  distroLoaded: false,
  status: null,
  repo: 'https://github.com/sqzer-x/php2shell-scanner',
  last: null,
};
const FAMILY_NAMES = { debian: 'Debian', ubuntu: 'Ubuntu' };
// The status.json source that feeds each distribution family's data.
const FAMILY_SOURCE = { debian: 'osv-debian', ubuntu: 'osv-ubuntu', rhel: 'redhat' };
const RHEL_IDS = ['rhel', 'centos', 'rocky', 'almalinux', 'ol', 'cloudlinux', 'eurolinux', 'amzn'];
const STALE_AFTER_MS = 3 * 24 * 3600 * 1000;
const NBSP = String.fromCharCode(0xa0);

const labels = () => (engine.verdictLabels ? engine.verdictLabels(LANG) : engine.VERDICT_LABELS);

// The empty result pane as shipped in the page, restored by Clear.
const EMPTY_RESULT = [...(document.getElementById('result')?.childNodes || [])].map((n) => n.cloneNode(true));

// ── DOM helpers ─────────────────────────────────────────────────────

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

// Engine text is plain. Command-line flags and PHP setting names inside it are
// set as code so they read as literals and never break across lines.
const LITERAL = /(--[a-z][\w-]*|\b[a-z][a-z0-9]*(?:[._][a-z0-9]+)*_[a-z0-9]+(?:[._][a-z0-9]+)*(?:=-?\d+)?)/g;
function rich(text) {
  return String(text).split(LITERAL).map((part, i) => (i % 2 ? h('code', { class: 'lit' }, part) : part));
}

// A package version with a line-break opportunity after "-" and "~" and before
// "+", so a long distribution revision can wrap between its parts and never
// inside a number. <wbr> is not copied with the text.
function breakable(text) {
  const s = String(text);
  const out = [];
  let start = 0;
  for (let i = 1; i < s.length; i++) {
    if (s[i] === '+' || s[i - 1] === '-' || s[i - 1] === '~') {
      out.push(s.slice(start, i), h('wbr'));
      start = i;
    }
  }
  out.push(s.slice(start));
  return out;
}

const COPY_ICONS = document.querySelector('.copy')?.innerHTML || '';
function cmdline(code) {
  const multi = code.includes('\n');
  const button = h('button', { class: 'copy', type: 'button', 'aria-label': T.copyCommand });
  button.innerHTML = COPY_ICONS; // static SVG markup taken from the page itself
  return h('div', { class: 'cmdline' }, h(multi ? 'pre' : 'code', { class: multi ? 'cmd multi' : 'cmd' }, code), button);
}

async function writeClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

async function copyCommand(button) {
  const code = button.closest('.cmdline')?.querySelector('.cmd');
  if (!code) return;
  if (await writeClipboard(code.textContent)) {
    const original = button.getAttribute('aria-label');
    button.classList.add('is-done');
    button.setAttribute('aria-label', T.copied);
    setTimeout(() => {
      button.classList.remove('is-done');
      button.setAttribute('aria-label', original);
    }, 1500);
  } else {
    const range = document.createRange();
    range.selectNodeContents(code);
    getSelection().removeAllRanges();
    getSelection().addRange(range);
  }
}

async function fetchOrNull(path, as) {
  try {
    const res = await fetch(at(path), { cache: 'no-cache' });
    if (!res.ok) return null;
    return as === 'text' ? await res.text() : await res.json();
  } catch {
    return null;
  }
}

const dateTime = new Intl.DateTimeFormat(T.locale, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'UTC' });
const dateOnly = new Intl.DateTimeFormat(T.locale, { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
const isDate = (iso) => typeof iso === 'string' && !Number.isNaN(Date.parse(iso));
const formatDateTime = (iso) => (isDate(iso) ? `${dateTime.format(new Date(iso))} ${T.utc}` : String(iso));
const formatDate = (iso) => (isDate(iso) ? dateOnly.format(new Date(iso)) : String(iso));
const listOf = (items) => (Intl.ListFormat ? new Intl.ListFormat(T.locale, { type: 'conjunction' }).format(items) : items.join(', '));

// ── Data freshness ──────────────────────────────────────────────────

// How current one source in status.json is. ok is true or false for the latest
// refresh, or null when status.json does not say. at is the last successful
// refresh when known: a source may report last_success, otherwise a source
// that succeeded counts as refreshed at checked_at.
function freshness(key) {
  const s = state.status?.sources?.[key];
  if (!s) return { ok: null, at: null };
  const last = isDate(s.last_success) ? s.last_success : null;
  if (s.ok) return { ok: true, at: last || (isDate(state.status.checked_at) ? state.status.checked_at : null) };
  return { ok: false, at: last };
}

// The distribution family whose data the verdict rests on, or null when it was
// judged against upstream releases only. Prefers what the engine reports, then
// the Distribution choice, then the facts in the observation.
function resultFamily(r, obs, choice) {
  // null from the engine means the verdict rests on upstream releases only.
  const reported = r.distro?.family !== undefined ? r.distro.family : r.family;
  if (typeof reported === 'string' || reported === null) return reported;
  if (choice && choice !== 'auto') return choice === 'upstream' ? null : choice.split(':')[0];
  const os = obs.os || {};
  const like = `${os.id || ''} ${os.idLike || ''}`;
  if (os.id === 'debian' || os.id === 'ubuntu') return os.id;
  if (RHEL_IDS.includes(os.id) || (/\brhel\b/.test(like) && os.id !== 'fedora')) return 'rhel';
  if (os.id) return null;
  const versions = [obs.phpVersion, ...(obs.packages || []).map((p) => p.version)].filter(Boolean).join(' ');
  if (/[~+]deb\d+u\d+/.test(versions)) return 'debian';
  if (/ubuntu/.test(versions)) return 'ubuntu';
  if (/\.el\d/.test(versions)) return 'rhel';
  return null;
}

// What the page adds to the engine's result: the data line under the verdict,
// and reasons and notes about data that did not load or is not current.
function dataContext(r, obs, choice) {
  const reasons = [...r.reasons];
  const notes = [...r.notes];
  const key = FAMILY_SOURCE[resultFamily(r, obs, choice)];
  let line = null;
  if (!key) {
    const s = state.status;
    const checked = s?.upstream_matches_advisory === true && isDate(s.checked_at);
    line = `${T.upstreamData}: ${checked ? T.crossChecked(formatDateTime(s.checked_at)) : formatDate(state.upstream.updated)}`;
  } else if (!state.distroLoaded) {
    reasons.unshift(T.distroNotLoaded);
    line = `${T.distroData}: ${T.notLoaded}`;
  } else {
    const f = freshness(key);
    const when = f.at ? formatDateTime(f.at) : null;
    if (f.ok === false) {
      line = `${T.distroData}: ${when ? T.refreshFailedSince(when) : T.refreshFailed}`;
      notes.push(T.sourceFailed(T.sourceNames[key] || key, when));
    } else if (f.ok && when) {
      line = `${T.distroData}: ${when}`;
      if (Date.now() - Date.parse(f.at) > STALE_AFTER_MS) notes.push(T.stale(when));
    } else if (isDate(state.distro.updated_at)) {
      line = `${T.distroData}: ${T.dataChanged(formatDateTime(state.distro.updated_at))}`;
    }
  }
  return { reasons, notes, line };
}

// ── Result ──────────────────────────────────────────────────────────

function block(title, ...body) {
  return h('section', { class: 'block' }, h('h4', {}, title), ...body);
}

const exposureLabel = (r) => (r.verdict === 'patched' ? T.exposurePatched : T.exposure);

function renderResult(r, obs, choice) {
  const out = document.getElementById('result');
  const sources = [...new Set(obs.sources)].map((s) => T.sources[s] || s);
  const { reasons, notes, line } = dataContext(r, obs, choice);
  const meta = [sources.length ? `${T.input}: ${sources.join(' + ')}` : null, line].filter(Boolean).join(' · ');

  const heading = h('h3', { tabindex: '-1' }, r.title);
  const parts = [h('div', { class: 'verdict', 'data-verdict': r.verdict },
    h('p', { class: 'verdict-label' }, labels()[r.verdict] || r.verdict),
    heading,
    reasons.length ? h('ul', { class: 'reasons' }, reasons.map((t) => h('li', {}, rich(t)))) : null,
    meta ? h('p', { class: 'verdict-meta' }, meta) : null)];

  const evidence = r.facts.map((f) => h('tr', {}, h('th', { scope: 'row' }, f.label), h('td', { class: 'mono' }, breakable(f.value))));
  if (r.exposure) {
    evidence.push(h('tr', {}, h('th', { scope: 'row' }, exposureLabel(r)),
      h('td', {}, h('span', { class: `badge badge-${r.exposure.level}` }, T.levels[r.exposure.level] || r.exposure.level), rich(r.exposure.text))));
  }
  if (evidence.length) parts.push(block(T.evidence, h('table', { class: 'kv' }, h('tbody', {}, evidence))));

  if (r.actions.length) {
    parts.push(block(T.actions, h('ol', { class: 'actions' }, r.actions.map((a) => h('li', {}, rich(a.text), a.code ? cmdline(a.code) : null)))));
  }

  if (r.findings?.length) {
    parts.push(block(T.indicators, h('ul', { class: 'indicators' }, r.findings.map((f) =>
      h('li', {}, h('span', { class: `badge badge-${f.level}` }, T.levels[f.level] || f.level), h('span', {}, rich(f.text)))))));
  }

  if (r.mitigations.length) {
    // On phones the value and status columns are hidden and shown under the
    // setting name instead (.mit-inline); only one of the two is ever displayed.
    const badge = (m) => h('span', { class: `badge badge-${m.status}` }, T.statuses[m.status] || m.status);
    const rows = r.mitigations.flatMap((m) => [
      h('tr', { class: 'mit-row' },
        h('td', { class: 'setting' }, h('span', { class: 'mit-name' }, m.name),
          h('span', { class: 'mit-inline' }, h('span', {}, m.value), badge(m))),
        h('td', { class: 'value' }, m.value),
        h('td', { class: 'status' }, badge(m))),
      h('tr', { class: 'mit-note' }, h('td', { colspan: '3' }, rich(m.note))),
    ]);
    const patched = r.verdict === 'patched';
    parts.push(block(patched ? T.hardening : T.mitigations,
      h('p', {}, rich(patched ? T.hardeningIntro : T.mitIntro)),
      h('table', { class: 'mit' },
        h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, T.setting), h('th', { scope: 'col' }, T.value), h('th', { scope: 'col', class: 'status' }, T.status))),
        h('tbody', {}, rows))));
  }

  if (r.advisories.length) {
    parts.push(block(T.advisories, h('table', { class: 'kv' }, h('tbody', {},
      r.advisories.map((a) => h('tr', {}, h('th', { scope: 'row' }, a.label), h('td', { class: 'mono' }, breakable(a.value))))))));
  }

  if (notes.length) parts.push(block(T.notes, h('ul', { class: 'plain' }, notes.map((t) => h('li', {}, rich(t))))));

  out.replaceChildren(...parts);
  state.last = { r, meta, reasons, notes };
  document.getElementById('copy-report').hidden = false;
  heading.focus({ preventScroll: true });
  if (matchMedia('(max-width: 75rem)').matches) {
    document.querySelector('.pane-result').scrollIntoView({ block: 'start' });
  } else {
    document.querySelector('.pane-result').scrollTop = 0;
  }
}

function resetResult() {
  document.getElementById('result').replaceChildren(...EMPTY_RESULT.map((n) => n.cloneNode(true)));
  document.getElementById('copy-report').hidden = true;
  state.last = null;
}

function reportMarkdown({ r, meta, reasons, notes }) {
  const lines = [`## ${T.reportTitle(labels()[r.verdict])}`, '', `**${r.title}**`, ''];
  for (const t of reasons) lines.push(`- ${t}`);
  if (meta) lines.push('', `_${meta}_`);
  if (r.facts.length) {
    lines.push('', `### ${T.evidence}`);
    for (const f of r.facts) lines.push(`- ${f.label}: \`${f.value}\``);
    if (r.exposure) lines.push(`- ${exposureLabel(r)}: ${T.levels[r.exposure.level] || r.exposure.level}. ${r.exposure.text}`);
  }
  if (r.actions.length) {
    lines.push('', `### ${T.actions}`);
    r.actions.forEach((a, i) => {
      lines.push(`${i + 1}. ${a.text}`);
      if (a.code) lines.push('', '   ```sh', ...a.code.split('\n').map((c) => `   ${c}`), '   ```');
    });
  }
  if (r.findings?.length) {
    lines.push('', `### ${T.indicators}`);
    for (const f of r.findings) lines.push(`- [${T.levels[f.level] || f.level}] ${f.text}`);
  }
  if (r.mitigations.length) {
    lines.push('', `### ${r.verdict === 'patched' ? T.hardening : T.mitigations}`);
    for (const m of r.mitigations) lines.push(`- \`${m.name}\` = \`${m.value}\`: ${T.statuses[m.status] || m.status}`);
  }
  if (r.advisories.length) {
    lines.push('', `### ${T.advisories}`);
    for (const a of r.advisories) lines.push(`- ${a.label}: ${a.value}`);
  }
  if (notes.length) {
    lines.push('', `### ${T.notes}`);
    for (const t of notes) lines.push(`- ${t}`);
  }
  lines.push('', T.reportFooter(state.repo, formatDateTime(new Date().toISOString())));
  return lines.join('\n') + '\n';
}

async function loadDistro() {
  const distro = await fetchOrNull('data/distro.json');
  state.distro = distro || {};
  state.distroLoaded = Boolean(distro);
}

async function runCheck(event) {
  event?.preventDefault();
  const input = document.getElementById('input');
  if (!input.value.trim()) {
    resetResult();
    input.focus();
    return;
  }
  // If the distribution data failed to load with the page, try once more
  // rather than judge without it.
  if (!state.distroLoaded) {
    await loadDistro();
    if (state.distroLoaded) renderReference();
  }
  const choice = document.getElementById('distro').value;
  const obs = parseInput(input.value, { lang: LANG });
  const result = engine.judge(obs, state.upstream, state.distro, { distro: choice, lang: LANG });
  // Download commands in the steps follow the page's own address, like the ones in step 1.
  if (engine.DEFAULT_DOWNLOADS) {
    for (const a of result.actions) if (a.code) a.code = a.code.split(engine.DEFAULT_DOWNLOADS).join(at('downloads/'));
  }
  renderResult(result, obs, choice);
}

// ── Reference ───────────────────────────────────────────────────────

function renderUpstreamTable() {
  const { fixed, eol, backport_branches: backports } = state.upstream;
  const rows = Object.entries(fixed).map(([branch, version]) => h('tr', {},
    h('th', { scope: 'row' }, `PHP${NBSP}${branch}`),
    h('td', { class: 'mono' }, `< ${version}`),
    h('td', { class: 'mono' }, version, eol?.[branch] ? h('span', { class: 'dim eol' }, T.eol(formatDate(eol[branch]))) : null)));
  const branches = Object.keys(backports || {});
  rows.push(h('tr', {}, h('th', { scope: 'row' }, T.branch81), h('td', {}, T.all54), h('td', {}, T.noUpstream(branches.length ? listOf(branches) : null))));
  document.querySelector('#upstream-table tbody').replaceChildren(...rows);
}

// A fixed version from distro.json: a version string, null when the
// distribution tracks the CVE without a fix yet, or missing when there is no
// record for it, which the engine treats as no data rather than as pending.
function fixedValue(value) {
  if (typeof value === 'string') return breakable(value);
  return value === null
    ? h('span', { class: 'badge badge-pending' }, T.fixPending)
    : h('span', { class: 'badge badge-unknown' }, T.noData);
}

function fixedCell(entry, cves) {
  const values = cves.map((c) => entry.fixed?.[c]);
  if (values.every((v) => v === values[0])) {
    return h('td', { class: typeof values[0] === 'string' ? 'mono ver' : null }, fixedValue(values[0]));
  }
  return h('td', { class: 'mono ver' }, cves.map((c, i) =>
    h('span', { class: 'ver-line' }, `${c.replace(/^CVE-\d{4}-/, '')}:${NBSP}`, fixedValue(values[i]))));
}

const sortedReleases = (family) => Object.entries(state.distro[family] || {}).sort(([a], [b]) => parseFloat(b) - parseFloat(a));

function renderDistroTables() {
  const cves = state.upstream.cves.map((c) => c.id);
  const rows = [];
  for (const family of ['debian', 'ubuntu']) {
    for (const [release, rel] of sortedReleases(family)) {
      for (const [pkg, entry] of Object.entries(rel.packages || {})) {
        rows.push(h('tr', {},
          h('th', { scope: 'row' }, `${FAMILY_NAMES[family]} ${release}`, rel.codename ? h('span', { class: 'dim' }, ` ${rel.codename}`) : null,
            entry.pro ? h('span', { class: 'badge badge-info', title: T.proTitle }, 'Pro') : null),
          h('td', { class: 'mono' }, pkg),
          fixedCell(entry, cves)));
      }
    }
  }
  if (!rows.length) rows.push(h('tr', {}, h('td', { colspan: '3' }, T.distroFailed)));
  document.querySelector('#distro-table tbody').replaceChildren(...rows);

  const rh = Object.entries(state.distro.redhat || {}).sort(([a], [b]) => Number(b) - Number(a));
  const rhRows = [];
  for (const [rel, v] of rh) {
    const seen = new Set();
    const items = [];
    for (const a of v.advisories || []) {
      const key = `${a.advisory} ${a.package}`;
      if (!seen.has(key)) { seen.add(key); items.push(`${a.advisory}  ${a.package}`); }
    }
    for (const s of v.states || []) {
      const key = `${s.package} ${s.state}`;
      if (!seen.has(key)) { seen.add(key); items.push(`${s.package}: ${s.state}`); }
    }
    items.forEach((item, i) => rhRows.push(h('tr', {}, i === 0 ? h('th', { scope: 'row', rowspan: String(items.length) }, `RHEL ${rel}`) : null, h('td', {}, item))));
  }
  document.getElementById('redhat-list').replaceChildren(...(rhRows.length
    ? [h('p', { class: 'rh-intro' }, T.rhIntro), h('table', { class: 'rh' }, h('tbody', {}, rhRows))]
    : [h('p', { class: 'rh-intro' }, T.rhFailed)]));
}

function renderDataStatus() {
  const s = state.status;
  const edited = formatDate(state.upstream.updated);
  const parts = [];
  if (!s) parts.push(T.statusUpstream(edited));
  else if (s.upstream_matches_advisory === true && isDate(s.checked_at)) parts.push(T.statusUpstreamChecked(formatDateTime(s.checked_at)));
  else if (s.upstream_matches_advisory === false) parts.push(T.statusUpstreamMismatch(edited));
  else parts.push(T.statusUpstreamUnchecked(edited));

  if (!state.distroLoaded) parts.push(T.statusDistroMissing);
  else if (isDate(state.distro.updated_at)) {
    parts.push(T.statusDistro(formatDateTime(state.distro.updated_at), isDate(s?.checked_at) ? formatDateTime(s.checked_at) : null));
  }
  // The php-src advisories only cross-check upstream.json; the line above covers them.
  const failed = Object.entries(s?.sources || {}).filter(([k, v]) => k !== 'ghsa' && v && !v.ok);
  const name = (k) => T.sourceNames[k] || k;
  if (failed.length) parts.push(T.statusFailed(listOf(failed.map(([k]) => name(k)))));
  for (const [k, v] of failed) {
    if (isDate(v.last_success)) parts.push(T.statusLastSuccess(name(k), formatDateTime(v.last_success)));
  }
  document.getElementById('data-status').textContent = parts.join(' ');
}

function fillDistroSelect() {
  const select = document.getElementById('distro');
  const chosen = select.value;
  select.replaceChildren(select.options[0]);
  for (const family of ['debian', 'ubuntu']) {
    const releases = sortedReleases(family);
    if (!releases.length) continue;
    select.append(h('optgroup', { label: FAMILY_NAMES[family] },
      releases.map(([release, rel]) => h('option', { value: `${family}:${release}` }, `${FAMILY_NAMES[family]} ${release}${rel.codename ? ` (${rel.codename})` : ''}`))));
  }
  const rh = Object.keys(state.distro.redhat || {}).sort((a, b) => Number(b) - Number(a));
  if (rh.length) select.append(h('optgroup', { label: T.rhelFamily }, rh.map((rel) => h('option', { value: `rhel:${rel}` }, T.rhelOption(rel)))));
  select.append(h('option', { value: 'upstream' }, T.upstreamOption));
  select.value = chosen;
  if (select.value !== chosen) select.value = 'auto';
}

function renderReference() {
  renderUpstreamTable();
  renderDistroTables();
  renderDataStatus();
  fillDistroSelect();
}

// ── Page wiring ─────────────────────────────────────────────────────

function setupTabs() {
  const tabs = [...document.querySelectorAll('.tab')];
  const select = (tab, focus) => {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute('aria-controls')).hidden = !on;
    }
    if (focus) tab.focus();
  };
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => select(tab));
    tab.addEventListener('keydown', (e) => {
      const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[e.key];
      if (next === undefined) return;
      e.preventDefault();
      select(tabs[(next + tabs.length) % tabs.length], true);
    });
  });
}

function setupDownloads(sums) {
  const base = at('downloads/');
  for (const code of document.querySelectorAll('.cmd[data-download]')) {
    const then = code.dataset.then;
    code.textContent = `curl -fsSLO ${base}${code.dataset.download}${then ? ` && ${then}` : ''}`;
  }
  for (const line of (sums || '').split('\n')) {
    const m = /^([0-9a-f]{64})\s+\*?(\S+)$/.exec(line.trim());
    const el = m && document.querySelector(`[data-sha-for="${m[2]}"]`);
    if (el) el.textContent = `sha256 ${m[1]}`;
  }
}

function setupRepoLinks(config) {
  if (!config?.repository) return;
  state.repo = config.repository;
  for (const a of document.querySelectorAll('#repo-link, .repo-link')) a.href = config.repository;
}

// ── Examples ────────────────────────────────────────────────────────

function probeOutput(report) {
  const full = {
    tool: 'php2shell-selfcheck', tool_version: '1.0.0', schema: 1, generated_at: '2026-10-23T01:00:00Z',
    php_os: 'Linux', container: false, extensions: { session: true, opcache: true }, self_deleted: true, ...report,
  };
  return `php2shell-selfcheck 1.0.0\n\n-----BEGIN PHP2SHELL SELFCHECK-----\n${JSON.stringify(full, null, 2)}\n-----END PHP2SHELL SELFCHECK-----\n`;
}

const UBUNTU_2204 = { PRETTY_NAME: 'Ubuntu 22.04.5 LTS', VERSION_ID: '22.04', VERSION_CODENAME: 'jammy', ID: 'ubuntu', ID_LIKE: 'debian' };
const DEFAULT_INI = {
  memory_limit: '128M', post_max_size: '8M', max_input_nesting_level: '64',
  'session.upload_progress.enabled': '1', 'session.auto_start': '0', expose_php: '1',
};
const UBUNTU_PACKAGES = [
  { name: 'libapache2-mod-php8.1', version: '8.1.2-1ubuntu2.28', source: 'php8.1' },
  { name: 'php8.1-common', version: '8.1.2-1ubuntu2.28', source: 'php8.1' },
];

const EXAMPLES = {
  backport: probeOutput({
    php_version: '8.1.2-1ubuntu2.28', sapi: 'apache2handler', config_path: '/etc/php/8.1/apache2',
    server_software: 'Apache/2.4.52 (Ubuntu)', os_release: UBUNTU_2204, dpkg_packages: UBUNTU_PACKAGES,
    ini: { ...DEFAULT_INI, expose_php: '' },
  }),
  restart: probeOutput({
    php_version: '8.1.2-1ubuntu2.20', sapi: 'apache2handler', config_path: '/etc/php/8.1/apache2',
    server_software: 'Apache/2.4.52 (Ubuntu)', os_release: UBUNTU_2204, dpkg_packages: UBUNTU_PACKAGES, ini: DEFAULT_INI,
  }),
  docker: probeOutput({
    php_version: '8.3.12', sapi: 'apache2handler', config_path: '/usr/local/etc/php',
    server_software: 'Apache/2.4.62 (Debian)', container: true,
    os_release: { PRETTY_NAME: 'Debian GNU/Linux 12 (bookworm)', VERSION_ID: '12', VERSION_CODENAME: 'bookworm', ID: 'debian' },
    dpkg_packages: [], ini: DEFAULT_INI,
  }),
  rhel: `php2shell-server-check 1.0.0
-----BEGIN PHP2SHELL SERVERCHECK-----
tool|php2shell-server-check|1.0.0
os|ID|almalinux
os|ID_LIKE|rhel centos fedora
os|VERSION_ID|9.8
os|PRETTY_NAME|AlmaLinux 9.8 (Olive Jaguar)
pkg|rpm|php-common|8.0.30-8.el9_8.1|
pkg|rpm|php-fpm|8.0.30-8.el9_8.1|
changelog|php-common|CVE-2026-109618|1
changelog|php-common|CVE-2026-109619|1
proc|php-fpm|1|ok
webuser_proc|0
log|oom|0
log|crash|0
log|bigsession|0
-----END PHP2SHELL SERVERCHECK-----
`,
};
const EXAMPLE_TEXTS = new Set(Object.values(EXAMPLES));

// Choosing an example only selects it; Load replaces the input and runs the
// check. Pasted output is never replaced without asking, because the probe
// has already deleted itself and cannot simply be run again.
function loadExample() {
  const example = document.getElementById('example');
  const input = document.getElementById('input');
  const text = EXAMPLES[example.value];
  if (!text) {
    example.focus();
    return;
  }
  if (input.value.trim() && !EXAMPLE_TEXTS.has(input.value) && !confirm(T.replaceConfirm)) return;
  input.value = text;
  example.value = '';
  document.getElementById('distro').value = 'auto';
  runCheck();
}

// ── Start ───────────────────────────────────────────────────────────

async function init() {
  setupTabs();
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.copy');
    if (btn) copyCommand(btn);
  });

  const [upstream, distro, status, config, sums] = await Promise.all([
    fetchOrNull('data/upstream.json'),
    fetchOrNull('data/distro.json'),
    fetchOrNull('data/status.json'),
    fetchOrNull('config.json'),
    fetchOrNull('downloads/SHA256SUMS', 'text'),
  ]);
  setupDownloads(sums);
  setupRepoLinks(config);

  if (!upstream) {
    document.getElementById('result').replaceChildren(h('div', { class: 'verdict', 'data-verdict': 'unknown' },
      h('h3', {}, T.loadFailedTitle), h('ul', { class: 'reasons' }, h('li', {}, T.loadFailedBody))));
    return;
  }
  state.upstream = upstream;
  state.distro = distro || {};
  state.distroLoaded = Boolean(distro);
  state.status = status;
  renderReference();

  const input = document.getElementById('input');
  document.getElementById('check-form').addEventListener('submit', runCheck);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) runCheck(e);
  });
  document.getElementById('clear').addEventListener('click', () => {
    input.value = '';
    document.getElementById('example').value = '';
    resetResult();
    input.focus();
  });
  document.getElementById('load-example').addEventListener('click', loadExample);
  const copyReport = document.getElementById('copy-report');
  copyReport.addEventListener('click', async () => {
    if (!state.last) return;
    const ok = await writeClipboard(reportMarkdown(state.last));
    copyReport.textContent = ok ? T.copied : T.copyFailed;
    setTimeout(() => { copyReport.textContent = T.copyReport; }, 1500);
  });
}

init();
