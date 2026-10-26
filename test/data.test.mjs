// The live data file site/data/distro.json is refreshed every six hours, so these tests check only its shape and
// that the engine reads every release in it, in both languages. The verdict tests run against a frozen copy
// (fixtures/distro-snapshot.json), so a data refresh never fails the build on its own.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseInput } from '../site/lib/parse.js';
import { judge, VERDICT_TITLES } from '../site/lib/judge.js';

const upstream = JSON.parse(readFileSync(new URL('../site/data/upstream.json', import.meta.url), 'utf8'));
const distro = JSON.parse(readFileSync(new URL('../site/data/distro.json', import.meta.url), 'utf8'));

const CVES = upstream.cves.map((c) => c.id);
const VERDICTS = Object.keys(VERDICT_TITLES);
const LEFTOVER = /\{\w+\}|undefined|NaN|\[object /;
const probe = (fields) => `-----BEGIN PHP2SHELL SELFCHECK-----\n${JSON.stringify({ tool: 'php2shell-selfcheck', tool_version: '1.0.0', schema: 1, ...fields })}\n-----END PHP2SHELL SELFCHECK-----\n`;
const server = (lines) => `-----BEGIN PHP2SHELL SERVERCHECK-----\n${['tool|php2shell-server-check|1.0.0', ...lines].join('\n')}\n-----END PHP2SHELL SERVERCHECK-----\n`;
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const text = (r) => [...r.reasons, ...r.notes, ...r.actions.map((a) => `${a.text} ${a.code || ''}`)].join('\n');

// Judges input in both languages and returns the English result.
function check(input, where) {
  const [en, ko] = ['en', 'ko'].map((lang) => judge(parseInput(input, { lang }), upstream, distro, { lang }));
  for (const [lang, r] of [['en', en], ['ko', ko]]) {
    assert.ok(VERDICTS.includes(r.verdict), `${where} (${lang}): ${r.verdict}`);
    assert.ok(r.reasons.length, `${where} (${lang})`);
    assert.doesNotMatch(text(r), LEFTOVER, `${where} (${lang})`);
  }
  assert.equal(ko.verdict, en.verdict, where);
  return en;
}

test('distro.json has the schema, the date and the three sources', () => {
  assert.equal(distro.schema, 1);
  assert.ok(!Number.isNaN(Date.parse(distro.updated_at)), distro.updated_at);
  for (const key of ['debian', 'ubuntu', 'redhat', 'redhat_notes']) assert.ok(isObject(distro[key]), key);
  assert.ok(Object.keys(distro.debian).length && Object.keys(distro.ubuntu).length && Object.keys(distro.redhat).length);
});

test('Debian and Ubuntu releases list packages with a fixed version or null for known CVEs', () => {
  for (const family of ['debian', 'ubuntu']) {
    for (const [release, rel] of Object.entries(distro[family])) {
      const where = `${family} ${release}`;
      assert.ok(rel.codename === null || typeof rel.codename === 'string', where);
      assert.ok(isObject(rel.packages) && Object.keys(rel.packages).length, where);
      for (const [name, pkg] of Object.entries(rel.packages)) {
        assert.equal(typeof pkg.pro, 'boolean', `${where} ${name}`);
        assert.ok(isObject(pkg.fixed) && Object.keys(pkg.fixed).length, `${where} ${name}`);
        for (const [cve, fixed] of Object.entries(pkg.fixed)) {
          assert.ok(CVES.includes(cve), `${where} ${name} ${cve}`);
          assert.ok(fixed === null || (typeof fixed === 'string' && fixed.length), `${where} ${name} ${cve}`);
        }
      }
    }
  }
});

test('Red Hat releases list advisories and package states for known CVEs', () => {
  for (const [release, rel] of Object.entries(distro.redhat)) {
    assert.ok(Array.isArray(rel.advisories) && Array.isArray(rel.states), `RHEL ${release}`);
    for (const a of rel.advisories) {
      assert.ok(CVES.includes(a.cve), `RHEL ${release} ${a.cve}`);
      assert.ok(typeof a.advisory === 'string' && typeof a.package === 'string', `RHEL ${release} ${a.advisory}`);
    }
    for (const s of rel.states) {
      assert.ok(CVES.includes(s.cve), `RHEL ${release} ${s.cve}`);
      assert.ok(typeof s.package === 'string' && typeof s.state === 'string', `RHEL ${release} ${s.state}`);
    }
  }
  for (const [cve, note] of Object.entries(distro.redhat_notes)) {
    assert.ok(CVES.includes(cve), cve);
    assert.ok(isObject(note), cve);
  }
});

test('the engine reads every Debian and Ubuntu release, and never calls an old package patched', () => {
  for (const family of ['debian', 'ubuntu']) {
    for (const [release, rel] of Object.entries(distro[family])) {
      for (const name of Object.keys(rel.packages)) {
        const branch = name.replace(/^php/, '');
        const r = check(probe({
          php_version: branch === '5' ? '5.5.9' : `${branch}.0`,
          sapi: 'fpm-fcgi',
          os_release: { ID: family, VERSION_ID: release, ...(rel.codename ? { VERSION_CODENAME: rel.codename } : {}) },
          dpkg_packages: [{ name: `${name}-common`, version: '0.1-1', source: name }],
        }), `${family} ${release} ${name}`);
        assert.notEqual(r.verdict, 'patched', `${family} ${release} ${name}`);
      }
    }
  }
});

test('the engine reads every Red Hat release', () => {
  for (const release of Object.keys(distro.redhat)) {
    check(server([
      'env|root|1', 'os|ID|rhel', 'os|ID_LIKE|fedora', `os|VERSION_ID|${release}`,
      `pkg|rpm|php-common|0.1-1.el${release}|`, ...CVES.map((cve) => `changelog|php-common|${cve}|0`), 'proc|php-fpm|4|ok',
    ]), `RHEL ${release}`);
  }
});
