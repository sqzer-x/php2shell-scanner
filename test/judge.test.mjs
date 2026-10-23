import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseInput } from '../site/lib/parse.js';
import { judge, VERDICT_TITLES, VERDICT_LABELS } from '../site/lib/judge.js';

const upstream = JSON.parse(readFileSync(new URL('../site/data/upstream.json', import.meta.url), 'utf8'));
const distro = JSON.parse(readFileSync(new URL('./fixtures/distro.json', import.meta.url), 'utf8'));

function selfcheck(fields) {
  const report = {
    tool: 'php2shell-selfcheck',
    tool_version: '1.0.0',
    schema: 1,
    php_version: '8.4.26',
    sapi: 'apache2handler',
    os_release: {},
    dpkg_packages: [],
    extensions: { session: true, opcache: true },
    ini: {
      memory_limit: '128M',
      'session.upload_progress.enabled': '1',
      'session.auto_start': '0',
      expose_php: '1',
    },
    self_deleted: true,
    ...fields,
  };
  return `php2shell-selfcheck 1.0.0\n\n-----BEGIN PHP2SHELL SELFCHECK-----\n${JSON.stringify(report, null, 2)}\n-----END PHP2SHELL SELFCHECK-----\n`;
}

const run = (text, options) => judge(parseInput(text), upstream, distro, options);

test('verdict titles and short labels cover the five canonical verdicts', () => {
  assert.deepEqual(VERDICT_LABELS, {
    patched: 'Patched',
    vulnerable: 'Vulnerable',
    pending: 'Fix pending',
    restart: 'Restart needed',
    unknown: 'Undetermined',
  });
  assert.deepEqual(Object.keys(VERDICT_TITLES).sort(), Object.keys(VERDICT_LABELS).sort());
});

test('upstream build: older than the fixed release is vulnerable', () => {
  const r = run(selfcheck({ php_version: '8.4.26', container: true, config_path: '/usr/local/etc/php', os_release: { ID: 'debian', VERSION_ID: '13' } }));
  assert.equal(r.verdict, 'vulnerable');
  assert.match(r.actions[0].text, /Dockerfile/);
  assert.equal(r.exposure.level, 'high');
});

test('upstream build: the fixed release or later is patched', () => {
  assert.equal(run(selfcheck({ php_version: '8.4.27' })).verdict, 'patched');
  assert.equal(run(selfcheck({ php_version: '8.5.12' })).verdict, 'patched');
});

test('Ubuntu 22.04: patched when the fix is backported, even though the version number is 8.1.2', () => {
  const r = run(selfcheck({
    php_version: '8.1.2-1ubuntu2.28',
    os_release: { ID: 'ubuntu', VERSION_ID: '22.04', VERSION_CODENAME: 'jammy' },
    dpkg_packages: [
      { name: 'libapache2-mod-php8.1', version: '8.1.2-1ubuntu2.28', source: 'php8.1' },
      { name: 'php8.1-common', version: '8.1.2-1ubuntu2.28', source: 'php8.1' },
    ],
  }));
  assert.equal(r.verdict, 'patched');
  assert.match(r.reasons.join(' '), /backported/);
});

test('Ubuntu 22.04: restart needed when the package is new but the running PHP is old', () => {
  const r = run(selfcheck({
    php_version: '8.1.2-1ubuntu2.20',
    os_release: { ID: 'ubuntu', VERSION_ID: '22.04' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.1', version: '8.1.2-1ubuntu2.28', source: 'php8.1' }],
  }));
  assert.equal(r.verdict, 'restart');
  assert.ok(r.actions.some((a) => a.code === 'sudo systemctl restart apache2'));
});

test('Ubuntu 22.04: vulnerable when the package is old as well', () => {
  const r = run(selfcheck({
    php_version: '8.1.2-1ubuntu2.20',
    sapi: 'fpm-fcgi',
    os_release: { ID: 'ubuntu', VERSION_ID: '22.04' },
    dpkg_packages: [{ name: 'php8.1-fpm', version: '8.1.2-1ubuntu2.20', source: 'php8.1' }],
  }));
  assert.equal(r.verdict, 'vulnerable');
  assert.match(r.reasons.join(' '), /8\.1\.2-1ubuntu2\.28/);
  assert.ok(r.actions.some((a) => a.code === 'sudo systemctl restart php8.1-fpm'));
});

test('a header alone is enough to infer the distribution from the Ubuntu revision', () => {
  assert.equal(run('HTTP/1.1 200 OK\nServer: Apache/2.4.52 (Ubuntu)\nX-Powered-By: PHP/8.1.2-1ubuntu2.28\n').verdict, 'patched');
  assert.equal(run('X-Powered-By: PHP/8.3.6-0ubuntu0.24.04.4').verdict, 'vulnerable');
});

test('Debian testing: fix pending when there is no fixed package', () => {
  const r = run(selfcheck({
    php_version: '8.4.26',
    os_release: { ID: 'debian', VERSION_CODENAME: 'forky' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.4', version: '8.4.26-1', source: 'php8.4' }],
  }));
  assert.equal(r.verdict, 'pending');
});

test('Debian 12: catches a missed restart by comparing with the installed package, even without a revision in PHP_VERSION', () => {
  const r = run(selfcheck({
    php_version: '8.2.26',
    os_release: { ID: 'debian', VERSION_ID: '12' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.2', version: '8.2.35-1~deb12u1', source: 'php8.2' }],
  }));
  assert.equal(r.verdict, 'restart');
});

test('Debian 12: vulnerable when not updated', () => {
  const r = run(selfcheck({
    php_version: '8.2.26',
    os_release: { ID: 'debian', VERSION_ID: '12' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.2', version: '8.2.26-1~deb12u1', source: 'php8.2' }],
  }));
  assert.equal(r.verdict, 'vulnerable');
});

test('a fix available only through Ubuntu Pro is pointed out', () => {
  const r = run(selfcheck({
    php_version: '7.4.3-4ubuntu2.29+esm5',
    os_release: { ID: 'ubuntu', VERSION_ID: '20.04' },
    dpkg_packages: [{ name: 'libapache2-mod-php7.4', version: '7.4.3-4ubuntu2.29+esm5', source: 'php7.4' }],
  }));
  assert.equal(r.verdict, 'patched');
  assert.match(r.notes.join(' '), /Ubuntu Pro/);
});

test('deb.sury.org builds are checked against upstream', () => {
  const r = run(selfcheck({
    php_version: '8.3.14',
    os_release: { ID: 'debian', VERSION_ID: '12' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.3', version: '8.3.14-1+0~20241122.43+debian12~1.gbp9f1e3a', source: 'php8.3' }],
  }));
  assert.equal(r.verdict, 'vulnerable');
  assert.match(r.notes.join(' '), /sury/);
});

test('an upstream build of an end-of-life branch is vulnerable and points to the backport branch', () => {
  const r = run('8.1.30');
  assert.equal(r.verdict, 'vulnerable');
  assert.match(r.notes.join(' '), /PHP-8\.1-CVE-2026-109618-109619/);
});

test('PHP older than 5.4 and development versions stay undetermined', () => {
  assert.equal(run('5.3.29').verdict, 'unknown');
  assert.equal(run('8.6.0RC3').verdict, 'unknown');
});

test('php -v output gets a CLI warning', () => {
  // 8.3.20 was never a distribution's backport version (8.3.6 is Ubuntu 24.04's, so it is Undetermined; see findings.test.mjs #5).
  const r = run('PHP 8.3.20 (cli) (built: Mar 1 2026) (NTS)');
  assert.equal(r.verdict, 'vulnerable');
  assert.match(r.notes.join(' '), /command-line/);
});

test('RHEL: patched when the package changelog has both CVEs, undetermined when it does not', () => {
  const block = (hits) => `-----BEGIN PHP2SHELL SERVERCHECK-----
tool|php2shell-server-check|1.0.0
os|ID|rocky
os|ID_LIKE|rhel centos fedora
os|VERSION_ID|9.6
pkg|rpm|php-common|8.0.30-8.el9_8.1|
changelog|php-common|CVE-2026-109618|${hits}
changelog|php-common|CVE-2026-109619|${hits}
-----END PHP2SHELL SERVERCHECK-----`;
  const fixed = run(block(2));
  assert.equal(fixed.verdict, 'patched');
  assert.ok(fixed.advisories.some((a) => /RHSA-2026:87151/.test(a.value)));
  assert.equal(run(block(0)).verdict, 'unknown');
});

test('with only the server script, the SAPI is inferred from processes to pick the restart command', () => {
  const r = run(`-----BEGIN PHP2SHELL SERVERCHECK-----
os|ID|ubuntu
os|VERSION_ID|22.04
pkg|dpkg|libapache2-mod-php8.1|8.1.2-1ubuntu2.28|php8.1
proc|apache2|1|stale
-----END PHP2SHELL SERVERCHECK-----`);
  assert.equal(r.verdict, 'restart');
  assert.ok(r.actions.some((a) => a.code === 'sudo systemctl restart apache2'));
  assert.match(r.facts.find((f) => f.label === 'SAPI').value, /inferred/);
});

test('patched when the changelog has both CVEs, even without distribution data', () => {
  const r = run(`-----BEGIN PHP2SHELL SERVERCHECK-----
os|ID|debian
os|VERSION_ID|11
pkg|dpkg|php7.4-fpm|7.4.33-1+deb11u9|php7.4
changelog|php7.4-fpm|CVE-2026-109618|1
changelog|php7.4-fpm|CVE-2026-109619|1
-----END PHP2SHELL SERVERCHECK-----`);
  assert.equal(r.verdict, 'patched');
  assert.match(r.reasons.join(' '), /changelog/);
});

test('restart needed when the server script finds processes using old PHP files', () => {
  const r = run(`-----BEGIN PHP2SHELL SERVERCHECK-----
os|ID|debian
os|VERSION_ID|12
pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2
proc|php-fpm8.2|812|stale
proc|php-fpm8.2|813|ok
-----END PHP2SHELL SERVERCHECK-----`);
  assert.equal(r.verdict, 'restart');
});

test('pasting the PHP probe and server script output together uses both', () => {
  const text = (sapi) => selfcheck({ php_version: '8.2.35', sapi, os_release: { ID: 'debian', VERSION_ID: '12' } })
    + '\n-----BEGIN PHP2SHELL SERVERCHECK-----\nproc|php-fpm8.2|900|stale\n-----END PHP2SHELL SERVERCHECK-----\n';
  const obs = parseInput(text('fpm-fcgi'));
  assert.deepEqual(obs.sources, ['selfcheck', 'servercheck']);
  // The FPM that ran the probe reports 8.2.35, so what runs has the fix: a newer package only waits for a restart.
  const fpm = judge(obs, upstream, distro);
  assert.equal(fpm.verdict, 'patched');
  assert.match(fpm.notes.join(' '), /php-fpm8\.2/);
  // Stale FPM processes next to a probe that ran under Apache may be an older build: restart needed.
  assert.equal(judge(parseInput(text('apache2handler')), upstream, distro).verdict, 'restart');
});

test('interim mitigations are evaluated', () => {
  const r = run(selfcheck({
    php_version: '8.5.11',
    ini: {
      memory_limit: '-1',
      'session.upload_progress.enabled': '',
      'session.auto_start': '0',
      fatal_error_backtraces: '1',
      expose_php: '',
    },
  }));
  const byName = Object.fromEntries(r.mitigations.map((m) => [m.name, m.status]));
  assert.equal(byName.memory_limit, 'ok');
  assert.equal(byName['session.upload_progress.enabled'], 'ok');
  assert.equal(byName['session.auto_start'], 'ok');
  assert.equal(byName.fatal_error_backtraces, 'warn');
  assert.equal(r.verdict, 'vulnerable', 'interim mitigations do not change the verdict');
});

test('interim mitigations are not recommended on a patched server', () => {
  const r = run(selfcheck({ php_version: '8.5.12', ini: { memory_limit: '-1', 'session.upload_progress.enabled': '1', 'session.auto_start': '0', fatal_error_backtraces: '1' } }));
  assert.equal(r.verdict, 'patched');
  assert.ok(r.mitigations.every((m) => m.status !== 'warn'));
  assert.match(r.mitigations.find((m) => m.name === 'memory_limit').note, /reverting/);
  assert.ok(!r.mitigations.some((m) => m.name === 'fatal_error_backtraces'));
});

test('a Docker image of an end-of-life version is told to move to a supported version', () => {
  const r = run(selfcheck({ php_version: '7.4.33', container: true, config_path: '/usr/local/etc/php' }));
  assert.equal(r.verdict, 'vulnerable');
  assert.match(r.actions[0].text, /end of life/);
  assert.equal(r.actions[0].code, 'FROM php:8.4.27-apache');
  assert.match(r.actions[0].text, /8\.3\.36/);
});

test('signs of compromise found by the server script are shown', () => {
  const r = run(`-----BEGIN PHP2SHELL SERVERCHECK-----
os|ID|debian
os|VERSION_ID|12
pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2
webuser_proc|2
log|oom|5
log|crash|0
log|bigsession|0
proc|unreadable|4|unknown
-----END PHP2SHELL SERVERCHECK-----`);
  const levels = r.findings.map((f) => f.level);
  // Web-account processes are a "check" item: daemons running as nobody are common (see findings.test.mjs #43).
  assert.deepEqual(levels, ['warn', 'warn', 'info']);
  assert.match(r.notes.join(' '), /root/);
});

test('a manually chosen distribution is used', () => {
  const r = run('X-Powered-By: PHP/8.1.2-1ubuntu2.28', { distro: 'ubuntu:22.04' });
  assert.equal(r.verdict, 'patched');
});

test('unrecognisable input is undetermined', () => {
  const r = run('hello world');
  assert.equal(r.verdict, 'unknown');
  assert.ok(r.notes.length > 0);
});

test('a failed self-delete is flagged', () => {
  const r = run(selfcheck({ php_version: '8.4.27', self_deleted: false }));
  assert.match(r.notes.join(' '), /Delete it yourself/);
});
