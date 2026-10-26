// Regression tests for the verdict-engine review findings. Each test reproduces the
// reviewer's scenario against site/data/upstream.json and a frozen copy of site/data/distro.json
// (fixtures/distro-snapshot.json), so data refreshes do not move the verdicts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseInput } from '../site/lib/parse.js';
import { judge, evaluateMitigations } from '../site/lib/judge.js';
import { parsePhpVersion } from '../site/lib/version.js';
import { MESSAGES } from '../site/lib/messages.js';

const upstream = JSON.parse(readFileSync(new URL('../site/data/upstream.json', import.meta.url), 'utf8'));
const distro = JSON.parse(readFileSync(new URL('./fixtures/distro-snapshot.json', import.meta.url), 'utf8'));

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
    ini: { memory_limit: '128M', 'session.upload_progress.enabled': '1', 'session.auto_start': '0', expose_php: '1' },
    self_deleted: true,
    ...fields,
  };
  return `-----BEGIN PHP2SHELL SELFCHECK-----\n${JSON.stringify(report, null, 2)}\n-----END PHP2SHELL SELFCHECK-----\n`;
}
const servercheck = (lines) => `-----BEGIN PHP2SHELL SERVERCHECK-----\n${lines.join('\n')}\n-----END PHP2SHELL SERVERCHECK-----\n`;
const run = (text, options = {}) => judge(parseInput(text, { lang: options.lang }), upstream, distro, options);
const all = (r) => [...r.reasons, ...r.notes].join(' ');
const fact = (r, label) => r.facts.find((f) => f.label === label)?.value;
const actionText = (r) => r.actions.map((a) => `${a.text} ${a.code || ''}`).join(' ');

const UBUNTU_2404 = { ID: 'ubuntu', VERSION_ID: '24.04', VERSION_CODENAME: 'noble', PRETTY_NAME: 'Ubuntu 24.04.3 LTS' };
const UBUNTU_2204 = { ID: 'ubuntu', VERSION_ID: '22.04', VERSION_CODENAME: 'jammy' };

// ── #1 deb.sury.org builds ───────────────────────────────────────────

test('#1 a deb.sury.org revision in PHP_VERSION is judged by upstream, never as an Ubuntu backport', () => {
  const header = run('X-Powered-By: PHP/8.3.20-1+ubuntu22.04.1+deb.sury.org+1');
  assert.equal(header.verdict, 'vulnerable');
  assert.match(header.notes.join(' '), /sury/);
  assert.doesNotMatch(fact(header, 'Distribution'), /24\.04/);
  assert.doesNotMatch(all(header), /backported/);

  // deb.sury.org builds of end-of-life branches may carry backported fixes (round 3), which only the changelog shows:
  // without it they are Undetermined, never Patched, and still never an Ubuntu backport.
  const cli = run('PHP 7.4.33-1+ubuntu20.04.1+deb.sury.org+1 (cli) (built: Nov  2 2026)');
  assert.equal(cli.verdict, 'unknown');
  assert.match(all(cli), /changelog/);
  assert.doesNotMatch(cli.notes.join(' '), /Ubuntu Pro/);

  const old = run('X-Powered-By: PHP/5.6.40-1+ubuntu20.04.1+deb.sury.org+1');
  assert.equal(old.verdict, 'unknown');
  assert.doesNotMatch(fact(old, 'Distribution'), /14\.04/);
  assert.doesNotMatch(all(old), /Ubuntu has backported/);

  const probe = run(selfcheck({ php_version: '8.3.20-1+ubuntu24.04.1+deb.sury.org+1', sapi: 'fpm-fcgi', os_release: UBUNTU_2404, dpkg_packages: null }));
  assert.equal(probe.verdict, 'vulnerable');
});

test('#1 general guard: a build newer upstream than the release package is not that release\'s build', () => {
  const r = run(selfcheck({ php_version: '8.3.20-1ubuntu1', os_release: UBUNTU_2404, dpkg_packages: null }));
  assert.notEqual(r.verdict, 'patched');
  assert.equal(r.verdict, 'vulnerable');
});

// ── #2 RHEL changelog must belong to the running PHP ─────────────────

const ALMA9 = ['os|ID|almalinux', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|9.6', 'env|root|1'];

test('#2 RHEL: a patched base php-common does not vouch for a remi PHP that is running', () => {
  const block = servercheck([...ALMA9,
    'pkg|rpm|php-common|8.2.30-1.module_el9.6.0+120+abcdef12|',
    'pkg|rpm|php83-php-common|8.3.20-1.el9.remi|',
    'pkg|rpm|php83-php-fpm|8.3.20-1.el9.remi|',
    'changelog|php-common|CVE-2026-109618|2', 'changelog|php-common|CVE-2026-109619|2',
    'changelog|php83-php-common|CVE-2026-109618|0', 'changelog|php83-php-common|CVE-2026-109619|0',
    'proc|php-fpm|6|ok']);
  const probe = selfcheck({ php_version: '8.3.20', sapi: 'fpm-fcgi', config_path: '/etc/opt/remi/php83', os_release: { ID: 'almalinux', ID_LIKE: 'rhel centos fedora', VERSION_ID: '9.6' } });
  const r = run(probe + block);
  assert.equal(r.verdict, 'vulnerable');
  assert.match(r.notes.join(' '), /remi/);
  assert.doesNotMatch(r.reasons.join(' '), /records fixes for both/);
});

test('#2 RHEL: a changelog from another build is not evidence for the PHP that ran the probe', () => {
  const block = servercheck(['os|ID|cloudlinux', 'os|ID_LIKE|rhel fedora centos', 'os|VERSION_ID|9.4', 'env|root|1',
    'pkg|rpm|php-common|8.2.30-1.module_el9.4.0+1+abc|',
    'changelog|php-common|CVE-2026-109618|2', 'changelog|php-common|CVE-2026-109619|2']);
  const r = run(selfcheck({ php_version: '8.3.20', sapi: 'litespeed', os_release: { ID: 'cloudlinux', VERSION_ID: '9.4' } }) + block);
  assert.equal(r.verdict, 'unknown');
  assert.match(r.reasons.join(' '), /php-common 8\.2\.30/);
});

test('#2 RHEL: the changelog of the package that matches the running PHP still counts', () => {
  // The probe and the server script ran on the same system, so they report the same os-release.
  const block = servercheck([...ALMA9, 'pkg|rpm|php-common|8.2.13-1.module_el9.4.0+20844+7c41d8d0|', 'pkg|rpm|php-fpm|8.2.13-1.module_el9.4.0+20844+7c41d8d0|',
    'changelog|php-common|CVE-2026-109618|2', 'changelog|php-common|CVE-2026-109619|1',
    'changelog|php-fpm|CVE-2026-109618|2', 'changelog|php-fpm|CVE-2026-109619|1', 'proc|php-fpm|4|ok']);
  const r = run(selfcheck({ php_version: '8.2.13', sapi: 'fpm-fcgi', config_path: '/etc', os_release: { ID: 'almalinux', ID_LIKE: 'rhel centos fedora', VERSION_ID: '9.6' }, dpkg_packages: null }) + block);
  assert.equal(r.verdict, 'patched');
});

test('#2 server script only: each RHEL build is judged with its own changelog', () => {
  const r = run(servercheck([...ALMA9,
    'pkg|rpm|php-common|8.2.30-1.module_el9.6.0+120+abcdef12|',
    'pkg|rpm|php83-php-common|8.3.20-1.el9.remi|',
    'changelog|php-common|CVE-2026-109618|2', 'changelog|php-common|CVE-2026-109619|2',
    'changelog|php83-php-common|CVE-2026-109618|0', 'changelog|php83-php-common|CVE-2026-109619|0']));
  assert.equal(r.verdict, 'vulnerable');
  assert.match(r.reasons.join(' '), /php83-php-common/);
});

test('#2 Debian changelog fallback only uses the changelog of the running build', () => {
  const block = servercheck(['os|ID|debian', 'os|VERSION_ID|11', 'env|root|1',
    'pkg|dpkg|php7.4-common|7.4.33-1+deb11u5|php7.4',
    'pkg|dpkg|php8.1-common|8.1.30-1+deb11u1|php8.1',
    'changelog|php7.4-common|CVE-2026-109618|0', 'changelog|php7.4-common|CVE-2026-109619|0',
    'changelog|php8.1-common|CVE-2026-109618|1', 'changelog|php8.1-common|CVE-2026-109619|1']);
  // The probe reads the same package list as the server script on the same system.
  const pkgs = [{ name: 'php7.4-common', version: '7.4.33-1+deb11u5', source: 'php7.4' }, { name: 'php8.1-common', version: '8.1.30-1+deb11u1', source: 'php8.1' }];
  const r = run(selfcheck({ php_version: '7.4.33', os_release: { ID: 'debian', VERSION_ID: '11' }, dpkg_packages: pkgs }) + block);
  assert.equal(r.verdict, 'unknown');
  // The php8.1 build is judged on its own changelog; the running 7.4 PHP is not credited with it.
  assert.match(r.reasons[0], /^Running PHP 7\.4\.33/);
  assert.doesNotMatch(r.reasons[0], /treated as fixed/);
});

// ── #3 inferred Ubuntu release must match the version string ─────────

test('#3 EOL Ubuntu interim releases are not mapped onto the LTS package', () => {
  for (const text of ['X-Powered-By: PHP/8.1.7-1ubuntu3.6', 'X-Powered-By: PHP/8.1.12-1ubuntu4.3', 'X-Powered-By: PHP/7.4.9-1ubuntu1.3', 'PHP 7.4.16-1ubuntu2.3 (cli) (built: Mar 1 2022)']) {
    const r = run(text);
    assert.equal(r.verdict, 'unknown', text);
    assert.doesNotMatch(fact(r, 'Distribution'), /22\.04|20\.04/, text);
    assert.doesNotMatch(r.notes.join(' '), /Ubuntu Pro/, text);
  }
  assert.equal(run('X-Powered-By: PHP/8.1.2-1ubuntu2.28').verdict, 'patched');
});

test('#3 picking the LTS by hand for an interim build does not make it Patched', () => {
  const r = run('X-Powered-By: PHP/8.1.7-1ubuntu3.6', { distro: 'ubuntu:22.04' });
  assert.equal(r.verdict, 'vulnerable');
});

// ── #4 a PHP that is not the installed distribution package ──────────

test('#4 a panel PHP is not judged by an unrelated distribution package of the same branch', () => {
  const pkgs = [{ name: 'php8.3-cli', version: '8.3.6-0ubuntu0.24.04.13', source: 'php8.3' }, { name: 'php8.3-common', version: '8.3.6-0ubuntu0.24.04.13', source: 'php8.3' }];
  const panel = run(selfcheck({ php_version: '8.3.12', sapi: 'fpm-fcgi', config_path: '/www/server/php/83/etc', os_release: UBUNTU_2404, dpkg_packages: pkgs }));
  assert.equal(panel.verdict, 'vulnerable');
  const noPath = run(selfcheck({ php_version: '8.3.12', sapi: 'fpm-fcgi', os_release: UBUNTU_2404, dpkg_packages: pkgs }));
  assert.equal(noPath.verdict, 'vulnerable');
});

test('#4 a container probe is not judged by host packages', () => {
  const host = servercheck(['os|ID|ubuntu', 'os|VERSION_ID|24.04', 'env|root|1', 'pkg|dpkg|php8.3-cli|8.3.6-0ubuntu0.24.04.13|php8.3']);
  const r = run(selfcheck({ php_version: '8.3.12', container: true, config_path: '/usr/local/etc/php', os_release: { ID: 'debian', VERSION_ID: '12' } }) + host);
  assert.equal(r.verdict, 'vulnerable');
  assert.match(r.notes.join(' '), /container/);

  const sameOs = servercheck(['os|ID|debian', 'os|VERSION_ID|12', 'env|root|1', 'pkg|dpkg|libapache2-mod-php8.2|8.2.35-1~deb12u1|php8.2']);
  const c = run(selfcheck({ php_version: '8.2.30', container: true, config_path: '/usr/local/etc/php', os_release: { ID: 'debian', VERSION_ID: '12' } }) + sameOs);
  assert.equal(c.verdict, 'vulnerable');
  assert.ok(c.actions.length > 0);
  assert.match(actionText(c), /Dockerfile/);
});

// ── #5 same version before and after an Ubuntu fix ──────────────────

test('#5 Ubuntu 24.04 without a package list is Undetermined, not Vulnerable', () => {
  const manual = run('X-Powered-By: PHP/8.3.6', { distro: 'ubuntu:24.04' });
  assert.equal(manual.verdict, 'unknown');
  assert.match(manual.reasons.join(' '), /server script/);

  const probe = run(selfcheck({ php_version: '8.3.6', sapi: 'fpm-fcgi', config_path: '/etc/php/8.3/fpm', os_release: UBUNTU_2404, dpkg_packages: null }));
  assert.equal(probe.verdict, 'unknown');
  assert.doesNotMatch(probe.notes.join(' '), /upstream build/);

  const resolute = run(selfcheck({ php_version: '8.5.4', os_release: { ID: 'ubuntu', VERSION_ID: '26.04' }, dpkg_packages: null }));
  assert.equal(resolute.verdict, 'unknown');

  const bare = run('X-Powered-By: PHP/8.3.6');
  assert.equal(bare.verdict, 'unknown');
  assert.match(bare.reasons.join(' '), /Ubuntu 24\.04/);
});

test('#5 a version Ubuntu 24.04 never shipped falls back to upstream', () => {
  assert.equal(run('X-Powered-By: PHP/8.3.12', { distro: 'ubuntu:24.04' }).verdict, 'vulnerable');
  // Without the distribution, 8.3.12 may also be a build of the RHEL 9 php:8.3 module stream, whose fix keeps the
  // upstream version (round 3): Undetermined. A branch with no such stream fix is still judged by upstream.
  const bare = run('X-Powered-By: PHP/8.3.12');
  assert.equal(bare.verdict, 'unknown');
  assert.match(bare.reasons.join(' '), /RHEL 9/);
  assert.equal(run('X-Powered-By: PHP/8.4.20').verdict, 'vulnerable');
});

// ── #6 every installed branch is judged ─────────────────────────────

test('#6 server script only: a vulnerable second branch is not hidden by a patched first one', () => {
  const r = run(servercheck(['os|ID|debian', 'os|VERSION_ID|12', 'env|root|1',
    'pkg|dpkg|php8.2-common|8.2.35-1~deb12u1|php8.2',
    'pkg|dpkg|php8.4-common|8.4.20-1+0~20260301.30+debian12~1.gbp1a2b3c|php8.4',
    'pkg|dpkg|php8.4-fpm|8.4.20-1+0~20260301.30+debian12~1.gbp1a2b3c|php8.4',
    'proc|php-fpm8.4|5|ok']));
  assert.equal(r.verdict, 'vulnerable');
  assert.match(r.reasons.join(' '), /php8\.4/);
  assert.match(r.reasons.join(' '), /php8\.2/);
});

// ── #7 -dev snapshots ───────────────────────────────────────────────

test('#7 -dev snapshots are pre-releases', () => {
  assert.equal(parsePhpVersion('8.5.12-dev').pre, 'dev');
  assert.equal(parsePhpVersion('8.5.12-dev').revision, '');
  assert.equal(run('PHP 8.5.12-dev (cli) (built: Oct 20 2026)').verdict, 'unknown');
  assert.equal(run('X-Powered-By: PHP/8.4.27-dev').verdict, 'unknown');
});

// ── #9 the running PHP was never checked ─────────────────────────────

test('#9 server script without root: the installed package alone is not Patched', () => {
  const r = run(servercheck(['os|ID|ubuntu', 'os|VERSION_ID|22.04', 'env|root|0',
    'pkg|dpkg|php8.1-common|8.1.2-1ubuntu2.28|php8.1', 'pkg|dpkg|libapache2-mod-php8.1|8.1.2-1ubuntu2.28|php8.1',
    'proc|unreadable|9|unknown']));
  assert.equal(r.verdict, 'unknown');
  assert.match(r.reasons.join(' '), /running PHP could not be checked/);
  assert.ok(fact(r, 'Installed package version'));
  assert.equal(fact(r, 'PHP version'), undefined);
});

test('#9 server script as root with the processes checked is Patched', () => {
  const r = run(servercheck(['os|ID|ubuntu', 'os|VERSION_ID|22.04', 'env|root|1',
    'pkg|dpkg|libapache2-mod-php8.1|8.1.2-1ubuntu2.28|php8.1', 'proc|apache2|3|ok']));
  assert.equal(r.verdict, 'patched');
  const none = run(servercheck(['os|ID|ubuntu', 'os|VERSION_ID|22.04', 'env|root|1', 'pkg|dpkg|libapache2-mod-php8.1|8.1.2-1ubuntu2.28|php8.1']));
  assert.equal(none.verdict, 'patched');
  assert.match(none.reasons.join(' '), /No running PHP process/);
});

// ── #10 Ubuntu 24.04+: the loaded build cannot be seen ──────────────

test('#10 Ubuntu 24.04 probe: Patched says the loaded build could not be confirmed', () => {
  const probe = selfcheck({ php_version: '8.3.6', sapi: 'fpm-fcgi', os_release: UBUNTU_2404, dpkg_packages: [{ name: 'php8.3-fpm', version: '8.3.6-0ubuntu0.24.04.13', source: 'php8.3' }] });
  const r = run(probe);
  assert.equal(r.verdict, 'patched');
  assert.match(r.reasons.join(' '), /server script/);
  // The server script on the same system lists the same package as the probe.
  const host = ['os|ID|ubuntu', 'os|VERSION_ID|24.04', 'env|root|1', 'pkg|dpkg|php8.3-fpm|8.3.6-0ubuntu0.24.04.13|php8.3'];
  const checked = run(probe + servercheck([...host, 'proc|php-fpm8.3|4|ok']));
  assert.equal(checked.verdict, 'patched');
  assert.doesNotMatch(checked.reasons.join(' '), /server script/);
  const stale = run(probe + servercheck([...host, 'proc|php-fpm8.3|4|stale']));
  assert.equal(stale.verdict, 'restart');
});

// ── #11 Ubuntu 14.04 +dfsg ──────────────────────────────────────────

test('#11 Ubuntu 14.04: PHP_VERSION without +dfsg compares equal to the fixed package', () => {
  assert.equal(run('X-Powered-By: PHP/5.5.9-1ubuntu4.29+esm18').verdict, 'patched');
  const os = { ID: 'ubuntu', VERSION_ID: '14.04' };
  const pkg = [{ name: 'libapache2-mod-php5', version: '5.5.9+dfsg-1ubuntu4.29+esm18', source: 'php5' }];
  assert.equal(run(selfcheck({ php_version: '5.5.9-1ubuntu4.29+esm18', os_release: os, dpkg_packages: pkg })).verdict, 'patched');
  assert.equal(run(selfcheck({ php_version: '5.5.9-1ubuntu4.29+esm17', os_release: os, dpkg_packages: pkg })).verdict, 'restart');
});

// ── #12 a running build that has the fix ────────────────────────────

test('#12 a fixed running build with a newer package waiting is Patched, with a note', () => {
  const r = run(selfcheck({
    php_version: '8.1.2-1ubuntu2.28', os_release: UBUNTU_2204,
    dpkg_packages: [{ name: 'libapache2-mod-php8.1', version: '8.1.2-1ubuntu2.29', source: 'php8.1' }],
  }));
  assert.equal(r.verdict, 'patched');
  assert.match(r.notes.join(' '), /8\.1\.2-1ubuntu2\.29/);

  const fpm = run(selfcheck({ php_version: '8.4.27', sapi: 'fpm-fcgi' }) + servercheck(['env|root|1', 'proc|php-fpm8.4|4|stale']));
  assert.equal(fpm.verdict, 'patched');
  assert.match(fpm.notes.join(' '), /php-fpm8\.4/);

  // Stale processes of another SAPI may be an older PHP: the server still needs a restart.
  const other = run(selfcheck({ php_version: '8.4.27', sapi: 'apache2handler' }) + servercheck(['env|root|1', 'proc|php-fpm8.4|4|stale']));
  assert.equal(other.verdict, 'restart');
  assert.ok(other.actions.length > 0, 'a restart verdict always has a next step');
});

// ── #22 #23 mitigation advice ────────────────────────────────────────

test('#22 the memory_limit advice never points to RLIMIT_AS', () => {
  const [mem] = evaluateMitigations({ memory_limit: '128M' }, null, null);
  assert.doesNotMatch(mem.note, /OS-level memory limit/);
  assert.match(mem.note, /cgroup/);
  assert.match(mem.note, /Do not use RLIMIT_AS or RLIMIT_DATA/);
  const [ko] = evaluateMitigations({ memory_limit: '128M' }, null, null, false, 'ko');
  assert.match(ko.note, /RLIMIT_AS/);
});

test('#23 without probe settings the mitigation action names the mitigations', () => {
  const r = run('X-Powered-By: PHP/8.4.26');
  assert.equal(r.mitigations.length, 0);
  assert.doesNotMatch(actionText(r), /listed in this result/);
  assert.match(actionText(r), /memory_limit=-1/);
  assert.match(actionText(r), /session\.upload_progress\.enabled=0/);

  const none = run('hello world');
  assert.doesNotMatch(actionText(none), /mitigation|compromise/);

  const pending = run(selfcheck({ php_version: '8.4.26', ini: null, os_release: { ID: 'debian', VERSION_CODENAME: 'forky' }, dpkg_packages: [{ name: 'libapache2-mod-php8.4', version: '8.4.26-1', source: 'php8.4' }] }));
  assert.equal(pending.verdict, 'pending');
  // With a known SAPI and layout, the mitigations come as a configuration snippet that names them.
  assert.match(actionText(pending), /php_admin_value memory_limit -1/);
  assert.match(actionText(pending), /php_admin_flag session\.upload_progress\.enabled off/);
});

// ── #24 other distributions ─────────────────────────────────────────

test('#24 other distributions get a note to check their own advisories', () => {
  // SUSE backports into its own PHP packages, so a version below the fix is Undetermined there (round 3).
  const r = run(selfcheck({ php_version: '8.2.20', os_release: { ID: 'opensuse-leap', ID_LIKE: 'suse opensuse', VERSION_ID: '15.6' } }));
  assert.equal(r.verdict, 'unknown');
  assert.match(all(r), /opensuse-leap/);
  assert.match(all(r), /advisories/);
  const arch = run(selfcheck({ php_version: '8.2.20', os_release: { ID: 'arch' } }));
  assert.equal(arch.verdict, 'vulnerable');
  assert.match(arch.notes.join(' '), /\(arch\).*advisories/);
});

// ── #26 Ubuntu and Debian derivatives ────────────────────────────────

test('#26 Ubuntu derivatives are judged with their parent release', () => {
  const mint = run(selfcheck({
    php_version: '8.1.2-1ubuntu2.28',
    os_release: { ID: 'linuxmint', ID_LIKE: 'ubuntu debian', VERSION_ID: '21.3', VERSION_CODENAME: 'virginia' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.1', version: '8.1.2-1ubuntu2.28', source: 'php8.1' }],
  }));
  assert.equal(mint.verdict, 'patched');
  const pop = run(servercheck(['os|ID|pop', 'os|ID_LIKE|ubuntu debian', 'os|VERSION_ID|22.04', 'os|VERSION_CODENAME|jammy', 'env|root|1',
    'pkg|dpkg|php8.1-common|8.1.2-1ubuntu2.28|php8.1', 'pkg|dpkg|libapache2-mod-php8.1|8.1.2-1ubuntu2.28|php8.1', 'proc|apache2|2|ok']));
  assert.equal(pop.verdict, 'patched');
});

// ── #27 legacy redhat-release ───────────────────────────────────────

test('#27 the probe\'s LEGACY_REDHAT-RELEASE key is recognised', () => {
  const r = run(selfcheck({ php_version: '5.6.25', os_release: { 'LEGACY_REDHAT-RELEASE': 'CentOS release 6.10 (Final)' } }));
  assert.equal(r.verdict, 'unknown');
  assert.match(fact(r, 'Distribution'), /CentOS release 6\.10/);
  assert.ok(r.advisories.some((a) => /RHEL 6/.test(a.label)));
});

// ── #28 container actions ───────────────────────────────────────────

test('#28 a distribution PHP in a container is told to update its packages, not FROM php:', () => {
  const r = run(selfcheck({
    php_version: '8.3.6', container: true, config_path: '/etc/php/8.3/apache2', os_release: UBUNTU_2404,
    dpkg_packages: [{ name: 'libapache2-mod-php8.3', version: '8.3.6-0ubuntu0.24.04.4', source: 'php8.3' }],
  }));
  assert.equal(r.verdict, 'vulnerable');
  assert.doesNotMatch(actionText(r), /FROM php:/);
  assert.match(actionText(r), /apt-get/);
  assert.match(actionText(r), /rebuild/);
});

test('#28 a restart verdict in a container says to recreate the container', () => {
  const r = run(selfcheck({
    php_version: '8.1.2-1ubuntu2.20', container: true, config_path: '/etc/php/8.1/apache2', os_release: UBUNTU_2204,
    dpkg_packages: [{ name: 'libapache2-mod-php8.1', version: '8.1.2-1ubuntu2.28', source: 'php8.1' }],
  }));
  assert.equal(r.verdict, 'restart');
  assert.match(actionText(r), /container/);
});

// ── #38 EOL wording ─────────────────────────────────────────────────

test('#38 the EOL reason says it is about upstream builds', () => {
  const r = run('8.1.30');
  assert.equal(r.verdict, 'vulnerable');
  assert.match(r.reasons.join(' '), /upstream build/);
});

// ── #39 #40 RHEL details ────────────────────────────────────────────

const CENTOS7 = ['os|ID|centos', 'os|ID_LIKE|rhel fedora', 'os|VERSION_ID|7', 'env|root|1', 'pkg|rpm|php-common|5.4.16-48.el7|', 'pkg|rpm|php|5.4.16-48.el7|'];

test('#39 RHEL: a CVE Red Hat lists as not affected does not count as missing', () => {
  const r = run(servercheck([...CENTOS7, 'changelog|php-common|CVE-2026-109618|1', 'changelog|php-common|CVE-2026-109619|0', 'proc|httpd|5|ok']));
  assert.equal(r.verdict, 'patched');
  assert.match(r.reasons.join(' '), /not affected/);
  assert.doesNotMatch(r.reasons.join(' '), /has not been updated/);
});

test('#40 RHEL 6 and 7 get yum and service commands', () => {
  const r7 = run(servercheck([...CENTOS7, 'changelog|php-common|CVE-2026-109618|0', 'changelog|php-common|CVE-2026-109619|0', 'proc|httpd|5|ok']));
  assert.match(actionText(r7), /yum/);
  assert.doesNotMatch(actionText(r7), /dnf/);
  const r6 = run(selfcheck({ php_version: '5.3.3', sapi: 'apache2handler', os_release: { 'LEGACY_REDHAT-RELEASE': 'CentOS release 6.10 (Final)' } }));
  assert.match(actionText(r6), /service httpd restart/);
  assert.doesNotMatch(actionText(r6), /systemctl/);
  const r9 = run(servercheck([...ALMA9, 'pkg|rpm|php-common|8.2.13-1.module_el9.4.0+1+ab|', 'changelog|php-common|CVE-2026-109618|0', 'changelog|php-common|CVE-2026-109619|0']));
  assert.match(actionText(r9), /dnf/);
});

// ── #41 pre-releases and newer branches ─────────────────────────────

test('#41 pre-releases and newer branches get the right reason and action', () => {
  const rc = run('8.3.12RC1');
  assert.equal(rc.verdict, 'unknown');
  assert.match(rc.reasons.join(' '), /pre-release/);
  assert.doesNotMatch(rc.reasons.join(' '), /development version/);
  const next = run('8.6.0');
  assert.equal(next.verdict, 'unknown');
  assert.match(next.reasons.join(' '), /newer than/);
  assert.doesNotMatch(actionText(next), /fixed release of the 8\.6 branch/);
  const eol = run('7.4.33');
  assert.doesNotMatch(actionText(eol), /fixed release of the 7\.4 branch/);
});

// ── #43 findings wording ────────────────────────────────────────────

test('#43 crash and web-account findings do not over-attribute', () => {
  const r = run(servercheck(['os|ID|debian', 'os|VERSION_ID|12', 'env|root|1', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2', 'proc|php-fpm8.2|3|ok', 'log|crash|2', 'webuser_proc|2']));
  const crash = r.findings.find((f) => /crash/.test(f.text));
  assert.match(crash.text, /web server or PHP/);
  const proc = r.findings.find((f) => /process/.test(f.text));
  assert.equal(proc.level, 'warn');
  assert.match(proc.text, /nobody/);
});

// ── Contracts: env|root, unknown counts, uname_release, open_basedir ─

test('contract: unknown counts and non-root runs are never reported as clean', () => {
  const unknown = run(servercheck(['os|ID|debian', 'os|VERSION_ID|12', 'env|root|1', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2', 'proc|php-fpm8.2|3|ok',
    'log|oom|unknown', 'log|crash|0', 'log|bigsession|unknown', 'webuser_proc|0']));
  assert.ok(!unknown.findings.some((f) => f.level === 'ok'), 'no "nothing suspicious" line');
  assert.ok(unknown.findings.some((f) => f.level === 'info' && /could not be read/.test(f.text)));
  assert.ok(!unknown.findings.some((f) => /isolate/.test(f.text)), 'no incident advice without a finding');

  const notRoot = run(servercheck(['os|ID|debian', 'os|VERSION_ID|12', 'env|root|0', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2',
    'log|oom|0', 'log|crash|0', 'log|bigsession|0', 'webuser_proc|0']));
  assert.ok(!notRoot.findings.some((f) => f.level === 'ok'));
  assert.ok(notRoot.findings.some((f) => /root/.test(f.text)));

  const clean = run(servercheck(['os|ID|debian', 'os|VERSION_ID|12', 'env|root|1', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2', 'proc|php-fpm8.2|3|ok',
    'log|oom|0', 'log|crash|0', 'log|bigsession|0', 'webuser_proc|0', 'webroot|recent_php|0']));
  assert.deepEqual(clean.findings.map((f) => f.level), ['ok']);

  const webroot = run(servercheck(['env|root|1', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2', 'webroot|recent_php|unknown']));
  assert.ok(!webroot.findings.some((f) => f.level === 'ok'));
});

test('contract: a RHEL kernel in uname_release identifies the RHEL family when os-release is empty', () => {
  const r = run(selfcheck({ php_version: '8.2.13', sapi: 'fpm-fcgi', os_release: [], open_basedir: true, uname_release: '5.14.0-427.el9_4.x86_64', dpkg_packages: null }));
  assert.equal(r.verdict, 'unknown');
  assert.match(fact(r, 'Distribution'), /RHEL family 9/);
  assert.match(r.notes.join(' '), /open_basedir/);
  // A container reports the host kernel, so it is not used there.
  const c = run(selfcheck({ php_version: '8.2.13', container: true, config_path: '/usr/local/etc/php', os_release: [], uname_release: '5.14.0-427.el9_4.x86_64' }));
  assert.equal(c.verdict, 'vulnerable');
});

test('contract: with open_basedir hiding the OS, a version below the fix is Undetermined', () => {
  const r = run(selfcheck({ php_version: '8.2.13', sapi: 'fpm-fcgi', config_path: '/etc', os_release: [], open_basedir: true, uname_release: '', dpkg_packages: null }));
  assert.equal(r.verdict, 'unknown');
  assert.match(r.reasons.join(' '), /open_basedir/);
  assert.equal(run(selfcheck({ php_version: '8.2.35', os_release: [], open_basedir: true, uname_release: '' })).verdict, 'patched');
});

// ── Korean catalog rules ────────────────────────────────────────────

// The word the Korean text must never use for a check, written as escapes so that it appears nowhere in the repository.
const BANNED_KO = /\uD310\uC815/;

test('the Korean catalog says 확인 for a check, and names the page controls', () => {
  for (const [key, msg] of Object.entries(MESSAGES.ko)) {
    const text = typeof msg === 'function' ? msg({ n: 2, items: 'x' }) : msg;
    assert.doesNotMatch(text, BANNED_KO, key);
  }
  assert.match(MESSAGES.ko['reason.debReleaseUnknown'], /배포판 목록에서 릴리스를 고른 뒤 결과확인을 다시 누르세요/);
  assert.match(MESSAGES.en['reason.debReleaseUnknown'], /Distribution list.*Run check/);
  assert.match(MESSAGES.ko['finding.incident'], /KISA/);
});
