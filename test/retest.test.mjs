// Regression tests for the second round of tester reports. Each test replays the tester's input against the
// real data files in site/data/. Numbers follow the report: tester 1 #1-#12, tester 2 #13-#30.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseInput } from '../site/lib/parse.js';
import { judge } from '../site/lib/judge.js';
import { parsePhpVersion } from '../site/lib/version.js';

const upstream = JSON.parse(readFileSync(new URL('../site/data/upstream.json', import.meta.url), 'utf8'));
const distro = JSON.parse(readFileSync(new URL('../site/data/distro.json', import.meta.url), 'utf8'));

const probe = (fields) => `-----BEGIN PHP2SHELL SELFCHECK-----\n${JSON.stringify({ tool: 'php2shell-selfcheck', schema: 1, ...fields })}\n-----END PHP2SHELL SELFCHECK-----\n`;
const server = (lines, closed = true) => `-----BEGIN PHP2SHELL SERVERCHECK-----\n${lines.join('\n')}\n${closed ? '-----END PHP2SHELL SERVERCHECK-----\n' : ''}`;
const run = (text, options = {}) => judge(parseInput(text, { lang: options.lang }), upstream, distro, options);
const reasons = (r) => r.reasons.join(' ');
const notes = (r) => r.notes.join(' ');
const fact = (r, label) => r.facts.find((f) => f.label === label)?.value;
const actionText = (r) => r.actions.map((a) => `${a.text} ${a.code || ''}`).join(' ');
const both = (text, options = {}) => ['en', 'ko'].map((lang) => run(text, { ...options, lang }));

const NOBLE = { ID: 'ubuntu', VERSION_ID: '24.04', VERSION_CODENAME: 'noble' };
const JAMMY = { ID: 'ubuntu', VERSION_ID: '22.04' };
const ROCKY94 = { ID: 'rocky', ID_LIKE: 'rhel centos fedora', VERSION_ID: '9.4' };
const NOBLE_HOST = ['os|ID|ubuntu', 'os|VERSION_ID|24.04', 'env|root|1', 'pkg|dpkg|php8.3-fpm|8.3.6-0ubuntu0.24.04.13|php8.3', 'pkg|dpkg|php8.3-common|8.3.6-0ubuntu0.24.04.13|php8.3'];
const ROCKY_RPMS = ['pkg|rpm|php-common|8.2.13-1.module+el9.4.0+20827+3f2b0b48|', 'pkg|rpm|php-fpm|8.2.13-1.module+el9.4.0+20827+3f2b0b48|',
  'changelog|php-common|CVE-2026-109618|1', 'changelog|php-common|CVE-2026-109619|1', 'changelog|php-fpm|CVE-2026-109618|1', 'changelog|php-fpm|CVE-2026-109619|1'];

// ── Tester 1 ────────────────────────────────────────────────────────

test('#1 a container probe that could not read its own OS is not judged by host packages', () => {
  const text = probe({ php_version: '8.3.6', sapi: 'fpm-fcgi', container: true, open_basedir: false, os_release: null, dpkg_packages: null, config_path: '/etc/php/8.3/fpm', uname_release: '6.8.0-45-generic' })
    + server([...NOBLE_HOST, 'proc|php-fpm8.3|4|ok']);
  for (const r of both(text)) {
    assert.equal(r.verdict, 'unknown');
    assert.match(notes(r), /docker exec/);
  }
  assert.equal(parseInput(text).packages.length, 0, 'host packages are not used');
});

test('#2 a container probe with an unreadable package list is not tied to same-OS host output', () => {
  const r = run(probe({ php_version: '8.3.6', sapi: 'fpm-fcgi', container: true, open_basedir: false, os_release: NOBLE, dpkg_packages: null, config_path: '/etc/php/8.3/fpm' })
    + server(['os|ID|ubuntu', 'os|VERSION_ID|24.04', 'env|root|1', 'pkg|dpkg|php8.3-fpm|8.3.6-0ubuntu0.24.04.13|php8.3', 'proc|php-fpm8.3|4|ok']));
  assert.equal(r.verdict, 'unknown');
  assert.match(notes(r), /nothing in its output shows that the server script ran in the same container/);
  // Positive control: the server script run inside the container lists the same packages as the probe.
  const pkgs = [{ name: 'php8.3-fpm', version: '8.3.6-0ubuntu0.24.04.13', source: 'php8.3' }];
  const linked = run(probe({ php_version: '8.3.6', sapi: 'fpm-fcgi', container: true, os_release: NOBLE, dpkg_packages: pkgs, config_path: '/etc/php/8.3/fpm' })
    + server(['os|ID|ubuntu', 'os|VERSION_ID|24.04', 'env|root|1', 'pkg|dpkg|php8.3-fpm|8.3.6-0ubuntu0.24.04.13|php8.3', 'proc|php-fpm8.3|4|ok']));
  assert.equal(linked.verdict, 'patched');
});

test('#3 a changelog read at one version is never credited to another version of the package', () => {
  const host = server(['os|ID|debian', 'os|VERSION_ID|11', 'env|root|1', 'pkg|dpkg|php7.4-fpm|7.4.33-1+deb11u9|php7.4',
    'changelog|php7.4-fpm|CVE-2026-109618|1', 'changelog|php7.4-fpm|CVE-2026-109619|1', 'proc|php-fpm7.4|3|ok']);
  const u5 = { php_version: '7.4.33-1+deb11u5', sapi: 'fpm-fcgi', open_basedir: false, os_release: { ID: 'debian', VERSION_ID: '11', VERSION_CODENAME: 'bullseye' },
    dpkg_packages: [{ name: 'php7.4-fpm', version: '7.4.33-1+deb11u5', source: 'php7.4' }], config_path: '/etc/php/7.4/fpm' };
  for (const container of [true, false]) {
    const r = run(probe({ ...u5, container }) + host);
    assert.equal(r.verdict, 'unknown', `container ${container}`);
    assert.doesNotMatch(r.reasons.filter((x) => !/^Server script output/.test(x)).join(' '), /treated as fixed/);
  }
  // The changelog is kept with the version it was read at.
  const obs = parseInput(host);
  assert.deepEqual(obs.packages[0].changelog, { 'CVE-2026-109618': 1, 'CVE-2026-109619': 1 });
  assert.equal(obs.packages[0].version, '7.4.33-1+deb11u9');
});

test('#4 a non-root server script run that saw no PHP process is not Patched', () => {
  const ubuntu = server(['os|ID|ubuntu', 'os|VERSION_ID|22.04', 'env|root|0', 'pkg|dpkg|php8.1-common|8.1.2-1ubuntu2.28|php8.1', 'pkg|dpkg|php8.1-fpm|8.1.2-1ubuntu2.28|php8.1']);
  const alma = server(['os|ID|almalinux', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|9.6', 'env|root|0', 'pkg|rpm|php-common|8.0.30-8.el9_8.1|', 'pkg|rpm|php-fpm|8.0.30-8.el9_8.1|',
    'changelog|php-common|CVE-2026-109618|2', 'changelog|php-common|CVE-2026-109619|2', 'changelog|php-fpm|CVE-2026-109618|2', 'changelog|php-fpm|CVE-2026-109619|2']);
  for (const text of [ubuntu, alma]) {
    for (const r of both(text)) {
      assert.equal(r.verdict, 'unknown');
      assert.match(reasons(r), /hidepid/);
    }
  }
  // With a probe whose PHP_VERSION cannot show a restart (Ubuntu 24.04), it is the same gap; it never says no PHP is
  // running.
  const pkgs = [{ name: 'php8.3-common', version: '8.3.6-0ubuntu0.24.04.13', source: 'php8.3' }, { name: 'php8.3-fpm', version: '8.3.6-0ubuntu0.24.04.13', source: 'php8.3' }];
  const noble = server(['os|ID|ubuntu', 'os|VERSION_ID|24.04', 'env|root|0', 'pkg|dpkg|php8.3-common|8.3.6-0ubuntu0.24.04.13|php8.3', 'pkg|dpkg|php8.3-fpm|8.3.6-0ubuntu0.24.04.13|php8.3']);
  const withProbe = run(probe({ php_version: '8.3.6', sapi: 'fpm-fcgi', os_release: NOBLE, dpkg_packages: pkgs, config_path: '/etc/php/8.3/fpm' }) + noble);
  assert.equal(withProbe.verdict, 'unknown');
  assert.doesNotMatch(reasons(withProbe), /No running PHP process/);
  // As root, with no PHP process found, the probe's PHP still runs: no "none found" claim either.
  const rootNone = run(probe({ php_version: '8.3.6', sapi: 'fpm-fcgi', os_release: NOBLE, dpkg_packages: pkgs, config_path: '/etc/php/8.3/fpm' })
    + server(['os|ID|ubuntu', 'os|VERSION_ID|24.04', 'env|root|1', 'pkg|dpkg|php8.3-common|8.3.6-0ubuntu0.24.04.13|php8.3', 'pkg|dpkg|php8.3-fpm|8.3.6-0ubuntu0.24.04.13|php8.3']));
  assert.equal(rootNone.verdict, 'patched');
  assert.doesNotMatch(reasons(rootNone), /No running PHP process/);
  assert.match(reasons(rootNone), /found no running process of this PHP/);
});

test('#5 a wrong manual distribution never overrides the os-release or the revision vendor', () => {
  const deb9 = probe({ php_version: '7.0.33-0+deb9u12', sapi: 'apache2handler', os_release: { ID: 'debian', VERSION_ID: '9', VERSION_CODENAME: 'stretch' },
    dpkg_packages: [{ name: 'libapache2-mod-php7.0', version: '7.0.33-0+deb9u12', source: 'php7.0' }], config_path: '/etc/php/7.0/apache2' });
  for (const text of [deb9, 'X-Powered-By: PHP/7.0.33-0+deb9u12']) {
    for (const [lang, label] of [['en', 'Distribution'], ['ko', '배포판']]) {
      const r = run(text, { distro: 'ubuntu:16.04', lang });
      assert.equal(r.verdict, 'unknown');
      assert.doesNotMatch(reasons(r), /backported the fixes|백포트했습니다/);
      assert.match(fact(r, label), /Debian 9/);
      assert.match(notes(r), /Ubuntu 16\.04/);
    }
  }
});

test('#6 a revision Ubuntu never built is not credited with the Ubuntu backport', () => {
  const ppa = run(server(['os|ID|ubuntu', 'os|VERSION_ID|24.04', 'env|root|1', 'pkg|dpkg|php8.3-fpm|8.3.6-1+ppa1|php8.3', 'proc|php-fpm8.3|2|ok']));
  assert.equal(ppa.verdict, 'unknown');
  assert.match(reasons(ppa), /not one that Ubuntu builds/);
  const debStyle = run(probe({ php_version: '8.1.2-2', sapi: 'apache2handler', os_release: JAMMY,
    dpkg_packages: [{ name: 'libapache2-mod-php8.1', version: '8.1.2-2', source: 'php8.1' }], config_path: '/etc/php/8.1/apache2' }));
  assert.equal(debStyle.verdict, 'unknown');
  // Positive control: Ubuntu's own revision is still Patched, and an older Ubuntu revision still Vulnerable.
  assert.equal(run('X-Powered-By: PHP/8.1.2-1ubuntu2.28').verdict, 'patched');
  assert.equal(run('X-Powered-By: PHP/8.1.2-1ubuntu2.20').verdict, 'vulnerable');
});

test('#7 an installed package downgraded below the running fixed build is not Patched', () => {
  const [en, ko] = both(probe({ php_version: '8.1.2-1ubuntu2.28', sapi: 'apache2handler', os_release: JAMMY,
    dpkg_packages: [{ name: 'libapache2-mod-php8.1', version: '8.1.2-1ubuntu2.20', source: 'php8.1' }], config_path: '/etc/php/8.1/apache2' }));
  assert.equal(en.verdict, 'vulnerable');
  assert.match(reasons(en), /next restart of the service loads the vulnerable build/);
  assert.equal(ko.verdict, 'vulnerable');
});

test('#8 a bare 8.0.30 or 7.4.33 could be a RHEL package with the fix backported', () => {
  for (const text of ['X-Powered-By: PHP/8.0.30', 'PHP 8.0.30 (cli) (built: Oct 20 2026 12:00:00) (NTS)', 'X-Powered-By: PHP/7.4.33',
    probe({ php_version: '8.0.30', sapi: 'fpm-fcgi', os_release: null, open_basedir: false, uname_release: '', config_path: '/etc', dpkg_packages: null })]) {
    const r = run(text);
    assert.equal(r.verdict, 'unknown', text);
    assert.match(reasons(r), /RHEL (8|9)/, text);
  }
  // Positive controls: a version no distribution ships with a backport is still judged by upstream.
  assert.equal(run('X-Powered-By: PHP/8.0.29').verdict, 'vulnerable');
  assert.equal(run('8.1.30').verdict, 'vulnerable');
});

test('#9 a manual release that contradicts the os-release is not used', () => {
  const r = run(probe({ php_version: '8.5.4-0ubuntu1.5', sapi: 'apache2handler', os_release: { ID: 'ubuntu', VERSION_ID: '26.04', VERSION_CODENAME: 'resolute' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.5', version: '8.5.4-0ubuntu1.5', source: 'php8.5' }], config_path: '/etc/php/8.5/apache2' }), { distro: 'ubuntu:26.10' });
  assert.equal(r.verdict, 'patched');
  assert.match(notes(r), /Distribution list is set to Ubuntu 26\.10/);
});

test('#10 a manual release that contradicts the release the version string belongs to is not used', () => {
  const r = run('X-Powered-By: PHP/8.5.9-0ubuntu2.1', { distro: 'ubuntu:26.04' });
  assert.notEqual(r.verdict, 'vulnerable');
  assert.match(notes(r), /Ubuntu 26\.10/);
});

test('#11 "Upstream build" is not applied to a PHP_VERSION with a distribution revision', () => {
  const r = run(probe({ php_version: '8.1.2-1ubuntu2.28', sapi: 'apache2handler', os_release: JAMMY,
    dpkg_packages: [{ name: 'libapache2-mod-php8.1', version: '8.1.2-1ubuntu2.28', source: 'php8.1' }], config_path: '/etc/php/8.1/apache2' }), { distro: 'upstream' });
  assert.equal(r.verdict, 'patched');
  assert.match(notes(r), /Upstream build/);
  // Positive control: an upstream choice for a plain version is still used.
  assert.equal(run('X-Powered-By: PHP/8.3.6', { distro: 'upstream' }).verdict, 'vulnerable');
});

test('#12 a Debian derivative with an unknown codename takes the release from the installed package', () => {
  const r = run(probe({ php_version: '8.2.26', sapi: 'apache2handler', os_release: { ID: 'linuxmint', ID_LIKE: 'debian', VERSION_ID: '6', VERSION_CODENAME: 'faye', PRETTY_NAME: 'LMDE 6 (faye)' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.2', version: '8.2.35-1~deb12u1', source: 'php8.2' }], config_path: '/etc/php/8.2/apache2' }));
  assert.equal(r.verdict, 'restart');
  assert.match(fact(r, 'Distribution'), /Debian 12/);
  // Even with no release at all, an installed package with the upstream fix shows a missed restart.
  const sid = run(probe({ php_version: '8.2.26', sapi: 'apache2handler', os_release: { ID: 'debian', VERSION_CODENAME: 'sid' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.2', version: '8.2.35-1', source: 'php8.2' }], config_path: '/etc/php/8.2/apache2' }));
  assert.equal(sid.verdict, 'restart');
});

// ── Tester 2 ────────────────────────────────────────────────────────

test('#13 every X-Powered-By header in a curl -IL paste is judged', () => {
  const chain = 'HTTP/1.1 301 Moved Permanently\nServer: nginx\nX-Powered-By: PHP/8.4.27\nLocation: https://www.example.com/\n\nHTTP/1.1 200 OK\nServer: nginx\nX-Powered-By: PHP/8.4.20\n';
  for (const r of both(chain)) assert.equal(r.verdict, 'vulnerable');
  assert.equal(run('HTTP/1.1 200 OK\nX-Powered-By: PHP/8.2.35\nX-Powered-By: PHP/8.1.20\n').verdict, 'vulnerable');
  assert.match(notes(run(chain)), /2 separate outputs/);
  // The same version on every hop is one output.
  assert.equal(parseInput('HTTP/1.1 301\nX-Powered-By: PHP/8.2.35\n\nHTTP/1.1 200 OK\nX-Powered-By: PHP/8.2.35\n').parts, undefined);
});

test('#14 every -v line is judged, so an old php-fpm is not hidden by a new CLI', () => {
  const r = run('$ php -v\nPHP 8.4.27 (cli) (built: Oct 21 2026 10:00:00) (NTS)\n$ php-fpm8.4 -v\nPHP 8.4.20 (fpm-fcgi) (built: Jun 10 2026 10:00:00)\n');
  assert.equal(r.verdict, 'vulnerable');
  assert.match(reasons(r), /8\.4\.20.*fpm-fcgi/);
});

test('#15 with the server script, other installed builds next to the probe PHP are judged too', () => {
  const sury = '8.4.27-1+0~20261021.1+debian12~1.gbp1a2b3c';
  const text = probe({ php_version: '8.4.27', sapi: 'apache2handler', config_path: '/etc/php/8.4/apache2', os_release: { ID: 'debian', VERSION_ID: '12', VERSION_CODENAME: 'bookworm' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.4', version: sury, source: 'php8.4' }, { name: 'php8.2-fpm', version: '8.2.29-1~deb12u1', source: 'php8.2' }] })
    + server(['env|root|1', 'os|ID|debian', 'os|VERSION_ID|12', 'os|VERSION_CODENAME|bookworm', `pkg|dpkg|libapache2-mod-php8.4|${sury}|php8.4`,
      'pkg|dpkg|php8.2-fpm|8.2.29-1~deb12u1|php8.2', 'proc|apache2|5|ok', 'proc|php-fpm8.2|6|ok']);
  for (const r of both(text)) assert.equal(r.verdict, 'vulnerable');
  const r = run(text);
  assert.match(reasons(r), /php8\.2-fpm 8\.2\.29-1~deb12u1/);
  assert.match(actionText(r), /restart php8\.2-fpm/);
  assert.equal(fact(r, 'Other installed PHP builds'), 'php8.2-fpm 8.2.29-1~deb12u1');
});

test('#16 a RHEL container probe is not judged by a same-OS host changelog', () => {
  const r = run(probe({ php_version: '8.2.13', sapi: 'fpm-fcgi', config_path: '/etc', container: true, open_basedir: false, uname_release: '5.14.0-427.el9_4.x86_64', os_release: ROCKY94, dpkg_packages: null })
    + server(['env|root|1', 'os|ID|rocky', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|9.4', ...ROCKY_RPMS, 'proc|php-fpm|6|ok']));
  assert.equal(r.verdict, 'unknown');
  assert.match(notes(r), /docker exec/);
  const ubuntu = run(probe({ php_version: '8.3.6', sapi: 'fpm-fcgi', container: true, os_release: NOBLE, dpkg_packages: [], config_path: '/etc/php/8.3/fpm' })
    + server([...NOBLE_HOST, 'proc|php-fpm8.3|4|ok']));
  assert.equal(ubuntu.verdict, 'unknown');
});

test('#17 a probe and a server script that disagree about the packages are not Patched', () => {
  const pkgs = [{ name: 'php8.3-fpm', version: '8.3.6-0ubuntu0.24.04.13', source: 'php8.3' }, { name: 'php8.3-common', version: '8.3.6-0ubuntu0.24.04.13', source: 'php8.3' }];
  const text = probe({ php_version: '8.3.6', sapi: 'fpm-fcgi', config_path: '/etc/php/8.3/fpm', os_release: { ...NOBLE, ID_LIKE: 'debian' }, dpkg_packages: pkgs })
    + server(['env|root|1', 'os|ID|ubuntu', 'os|ID_LIKE|debian', 'os|VERSION_ID|24.04', 'os|VERSION_CODENAME|noble',
      'pkg|dpkg|php8.3-fpm|8.3.6-0ubuntu0.24.04.5|php8.3', 'pkg|dpkg|php8.3-common|8.3.6-0ubuntu0.24.04.5|php8.3', 'proc|php-fpm8.3|3|ok']);
  for (const r of both(text)) assert.equal(r.verdict, 'unknown');
  assert.match(notes(run(text)), /different times/);
});

test('#18 hidepid without root: missing proc lines are not "no PHP running"', () => {
  const rocky = server(['tool|php2shell-server-check|1.0.0', 'env|root|0', 'os|ID|rocky', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|9.4', ...ROCKY_RPMS, 'webuser_proc|unknown']);
  const noble = server(['tool|php2shell-server-check|1.0.0', 'env|root|0', 'os|ID|ubuntu', 'os|ID_LIKE|debian', 'os|VERSION_ID|24.04', 'os|VERSION_CODENAME|noble',
    'pkg|dpkg|php8.3-fpm|8.3.6-0ubuntu0.24.04.13|php8.3', 'pkg|dpkg|php8.3-common|8.3.6-0ubuntu0.24.04.13|php8.3', 'webuser_proc|unknown']);
  assert.equal(run(rocky).verdict, 'unknown');
  assert.equal(run(noble).verdict, 'unknown');
  assert.equal(run(probe({ php_version: '8.3.6', sapi: 'fpm-fcgi', config_path: '/etc/php/8.3/fpm', os_release: NOBLE, dpkg_packages: null }) + noble).verdict, 'unknown');
  // Positive controls: as root, with the process checked, it is Patched. A CLI-only build has no service process
  // that could keep an old build loaded, so a non-root run does not make it Undetermined.
  assert.equal(run(server([...NOBLE_HOST, 'proc|php-fpm8.3|3|ok'])).verdict, 'patched');
  assert.equal(run(server(['env|root|0', 'os|ID|ubuntu', 'os|VERSION_ID|24.04', 'pkg|dpkg|php8.3-cli|8.3.6-0ubuntu0.24.04.13|php8.3', 'pkg|dpkg|php8.3-common|8.3.6-0ubuntu0.24.04.13|php8.3'])).verdict, 'patched');
});

test('#19 a server script block cut off before its END line is not Patched', () => {
  const head = ['tool|php2shell-server-check|1.0.0', 'env|root|1', 'os|ID|rocky', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|9.4', ...ROCKY_RPMS];
  for (const lines of [head, [...head, 'proc|php-fpm|6|sta']]) {
    for (const r of both(server(lines, false))) {
      assert.equal(r.verdict, 'unknown');
      assert.ok(r.notes.some((n) => /END/.test(n)));
    }
  }
  // A status other than ok or stale is a process that was not checked, even with the END line.
  const bad = run(server(['env|root|1', 'os|ID|rocky', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|9.4', ...ROCKY_RPMS, 'proc|php-fpm|6|']));
  assert.equal(bad.verdict, 'unknown');
  // Positive control: the same block with its END line and a checked process is Patched.
  assert.equal(run(server([...head, 'proc|php-fpm|6|ok'])).verdict, 'patched');
});

test('#20 a php-fpm or apache2 that no installed Debian package can run is not checked, so not Patched', () => {
  const docker = run(server(['env|root|1', 'os|ID|ubuntu', 'os|ID_LIKE|debian', 'os|VERSION_ID|22.04', 'os|VERSION_CODENAME|jammy',
    'pkg|dpkg|php8.1-cli|8.1.2-1ubuntu2.28|php8.1', 'pkg|dpkg|php8.1-common|8.1.2-1ubuntu2.28|php8.1', 'proc|php-fpm|12|ok']));
  assert.equal(docker.verdict, 'unknown');
  assert.match(reasons(docker), /belong to none of the PHP builds/);
  const apache = run(server(['env|root|1', 'os|ID|debian', 'os|VERSION_ID|12',
    'pkg|dpkg|php8.2-cli|8.2.35-1~deb12u1|php8.2', 'pkg|dpkg|php8.2-common|8.2.35-1~deb12u1|php8.2', 'proc|apache2|9|ok']));
  assert.equal(apache.verdict, 'unknown');
});

test('#21 a running php-fpm8.3 with no php8.3 package is not checked, so not Patched', () => {
  const base = ['env|root|1', 'os|ID|ubuntu', 'os|ID_LIKE|debian', 'os|VERSION_ID|22.04', 'os|VERSION_CODENAME|jammy', 'pkg|dpkg|php8.1-fpm|8.1.2-1ubuntu2.28|php8.1', 'proc|php-fpm8.1|5|ok'];
  assert.equal(run(server([...base, 'proc|php-fpm8.3|4|ok'])).verdict, 'unknown');
  const stale = run(server([...base, 'proc|php-fpm8.3|4|stale']));
  assert.equal(stale.verdict, 'restart');
  assert.match(reasons(stale), /php-fpm8\.3/);
  assert.doesNotMatch(actionText(stale), /restart php8\.1-fpm/, 'the restart command names no unrelated service');
  // Positive control: the same server without the extra process is Patched.
  assert.equal(run(server(base)).verdict, 'patched');
});

test('#22 several outputs in one paste are all judged', () => {
  const deb12 = { ID: 'debian', VERSION_ID: '12', VERSION_CODENAME: 'bookworm' };
  const pools = probe({ php_version: '8.2.35', sapi: 'fpm-fcgi', config_path: '/etc/php/8.2/fpm', os_release: deb12, dpkg_packages: [] })
    + probe({ php_version: '8.1.33', sapi: 'fpm-fcgi', config_path: '/etc/php/8.1/fpm', os_release: deb12, dpkg_packages: [] });
  const hosts = server(['env|root|1', 'os|ID|debian', 'os|VERSION_ID|12', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2', 'proc|php-fpm8.2|3|ok'])
    + server(['env|root|1', 'os|ID|debian', 'os|VERSION_ID|12', 'pkg|dpkg|php8.2-fpm|8.2.29-1~deb12u1|php8.2', 'proc|php-fpm8.2|3|ok']);
  const probeHeader = probe({ php_version: '8.2.35', sapi: 'fpm-fcgi', config_path: '/etc/php/8.2/fpm', os_release: deb12, dpkg_packages: [] }) + 'HTTP/1.1 200 OK\nX-Powered-By: PHP/8.4.20\n';
  const headerCli = 'X-Powered-By: PHP/8.4.27\n\n$ php -v\nPHP 8.4.20 (cli) (built: Oct 20 2026 12:00:00) (NTS)\n';
  for (const text of [pools, hosts, probeHeader, headerCli]) {
    for (const r of both(text)) assert.equal(r.verdict, 'vulnerable');
  }
  // The same output pasted twice is one output, and the server script's own indented text is never read as a header.
  const one = probe({ php_version: '8.2.35', sapi: 'fpm-fcgi', config_path: '/etc/php/8.2/fpm', os_release: deb12, dpkg_packages: [] });
  assert.equal(parseInput(one + one).parts, undefined);
  assert.equal(run(one + one).verdict, 'patched');
  assert.equal(parseInput(server(['env|root|1']) + server(['env|root|1'])).parts, undefined);
  assert.equal(parseInput(`${server(['env|root|1', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2'])}  X-Powered-By: PHP/8.2.20\n`).parts, undefined);
});

test('#23 a container probe with no OS of its own is not judged by an Ubuntu host', () => {
  const r = run(probe({ php_version: '8.3.6', sapi: 'frankenphp', config_path: '/etc/frankenphp', container: true, open_basedir: false, os_release: null, dpkg_packages: null })
    + server([...NOBLE_HOST, 'proc|php-fpm8.3|3|ok']));
  assert.notEqual(r.verdict, 'patched');
  assert.doesNotMatch(r.reasons.filter((x) => !/^Server script output/.test(x)).join(' '), /backported the fixes/);
});

test('#24 php-fpm -v shows the binary on disk, so Patched carries the restart caveat', () => {
  for (const text of ['PHP 8.1.2-1ubuntu2.28 (fpm-fcgi) (built: Oct 20 2026 12:00:00)\nCopyright (c) The PHP Group\n', 'PHP 8.2.35 (fpm-fcgi) (built: Oct 20 2026 12:00:00)\n']) {
    const [en, ko] = both(text);
    assert.equal(en.verdict, 'patched');
    assert.match(reasons(en), /binary installed on disk/);
    assert.match(reasons(ko), /디스크에 설치된 바이너리/);
  }
});

test('#25 php -v with CLI in capitals or extra spaces still gets the CLI note', () => {
  for (const text of ['PHP 8.2.35 (CLI) (built: Oct 21 2026 10:00:00) (NTS)\n', 'PHP 8.2.35  (cli) (built: Oct 21 2026 10:00:00) (NTS)\n']) {
    const r = run(text);
    assert.equal(r.verdict, 'patched');
    assert.match(notes(r), /command-line PHP/, text);
    assert.equal(r.exposure.level, 'info', text);
  }
});

test('#26 Red Hat\'s "Not affected" for plain php covers only the branch Red Hat ships', () => {
  const r = run(server(['env|root|1', 'os|ID|centos', 'os|ID_LIKE|rhel fedora', 'os|VERSION_ID|7', 'pkg|rpm|php-common|8.1.20-1.el7|', 'pkg|rpm|php-fpm|8.1.20-1.el7|',
    'changelog|php-common|CVE-2026-109618|1', 'changelog|php-common|CVE-2026-109619|0', 'changelog|php-fpm|CVE-2026-109618|1', 'changelog|php-fpm|CVE-2026-109619|0', 'proc|php-fpm|3|ok']));
  assert.equal(r.verdict, 'unknown');
  assert.doesNotMatch(reasons(r), /not affected/);
});

test('#27 Alpine _rc and _pre builds are pre-releases', () => {
  assert.equal(parsePhpVersion('8.5.12_rc1-r0').pre, 'rc1');
  assert.equal(parsePhpVersion('8.5.0_pre1').pre, 'pre1');
  assert.equal(parsePhpVersion('8.5.12_p1-r0').pre, '');
  assert.equal(run(server(['env|root|1', 'os|ID|alpine', 'os|VERSION_ID|3.22.0', 'pkg|apk|php85|8.5.12_rc1-r0|', 'pkg|apk|php85-fpm|8.5.12_rc1-r0|', 'proc|php-fpm85|2|ok'])).verdict, 'unknown');
  assert.equal(run('8.2.35_rc1').verdict, 'unknown');
  // Positive control: the release itself on Alpine is Patched, and php-fpm85 belongs to the php85 build.
  assert.equal(run(server(['env|root|1', 'os|ID|alpine', 'os|VERSION_ID|3.22.0', 'pkg|apk|php85|8.5.12-r0|', 'pkg|apk|php85-fpm|8.5.12-r0|', 'proc|php-fpm85|2|ok'])).verdict, 'patched');
});

test('#28 dropped host output does not turn a RHEL container probe into an upstream build', () => {
  const container = { php_version: '8.0.30', sapi: 'fpm-fcgi', config_path: '/etc', container: true, open_basedir: false, os_release: { ID: 'rocky', ID_LIKE: 'rhel centos fedora', VERSION_ID: '9.6' }, dpkg_packages: null };
  const alone = run(probe(container));
  assert.equal(alone.verdict, 'unknown');
  const ubuntuHost = run(probe(container) + server(['env|root|1', 'os|ID|ubuntu', 'os|ID_LIKE|debian', 'os|VERSION_ID|24.04', 'os|VERSION_CODENAME|noble', 'pkg|dpkg|php8.3-fpm|8.3.6-0ubuntu0.24.04.13|php8.3', 'proc|php-fpm8.3|3|ok']));
  assert.equal(ubuntuHost.verdict, 'unknown');
  assert.doesNotMatch(notes(ubuntuHost), /found no PHP installed with rpm/);
  const olderHost = run(probe(container) + server(['env|root|1', 'os|ID|rocky', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|9.4', 'pkg|rpm|php-common|8.0.30-8.el9_8.1|',
    'changelog|php-common|CVE-2026-109618|1', 'changelog|php-common|CVE-2026-109619|1']));
  assert.equal(olderHost.verdict, 'unknown');
});

test('#29 a bare 8.0.30 header, with or without a RHEL Server header, is Undetermined', () => {
  for (const text of ['X-Powered-By: PHP/8.0.30\n', 'PHP 8.0.30 (cli) (built: Aug  3 2026 17:13:08) ( NTS gcc x86_64 )', 'HTTP/1.1 200 OK\nServer: Apache/2.4.57 (Rocky Linux)\nX-Powered-By: PHP/8.0.30\n', 'X-Powered-By: PHP/7.4.33\n']) {
    for (const r of both(text)) assert.equal(r.verdict, 'unknown', text);
  }
  const rocky = run('HTTP/1.1 200 OK\nServer: Apache/2.4.57 (Rocky Linux)\nX-Powered-By: PHP/8.2.13\n');
  assert.equal(rocky.verdict, 'unknown', 'the Server header names a RHEL rebuild');
  assert.match(fact(rocky, 'Distribution'), /Server header/);
});

test('#30 a Remi collection of an EOL branch is judged by its changelog when it records both fixes', () => {
  const block = server(['env|root|1', 'os|ID|centos', 'os|VERSION_ID|7', 'pkg|rpm|php74-php-common|7.4.33-18.el7.remi|', 'pkg|rpm|php74-php-fpm|7.4.33-18.el7.remi|',
    'changelog|php74-php-common|CVE-2026-109618|1', 'changelog|php74-php-common|CVE-2026-109619|1', 'changelog|php74-php-fpm|CVE-2026-109618|1', 'changelog|php74-php-fpm|CVE-2026-109619|1', 'proc|php-fpm|4|ok']);
  for (const r of both(block)) assert.equal(r.verdict, 'patched');
  assert.match(reasons(run(block)), /Remi/);
  const withProbe = run(probe({ php_version: '7.4.33', sapi: 'fpm-fcgi', config_path: '/etc/opt/remi/php74', os_release: { ID: 'centos', VERSION_ID: '7' }, dpkg_packages: null }) + block);
  assert.equal(withProbe.verdict, 'patched');
  // Positive control: without the changelog entries a Remi EOL build is still judged by upstream.
  const none = run(server(['env|root|1', 'os|ID|centos', 'os|VERSION_ID|7', 'pkg|rpm|php74-php-common|7.4.33-18.el7.remi|',
    'changelog|php74-php-common|CVE-2026-109618|1', 'changelog|php74-php-common|CVE-2026-109619|0']));
  assert.equal(none.verdict, 'vulnerable');
});
