// Regression tests for the third round of tester reports, and for the engine notes of the same round. Each test
// replays the tester's input (real probe and server script outputs where the tester had them) against the real
// data files in site/data/. Groups: D (Debian and Ubuntu), R (RHEL family and Docker), C (crafted inputs),
// X (rendering and robustness), N (notes from the server script and probe work).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseInput } from '../site/lib/parse.js';
import { judge, sapiLabel } from '../site/lib/judge.js';

const upstream = JSON.parse(readFileSync(new URL('../site/data/upstream.json', import.meta.url), 'utf8'));
const distro = JSON.parse(readFileSync(new URL('../site/data/distro.json', import.meta.url), 'utf8'));

// A probe block as the probe prints it (the fields in the probe's own order).
const probe = (fields) => `-----BEGIN PHP2SHELL SELFCHECK-----\n${JSON.stringify({ tool: 'php2shell-selfcheck', tool_version: '1.0.0', schema: 1, ...fields })}\n-----END PHP2SHELL SELFCHECK-----\n`;
const serverLines = (lines) => ['tool|php2shell-server-check|1.0.0', ...lines].join('\n');
const server = (lines) => `-----BEGIN PHP2SHELL SERVERCHECK-----\n${serverLines(lines)}\n-----END PHP2SHELL SERVERCHECK-----\n`;
const run = (text, options = {}) => judge(parseInput(text, { lang: options.lang }), upstream, distro, options);
const both = (text, options = {}) => ['en', 'ko'].map((lang) => run(text, { ...options, lang }));
const reasons = (r) => r.reasons.join(' ');
const notes = (r) => r.notes.join(' ');
const actionText = (r) => r.actions.map((a) => `${a.text}\n${a.code || ''}`).join('\n');
const all = (r) => [...r.reasons, ...r.notes, actionText(r)].join('\n');
const codes = (r) => r.actions.map((a) => a.code || '').join('\n');
const CVES = ['CVE-2026-109618', 'CVE-2026-109619'];
const logged = (pkgs, n) => pkgs.flatMap((p) => CVES.map((c) => `changelog|${p}|${c}|${typeof n === 'number' ? n : n[c]}`));
const verdicts = (text, options) => both(text, options).map((r) => r.verdict);

// ── Real outputs from the tester's containers ───────────────────────

const PROBE_BASE = { open_basedir: false, container: false, self_deleted: true, extensions: { session: true, opcache: true } };
const JAMMY_OS = { PRETTY_NAME: 'Ubuntu 22.04.5 LTS', VERSION_ID: '22.04', VERSION_CODENAME: 'jammy', ID: 'ubuntu', ID_LIKE: 'debian' };
const NOBLE_OS = { PRETTY_NAME: 'Ubuntu 24.04.5 LTS', VERSION_ID: '24.04', VERSION_CODENAME: 'noble', ID: 'ubuntu', ID_LIKE: 'debian' };
const BOOKWORM_OS = { PRETTY_NAME: 'Debian GNU/Linux 12 (bookworm)', VERSION_ID: '12', VERSION_CODENAME: 'bookworm', ID: 'debian' };
const deb = (names, version, source) => names.map((name) => ({ name, version, source }));
const JAMMY_LINES = ['env|root|1', 'os|ID|ubuntu', 'os|ID_LIKE|debian', 'os|VERSION_ID|22.04', 'os|VERSION_CODENAME|jammy', 'os|PRETTY_NAME|Ubuntu 22.04.5 LTS'];
const NOBLE_LINES = ['env|root|1', 'os|ID|ubuntu', 'os|ID_LIKE|debian', 'os|VERSION_ID|24.04', 'os|VERSION_CODENAME|noble', 'os|PRETTY_NAME|Ubuntu 24.04.5 LTS'];
const BOOKWORM_LINES = ['env|root|1', 'os|ID|debian', 'os|VERSION_ID|12', 'os|VERSION_CODENAME|bookworm', 'os|PRETTY_NAME|Debian GNU/Linux 12 (bookworm)'];
const LOGS = ['webuser_proc|0', 'log|oom|0', 'log|crash|unknown', 'log|bigsession|0'];

const JAMMY_FIXED = '8.1.2-1ubuntu2.28';
const NOBLE_FIXED = '8.3.6-0ubuntu0.24.04.13';
const MOD81 = ['libapache2-mod-php8.1', 'php8.1-cli', 'php8.1-common'];
const NOBLE3 = ['php8.3-cli', 'php8.3-common', 'php8.3-fpm'];
const DEB82 = ['php8.2-cli', 'php8.2-common', 'php8.2-fpm'];

// Ubuntu 22.04, Apache mod_php, updated from the jammy GA build with no restart (p2s-pa-u22-stale-probe.txt).
const F1 = probe({ ...PROBE_BASE, php_version: '8.1.2', php_extra_version: '', sapi: 'apache2handler', config_path: '/etc/php/8.1/apache2', server_software: 'Apache/2.4.52 (Ubuntu)', os_release: JAMMY_OS, dpkg_packages: deb(MOD81, JAMMY_FIXED, 'php8.1') });
// Debian 12 php8.2-fpm running 8.2.35, downgraded on disk to 8.2.32 with no restart (p2s-pa-d12-downgrade-probe.txt).
const F2 = probe({ ...PROBE_BASE, php_version: '8.2.35', php_extra_version: '', sapi: 'fpm-fcgi', config_path: '/etc/php/8.2/fpm', server_software: 'nginx/1.22.1', os_release: BOOKWORM_OS, dpkg_packages: deb(DEB82, '8.2.32-1~deb12u1', 'php8.2') });
// Ubuntu 24.04 php8.3-fpm updated with no restart: the probe, and the server script output copied without its BEGIN line.
const F3_PROBE = probe({ ...PROBE_BASE, php_version: '8.3.6', php_extra_version: '', sapi: 'fpm-fcgi', config_path: '/etc/php/8.3/fpm', server_software: 'nginx/1.24.0', os_release: NOBLE_OS, dpkg_packages: deb(NOBLE3, NOBLE_FIXED, 'php8.3') });
const F3_LINES = [...NOBLE_LINES, ...NOBLE3.map((p) => `pkg|dpkg|${p}|${NOBLE_FIXED}|php8.3`), ...logged(NOBLE3, { 'CVE-2026-109618': 2, 'CVE-2026-109619': 1 }), 'proc|php-fpm8.3|1|stale', ...LOGS];
const F3_HEADLESS = `${serverLines(F3_LINES)}\n-----END PHP2SHELL SERVERCHECK-----\n`;
// Ubuntu 24.04 interrupted upgrade: php8.3-fpm half-configured at 8.3.6-0maysync1, so neither collector lists it.
const F6_PROBE = probe({ ...PROBE_BASE, extensions: { session: true, opcache: false }, php_version: '8.3.6', php_extra_version: '', sapi: 'fpm-fcgi', config_path: '/etc/php/8.3/fpm', server_software: 'nginx/1.24.0', os_release: NOBLE_OS, dpkg_packages: deb(['php8.3-cli', 'php8.3-common'], NOBLE_FIXED, 'php8.3') });
const F6_ROOT = server([...NOBLE_LINES, `pkg|dpkg|php8.3-cli|${NOBLE_FIXED}|php8.3`, `pkg|dpkg|php8.3-common|${NOBLE_FIXED}|php8.3`, ...logged(['php8.3-cli', 'php8.3-common'], { 'CVE-2026-109618': 2, 'CVE-2026-109619': 1 }), 'proc|php-fpm8.3|1|ok', ...LOGS]);
// Ubuntu 22.04: a probe while .28 ran, and a server script output after a downgrade to the GA build with no restart.
const F7_PROBE = probe({ ...PROBE_BASE, php_version: JAMMY_FIXED, php_extra_version: '-1ubuntu2.28', sapi: 'apache2handler', config_path: '/etc/php/8.1/apache2', server_software: 'Apache/2.4.52 (Ubuntu)', os_release: JAMMY_OS, dpkg_packages: deb(MOD81, JAMMY_FIXED, 'php8.1') });
const F7_SERVER = server([...JAMMY_LINES, ...MOD81.map((p) => `pkg|dpkg|${p}|8.1.2-1ubuntu2|php8.1`), ...logged(MOD81, 0), 'proc|apache2|1|stale', ...LOGS]);
// deb.sury.org PHP 8.1 (end of life upstream) whose 8.1.34-9 changelog records the backported fixes.
const SURY_DEB = '8.1.34-9+0~20261021.82+debian12~1.gbp4e430a';
const SURY_PPA = '8.1.34-9+ubuntu22.04.1+deb.sury.org+1';
const FPM81 = ['php8.1-cli', 'php8.1-common', 'php8.1-fpm'];
const F4_DEB_PROBE = probe({ ...PROBE_BASE, php_version: '8.1.34', php_extra_version: '', sapi: 'fpm-fcgi', config_path: '/etc/php/8.1/fpm', server_software: 'nginx/1.22.1', os_release: BOOKWORM_OS, dpkg_packages: deb(FPM81, SURY_DEB, 'php8.1') });
const F4_DEB = F4_DEB_PROBE + server([...BOOKWORM_LINES, ...FPM81.map((p) => `pkg|dpkg|${p}|${SURY_DEB}|php8.1`), ...logged(FPM81, 1), 'proc|php-fpm8.1|1|ok', 'webuser_proc|0']);
const F4_PPA_PROBE = probe({ ...PROBE_BASE, php_version: '8.1.34', php_extra_version: '', sapi: 'apache2handler', config_path: '/etc/php/8.1/apache2', server_software: 'Apache/2.4.52 (Ubuntu)', os_release: JAMMY_OS, dpkg_packages: deb(MOD81, SURY_PPA, 'php8.1') });
const F4_PPA = F4_PPA_PROBE + server(['env|root|1', 'os|ID|ubuntu', 'os|ID_LIKE|debian', 'os|VERSION_ID|22.04', 'os|VERSION_CODENAME|jammy', ...MOD81.map((p) => `pkg|dpkg|${p}|${SURY_PPA}|php8.1`), ...logged(MOD81, 1), 'proc|apache2|1|ok', 'webuser_proc|0']);
// Debian 12 downgrade: the probe (8.2.35 running, 8.2.32 on disk) and the root server script of the same moment.
const F5_SERVER = server([...BOOKWORM_LINES, ...DEB82.map((p) => `pkg|dpkg|${p}|8.2.32-1~deb12u1|php8.2`), ...logged(DEB82, 0), 'proc|php-fpm8.2|1|stale', ...LOGS]);
const F5 = F2 + F5_SERVER;

// ── D: Debian and Ubuntu ────────────────────────────────────────────

test('D1 Ubuntu 22.04: a plain 8.1.2 next to the updated .28 package is the GA build loaded before the update', () => {
  const header = 'HTTP/1.1 200 OK\nDate: Fri, 23 Oct 2026 06:00:00 GMT\nServer: Apache/2.4.52 (Ubuntu)\nContent-Type: text/html; charset=UTF-8\n';
  for (const text of [F1, F1 + F1, `${header}\n${F1}`]) {
    for (const r of both(text)) {
      assert.equal(r.verdict, 'restart', text.slice(0, 40));
      assert.doesNotMatch(reasons(r), /is the same for the old and the fixed build|이전 빌드와 수정된 빌드가 같으므로/);
    }
    assert.match(reasons(run(text)), /original build of the release reports the plain version/);
    assert.ok(run(text).actions.some((a) => a.code === 'sudo systemctl restart apache2'));
  }
  // Positive controls: Ubuntu 24.04 really reports a plain 8.3.6 after the fix, and the GA package itself is Vulnerable.
  assert.equal(run(F3_PROBE).verdict, 'patched');
  assert.equal(run(probe({ ...PROBE_BASE, php_version: '8.1.2', sapi: 'apache2handler', config_path: '/etc/php/8.1/apache2', os_release: JAMMY_OS, dpkg_packages: deb(MOD81, '8.1.2-1ubuntu2', 'php8.1') })).verdict, 'vulnerable');
});

test('D2 Debian 12: PHP-FPM still running 8.2.35 after a downgrade to 8.2.32 is Vulnerable, with no reload before the reinstall', () => {
  for (const text of [F2, F2 + F2]) {
    for (const r of both(text)) {
      assert.equal(r.verdict, 'vulnerable');
      assert.match(reasons(r), /8\.2\.32-1~deb12u1/);
      assert.doesNotMatch(codes(r), /reload/, 'no reload while the vulnerable build is on disk');
    }
  }
  const r = run(F2);
  assert.match(reasons(r), /next restart of the service loads the vulnerable build/);
  assert.equal(r.actions[0].code, 'sudo apt-get update\nsudo apt-get install --only-upgrade php8.2-cli php8.2-common php8.2-fpm');
  assert.match(r.actions[0].text, /install php8\.2 8\.2\.35-1~deb12u1 or later again before the service restarts/);
  // Positive controls: the fixed package on disk is Patched, and an older package that has the fix gets a note only.
  assert.equal(run(probe({ ...PROBE_BASE, php_version: '8.2.35', sapi: 'fpm-fcgi', config_path: '/etc/php/8.2/fpm', os_release: BOOKWORM_OS, dpkg_packages: deb(DEB82, '8.2.35-1~deb12u1', 'php8.2') })).verdict, 'patched');
  const sury = run(probe({ ...PROBE_BASE, php_version: '8.3.36', sapi: 'fpm-fcgi', config_path: '/etc/php/8.3/fpm', os_release: NOBLE_OS, dpkg_packages: deb(NOBLE3, NOBLE_FIXED, 'php8.3') }));
  assert.equal(sury.verdict, 'patched');
  assert.match(notes(sury), /older than the running PHP .* but it has the fix too/);
});

test('D3 a server script output copied without its BEGIN line is still read', () => {
  for (const text of [F3_PROBE + F3_HEADLESS, F3_HEADLESS + F3_PROBE, F3_HEADLESS]) {
    for (const r of both(text)) assert.equal(r.verdict, 'restart', text.slice(0, 40));
    assert.match(notes(run(text)), /no BEGIN line/);
  }
  // Positive control: the same text with its BEGIN line.
  assert.equal(run(F3_PROBE + server(F3_LINES)).verdict, 'restart');
  // Cut further down (the tool, env and os lines lost): never Patched, and the step asks for the whole output.
  const cut = `${[`pkg|dpkg|php8.3-fpm|${NOBLE_FIXED}|php8.3`, ...logged(['php8.3-fpm'], 1), 'proc|php-fpm8.3|3|ok'].join('\n')}\n-----END PHP2SHELL SERVERCHECK-----\n`;
  for (const r of both(cut)) assert.equal(r.verdict, 'unknown');
  assert.match(reasons(run(cut)), /no BEGIN line and starts below its first line/);
  // A paste with no marker at all is unchanged.
  assert.equal(parseInput('8.2.35').phpVersion, '8.2.35');
});

test('D4 a running php-fpm8.3 whose php8.3-fpm package is not installed is not vouched for by php8.3-common', () => {
  for (const text of [F6_PROBE, F6_ROOT, F6_PROBE + F6_ROOT]) {
    for (const r of both(text)) assert.equal(r.verdict, 'unknown', text.slice(0, 40));
  }
  assert.match(reasons(run(F6_PROBE)), /php8\.3-fpm/);
  assert.match(reasons(run(F6_ROOT)), /belong to none of the PHP builds/);
  const steps = run(F6_PROBE);
  assert.ok(steps.actions[0].code.includes('sudo dpkg --audit'));
  // Positive control: with php8.3-fpm installed and its process checked, the backport is Patched.
  const whole = server([...NOBLE_LINES, ...NOBLE3.map((p) => `pkg|dpkg|${p}|${NOBLE_FIXED}|php8.3`), ...logged(NOBLE3, 1), 'proc|php-fpm8.3|1|ok']);
  assert.equal(run(whole).verdict, 'patched');
  assert.equal(run(F3_PROBE + whole).verdict, 'patched');
});

test('D5 a probe and a server script that disagree are not Patched, even when the probe shows a fixed revision', () => {
  for (const r of both(F7_PROBE + F7_SERVER)) {
    assert.equal(r.verdict, 'unknown');
    assert.ok(r.actions.some((a) => /together|함께/.test(a.text)));
  }
  const debProbe = probe({ ...PROBE_BASE, php_version: '8.2.35', sapi: 'fpm-fcgi', config_path: '/etc/php/8.2/fpm', os_release: BOOKWORM_OS, dpkg_packages: deb(DEB82, '8.2.35-1~deb12u1', 'php8.2') });
  assert.equal(run(debProbe + F5_SERVER).verdict, 'unknown');
  // The server script output alone is Vulnerable, and the probe alone is Patched.
  assert.equal(run(F7_SERVER).verdict, 'vulnerable');
  assert.equal(run(F7_PROBE).verdict, 'patched');
});

test('D6 deb.sury.org PHP 8.1 whose changelog records both backported fixes is Patched', () => {
  for (const text of [F4_DEB, F4_PPA]) {
    for (const r of both(text)) assert.equal(r.verdict, 'patched', text.slice(0, 60));
    assert.match(reasons(run(text)), /backported by deb\.sury\.org/);
  }
  // Without the changelog the build is Undetermined, never Vulnerable, and the steps never replace a package with itself.
  for (const text of [F4_DEB_PROBE, F4_PPA_PROBE]) {
    for (const r of both(text)) {
      assert.equal(r.verdict, 'unknown');
      assert.doesNotMatch(codes(r), /make install|php-fpm -i|apt-get install libapache2-mod-php8\.1\b/);
    }
  }
  const ppa = run(F4_PPA_PROBE);
  assert.ok(ppa.actions.some((a) => /--allow-downgrades/.test(a.code || '') && /print \$1"=8\.1\.2-1ubuntu2\.28"/.test(a.code)));
  assert.doesNotMatch(actionText(ppa), /turn off the Apache PHP module/);
  // A changelog that was read without the fixes, or a Debian build made before the fixed releases, is Vulnerable.
  const noFix = F4_DEB_PROBE + server([...BOOKWORM_LINES, ...FPM81.map((p) => `pkg|dpkg|${p}|${SURY_DEB}|php8.1`), ...logged(FPM81, 0), 'proc|php-fpm8.1|1|ok']);
  assert.equal(run(noFix).verdict, 'vulnerable');
  const old = '8.1.31-1+0~20250101.1+debian12~1.gbp1234567';
  const before = run(probe({ ...PROBE_BASE, php_version: '8.1.31', sapi: 'fpm-fcgi', config_path: '/etc/php/8.1/fpm', os_release: BOOKWORM_OS, dpkg_packages: deb(FPM81, old, 'php8.1') }));
  assert.equal(before.verdict, 'vulnerable');
  assert.match(reasons(before), /before the fixed releases/);
});

test('D7 after a downgrade, no step reloads or restarts PHP before the fixed package is back', () => {
  for (const r of both(F5)) {
    assert.equal(r.verdict, 'vulnerable');
    assert.doesNotMatch(notes(r), /restart the service when convenient|적당한 때에 서비스를 재시작/);
    assert.doesNotMatch(codes(r), /reload/);
  }
  assert.match(notes(run(F5)), /Do not restart or reload them before the fixed package is installed again/);
  // The server script output alone: stale processes over a build without the fix are not "from before the update".
  const noble = server([...NOBLE_LINES, ...NOBLE3.map((p) => `pkg|dpkg|${p}|8.3.6-0maysync1|php8.3`), ...logged(NOBLE3, 0), 'proc|php-fpm8.3|1|stale']);
  for (const text of [noble, F5_SERVER]) {
    const r = run(text);
    assert.equal(r.verdict, 'vulnerable');
    assert.match(reasons(r), /by an update or a downgrade/);
    assert.doesNotMatch(reasons(r), /from before the update\./);
    const mitigation = r.actions.find((a) => /reload/.test(a.code || ''));
    assert.ok(mitigation, 'the interim mitigation is still offered');
    assert.match(mitigation.text, /if that change was a downgrade, install the fixed package first/);
  }
  // Apache: logrotate's graceful restart does not reload mod_php, so the reason no longer says it does.
  const apache = run(probe({ ...PROBE_BASE, php_version: JAMMY_FIXED, sapi: 'apache2handler', config_path: '/etc/php/8.1/apache2', os_release: JAMMY_OS, dpkg_packages: deb(MOD81, '8.1.2-1ubuntu2.20', 'php8.1') }));
  assert.equal(apache.verdict, 'vulnerable');
  assert.doesNotMatch(reasons(apache), /log rotation|reloads Apache/);
});

// ── R: RHEL family and Docker ───────────────────────────────────────

const ALMA9_LINES = ['env|root|1', 'os|ID|almalinux', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|9.8', 'os|PRETTY_NAME|AlmaLinux 9.8 (Olive Jaguar)'];
const ALMA10_LINES = ['env|root|1', 'os|ID|almalinux', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|10.2', 'os|PRETTY_NAME|AlmaLinux 10.2 (Lavender Lion)'];
const AL2023_LINES = ['env|root|1', 'os|ID|amzn', 'os|ID_LIKE|fedora', 'os|VERSION_ID|2023', 'os|PRETTY_NAME|Amazon Linux 2023.12.20261021'];
const INI = { memory_limit: '128M', 'session.upload_progress.enabled': '1', 'session.auto_start': '0', expose_php: '1' };
const RHEL_PROBE = { uname_release: '6.18.54.1-microsoft-standard-WSL2', open_basedir: false, dpkg_packages: null, extensions: { session: true, opcache: false }, ini: INI, self_deleted: true };
const rpm = (names, version) => names.map((n) => `pkg|rpm|${n}|${version}|`);

test('R1 server script output from another system is judged on its own, not dropped', () => {
  const docker = probe({ ...RHEL_PROBE, php_version: '8.4.27', sapi: 'apache2handler', config_path: '/usr/local/etc/php', server_software: 'Apache/2.4.69 (Debian)', container: true, os_release: { PRETTY_NAME: 'Debian GNU/Linux 13 (trixie)', ID: 'debian', VERSION_ID: '13', VERSION_CODENAME: 'trixie' }, dpkg_packages: [] })
    + server(['env|root|1', 'os|ID|alpine', 'os|VERSION_ID|3.20.10', 'os|PRETTY_NAME|Alpine Linux v3.20', ...rpm([], ''), 'pkg|apk|php83|8.3.15-r0|', 'pkg|apk|php83-common|8.3.15-r0|', 'pkg|apk|php83-fpm|8.3.15-r0|', 'proc|php-fpm83|1|ok', 'webuser_proc|0']);
  const remi = probe({ ...RHEL_PROBE, php_version: '8.2.35', sapi: 'fpm-fcgi', config_path: '/etc', server_software: 'Apache/2.4.62 (AlmaLinux)', container: true, os_release: { ID: 'almalinux', ID_LIKE: 'rhel centos fedora', VERSION_ID: '9.8', PRETTY_NAME: 'AlmaLinux 9.8 (Olive Jaguar)' } })
    + server([...ALMA9_LINES, ...rpm(['php74-php-common', 'php74-php-cli', 'php74-php-fpm'], '7.4.33-29.el9.remi'), ...logged(['php74-php-common', 'php74-php-cli', 'php74-php-fpm'], 0), 'proc|php-fpm|1|ok', 'webuser_proc|0']);
  for (const text of [docker, remi]) {
    for (const r of both(text)) assert.equal(r.verdict, 'vulnerable');
    assert.match(notes(run(text)), /2 separate outputs/);
  }
  assert.match(reasons(run(docker)), /PHP 8\.3\.15/);
});

test('R2 a stale php-fpm next to a current one of the same name is another PHP, not the probe\'s', () => {
  const text = probe({ ...RHEL_PROBE, php_version: '8.3.36', sapi: 'fpm-fcgi', config_path: '/etc', server_software: 'Apache/2.4.63 (AlmaLinux)', container: false, os_release: { ID: 'almalinux', ID_LIKE: 'rhel centos fedora', VERSION_ID: '10.2', PRETTY_NAME: 'AlmaLinux 10.2 (Lavender Lion)' } })
    + server([...ALMA10_LINES, ...rpm(['php-common', 'php-fpm', 'php-cli'], '8.3.36-1.el10_2'), ...logged(['php-common', 'php-fpm', 'php-cli'], 0), 'proc|php-fpm|1|ok', 'proc|php-fpm|1|stale', 'webuser_proc|0']);
  for (const r of both(text)) {
    assert.equal(r.verdict, 'restart');
    assert.ok(r.actions.some((a) => a.code === 'ps -o pid,user,cgroup,args -C php-fpm'));
  }
  // Positive control: stale processes alone, of the probe's SAPI, are the probe's own PHP waiting for a restart.
  const self = run(probe({ ...RHEL_PROBE, php_version: '8.3.36', sapi: 'fpm-fcgi', config_path: '/etc', container: false, os_release: { ID: 'almalinux', VERSION_ID: '10.2' } })
    + server([...ALMA10_LINES, ...rpm(['php-common', 'php-fpm'], '8.3.36-1.el10_2'), 'proc|php-fpm|3|stale']));
  assert.equal(self.verdict, 'patched');
});

test('R3 Alpine Apache with mod_php83.so, which the server script cannot see, is not "nothing running"', () => {
  const lines = ['env|root|1', 'os|ID|alpine', 'os|VERSION_ID|3.22.7', 'os|PRETTY_NAME|Alpine Linux v3.22', 'pkg|apk|php83|8.3.36-r0|', 'pkg|apk|php83-apache2|8.3.36-r0|', 'pkg|apk|php83-common|8.3.36-r0|'];
  for (const r of both(server([...lines, 'webuser_proc|0']))) {
    assert.equal(r.verdict, 'unknown');
    assert.ok(r.actions.some((a) => a.code === "ps -o pid,args | grep '[h]ttpd'"));
    assert.ok(r.actions.some((a) => a.code === 'rc-service apache2 restart'));
  }
  // Positive control: once the script reports the Apache processes, they are checked like any other.
  assert.equal(run(server([...lines, 'proc|httpd|4|ok'])).verdict, 'patched');
  assert.equal(run(server([...lines, 'proc|httpd|4|stale'])).verdict, 'restart');
});

test('R4 an open_basedir probe that cannot tell whether it runs in a container is not tied to a server script output', () => {
  const text = probe({ ...RHEL_PROBE, php_version: '8.0.30', php_extra_version: '', sapi: 'fpm-fcgi', php_os: 'Linux', config_path: '/etc', server_software: 'Apache/2.4.62 (AlmaLinux)', open_basedir: true, container: null, os_release: null })
    + server([...ALMA9_LINES, ...rpm(['php-common', 'php-fpm', 'php-cli'], '8.0.30-8.el9_8.1'), ...logged(['php-common', 'php-fpm', 'php-cli'], 1), 'proc|php-fpm|1|ok', 'webuser_proc|0']);
  for (const r of both(text)) assert.equal(r.verdict, 'unknown');
  assert.match(notes(run(text)), /could not see whether it runs in a container|open_basedir kept the PHP probe from seeing/);
  assert.equal(parseInput(text).parts[0].packages.length, 0, 'the server script packages are not credited to the probe');
  // Positive control: a probe that knows it is not in a container is still combined.
  const host = probe({ ...RHEL_PROBE, php_version: '8.0.30', sapi: 'fpm-fcgi', config_path: '/etc', container: false, os_release: { ID: 'almalinux', ID_LIKE: 'rhel centos fedora', VERSION_ID: '9.8' } })
    + server([...ALMA9_LINES, ...rpm(['php-common', 'php-fpm', 'php-cli'], '8.0.30-8.el9_8.1'), ...logged(['php-common', 'php-fpm', 'php-cli'], 1), 'proc|php-fpm|1|ok']);
  assert.equal(run(host).verdict, 'patched');
});

test('R6 a Remi collection of an end-of-life branch with no changelog read is Undetermined, not Vulnerable', () => {
  const remiProbe = probe({ ...RHEL_PROBE, php_version: '7.4.33', sapi: 'fpm-fcgi', config_path: '/etc/opt/remi/php74', server_software: 'Apache/2.4.62 (AlmaLinux)', container: false, os_release: { ID: 'almalinux', ID_LIKE: 'rhel centos fedora', VERSION_ID: '9.8', PRETTY_NAME: 'AlmaLinux 9.8 (Olive Jaguar)' } });
  for (const r of both(remiProbe)) {
    assert.equal(r.verdict, 'unknown');
    assert.match(r.actions[0].code, /php2shell-server-check\.sh$/);
  }
  assert.match(reasons(run(remiProbe)), /changelog/);
  assert.doesNotMatch(all(run(remiProbe)), /follows upstream versions/);
  // With the changelog of exactly this build: Patched when it records both, Vulnerable when it was read without them.
  const pkgs = ['php74-php-common', 'php74-php-cli', 'php74-php-fpm'];
  assert.equal(run(remiProbe + server([...ALMA9_LINES, ...rpm(pkgs, '7.4.33-31.el9.remi'), ...logged(pkgs, 1), 'proc|php-fpm|1|ok'])).verdict, 'patched');
  assert.equal(run(remiProbe + server([...ALMA9_LINES, ...rpm(pkgs, '7.4.33-29.el9.remi'), ...logged(pkgs, 0), 'proc|php-fpm|1|ok'])).verdict, 'vulnerable');
});

test('R7 a RHEL build older than the build Red Hat names as fixed, with no changelog entry, is Vulnerable', () => {
  const alma = server([...ALMA9_LINES, ...rpm(['php-common', 'php-fpm', 'php-cli'], '8.0.30-8.el9_8'), ...logged(['php-common', 'php-fpm', 'php-cli'], 0), 'proc|php-fpm|1|ok', 'webuser_proc|0']);
  const rhel10 = server([...ALMA10_LINES, ...rpm(['php-common', 'php-fpm'], '8.3.30-1.el10_1'), ...logged(['php-common', 'php-fpm'], 0), 'proc|php-fpm|1|ok']);
  const al2 = server(['env|root|1', 'os|ID|amzn', 'os|ID_LIKE|centos rhel fedora', 'os|VERSION_ID|2', ...rpm(['php-common', 'php-fpm'], '8.2.30-1.amzn2.0.1'), ...logged(['php-common', 'php-fpm'], 0), 'proc|php-fpm|1|ok']);
  for (const text of [alma, rhel10, al2]) {
    for (const r of both(text)) assert.equal(r.verdict, 'vulnerable', text.slice(60, 160));
  }
  assert.match(reasons(run(alma)), /older than 8\.0\.30-8\.el9_8\.1, the build that fixes both CVEs \(RHSA-2026:87151\)/);
  // A module stream build: the advisory names no package version, so it stays Undetermined.
  const module = server([...ALMA9_LINES, ...rpm(['php-common', 'php-fpm'], '8.2.13-1.module_el9.4.0+20844+7c41d8d0'), ...logged(['php-common', 'php-fpm'], 0), 'proc|php-fpm|1|ok']);
  assert.equal(run(module).verdict, 'unknown');
});

test('R8 Amazon Linux 2023: no "built from source" claim, and the update is confirmed by its version', () => {
  const text = probe({ ...RHEL_PROBE, php_version: '8.3.20', sapi: 'fpm-fcgi', config_path: '/etc', server_software: 'Apache/2.4.69 (Amazon Linux)', container: false, os_release: { ID: 'amzn', ID_LIKE: 'fedora', VERSION_ID: '2023', PRETTY_NAME: 'Amazon Linux 2023.12.20261021' } })
    + server([...AL2023_LINES, 'proc|php-fpm|1|ok', 'webuser_proc|0']);
  for (const r of both(text)) {
    assert.equal(r.verdict, 'vulnerable');
    assert.doesNotMatch(codes(r), /rpm -q --changelog php-common/);
  }
  assert.doesNotMatch(notes(run(text)), /so this PHP was built from source or comes/);
  assert.match(notes(run(text)), /current server script/);
  assert.match(actionText(run(text)), /each package version below should now start with 8\.3\.36/);
  // The server script now lists php8.3-* packages: the upstream fixed release is Patched, an older one Vulnerable.
  const pkgs = ['php8.3-common', 'php8.3-cli', 'php8.3-fpm'];
  assert.equal(run(server([...AL2023_LINES, ...rpm(pkgs, '8.3.36-1.amzn2023.0.1'), ...logged(pkgs, 0), 'proc|php-fpm|1|ok'])).verdict, 'patched');
  assert.equal(run(server([...AL2023_LINES, ...rpm(pkgs, '8.3.20-1.amzn2023.0.1'), ...logged(pkgs, 0), 'proc|php-fpm|1|ok'])).verdict, 'vulnerable');
});

// ── C: crafted inputs ───────────────────────────────────────────────

const D12_PROBE = probe({ php_version: '8.2.35', sapi: 'fpm-fcgi', config_path: '/etc/php/8.2/fpm', os_release: { ID: 'debian', VERSION_ID: '12', VERSION_CODENAME: 'bookworm' }, dpkg_packages: [{ name: 'php8.2-fpm', version: '8.2.35-1~deb12u1', source: 'php8.2' }], container: false, open_basedir: false });
const D12_SERVER = ['env|root|1', 'os|ID|debian', 'os|VERSION_ID|12', 'os|VERSION_CODENAME|bookworm', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2'];

test('C1 ok and stale lines of the same php-fpm name are two masters: the stale one is not the probe\'s', () => {
  for (const r of both(D12_PROBE + server([...D12_SERVER, 'proc|php-fpm8.2|3|ok', 'proc|php-fpm8.2|2|stale']))) assert.equal(r.verdict, 'restart');
  // Positive control: all stale, so the probe's own pool waits for a restart.
  assert.equal(run(D12_PROBE + server([...D12_SERVER, 'proc|php-fpm8.2|3|stale'])).verdict, 'patched');
});

test('C2 PHP processes the server script could not check rule out Patched, also next to a probe that shows the fix', () => {
  for (const last of ['proc|unreadable|4|unknown', 'proc|apache2|4|']) {
    for (const r of both(D12_PROBE + server([...D12_SERVER, 'proc|php-fpm8.2|3|ok', last]))) assert.equal(r.verdict, 'unknown', last);
  }
  assert.equal(run(D12_PROBE + server([...D12_SERVER, 'proc|php-fpm8.2|3|ok'])).verdict, 'patched');
});

test('C3 without root, processes the script saw are not all that run: a web-serving build is not Patched', () => {
  const jammy = server(['env|root|0', 'os|ID|ubuntu', 'os|VERSION_ID|22.04', 'os|VERSION_CODENAME|jammy', 'pkg|dpkg|libapache2-mod-php8.1|8.1.2-1ubuntu2.28|php8.1',
    'pkg|dpkg|php8.1-fpm|8.1.2-1ubuntu2.28|php8.1', 'pkg|dpkg|php8.1-common|8.1.2-1ubuntu2.28|php8.1', 'proc|php-fpm8.1|2|ok']);
  const rocky = server(['env|root|0', 'os|ID|rocky', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|9.4', ...rpm(['php-common', 'php-fpm'], '8.2.13-1.module+el9.4.0+20827+3f2b0b48'),
    ...logged(['php-common', 'php-fpm'], 1), 'proc|php-fpm|3|ok']);
  for (const text of [jammy, rocky]) {
    for (const r of both(text)) {
      assert.equal(r.verdict, 'unknown');
      assert.match(r.actions[0].text, /sudo|root/);
    }
  }
});

test('C4 a fixed running PHP over an older unfixed package of its own SAPI is Vulnerable', () => {
  const os12 = { ID: 'debian', VERSION_ID: '12', VERSION_CODENAME: 'bookworm' };
  const cases = [
    probe({ php_version: '8.2.35', sapi: 'fpm-fcgi', config_path: '/etc/php/8.2/fpm', os_release: os12, dpkg_packages: deb(['php8.2-fpm', 'php8.2-common'], '8.2.29-1~deb12u1', 'php8.2'), container: false, open_basedir: false }),
    probe({ php_version: '8.2.35', sapi: 'apache2handler', config_path: '/etc/php/8.2/apache2', os_release: os12, dpkg_packages: deb(['libapache2-mod-php8.2'], '8.2.29-1~deb12u1', 'php8.2'), container: false, open_basedir: false }),
    probe({ php_version: '8.3.36', sapi: 'fpm-fcgi', config_path: '/etc/php/8.3/fpm', os_release: { ID: 'ubuntu', VERSION_ID: '24.04' }, dpkg_packages: deb(['php8.3-fpm'], '8.3.6-0ubuntu0.24.04.4', 'php8.3'), container: false, open_basedir: false }),
  ];
  for (const text of cases) {
    for (const r of both(text)) assert.equal(r.verdict, 'vulnerable');
  }
  // Positive control: a PHP configured outside the package's directory is not that package.
  assert.equal(run(probe({ php_version: '8.2.35', sapi: 'fpm-fcgi', config_path: '/opt/php/etc', os_release: os12, dpkg_packages: deb(['php8.2-fpm'], '8.2.29-1~deb12u1', 'php8.2') })).verdict, 'patched');
});

test('C5 C6 every PHP version in a paste is judged: bare lines, Server headers and merged X-Powered-By values', () => {
  const pastes = [
    '8.4.27\n8.4.20\n',
    'PHP/8.4.27\nPHP/8.4.20\n',
    'HTTP/1.1 301 Moved Permanently\nServer: Apache/2.4.62 (Unix) PHP/8.4.27\nLocation: https://www.example.com/\n\nHTTP/1.1 200 OK\nServer: Apache/2.4.29 (Unix) PHP/8.4.20\n',
    'HTTP/1.1 301 Moved Permanently\nX-Powered-By: PHP/8.4.27\n\nHTTP/2 200\nx-powered-by: PleskLin, PHP/8.4.20\n',
    'X-Powered-By: PHP/8.4.27, PHP/8.4.20\n',
  ];
  for (const text of pastes) {
    for (const r of both(text)) assert.equal(r.verdict, 'vulnerable', text);
    assert.equal(parseInput(text).parts.length, 2, text);
  }
  // The tester's own versions (8.2.20, 7.4.33) may be RHEL module builds: Undetermined, never Patched.
  for (const text of ['8.4.27\n8.2.20\n', 'X-Powered-By: PHP/8.4.27, PHP/8.2.20\n', 'HTTP/1.1 301 Moved\nServer: Apache/2.4.62 (Unix) PHP/8.4.27\n\nHTTP/1.1 200 OK\nServer: Apache/2.4.29 (Unix) PHP/7.4.33\n']) {
    assert.notEqual(run(text).verdict, 'patched', text);
  }
  // Positive controls: one version alone, and the same version twice, are one output.
  assert.equal(run('8.4.27').verdict, 'patched');
  assert.equal(parseInput('X-Powered-By: PHP/8.4.27\nServer: nginx PHP/8.4.27\n').parts, undefined);
});

test('C7 php5-fpm, which the server script cannot see, is not "no running PHP"; a php5-fpm line maps to its build', () => {
  const trusty = ['env|root|1', 'os|ID|ubuntu', 'os|ID_LIKE|debian', 'os|VERSION_ID|14.04', 'os|PRETTY_NAME|Ubuntu 14.04.6 LTS',
    'pkg|dpkg|php5-fpm|5.5.9+dfsg-1ubuntu4.29+esm18|php5', 'pkg|dpkg|php5-common|5.5.9+dfsg-1ubuntu4.29+esm18|php5', 'pkg|dpkg|php5-cli|5.5.9+dfsg-1ubuntu4.29+esm18|php5'];
  for (const r of both(server(trusty))) {
    assert.equal(r.verdict, 'unknown');
    assert.ok(r.actions.some((a) => a.code === 'ps -o pid,lstart,args -C php5-fpm'));
    assert.ok(r.actions.some((a) => a.code === 'sudo service php5-fpm restart'));
  }
  assert.equal(run(server([...trusty, 'proc|php5-fpm|3|ok'])).verdict, 'patched');
  assert.equal(run(server([...trusty, 'proc|php5-fpm|3|stale'])).verdict, 'restart');
});

test('C8 an open_basedir probe of unknown container status is not judged by an Ubuntu host\'s package', () => {
  const text = probe({ php_version: '8.3.6', sapi: 'fpm-fcgi', config_path: '/etc/php/8.3/fpm', os_release: null, open_basedir: true, container: null, dpkg_packages: null, uname_release: '6.8.0-45-generic' })
    + server(['env|root|1', 'os|ID|ubuntu', 'os|VERSION_ID|24.04', `pkg|dpkg|php8.3-fpm|${NOBLE_FIXED}|php8.3`, 'proc|php-fpm8.3|4|ok']);
  for (const r of both(text)) assert.equal(r.verdict, 'unknown');
});

test('C9 a Debian snapshot version with "~" before the release is a pre-release', () => {
  for (const r of both(server(['env|root|1', 'os|ID|debian', 'os|VERSION_ID|13', 'pkg|dpkg|php8.4-fpm|8.4.27~git20261001-1|php8.4', 'proc|php-fpm8.4|2|ok']))) {
    assert.equal(r.verdict, 'unknown');
    assert.match(reasons(r), /8\.4\.27~git20261001-1/);
  }
  assert.equal(run(server(['env|root|1', 'os|ID|debian', 'os|VERSION_ID|13', 'pkg|dpkg|php8.4-fpm|8.4.27-1~deb13u1|php8.4', 'proc|php-fpm8.4|2|ok'])).verdict, 'patched');
});

test('C10 a bare 8.2.x or 8.3.x below the fix may be a RHEL module stream build', () => {
  for (const text of ['X-Powered-By: PHP/8.2.13\n', 'PHP 8.2.13 (cli) (built: Oct 20 2026 12:00:00) (NTS)', 'X-Powered-By: PHP/8.3.20\n']) {
    for (const r of both(text)) assert.equal(r.verdict, 'unknown', text);
    assert.match(reasons(run(text)), /RHEL (8, RHEL 9|9)/, text);
  }
  // Positive controls: a branch with no such fix, and a Distribution list choice, are judged by version.
  assert.equal(run('X-Powered-By: PHP/8.4.20').verdict, 'vulnerable');
  assert.equal(run('X-Powered-By: PHP/8.2.13', { distro: 'debian:12' }).verdict, 'vulnerable');
});

test('C11 a Remi end-of-life collection whose changelog was not read is Undetermined', () => {
  const remi = { php_version: '7.4.33', sapi: 'fpm-fcgi', config_path: '/etc/opt/remi/php74', os_release: { ID: 'rocky', ID_LIKE: 'rhel centos fedora', VERSION_ID: '9.4' }, dpkg_packages: null, container: false, open_basedir: false };
  const lines = ['env|root|1', 'os|ID|rocky', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|9.4', 'pkg|rpm|php74-php-common|7.4.33-18.el9.remi|', 'pkg|rpm|php74-php-fpm|7.4.33-18.el9.remi|', 'proc|php-fpm|3|ok'];
  for (const text of [probe(remi), server(lines), server([...lines, ...logged(['php74-php-common', 'php74-php-fpm'], { 'CVE-2026-109618': 'unknown', 'CVE-2026-109619': 'unknown' })])]) {
    for (const r of both(text)) assert.equal(r.verdict, 'unknown', text.slice(0, 80));
  }
});

test('C12 SUSE backports into its own PHP packages: Undetermined, with zypper and no RHEL package or source build', () => {
  const sles = probe({ php_version: '8.0.30', sapi: 'apache2handler', config_path: '/etc/php8/apache2', os_release: { ID: 'sles', ID_LIKE: 'suse', VERSION_ID: '15.5', PRETTY_NAME: 'SUSE Linux Enterprise Server 15 SP5' }, dpkg_packages: null, container: false, open_basedir: false });
  for (const r of both(sles)) {
    assert.equal(r.verdict, 'unknown');
    assert.doesNotMatch(codes(r), /make install|git clone|dnf|apt-get/);
    assert.ok(r.actions.some((a) => a.code === "sudo zypper refresh\nsudo zypper update 'php8*'"));
    assert.ok(r.actions.some((a) => /rpm -q --changelog php8 \| grep -e CVE-2026-109618 -e CVE-2026-109619/.test(a.code || '')));
  }
  assert.doesNotMatch(actionText(run(sles)), /RHEL 9 \(/);
});

test('C13 CentOS 6: the server script\'s "rhel" from /etc/redhat-release is the same system as the probe\'s CentOS', () => {
  const text = probe({ php_version: '5.3.3', sapi: 'apache2handler', config_path: '/etc', os_release: { 'LEGACY_REDHAT-RELEASE': 'CentOS release 6.10 (Final)' }, open_basedir: false, container: false, dpkg_packages: null, uname_release: '2.6.32-754.35.1.el6.x86_64' })
    + server(['env|root|1', 'os|ID|rhel', 'os|VERSION_ID|6', 'pkg|rpm|php|5.3.3-50.el6_10|', 'pkg|rpm|php-common|5.3.3-50.el6_10|', ...logged(['php', 'php-common'], 1), 'proc|httpd|5|ok']);
  for (const r of both(text)) assert.equal(r.verdict, 'patched');
  assert.doesNotMatch(notes(run(text)), /another system/);
  // A different release is still another system.
  const other = probe({ php_version: '5.3.3', sapi: 'apache2handler', config_path: '/etc', os_release: { 'LEGACY_REDHAT-RELEASE': 'CentOS release 6.10 (Final)' }, dpkg_packages: null })
    + server(['env|root|1', 'os|ID|rhel', 'os|VERSION_ID|7', 'pkg|rpm|php|5.4.16-48.el7|', 'proc|httpd|5|ok']);
  assert.match(notes(run(other)), /another system/);
});

test('C14 processes unreadable as root: the advice is the host or the probe, not sudo again', () => {
  const text = server(['env|root|1', 'os|ID|debian', 'os|VERSION_ID|12', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2', 'proc|unreadable|3|unknown']);
  for (const r of both(text)) {
    assert.equal(r.verdict, 'unknown');
    assert.match(r.actions[0].text, /CAP_SYS_PTRACE/);
  }
  const r = run(text);
  assert.doesNotMatch(notes(r), /missing permissions/);
  assert.doesNotMatch(r.actions[0].text, /^Run the server script again as root \(with sudo\)/);
  // Without root it is a matter of permissions.
  const nonRoot = run(server(['env|root|0', 'os|ID|debian', 'os|VERSION_ID|12', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2', 'proc|unreadable|3|unknown']));
  assert.match(notes(nonRoot), /missing permissions/);
});

test('C15 end-of-life steps use the real binary names, warn about deb.sury.org, and build from source only for a self-built PHP', () => {
  const jammySury = probe({ php_version: '7.4.33', sapi: 'fpm-fcgi', config_path: '/etc/php/7.4/fpm', os_release: { ID: 'ubuntu', VERSION_ID: '22.04', VERSION_CODENAME: 'jammy' },
    dpkg_packages: [{ name: 'php7.4-fpm', version: '1:7.4.33-1+ubuntu22.04.1+deb.sury.org+1', source: 'php7.4' }], container: false, open_basedir: false });
  for (const r of both(jammySury)) {
    assert.notEqual(r.verdict, 'patched');
    assert.doesNotMatch(codes(r), /php-fpm -i|make install/);
    const host = r.actions.find((a) => /apt-get install php8\.1-fpm/.test(a.code || ''));
    assert.ok(host);
    assert.match(host.code, /apt-cache policy php8\.1-fpm/);
    assert.match(host.text, /deb\.sury\.org/);
  }
  const alpine = server(['env|root|1', 'os|ID|alpine', 'os|VERSION_ID|3.19.4', 'pkg|apk|php81|8.1.31-r0|', 'pkg|apk|php81-fpm|8.1.31-r0|', 'proc|php-fpm81|2|ok']);
  for (const r of both(alpine)) {
    assert.equal(r.verdict, 'vulnerable');
    assert.doesNotMatch(codes(r), /php-fpm -i|make install/);
  }
  // A self-built PHP still gets the php-src backport branch, with the binary of its SAPI.
  const self = run(probe({ php_version: '8.1.30', sapi: 'fpm-fcgi', config_path: '/usr/local/lib', os_release: { ID: 'debian', VERSION_ID: '12' }, dpkg_packages: [] }));
  assert.match(codes(self), /^php-fpm -i \| grep -i 'configure command'\ngit clone/m);
});

// ── X: rendering and robustness ─────────────────────────────────────

test('X1 a SAPI named like an Object member never throws and is shown as it is', () => {
  for (const sapi of ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__', 'isPrototypeOf', 'toLocaleString', '__defineGetter__']) {
    for (const os of [{ ID: 'ubuntu', VERSION_ID: '22.04' }, null]) {
      const text = probe({ php_version: '8.1.2-1ubuntu2.20', sapi, config_path: '/etc/php/8.1/fpm', os_release: os, dpkg_packages: [{ name: 'php8.1-common', version: '8.1.2-1ubuntu2.20', source: 'php8.1' }] });
      for (const r of both(text)) {
        assert.ok(['vulnerable', 'unknown'].includes(r.verdict), `${sapi}: ${r.verdict}`);
        for (const value of [...r.facts.map((f) => f.value), r.exposure?.text || '', ...r.actions.map((a) => `${a.text} ${a.code || ''}`)]) {
          assert.doesNotMatch(value, /function |native code|\[object /, `${sapi}: ${value}`);
        }
      }
    }
    assert.equal(sapiLabel(sapi), sapi);
  }
});

test('X2 X3 settings and OS release values that are not text are left out, never shown as [object Object]', () => {
  const texts = [
    JSON.stringify({ tool: 'php2shell-selfcheck', php_version: '8.2.20', sapi: 'fpm-fcgi', ini: { expose_php: { toString: 0 } } }),
    JSON.stringify({ tool: 'php2shell-selfcheck', php_version: '8.2.20', sapi: 'fpm-fcgi', ini: { memory_limit: {}, 'session.upload_progress.enabled': [], expose_php: 1 } }),
    probe({ php_version: '8.2.20', sapi: 'fpm-fcgi', os_release: { ID: { a: 1 }, VERSION_ID: '9' } }),
    probe({ php_version: '8.2.20', sapi: 'fpm-fcgi', os_release: { ID: 'ubuntu', VERSION_ID: ['2', '2'] } }),
    probe({ php_version: '8.2.20', sapi: 'fpm-fcgi', dpkg_packages: [{ name: { x: 1 }, version: '1' }, { name: 'php8.2-fpm', version: ['8.2.20'] }] }),
  ];
  for (const text of texts) {
    for (const r of both(text)) {
      const shown = [...r.facts.map((f) => f.value), ...r.notes, ...r.reasons, ...r.mitigations.map((m) => `${m.name} ${m.value} ${m.note}`)].join('\n');
      assert.doesNotMatch(shown, /\[object |undefined/, text);
    }
  }
  const mit = run(texts[1]).mitigations;
  assert.equal(mit.find((m) => m.name === 'memory_limit').value, '(not set)');
  assert.equal(mit.find((m) => m.name === 'expose_php').value, '1');
});

test('X4 a large paste is read in time proportional to its size', () => {
  const markers = '-----BEGIN PHP2SHELL SELFCHECK-----\n'.repeat(58000);
  let start = Date.now();
  const r1 = run(markers);
  assert.ok(Date.now() - start < 3000, `marker paste took ${Date.now() - start} ms`);
  assert.notEqual(r1.verdict, 'patched');
  start = Date.now();
  const r2 = run(`PHP 8.1.${'7'.repeat(64000)}`);
  assert.ok(Date.now() - start < 1000, `digit paste took ${Date.now() - start} ms`);
  assert.notEqual(r2.verdict, 'patched');
  // An input over the limit is cut, and what was cut may be worse, so it is never Patched.
  const long = `X-Powered-By: PHP/8.4.27\n${' '.repeat(2000001)}\nX-Powered-By: PHP/8.2.20\n`;
  const r3 = run(long);
  assert.notEqual(r3.verdict, 'patched');
  assert.match(notes(r3), /2 million characters/);
});

test('X5 a changelog line cannot change the changelog of another package', () => {
  const text = server(['env|root|1', 'os|ID|rocky', 'os|VERSION_ID|9.4', 'pkg|rpm|php-common|8.2.13-1.module+el9.4.0+20827+3f2b0b48|', 'pkg|rpm|php-fpm|8.2.13-1.module+el9.4.0+20827+3f2b0b48|',
    'changelog|__proto__|CVE-2026-109618|1', 'changelog|__proto__|CVE-2026-109619|1', 'changelog|php-common|__proto__|1', 'log|__proto__|1', 'proc|php-fpm|2|ok']);
  for (const r of both(text)) assert.equal(r.verdict, 'unknown');
  assert.equal({}['CVE-2026-109618'], undefined, 'nothing reaches Object.prototype');
});

test('X6 the engine never throws, so the page always shows a result', () => {
  for (const obs of [{}, { parts: [{}, null] }, { phpVersion: '8.2.20', packages: null }]) {
    for (const lang of ['en', 'ko']) {
      const r = judge(obs, upstream, distro, { lang });
      assert.equal(r.verdict, 'unknown');
      assert.equal(typeof r.title, 'string');
      assert.ok(r.reasons.length > 0);
      for (const k of ['actions', 'facts', 'mitigations', 'notes', 'advisories', 'findings']) assert.ok(Array.isArray(r[k]), k);
    }
  }
  // A probe output copied without its BEGIN line is read too.
  const headless = `php2shell-selfcheck 1.0.0\n${JSON.stringify({ tool: 'php2shell-selfcheck', php_version: '8.4.27', sapi: 'fpm-fcgi' })}\n-----END PHP2SHELL SELFCHECK-----\n`;
  assert.equal(parseInput(headless).phpVersion, '8.4.27');
});

// ── N: notes from the server script and probe work ──────────────────

const ALMA10_84 = (version, n = 0) => [...ALMA10_LINES, ...rpm(['php8.4-common', 'php8.4-cli', 'php8.4-fpm', 'php8.4'], version),
  ...logged(['php8.4-common', 'php8.4-cli', 'php8.4-fpm', 'php8.4'], n)];
const AL2023_84 = (version) => [...AL2023_LINES, ...rpm(['php8.4-common', 'php8.4-cli', 'php8.4-fpm', 'php8.4-modphp'], version),
  ...logged(['php8.4-common', 'php8.4-cli', 'php8.4-fpm', 'php8.4-modphp'], 0)];

test('N1 RHEL 10 and Amazon Linux 2023 php8.4 packages run php-fpm and httpd', () => {
  for (const text of [server([...ALMA10_84('8.4.27-1.el10_2'), 'proc|php-fpm|1|ok', 'webuser_proc|unknown']),
    server([...AL2023_84('8.4.27-1.amzn2023.0.1'), 'proc|httpd|1|ok', 'proc|php-fpm|1|ok'])]) {
    for (const r of both(text)) assert.equal(r.verdict, 'patched');
  }
  for (const text of [server([...ALMA10_84('8.4.27-1.el10_2'), 'proc|php-fpm|1|stale']), server([...AL2023_84('8.4.27-1.amzn2023.0.1'), 'proc|php-fpm|1|stale'])]) {
    const r = run(text);
    assert.equal(r.verdict, 'restart');
    assert.equal(r.actions[0].code, 'sudo systemctl restart php-fpm');
  }
});

test('N2 an update that is a new upstream release is confirmed by its version, not by CVE lines in the changelog', () => {
  const alma = run(server([...ALMA10_84('8.4.24-1.el10_2'), 'proc|php-fpm|1|ok']));
  assert.equal(alma.verdict, 'vulnerable');
  assert.ok(alma.actions.some((a) => a.code === 'rpm -q php8.4-common php8.4-cli php8.4-fpm php8.4' && /8\.4\.27-1\.el10_2 or later/.test(a.text)));
  assert.doesNotMatch(codes(alma), /rpm -q --changelog/);
  const amazon = run(server([...AL2023_84('8.4.26-1.amzn2023.0.1'), 'proc|php-fpm|1|ok']));
  assert.equal(amazon.verdict, 'vulnerable');
  assert.doesNotMatch(codes(amazon), /rpm -q --changelog/);
  // A Red Hat backport is still confirmed in the changelog.
  const rhel9 = run(server([...ALMA9_LINES, ...rpm(['php-common', 'php-fpm'], '8.0.30-8.el9_8'), ...logged(['php-common', 'php-fpm'], 0), 'proc|php-fpm|1|ok']));
  assert.match(codes(rhel9), /rpm -q --changelog php-common \| grep -e CVE-2026-109618 -e CVE-2026-109619/);
});

test('every result of this round is the same shape in both languages', () => {
  const inputs = [F1, F2, F3_PROBE + F3_HEADLESS, F6_PROBE, F7_PROBE + F7_SERVER, F4_DEB, F4_PPA_PROBE, F5, D12_PROBE + server([...D12_SERVER, 'proc|php-fpm8.2|3|ok', 'proc|unreadable|4|unknown'])];
  for (const text of inputs) {
    const [en, ko] = both(text);
    assert.equal(ko.verdict, en.verdict);
    for (const k of ['reasons', 'notes', 'actions', 'facts', 'advisories']) assert.equal(ko[k].length, en[k].length, k);
    for (const a of ko.actions) assert.match(a.text, /[가-힣]/);
    assert.deepEqual(verdicts(text), [en.verdict, en.verdict]);
  }
});
