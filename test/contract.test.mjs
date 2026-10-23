// Regression tests for the engine side of the server script, PHP probe and page contract: what the script and the
// probe now emit (env|root, changelog lines, unknown counts, os_release null, open_basedir, the legacy release keys)
// and what the page reads from a result (r.family, string facts and advisories). Real data files in site/data/.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseInput } from '../site/lib/parse.js';
import { judge, sapiExposure } from '../site/lib/judge.js';

const upstream = JSON.parse(readFileSync(new URL('../site/data/upstream.json', import.meta.url), 'utf8'));
const distro = JSON.parse(readFileSync(new URL('../site/data/distro.json', import.meta.url), 'utf8'));

const probe = (fields) => `-----BEGIN PHP2SHELL SELFCHECK-----\n${JSON.stringify({ tool: 'php2shell-selfcheck', tool_version: '1.0.0', schema: 1, ...fields })}\n-----END PHP2SHELL SELFCHECK-----\n`;
const server = (lines) => `-----BEGIN PHP2SHELL SERVERCHECK-----\n${['tool|php2shell-server-check|1.0.0', ...lines].join('\n')}\n-----END PHP2SHELL SERVERCHECK-----\n`;
const run = (text, options = {}, data = distro) => judge(parseInput(text, { lang: options.lang }), upstream, data, options);
const both = (text, options = {}) => ['en', 'ko'].map((lang) => run(text, { ...options, lang }));
const reasons = (r) => r.reasons.join(' ');
const notes = (r) => r.notes.join(' ');
const fact = (r, label) => r.facts.find((f) => f.label === label)?.value;
const actionText = (r) => r.actions.map((a) => `${a.text} ${a.code || ''}`).join(' ');

const ROCKY94 = ['env|root|1', 'os|ID|rocky', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|9.4'];
const NOBLE = ['env|root|1', 'os|ID|ubuntu', 'os|ID_LIKE|debian', 'os|VERSION_ID|24.04', 'os|VERSION_CODENAME|noble'];
const MODULE = '8.2.13-1.module+el9.4.0+20827+3f2b0b48';
const CVES = ['CVE-2026-109618', 'CVE-2026-109619'];
const logged = (pkg, n) => CVES.map((cve) => `changelog|${pkg}|${cve}|${n}`);

// ── Changelog lines ─────────────────────────────────────────────────

test('a package with no changelog lines was not checked, which is never a count of 0', () => {
  // php-fpm, the package that runs, is another build than the php-common whose changelog was read.
  const mixed = server([...ROCKY94, `pkg|rpm|php-common|${MODULE}|`, 'pkg|rpm|php-fpm|8.2.13-1.module+el9.2.0+19000+aaaaaaaa|', ...logged('php-common', 1), 'proc|php-fpm|4|ok']);
  for (const r of both(mixed)) {
    assert.equal(r.verdict, 'unknown');
    assert.match(reasons(r), /php-fpm 8\.2\.13-1\.module\+el9\.2\.0/);
  }
  assert.match(reasons(run(mixed)), /was not checked/);
  assert.doesNotMatch(reasons(run(mixed)), /has no record of a fix/);
  // Positive control: a package of exactly the same build carries the same changelog.
  const same = server([...ROCKY94, `pkg|rpm|php-common|${MODULE}|`, `pkg|rpm|php-fpm|${MODULE}|`, ...logged('php-common', 1), 'proc|php-fpm|4|ok']);
  assert.equal(run(same).verdict, 'patched');

  // No changelog lines at all: not checked, not "not updated yet".
  const none = run(server([...ROCKY94, `pkg|rpm|php-common|${MODULE}|`, `pkg|rpm|php-fpm|${MODULE}|`, 'proc|php-fpm|4|ok']));
  assert.equal(none.verdict, 'unknown');
  assert.match(reasons(none), /was not checked/);
  assert.doesNotMatch(reasons(none), /has no record|not been updated/);

  // A Debian package without changelog lines is not credited with a fix it was never checked for.
  const deb = run(server(['env|root|1', 'os|ID|debian', 'os|VERSION_ID|11', 'pkg|dpkg|php7.4-fpm|7.4.33-1+deb11u9|php7.4', 'proc|php-fpm7.4|3|ok']));
  assert.equal(deb.verdict, 'unknown');
  assert.doesNotMatch(reasons(deb), /treated as fixed|has no record of a fix/);
  const obs = parseInput(server(['env|root|1', 'pkg|dpkg|php7.4-fpm|7.4.33-1+deb11u9|php7.4']));
  assert.equal(obs.packages[0].changelog, undefined);
});

test('a changelog count that is missing or not a number is not checked, never 0', () => {
  for (const lines of [
    ['changelog|php-common|CVE-2026-109618|1', 'changelog|php-common|CVE-2026-109619|'],
    ['changelog|php-common|CVE-2026-109618|1', 'changelog|php-common|CVE-2026-109619|unknown'],
    ['changelog|php-common|CVE-2026-109618|1'],
  ]) {
    const block = server([...ROCKY94, `pkg|rpm|php-common|${MODULE}|`, `pkg|rpm|php-fpm|${MODULE}|`, ...lines, 'proc|php-fpm|4|ok']);
    for (const r of both(block)) assert.equal(r.verdict, 'unknown', lines.join(' '));
    const r = run(block);
    assert.match(reasons(r), /was not checked for CVE-2026-109619/, lines.join(' '));
    assert.doesNotMatch(reasons(r), /has no record of a fix/, lines.join(' '));
  }
  // A count of 0 is a changelog that was read and has no entry.
  const zero = run(server([...ROCKY94, `pkg|rpm|php-common|${MODULE}|`, 'changelog|php-common|CVE-2026-109618|1', 'changelog|php-common|CVE-2026-109619|0']));
  assert.match(reasons(zero), /has no record of a fix for CVE-2026-109619/);
  assert.equal(parseInput(server(['pkg|rpm|php-common|8.2.13-1.el9|', 'changelog|php-common|CVE-2026-109619|unknown'])).packages[0].changelog['CVE-2026-109619'], null);
});

// ── Unknown counts ──────────────────────────────────────────────────

test('an unknown count never gives a "nothing suspicious" (Clear) finding', () => {
  const base = [...NOBLE, 'pkg|dpkg|php8.3-fpm|8.3.6-0ubuntu0.24.04.13|php8.3', 'proc|php-fpm8.3|3|ok'];
  const counts = { 'log|oom': 'logs', 'log|crash': 'logs', 'log|bigsession': 'session files', webuser_proc: 'web server account processes', 'webroot|recent_php': 'web root' };
  for (const [key, source] of Object.entries(counts)) {
    const lines = Object.keys(counts).map((k) => `${k}|${k === key ? 'unknown' : 0}`);
    for (const r of both(server([...base, ...lines]))) {
      assert.ok(!r.findings.some((f) => f.level === 'ok'), key);
      assert.ok(r.findings.some((f) => f.level === 'info'), key);
    }
    assert.match(run(server([...base, ...lines])).findings.map((f) => f.text).join(' '), new RegExp(`could not be read \\(${source}\\)`), key);
  }
  // Several outputs: one clean output does not make the other's unread source "nothing suspicious".
  const two = run(server([...base, 'webuser_proc|0']) + server(['env|root|1', 'os|ID|debian', 'os|VERSION_ID|12', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2', 'proc|php-fpm8.2|3|ok', 'webuser_proc|unknown']));
  assert.ok(two.parts === undefined && two.findings.length > 0);
  assert.ok(!two.findings.some((f) => f.level === 'ok'));
  // Positive control: zero counts from sources that were all read, as root, are Clear, and say what was checked.
  const clean = run(server([...base, 'webuser_proc|0']));
  assert.deepEqual(clean.findings.map((f) => f.level), ['ok']);
  assert.match(clean.findings[0].text, /\(web server account processes\)/);
  assert.doesNotMatch(clean.findings[0].text, /logs|web root/);
  assert.match(run(server([...base, 'webuser_proc|0']), { lang: 'ko' }).findings[0].text, /웹 서버 계정 프로세스/);
});

// ── env|root|0 ──────────────────────────────────────────────────────

test('env|root|0 with no proc lines means the processes were not checked', () => {
  const nonRoot = ['env|root|0', 'os|ID|ubuntu', 'os|VERSION_ID|24.04', 'os|VERSION_CODENAME|noble'];
  for (const r of both(server([...nonRoot, 'pkg|dpkg|php8.3-fpm|8.3.6-0ubuntu0.24.04.13|php8.3', 'webuser_proc|unknown']))) {
    assert.equal(r.verdict, 'unknown');
  }
  // A CLI-only build has no web service process, so it stays Patched, but never with "no PHP process was found".
  const [en, ko] = both(server([...nonRoot, 'pkg|dpkg|php8.3-cli|8.3.6-0ubuntu0.24.04.13|php8.3', 'pkg|dpkg|php8.3-common|8.3.6-0ubuntu0.24.04.13|php8.3']));
  assert.equal(en.verdict, 'patched');
  assert.equal(ko.verdict, 'patched');
  assert.match(reasons(en), /did not run as root, so running processes were not checked/);
  assert.doesNotMatch(reasons(en), /No running PHP process/);
  assert.match(reasons(ko), /실행 중인 프로세스는 확인하지 못했습니다/);
  // Positive control: as root, no proc lines do mean that no PHP process of this build runs.
  const root = run(server([...NOBLE, 'pkg|dpkg|php8.3-cli|8.3.6-0ubuntu0.24.04.13|php8.3', 'pkg|dpkg|php8.3-common|8.3.6-0ubuntu0.24.04.13|php8.3']));
  assert.equal(root.verdict, 'patched');
  assert.match(reasons(root), /No running PHP process of this build was found/);
});

// ── os_release null, open_basedir true ──────────────────────────────

test('os_release null or open_basedir true never makes an upstream-looking version Vulnerable on RHEL-like or unknown systems', () => {
  const base = { php_version: '8.2.13', sapi: 'fpm-fcgi', config_path: '/etc', container: false, uname_release: '', dpkg_packages: null };
  for (const [fields, pattern] of [
    [{ os_release: null, open_basedir: false }, /could not read the OS release/],
    [{ os_release: [], open_basedir: false }, /could not read the OS release/],
    [{ os_release: null, open_basedir: true, container: null }, /open_basedir/],
    [{ os_release: null, open_basedir: false, php_version: '8.3.12', uname_release: '6.8.0-45-generic' }, /could not read the OS release/],
  ]) {
    const text = probe({ ...base, ...fields });
    for (const r of both(text)) {
      assert.equal(r.verdict, 'unknown', JSON.stringify(fields));
      assert.ok(r.notes.length > 0, 'the hidden OS is explained');
    }
    const r = run(text);
    assert.match(reasons(r), pattern);
    assert.match(notes(r), /could not read the OS release/);
    assert.equal(r.family, null);
  }
  // A RHEL kernel outside a container still names the family, and the version alone does not settle it.
  const kernel = run(probe({ ...base, os_release: null, open_basedir: false, uname_release: '5.14.0-427.el9_4.x86_64' }));
  assert.equal(kernel.verdict, 'unknown');
  assert.match(fact(kernel, 'Distribution'), /RHEL family 9/);
  // Positive controls: a fixed upstream release, an official Docker image and a readable Debian release are still judged.
  assert.equal(run(probe({ ...base, os_release: null, open_basedir: false, php_version: '8.2.35' })).verdict, 'patched');
  assert.equal(run(probe({ ...base, os_release: null, open_basedir: false, container: true, config_path: '/usr/local/etc/php' })).verdict, 'vulnerable');
  assert.equal(run(probe({ ...base, php_version: '8.2.26', config_path: '/etc/php/8.2/fpm', os_release: { ID: 'debian', VERSION_ID: '12' }, open_basedir: false })).verdict, 'vulnerable');
});

test('the server script supplies the OS and packages the probe could not read, and the warning goes away', () => {
  const text = probe({ php_version: '8.2.13', sapi: 'fpm-fcgi', config_path: '/etc', container: false, os_release: null, open_basedir: false, uname_release: '', dpkg_packages: null })
    + server([...ROCKY94, `pkg|rpm|php-common|${MODULE}|`, `pkg|rpm|php-fpm|${MODULE}|`, ...logged('php-common', 1), ...logged('php-fpm', 1), 'proc|php-fpm|4|ok']);
  const r = run(text);
  assert.equal(r.verdict, 'patched');
  assert.doesNotMatch(notes(r), /could not read the OS release/);
  assert.equal(r.family, 'rhel');
});

// ── r.family ────────────────────────────────────────────────────────

test('r.family names the distribution data the verdict rests on, and null for upstream-only verdicts', () => {
  const cases = [
    ['debian', server(['env|root|1', 'os|ID|debian', 'os|VERSION_ID|12', 'pkg|dpkg|php8.2-fpm|8.2.29-1~deb12u1|php8.2', 'proc|php-fpm8.2|3|ok'])],
    ['ubuntu', 'X-Powered-By: PHP/8.1.2-1ubuntu2.20'],
    ['rhel', server([...ROCKY94, `pkg|rpm|php-common|${MODULE}|`, ...logged('php-common', 1)])],
    [null, probe({ php_version: '8.3.12', sapi: 'apache2handler', container: true, config_path: '/usr/local/etc/php', os_release: { ID: 'debian', VERSION_ID: '12', VERSION_CODENAME: 'bookworm' }, dpkg_packages: [] })],
    [null, 'X-Powered-By: PHP/8.3.12'],
    [null, 'X-Powered-By: PHP/8.3.20-1+ubuntu22.04.1+deb.sury.org+1'],
    [null, server(['env|root|1', 'os|ID|alpine', 'os|VERSION_ID|3.22.0', 'pkg|apk|php84|8.4.20-r0|', 'pkg|apk|php84-fpm|8.4.20-r0|', 'proc|php-fpm84|2|ok'])],
    [null, server(['env|root|1', 'os|ID|centos', 'os|VERSION_ID|7', 'pkg|rpm|php83-php-common|8.3.20-1.el7.remi|'])],
    [null, probe({ php_version: '8.2.20', os_release: { ID: 'opensuse-leap', ID_LIKE: 'suse opensuse', VERSION_ID: '15.6' } })],
    [null, '8.6.0RC3'],
    [null, 'hello world'],
  ];
  for (const [family, text] of cases) {
    for (const r of both(text)) assert.equal(r.family, family, text);
  }
  // Several outputs: the family of the worst one.
  assert.equal(run('X-Powered-By: PHP/8.3.12\n\nX-Powered-By: PHP/8.1.2-1ubuntu2.28\n').family, null);
});

// ── Strings for the page ────────────────────────────────────────────

test('facts and advisories values are always strings', () => {
  const odd = run(probe({ php_version: '8.2.20', sapi: 7, server_software: { name: 'x' }, config_path: 5, os_release: { ID: 'debian', VERSION_ID: '12' }, dpkg_packages: [], ini: [] }));
  assert.equal(odd.verdict, 'vulnerable');
  assert.equal(odd.mitigations.length, 0, 'an empty ini list is no settings');
  // Advisory data with fields missing never shows "undefined" or "null".
  const data = JSON.parse(JSON.stringify(distro));
  data.redhat['9'].advisories.push({ advisory: 'RHSA-2026:99999', cve: 'CVE-2026-109618' });
  data.redhat['9'].states.push({ cve: 'CVE-2026-109619', state: 'Affected' }, { cve: 'CVE-2026-109619', package: 'php' });
  const rhel = run(server([...ROCKY94, `pkg|rpm|php-common|${MODULE}|`, ...logged('php-common', 1)]), {}, data);
  assert.ok(rhel.advisories.some((a) => a.value === 'RHSA-2026:99999'));
  for (const r of [odd, rhel, run('X-Powered-By: PHP/8.3.6-0ubuntu0.24.04.4'), run('8.1.30'), run('hello world')]) {
    for (const row of [...r.facts, ...r.advisories]) {
      assert.equal(typeof row.label, 'string');
      assert.equal(typeof row.value, 'string');
      assert.doesNotMatch(row.value, /^(null|undefined)$|\[object |undefined/, JSON.stringify(row));
    }
  }
  assert.equal(fact(odd, 'Web server'), undefined);
  assert.equal(fact(odd, 'SAPI'), undefined);
});

// ── Texts ───────────────────────────────────────────────────────────

test('the default exposure text says to treat the SAPI as exposed until it is patched', () => {
  assert.match(sapiExposure('cgi-fcgi').text, /Treat it as exposed until it is patched\.$/);
  assert.match(sapiExposure('embed').text, /^The official advisory does not mention embed separately\./);
  assert.match(sapiExposure('cgi-fcgi', 'ko').text, /패치를 적용할 때까지는 노출된 것으로 간주해야 합니다\.$/);
  assert.equal(sapiExposure('cgi-fcgi').level, 'medium');
});

test('restart advice uses a full restart, and says a reload or graceful restart keeps the old build only for mod_php', () => {
  const restart = both(probe({ php_version: '8.1.2-1ubuntu2.20', sapi: 'apache2handler', os_release: { ID: 'ubuntu', VERSION_ID: '22.04' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.1', version: '8.1.2-1ubuntu2.28', source: 'php8.1' }], config_path: '/etc/php/8.1/apache2' }));
  for (const r of restart) {
    assert.equal(r.verdict, 'restart');
    const step = r.actions.find((a) => a.code === 'sudo systemctl restart apache2');
    assert.ok(step, 'a full restart command, not a reload');
  }
  assert.match(actionText(restart[0]), /mod_php.*only a full restart of Apache, not a reload or a graceful restart, loads the new build/);
  assert.match(actionText(restart[1]), /reload나 graceful 재시작이 아니라 Apache를 완전히 재시작해야/);
  // PHP-FPM: a reload re-executes the master from disk, so the mod_php sentence is not given.
  const fpm = run(probe({ php_version: '8.1.2-1ubuntu2.20', sapi: 'fpm-fcgi', os_release: { ID: 'ubuntu', VERSION_ID: '22.04' },
    dpkg_packages: [{ name: 'php8.1-fpm', version: '8.1.2-1ubuntu2.28', source: 'php8.1' }], config_path: '/etc/php/8.1/fpm' }));
  assert.equal(fpm.actions[0].code, 'sudo systemctl restart php8.1-fpm');
  assert.doesNotMatch(actionText(fpm), /graceful|keeps the old PHP build/);
  // Without a known service name, the advice names what started the processes.
  const generic = run(server(['env|root|1', 'os|ID|ubuntu', 'os|VERSION_ID|22.04', 'pkg|dpkg|php8.1-fpm|8.1.2-1ubuntu2.28|php8.1', 'proc|php-fpm8.1|5|ok', 'proc|php-fpm8.3|4|stale']));
  assert.equal(generic.verdict, 'restart');
  assert.match(actionText(generic), /Restart whatever runs these PHP processes \(php-fpm8\.3\)/);
  // After an update, the restart step names both possible services when the SAPI is not known.
  assert.match(actionText(run('X-Powered-By: PHP/8.3.6-0ubuntu0.24.04.4')), /After the update, restart the service that runs PHP with the command below/);
  for (const r of [...restart, generic]) {
    for (const a of r.actions) assert.doesNotMatch(a.code || '', /reload|graceful/);
  }
});

// ── Legacy release files ────────────────────────────────────────────

test('the probe\'s LEGACY_REDHAT-RELEASE key (with a hyphen) is recognised', () => {
  const rhel7 = probe({ php_version: '5.4.16', sapi: 'apache2handler', config_path: '/etc', os_release: { 'LEGACY_REDHAT-RELEASE': 'Red Hat Enterprise Linux Server release 7.9 (Maipo)' }, dpkg_packages: null });
  const obs = parseInput(rhel7);
  assert.equal(obs.os.id, 'rhel');
  assert.equal(obs.os.versionId, '7');
  assert.equal(obs.osBlocked, false);
  const r = run(rhel7);
  assert.equal(r.family, 'rhel');
  assert.match(fact(r, 'Distribution'), /Red Hat Enterprise Linux Server release 7\.9/);
  assert.ok(r.advisories.some((a) => /^RHEL 7 /.test(a.label)));
  // RHEL 7 has systemd; RHEL 6 does not.
  assert.match(actionText(r), /systemctl restart httpd/);
  const centos6 = run(probe({ php_version: '5.3.3', sapi: 'apache2handler', os_release: { 'LEGACY_REDHAT-RELEASE': 'CentOS release 6.10 (Final)' } }));
  assert.match(actionText(centos6), /service httpd restart/);
  assert.equal(parseInput(probe({ php_version: '8.2.13', os_release: { 'LEGACY_REDHAT-RELEASE': 'Rocky Linux release 8.9 (Green Obsidian)' } })).os.id, 'rocky');
  assert.equal(parseInput(probe({ php_version: '8.2.13', os_release: { LEGACY_REDHAT_RELEASE: 'AlmaLinux release 9.4 (Seafoam Ocelot)' } })).os.id, 'almalinux');
  // Fedora writes the same file but is not the RHEL family.
  const fedora = run(probe({ php_version: '8.3.12', os_release: { 'LEGACY_REDHAT-RELEASE': 'Fedora release 40 (Forty)' } }));
  assert.equal(parseInput(probe({ php_version: '8.3.12', os_release: { 'LEGACY_REDHAT-RELEASE': 'Fedora release 40 (Forty)' } })).os.id, 'fedora');
  assert.doesNotMatch(fact(fedora, 'Distribution'), /RHEL/);
  // LEGACY_DEBIAN_VERSION keeps its underscore.
  assert.deepEqual(parseInput(probe({ php_version: '8.2.26', os_release: { LEGACY_DEBIAN_VERSION: '12.7' } })).os, { id: 'debian', versionId: '12' });
});

test('the probe\'s plain-text notices without markers give no version', () => {
  for (const text of [
    'php2shell-selfcheck 1.0.0\nThe file on the server has changed, but PHP ran an older cached copy of it.\nThe cached copy has now been cleared. Load this page again. If this message comes back, upload the file under a new name.\n',
    'php2shell-selfcheck 1.0.0\nThe probe stopped without collecting anything. Something was sent before it started, so it could not set its own headers. The usual cause is a byte order mark (BOM) or blank space before the opening PHP tag.\nSave the file as UTF-8 without a BOM, with nothing before the opening PHP tag, and upload it again.\n',
  ]) {
    const r = run(text);
    assert.equal(r.verdict, 'unknown');
    assert.equal(parseInput(text).phpVersion, null);
  }
});
