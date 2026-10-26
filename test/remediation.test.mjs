// Remediation steps (r.actions): for each kind of result, the steps name what runs now, the release or package that
// fixes it, the exact commands built from the observation (package names, image tag, service names) and how to
// confirm the fix, in English and Korean. Runs against site/data/upstream.json and a frozen copy of
// site/data/distro.json (fixtures/distro-snapshot.json), so data refreshes do not move the verdicts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseInput } from '../site/lib/parse.js';
import { judge } from '../site/lib/judge.js';

const upstream = JSON.parse(readFileSync(new URL('../site/data/upstream.json', import.meta.url), 'utf8'));
const distro = JSON.parse(readFileSync(new URL('./fixtures/distro-snapshot.json', import.meta.url), 'utf8'));

const probe = (fields) => `-----BEGIN PHP2SHELL SELFCHECK-----\n${JSON.stringify({ tool: 'php2shell-selfcheck', tool_version: '1.0.0', schema: 1, ...fields })}\n-----END PHP2SHELL SELFCHECK-----\n`;
const server = (lines, closed = true) => `-----BEGIN PHP2SHELL SERVERCHECK-----\n${['tool|php2shell-server-check|1.0.0', ...lines].join('\n')}\n${closed ? '-----END PHP2SHELL SERVERCHECK-----\n' : ''}`;
const run = (text, lang = 'en', data = distro, options = {}) => judge(parseInput(text, { lang }), upstream, data, { ...options, lang });
const both = (text, data = distro, options = {}) => ['en', 'ko'].map((lang) => run(text, lang, data, options));
const codes = (r) => r.actions.map((a) => a.code || '');
const all = (r) => r.actions.map((a) => `${a.text}\n${a.code || ''}`).join('\n');
// The step whose code block matches re (a string is matched exactly).
const stepWith = (r, re) => r.actions.find((a) => (typeof re === 'string' ? a.code === re : re.test(a.code || '')));
const indexWith = (r, re) => r.actions.findIndex((a) => (typeof re === 'string' ? a.code === re : re.test(a.code || '')));

const INI = { memory_limit: '128M', 'session.upload_progress.enabled': '1', 'session.auto_start': '0', expose_php: '1' };
const CVES = 'CVE-2026-109618 --cve CVE-2026-109619';
const GREP = 'grep -e CVE-2026-109618 -e CVE-2026-109619';
const MODULE = '8.2.13-1.module+el9.4.0+20827+3f2b0b48';
// The download lines of the page's Server script and PHP probe tabs.
const FETCH = 'curl -fsSLO https://php2shell.sqzer.com/downloads/php2shell-server-check.sh\nsha256sum php2shell-server-check.sh';
const PROBE = "curl -fsSLO https://php2shell.sqzer.com/downloads/php2shell-selfcheck.php\ncurl -s 'https://<site>/<file>.php?k=<TOKEN>'";

// Every fixture used below, with the verdict it must keep: the remediation work changes no verdict.
const F = {
  dockerApache: probe({ php_version: '8.3.12', sapi: 'apache2handler', container: true, config_path: '/usr/local/etc/php', os_release: { ID: 'debian', VERSION_ID: '12', VERSION_CODENAME: 'bookworm' }, ini: INI }),
  dockerFpmAlpine: probe({ php_version: '8.4.20', sapi: 'fpm-fcgi', container: true, config_path: '/usr/local/etc/php', os_release: { ID: 'alpine', VERSION_ID: '3.20.3' }, dpkg_packages: null, ini: INI }),
  dockerCliTrixie: probe({ php_version: '8.4.20', sapi: 'cli', container: true, config_path: '/usr/local/etc/php', os_release: { ID: 'debian', VERSION_ID: '13' }, ini: INI }),
  dockerBullseye: probe({ php_version: '8.3.12', sapi: 'apache2handler', container: true, config_path: '/usr/local/etc/php', os_release: { ID: 'debian', VERSION_ID: '11', VERSION_CODENAME: 'bullseye' }, ini: INI }),
  dockerEol: probe({ php_version: '7.4.33', sapi: 'apache2handler', container: true, config_path: '/usr/local/etc/php', os_release: { ID: 'debian', VERSION_ID: '12', VERSION_CODENAME: 'bookworm' }, ini: INI }),
  containerDeb: probe({ php_version: '8.3.6', sapi: 'apache2handler', container: true, config_path: '/etc/php/8.3/apache2', os_release: { ID: 'ubuntu', VERSION_ID: '24.04', VERSION_CODENAME: 'noble' }, dpkg_packages: [{ name: 'libapache2-mod-php8.3', version: '8.3.6-0ubuntu0.24.04.4', source: 'php8.3' }, { name: 'php8.3-common', version: '8.3.6-0ubuntu0.24.04.4', source: 'php8.3' }], ini: INI }),
  containerRestart: probe({ php_version: '8.1.2-1ubuntu2.20', sapi: 'apache2handler', container: true, config_path: '/etc/php/8.1/apache2', os_release: { ID: 'ubuntu', VERSION_ID: '22.04' }, dpkg_packages: [{ name: 'libapache2-mod-php8.1', version: '8.1.2-1ubuntu2.28', source: 'php8.1' }], ini: INI }),
  jammyFpm: probe({ php_version: '8.1.2-1ubuntu2.20', sapi: 'fpm-fcgi', config_path: '/etc/php/8.1/fpm', os_release: { ID: 'ubuntu', VERSION_ID: '22.04', VERSION_CODENAME: 'jammy' }, dpkg_packages: [{ name: 'php8.1-fpm', version: '8.1.2-1ubuntu2.20', source: 'php8.1' }, { name: 'php8.1-common', version: '8.1.2-1ubuntu2.20', source: 'php8.1' }, { name: 'php8.1-cli', version: '8.1.2-1ubuntu2.20', source: 'php8.1' }], ini: INI }),
  focalPro: probe({ php_version: '7.4.3-4ubuntu2.20', sapi: 'apache2handler', config_path: '/etc/php/7.4/apache2', os_release: { ID: 'ubuntu', VERSION_ID: '20.04', VERSION_CODENAME: 'focal' }, dpkg_packages: [{ name: 'libapache2-mod-php7.4', version: '7.4.3-4ubuntu2.20', source: 'php7.4' }, { name: 'php7.4-common', version: '7.4.3-4ubuntu2.20', source: 'php7.4' }], ini: INI }),
  trusty: probe({ php_version: '5.5.9-1ubuntu4.20', sapi: 'apache2handler', config_path: '/etc/php5/apache2', os_release: { ID: 'ubuntu', VERSION_ID: '14.04' }, dpkg_packages: [{ name: 'libapache2-mod-php5', version: '5.5.9+dfsg-1ubuntu4.20', source: 'php5' }], ini: INI }),
  nobleHeader: 'X-Powered-By: PHP/8.3.6-0ubuntu0.24.04.4',
  resolute85: probe({ php_version: '8.5.4-0ubuntu1.2', sapi: 'apache2handler', config_path: '/etc/php/8.5/apache2', os_release: { ID: 'ubuntu', VERSION_ID: '26.04' }, dpkg_packages: [{ name: 'libapache2-mod-php8.5', version: '8.5.4-0ubuntu1.2', source: 'php8.5' }], ini: { ...INI, fatal_error_backtraces: '1' } }),
  rockyModule: server(['env|root|1', 'os|ID|rocky', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|9.4', `pkg|rpm|php-common|${MODULE}|`, `pkg|rpm|php-fpm|${MODULE}|`, `pkg|rpm|php-cli|${MODULE}|`, 'changelog|php-common|CVE-2026-109618|0', 'changelog|php-common|CVE-2026-109619|0', 'proc|php-fpm|5|ok']),
  rhel9Base: server(['env|root|1', 'os|ID|rhel', 'os|ID_LIKE|fedora', 'os|VERSION_ID|9.6', 'pkg|rpm|php-common|8.0.30-3.el9_6|', 'pkg|rpm|php|8.0.30-3.el9_6|', 'changelog|php-common|CVE-2026-109618|0', 'changelog|php-common|CVE-2026-109619|0', 'proc|httpd|8|ok']),
  rhel7Probe: probe({ php_version: '5.4.16', sapi: 'apache2handler', config_path: '/etc', os_release: { 'LEGACY_REDHAT-RELEASE': 'Red Hat Enterprise Linux Server release 7.9 (Maipo)' }, dpkg_packages: null, ini: INI }),
  centos6: probe({ php_version: '5.3.3', sapi: 'apache2handler', os_release: { 'LEGACY_REDHAT-RELEASE': 'CentOS release 6.10 (Final)' }, ini: INI }),
  alma84: server(['env|root|1', 'os|ID|almalinux', 'os|VERSION_ID|9.6', 'pkg|rpm|php-common|8.4.20-1.module_el9.6.0+1+aa|', 'pkg|rpm|php-fpm|8.4.20-1.module_el9.6.0+1+aa|', 'changelog|php-common|CVE-2026-109618|0', 'changelog|php-common|CVE-2026-109619|0', 'proc|php-fpm|5|ok']),
  remiScl: server(['env|root|1', 'os|ID|almalinux', 'os|VERSION_ID|9.6', 'pkg|rpm|php82-php-common|8.2.20-1.el9.remi|', 'pkg|rpm|php82-php-fpm|8.2.20-1.el9.remi|', 'proc|php-fpm|4|ok']),
  selfFpm: probe({ php_version: '8.3.20', sapi: 'fpm-fcgi', config_path: '/usr/local/lib', os_release: { ID: 'ubuntu', VERSION_ID: '24.04' }, dpkg_packages: [], ini: INI }),
  selfApache: probe({ php_version: '8.4.10', sapi: 'apache2handler', config_path: '/opt/php/etc', os_release: { ID: 'debian', VERSION_ID: '12' }, dpkg_packages: [], ini: INI }),
  eol81: probe({ php_version: '8.1.30', sapi: 'fpm-fcgi', config_path: '/usr/local/lib', os_release: { ID: 'debian', VERSION_ID: '12' }, dpkg_packages: [], ini: INI }),
  eol80: probe({ php_version: '8.0.30', sapi: 'fpm-fcgi', config_path: '/usr/local/lib', os_release: { ID: 'debian', VERSION_ID: '12' }, dpkg_packages: [], ini: INI }),
  eol73: probe({ php_version: '7.3.33', sapi: 'fpm-fcgi', config_path: '/usr/local/lib', os_release: { ID: 'debian', VERSION_ID: '12' }, dpkg_packages: [], ini: INI }),
  jammyRestart: probe({ php_version: '8.1.2-1ubuntu2.20', sapi: 'apache2handler', config_path: '/etc/php/8.1/apache2', os_release: { ID: 'ubuntu', VERSION_ID: '22.04' }, dpkg_packages: [{ name: 'libapache2-mod-php8.1', version: '8.1.2-1ubuntu2.28', source: 'php8.1' }], ini: INI }),
  debianStale: server(['env|root|1', 'os|ID|debian', 'os|VERSION_ID|12', 'os|VERSION_CODENAME|bookworm', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2', 'pkg|dpkg|php8.2-common|8.2.35-1~deb12u1|php8.2', 'proc|php-fpm8.2|6|stale']),
  rockyStale: server(['env|root|1', 'os|ID|rocky', 'os|VERSION_ID|9.4', `pkg|rpm|php-common|${MODULE}|`, `pkg|rpm|php|${MODULE}|`, 'changelog|php-common|CVE-2026-109618|1', 'changelog|php-common|CVE-2026-109619|1', 'proc|httpd|6|stale']),
  forkyApache: probe({ php_version: '8.4.26', sapi: 'apache2handler', config_path: '/etc/php/8.4/apache2', os_release: { ID: 'debian', VERSION_CODENAME: 'forky' }, dpkg_packages: [{ name: 'libapache2-mod-php8.4', version: '8.4.26-1', source: 'php8.4' }, { name: 'php8.4-common', version: '8.4.26-1', source: 'php8.4' }], ini: INI }),
  forkyFpm: probe({ php_version: '8.4.26', sapi: 'fpm-fcgi', config_path: '/etc/php/8.4/fpm', os_release: { ID: 'debian', VERSION_CODENAME: 'forky' }, dpkg_packages: [{ name: 'php8.4-fpm', version: '8.4.26-1', source: 'php8.4' }], ini: INI }),
  osUnread: probe({ php_version: '8.2.13', sapi: 'fpm-fcgi', config_path: '/etc', os_release: null, open_basedir: false, dpkg_packages: null, ini: INI }),
  hidden: server(['env|root|0', 'os|ID|ubuntu', 'os|VERSION_ID|24.04', 'pkg|dpkg|php8.3-fpm|8.3.6-0ubuntu0.24.04.13|php8.3', 'webuser_proc|unknown']),
  truncated: server(['env|root|1', 'os|ID|rocky', 'os|VERSION_ID|9.4', `pkg|rpm|php-common|${MODULE}|`, 'changelog|php-common|CVE-2026-109618|1', 'changelog|php-common|CVE-2026-109619|1'], false),
  unaccounted: server(['env|root|1', 'os|ID|ubuntu', 'os|VERSION_ID|22.04', 'pkg|dpkg|php8.1-cli|8.1.2-1ubuntu2.28|php8.1', 'pkg|dpkg|php8.1-common|8.1.2-1ubuntu2.28|php8.1', 'proc|php-fpm|12|ok']),
  conflict: probe({ php_version: '8.3.6', sapi: 'fpm-fcgi', config_path: '/etc/php/8.3/fpm', os_release: { ID: 'ubuntu', ID_LIKE: 'debian', VERSION_ID: '24.04', VERSION_CODENAME: 'noble' }, dpkg_packages: [{ name: 'php8.3-fpm', version: '8.3.6-0ubuntu0.24.04.13', source: 'php8.3' }] })
    + server(['env|root|1', 'os|ID|ubuntu', 'os|ID_LIKE|debian', 'os|VERSION_ID|24.04', 'os|VERSION_CODENAME|noble', 'pkg|dpkg|php8.3-fpm|8.3.6-0ubuntu0.24.04.5|php8.3', 'proc|php-fpm8.3|3|ok']),
  foreign: probe({ php_version: '8.3.6', sapi: 'fpm-fcgi', config_path: '/etc/php/8.3/fpm', os_release: { ID: 'ubuntu', VERSION_ID: '24.04' }, dpkg_packages: [{ name: 'php8.3-fpm', version: '8.3.6-1+ppa1', source: 'php8.3' }] }),
  debianNoRelease: server(['env|root|1', 'os|ID|debian', 'pkg|dpkg|php8.2-common|8.2.26-1|php8.2', 'proc|php-fpm8.2|3|ok']),
  noVersion: 'hello world',
  rhelProbe: probe({ php_version: '8.2.13', sapi: 'fpm-fcgi', config_path: '/etc', os_release: { ID: 'rocky', ID_LIKE: 'rhel centos fedora', VERSION_ID: '9.4' }, dpkg_packages: null, ini: INI }),
  patchedFpm: probe({ php_version: '8.3.6-0ubuntu0.24.04.13', sapi: 'fpm-fcgi', config_path: '/etc/php/8.3/fpm', os_release: { ID: 'ubuntu', VERSION_ID: '24.04' }, dpkg_packages: [{ name: 'php8.3-fpm', version: '8.3.6-0ubuntu0.24.04.13', source: 'php8.3' }], ini: INI }),
  patchedDocker: probe({ php_version: '8.4.27', sapi: 'apache2handler', container: true, config_path: '/usr/local/etc/php', os_release: { ID: 'debian', VERSION_ID: '13', VERSION_CODENAME: 'trixie' }, ini: { ...INI, 'session.upload_progress.enabled': '0' } }),
  patchedQuiet: probe({ php_version: '8.4.27', sapi: 'fpm-fcgi', config_path: '/etc/php/8.4/fpm', os_release: {}, ini: { ...INI, expose_php: '0' } }),
  patchedHeader: 'X-Powered-By: PHP/8.4.27',
  // Cases from the review of the remediation steps.
  dockerWp: probe({ php_version: '8.2.20', sapi: 'apache2handler', container: true, config_path: '/usr/local/etc/php', os_release: { ID: 'debian', VERSION_ID: '12', VERSION_CODENAME: 'bookworm' }, ini: INI }),
  dockerAlpine324: probe({ php_version: '8.4.20', sapi: 'fpm-fcgi', container: true, config_path: '/usr/local/etc/php', os_release: { ID: 'alpine', VERSION_ID: '3.24.1' }, ini: INI }),
  focalContainer: probe({ php_version: '7.4.3-4ubuntu2.20', sapi: 'apache2handler', container: true, config_path: '/etc/php/7.4/apache2', os_release: { ID: 'ubuntu', VERSION_ID: '20.04' }, dpkg_packages: [{ name: 'libapache2-mod-php7.4', version: '7.4.3-4ubuntu2.20', source: 'php7.4' }], ini: INI }),
  rhelContainer: probe({ php_version: '8.2.13', sapi: 'fpm-fcgi', container: true, config_path: '/etc', os_release: { ID: 'rocky', VERSION_ID: '9.4' }, dpkg_packages: null, ini: INI }),
  deb13both: server(['env|root|1', 'os|ID|debian', 'os|VERSION_ID|13', 'pkg|dpkg|php8.4-fpm|8.4.20-1~deb13u1|php8.4', 'pkg|dpkg|libapache2-mod-php8.4|8.4.20-1~deb13u1|php8.4', 'pkg|dpkg|php8.4-common|8.4.20-1~deb13u1|php8.4', 'proc|php-fpm8.4|4|ok', 'proc|apache2|5|ok']),
  deb11: probe({ php_version: '7.4.33', sapi: 'fpm-fcgi', config_path: '/etc/php/7.4/fpm', os_release: { ID: 'debian', VERSION_ID: '11' }, dpkg_packages: [{ name: 'php7.4-fpm', version: '7.4.33-1+deb11u5', source: 'php7.4' }], ini: INI }),
  cgi: probe({ php_version: '8.2.20', sapi: 'cgi-fcgi', config_path: '/etc/php/8.2/cgi', os_release: { ID: 'debian', VERSION_ID: '12' }, dpkg_packages: [{ name: 'php8.2-cgi', version: '8.2.20-1~deb12u1', source: 'php8.2' }], ini: INI }),
  alpine: server(['env|root|1', 'os|ID|alpine', 'os|VERSION_ID|3.20.3', 'pkg|apk|php83|8.3.15-r0|', 'pkg|apk|php83-fpm|8.3.15-r0|', 'pkg|apk|php83-common|8.3.15-r0|', 'proc|php-fpm83|2|ok']),
  fedora: probe({ php_version: '8.3.12', sapi: 'fpm-fcgi', config_path: '/etc', os_release: { ID: 'fedora', VERSION_ID: '41', PRETTY_NAME: 'Fedora Linux 41 (Server Edition)' }, ini: INI }),
  suse: probe({ php_version: '8.2.20', sapi: 'apache2handler', config_path: '/etc/php8/apache2', os_release: { ID: 'opensuse-leap', ID_LIKE: 'suse opensuse', VERSION_ID: '15.6', PRETTY_NAME: 'openSUSE Leap 15.6' }, ini: INI }),
  rhel9php81: server(['env|root|1', 'os|ID|almalinux', 'os|VERSION_ID|9.6', 'pkg|rpm|php-common|8.1.32-1.module_el9.6.0+1+aa|', 'pkg|rpm|php-fpm|8.1.32-1.module_el9.6.0+1+aa|', 'changelog|php-common|CVE-2026-109618|0', 'changelog|php-common|CVE-2026-109619|0', 'proc|php-fpm|5|ok']),
  centos7srv: server(['env|root|1', 'os|ID|centos', 'os|ID_LIKE|rhel fedora', 'os|VERSION_ID|7', 'pkg|rpm|php-common|5.4.16-48.el7|', 'pkg|rpm|php|5.4.16-48.el7|', 'changelog|php-common|CVE-2026-109618|0', 'changelog|php-common|CVE-2026-109619|0', 'proc|httpd|5|ok']),
  rhel10: probe({ php_version: '8.4.20', sapi: 'fpm-fcgi', config_path: '/etc', os_release: { ID: 'almalinux', VERSION_ID: '10.2' }, dpkg_packages: null, ini: INI })
    + server(['env|root|1', 'os|ID|almalinux', 'os|VERSION_ID|10.2', 'proc|php-fpm|3|ok']),
  rockyHeader: 'Server: Apache/2.4.57 (Rocky Linux)\nX-Powered-By: PHP/8.2.13',
  amzn2023: server(['env|root|1', 'os|ID|amzn', 'os|VERSION_ID|2023', 'pkg|rpm|php8.3-common|8.3.10-1.amzn2023|', 'pkg|rpm|php8.3-fpm|8.3.10-1.amzn2023|', 'proc|php-fpm|3|ok']),
  amzn2: server(['env|root|1', 'os|ID|amzn', 'os|VERSION_ID|2', 'pkg|rpm|php-common|7.4.33-1.amzn2|', 'proc|httpd|3|ok']),
  remi74: server(['env|root|1', 'os|ID|rocky', 'os|VERSION_ID|9.4', 'pkg|rpm|php74-php-common|7.4.33-20.el9.remi|', 'pkg|rpm|php74-php-fpm|7.4.33-20.el9.remi|', 'proc|php-fpm|4|ok']),
  eol74apache: probe({ php_version: '7.4.33', sapi: 'apache2handler', config_path: '/usr/local/lib', os_release: { ID: 'debian', VERSION_ID: '12' }, dpkg_packages: [], ini: INI }),
  cliVersion: 'PHP 8.4.20 (cli) (built: Mar 1 2026) (NTS)',
  staleOther: server(['env|root|1', 'os|ID|ubuntu', 'os|VERSION_ID|22.04', 'pkg|dpkg|php8.1-fpm|8.1.2-1ubuntu2.28|php8.1', 'proc|php-fpm8.1|5|ok', 'proc|php-fpm8.3|4|stale']),
  patchedApache: probe({ php_version: '8.2.35-1~deb12u1', sapi: 'apache2handler', config_path: '/etc/php/8.2/apache2', os_release: { ID: 'debian', VERSION_ID: '12' }, dpkg_packages: [{ name: 'libapache2-mod-php8.2', version: '8.2.35-1~deb12u1', source: 'php8.2' }], ini: INI }),
};
const VERDICTS = {
  dockerApache: 'vulnerable', dockerFpmAlpine: 'vulnerable', dockerCliTrixie: 'vulnerable', dockerBullseye: 'vulnerable', dockerEol: 'vulnerable',
  containerDeb: 'vulnerable', containerRestart: 'restart', jammyFpm: 'vulnerable', focalPro: 'vulnerable', trusty: 'vulnerable', nobleHeader: 'vulnerable',
  resolute85: 'vulnerable', rockyModule: 'unknown', rhel9Base: 'vulnerable', rhel7Probe: 'unknown', centos6: 'unknown', alma84: 'unknown', remiScl: 'vulnerable',
  selfFpm: 'vulnerable', selfApache: 'vulnerable', eol81: 'vulnerable', eol80: 'vulnerable', eol73: 'vulnerable', jammyRestart: 'restart',
  debianStale: 'restart', rockyStale: 'restart', forkyApache: 'pending', forkyFpm: 'pending', osUnread: 'unknown', hidden: 'unknown', truncated: 'unknown',
  unaccounted: 'unknown', conflict: 'unknown', foreign: 'unknown', debianNoRelease: 'unknown', noVersion: 'unknown', rhelProbe: 'unknown',
  patchedFpm: 'patched', patchedDocker: 'patched', patchedQuiet: 'patched', patchedHeader: 'patched',
  dockerWp: 'vulnerable', dockerAlpine324: 'vulnerable', focalContainer: 'vulnerable', rhelContainer: 'unknown', deb13both: 'vulnerable',
  deb11: 'unknown', cgi: 'vulnerable', alpine: 'vulnerable', fedora: 'vulnerable', suse: 'unknown', rhel9php81: 'unknown', centos7srv: 'unknown',
  rhel10: 'vulnerable', rockyHeader: 'unknown', amzn2023: 'unknown', amzn2: 'unknown', remi74: 'unknown', eol74apache: 'vulnerable',
  cliVersion: 'vulnerable', staleOther: 'restart', patchedApache: 'patched',
};

test('the remediation work changes no verdict, and both languages agree', () => {
  assert.deepEqual(Object.keys(VERDICTS).sort(), Object.keys(F).sort());
  for (const [name, text] of Object.entries(F)) {
    const [en, ko] = both(text);
    assert.equal(en.verdict, VERDICTS[name], name);
    assert.equal(ko.verdict, VERDICTS[name], name);
  }
});

// ── 1. Official Docker image and other containers ──────────────────

test('1. official image: the exact tag of the fixed release in the same variant, rebuilt with --pull, confirmed inside', () => {
  for (const [text, tag, current, floating] of [
    [F.dockerApache, 'php:8.3.36-apache-bookworm', '8.3.12', 'php:8.3-apache-bookworm'],
    [F.dockerFpmAlpine, 'php:8.4.27-fpm-alpine', '8.4.20', 'php:8.4-fpm-alpine'],
    [F.dockerCliTrixie, 'php:8.4.27-cli-trixie', '8.4.20', 'php:8.4-cli-trixie'],
  ]) {
    for (const r of both(text)) {
      const from = stepWith(r, `FROM ${tag}`);
      assert.ok(from, `${r.verdict}: FROM ${tag}`);
      assert.ok(from.text.includes(current), 'names the running version');
      assert.ok(from.text.includes(tag.split(':')[1].split('-')[0]), 'names the fixed release');
      assert.ok(from.text.includes(floating), 'explains the floating tag');
      // Images built on the PHP image keep their own name; services that use an image directly are pulled.
      assert.match(from.text, /wordpress/);
      assert.match(from.text, /docker run --rm <your-image> php -v/);
      const rebuild = indexWith(r, /^# Docker\ndocker build --pull -t <your-image> \.\n# Docker Compose\ndocker compose build --pull\ndocker compose pull --ignore-buildable\ndocker compose up -d$/);
      const confirm = indexWith(r, "docker exec <container> php -r 'echo PHP_VERSION, PHP_EOL;'");
      assert.ok(indexWith(r, `FROM ${tag}`) < rebuild && rebuild < confirm, 'tag, rebuild, confirm in that order');
      assert.ok(r.actions[confirm].text.includes(tag.split(':')[1].split('-')[0]), 'the confirm step names the version to expect');
      assert.doesNotMatch(all(r), /apt-get|dnf |apk upgrade|systemctl/, 'no package or host service commands for the official image');
    }
  }
  const [en, ko] = both(F.dockerApache);
  assert.match(stepWith(en, /^FROM/).text, /does not pin the version/);
  assert.match(stepWith(ko, /^FROM/).text, /버전을 고정하지 않으므로/);
  assert.match(stepWith(ko, /^FROM/).text, /이미지 종류\(-apache-bookworm\)/);
  assert.doesNotMatch(stepWith(ko, /^FROM/).text, /변형|유동 태그/);
  assert.match(stepWith(ko, /docker exec <container> php -r/).text, /결과확인/);
  // The interim mitigation goes into the running container and into the image.
  for (const r of [en, ko]) {
    assert.equal(stepWith(r, /PHP_INI_DIR/).code, [
      'docker exec -u 0 <container> sh -c \'printf "session.upload_progress.enabled = 0\\n" > "$PHP_INI_DIR/conf.d/zz-php2shell-mitigation.ini"\'',
      'docker restart <container>',
      '# Dockerfile',
      'RUN printf \'session.upload_progress.enabled = 0\\n\' > "$PHP_INI_DIR/conf.d/zz-php2shell-mitigation.ini"',
    ].join('\n'));
  }
  assert.match(stepWith(en, /PHP_INI_DIR/).text, /does not replace the patch/);
});

test('1. an image on a Debian release that gets no new PHP images moves to the nearest one that does, and says so', () => {
  const [en, ko] = both(F.dockerBullseye);
  for (const r of [en, ko]) {
    const from = stepWith(r, 'FROM php:8.3.36-apache-bookworm');
    assert.ok(from);
    assert.match(from.text, /Debian 11 ?\(bullseye\)/);
    assert.match(from.text, /Debian 12 ?\(bookworm\)/);
  }
  assert.match(stepWith(en, /^FROM/).text, /keeps your variant \(-apache\)\./);
});

test('1. Alpine images: the Alpine release is kept when its tags are published, otherwise the floating -alpine tag is explained', () => {
  for (const r of both(F.dockerAlpine324)) {
    assert.ok(stepWith(r, 'FROM php:8.4.27-fpm-alpine3.24'));
    assert.doesNotMatch(stepWith(r, /^FROM/).text, /newest Alpine|최신 Alpine/);
  }
  const [en, ko] = both(F.dockerFpmAlpine);
  assert.match(stepWith(en, /^FROM/).text, /newer than the Alpine 3\.20 your image uses now.*php:8\.4\.27-fpm-alpine3\.24/);
  assert.match(stepWith(ko, /^FROM/).text, /Alpine 3\.20보다 새 릴리스/);
});

test('1. a branch with an announced end of life says so next to its fixed release', () => {
  const [en, ko] = both(F.dockerWp);
  assert.ok(stepWith(en, 'FROM php:8.2.35-apache-bookworm'));
  assert.match(stepWith(en, /^FROM/).text, /PHP 8\.2 reaches end of life on 31 December 2026, so plan the move to 8\.3 or 8\.4 as well\./);
  assert.match(stepWith(ko, /^FROM/).text, /PHP 8\.2 브랜치는 2026년 12월 31일에 지원이 종료되므로 8\.3 또는 8\.4 브랜치로/);
  for (const r of both(F.remiScl)) assert.match(stepWith(r, /^sudo dnf upgrade/).text, /31 December 2026|2026년 12월 31일/);
  for (const r of both(F.dockerApache)) assert.doesNotMatch(all(r), /end of life on|지원이 종료되므로/);
});

test('1. an end-of-life official image moves to a supported branch and is tested first', () => {
  const [en, ko] = both(F.dockerEol);
  for (const r of [en, ko]) {
    const from = stepWith(r, 'FROM php:8.4.27-apache-bookworm');
    assert.ok(from);
    assert.match(from.text, /7\.4\.33/);
    assert.match(from.text, /8\.3\.36/);
    assert.ok(stepWith(r, /docker exec <container> php -r/).text.includes('8.4.27'));
  }
  assert.match(stepWith(en, /^FROM/).text, /end of life.*test your application/);
  assert.match(stepWith(ko, /^FROM/).text, /지원이 종료\(EOL\).*테스트하세요/);
});

test('1. PHP from distribution packages inside a container gets the package route, not a FROM tag', () => {
  for (const r of both(F.containerDeb)) {
    assert.doesNotMatch(all(r), /FROM php:/);
    const update = stepWith(r, 'RUN apt-get update && apt-get install -y --only-upgrade libapache2-mod-php8.3 php8.3-common');
    assert.ok(update);
    assert.ok(update.text.includes('8.3.6-0ubuntu0.24.04.4') && update.text.includes('8.3.6-0ubuntu0.24.04.13'), 'installed and fixed versions');
    assert.ok(stepWith(r, /docker build --pull/));
    const confirm = stepWith(r, 'docker exec <container> dpkg-query -W libapache2-mod-php8.3 php8.3-common');
    assert.ok(confirm.text.includes('8.3.6-0ubuntu0.24.04.13'));
  }
});

test('1. a container whose packages were updated in place is restarted, and the update goes into the image', () => {
  const [en, ko] = both(F.containerRestart);
  for (const r of [en, ko]) {
    assert.ok(stepWith(r, 'docker restart <container>'));
    assert.ok(stepWith(r, 'RUN apt-get update && apt-get install -y --only-upgrade libapache2-mod-php8.1'));
    assert.doesNotMatch(all(r), /systemctl/);
  }
  assert.match(stepWith(en, /^RUN/).text, /goes back to the old build/);
  assert.match(stepWith(ko, /^RUN/).text, /이전 빌드로 돌아갑니다/);
  // The vulnerable build served requests until the restart.
  for (const r of [en, ko]) assert.match(r.actions[r.actions.length - 1].code, /--logs --webroot <webroot>$/);
});

test('1. an Ubuntu Pro fix in a container is installed while Pro is attached for the build only', () => {
  for (const r of both(F.focalContainer)) {
    assert.equal(stepWith(r, /^RUN/).code, [
      'RUN --mount=type=secret,id=pro-attach-config \\',
      '    apt-get update && apt-get install -y --no-install-recommends ubuntu-advantage-tools ca-certificates && \\',
      '    pro attach --attach-config /run/secrets/pro-attach-config && \\',
      '    apt-get update && apt-get install -y --only-upgrade libapache2-mod-php7.4 && \\',
      '    pro detach --assume-yes',
    ].join('\n'));
    assert.match(stepWith(r, /^RUN/).text, /pro-attach-config\.yaml/);
    assert.ok(stepWith(r, /^# Docker\ndocker build --pull --secret id=pro-attach-config,src=pro-attach-config\.yaml -t <your-image> \./));
  }
});

test('1. a RHEL-family container is confirmed by its changelog, since the fixed build keeps its version', () => {
  for (const r of both(F.rhelContainer)) {
    const confirm = stepWith(r, /rpm -q --changelog/);
    assert.equal(confirm.code, 'docker exec <container> rpm -q php-common\ndocker exec <container> sh -c "rpm -q --changelog php-common | grep -e CVE-2026-109618 -e CVE-2026-109619"');
    assert.doesNotMatch(confirm.text, /8\.2\.35/);
  }
});

// ── 2. Debian and Ubuntu packages ───────────────────────────────────

test('2. Ubuntu package below the fixed version: installed and fixed versions, apt with the detected names, dpkg-query, restart, re-check', () => {
  const [en, ko] = both(F.jammyFpm);
  for (const r of [en, ko]) {
    const update = indexWith(r, 'sudo apt-get update\nsudo apt-get install --only-upgrade php8.1-fpm php8.1-common php8.1-cli');
    const confirm = indexWith(r, 'dpkg-query -W php8.1-fpm php8.1-common php8.1-cli');
    const restart = indexWith(r, 'sudo systemctl restart php8.1-fpm');
    assert.ok(update >= 0 && update < confirm && confirm < restart, 'update, confirm, restart in that order');
    assert.ok(r.actions[update].text.includes('php8.1-fpm 8.1.2-1ubuntu2.20'), 'the installed package');
    assert.ok(r.actions[update].text.includes('8.1.2-1ubuntu2.28'), 'the fixed package');
    assert.ok(r.actions[confirm].text.includes('8.1.2-1ubuntu2.28'));
    assert.match(r.actions[update].text, /apt full-upgrade/);
    assert.match(r.actions[restart + 1].text, en === r ? /Run check.*Patched/ : /결과확인.*패치됨/);
  }
  assert.match(en.actions[0].text, /extension packages/);
  assert.match(ko.actions[0].text, /확장 패키지/);
});

test('2. Ubuntu Pro: attach first (free for personal use), then update to the ESM version', () => {
  const [en, ko] = both(F.focalPro);
  for (const r of [en, ko]) {
    assert.equal(r.actions[0].code, 'sudo pro attach <token>');
    assert.ok(stepWith(r, 'sudo apt-get update\nsudo apt-get install --only-upgrade libapache2-mod-php7.4 php7.4-common').text.includes('7.4.3-4ubuntu2.29+esm5'));
    assert.ok(stepWith(r, 'sudo systemctl restart apache2'));
  }
  assert.match(en.actions[0].text, /free for personal use/);
  assert.match(ko.actions[0].text, /개인 사용이면.*무료/);
  // Ubuntu 14.04 has the older client (ua) and no systemd, and is past its ESM window: the fix needs the paid
  // Legacy Support add-on, not the free personal subscription.
  const [enT, koT] = both(F.trusty);
  for (const r of [enT, koT]) {
    assert.equal(r.actions[0].code, 'sudo ua attach <token>');
    assert.ok(stepWith(r, 'sudo service apache2 restart'));
    assert.doesNotMatch(all(r), /systemctl/);
    assert.match(all(r), /<IfModule php5_module>/);
  }
  assert.match(enT.actions[0].text, /Legacy Support add-on, which is paid and not part of the free personal subscription/);
  assert.doesNotMatch(enT.actions[0].text, /free for personal use/);
  assert.match(koT.actions[0].text, /유료인 Ubuntu Pro Legacy Support 애드온/);
  assert.match(enT.notes.join(' '), /Legacy Support add-on/);
});

test('2. a build from another repository is not "updated": the distribution build is installed at its exact version', () => {
  const [en, ko] = both(F.foreign);
  for (const r of [en, ko]) {
    assert.equal(r.actions[0].code, 'apt-cache policy php8.3-fpm');
    assert.doesNotMatch(all(r), /--only-upgrade|or later|이상으로/);
    const install = stepWith(r, /--allow-downgrades/);
    assert.equal(install.code, "sudo apt-get update\nsudo apt-get install --allow-downgrades $(dpkg-query -W -f='${Package} ${Version}\\n' 'php8.3-*' 'libapache2-mod-php8.3' 2>/dev/null | awk '$2 == \"8.3.6-1+ppa1\" {print $1\"=8.3.6-0ubuntu0.24.04.13\"}')");
    assert.ok(stepWith(r, "dpkg -l 'php8.3-*' 'libapache2-mod-php8.3' | grep '^ii'"));
  }
  assert.match(stepWith(en, /--allow-downgrades/).text, /turn off the repository/);
  assert.match(stepWith(en, /grep '\^ii'/).text, /exactly 8\.3\.6-0ubuntu0\.24\.04\.13, the Ubuntu revision/);
  assert.match(stepWith(ko, /grep '\^ii'/).text, /정확히 8\.3\.6-0ubuntu0\.24\.04\.13 버전/);
});

test('2. a release the data does not cover: compare with the tracker by hand, then let the server script read the changelog', () => {
  const [en, ko] = both(F.deb11);
  for (const r of [en, ko]) {
    assert.match(r.actions[0].code, /^https:\/\/security-tracker\.debian\.org\/tracker\/CVE-2026-109618/);
    assert.ok(stepWith(r, 'dpkg-query -W php7.4-fpm'));
    assert.equal(stepWith(r, 'sudo sh php2shell-server-check.sh').text.includes('changelog'), true);
    assert.doesNotMatch(all(r), /PHP probe again through the web server and press Run check: the result should be Patched/);
  }
  assert.match(stepWith(en, 'dpkg-query -W php7.4-fpm').text, /Debian pages in the first step/);
  // The fix.debOpen wording: no jargon, and no "before the result" in Korean.
  assert.match(all(en), /Even while the result is Undetermined, install the latest Debian updates for php7\.4 now\./);
  assert.match(all(ko), /결과가 판단 불가이더라도 Debian의 최신 php7\.4 업데이트는 지금 설치하세요\./);
});

test('2. Apache mod_php and PHP-FPM both running this build: both are restarted, and both get the mitigation', () => {
  const [en, ko] = both(F.deb13both);
  for (const r of [en, ko]) {
    const restart = stepWith(r, 'sudo systemctl restart php8.4-fpm\nsudo systemctl restart apache2');
    assert.ok(restart);
    assert.match(restart.text, /full restart of Apache|Apache를 완전히 재시작/);
    assert.ok(stepWith(r, /conf-available\/php2shell-mitigation\.conf/));
    assert.ok(stepWith(r, /pool\.d\/zz-php2shell-mitigation\.conf/));
  }
  // The second mitigation step does not repeat the first one's introduction.
  assert.match(stepWith(en, /pool\.d\/zz-php2shell/).text, /^PHP-FPM runs this PHP as well/);
});

test('2. without a package list the installed packages are looked up, and the restart names both services', () => {
  for (const r of both(F.nobleHeader)) {
    const update = stepWith(r, "sudo apt-get update\nsudo apt-get install --only-upgrade $(dpkg -l 'php8.3-*' 'libapache2-mod-php8.3' 2>/dev/null | awk '/^ii/ {print $2}')");
    assert.ok(update);
    assert.ok(update.text.includes('8.3.6-0ubuntu0.24.04.4') && update.text.includes('8.3.6-0ubuntu0.24.04.13'));
    assert.ok(stepWith(r, "dpkg -l 'php8.3-*' 'libapache2-mod-php8.3' | grep '^ii'"));
    assert.ok(stepWith(r, 'sudo systemctl restart apache2   # Apache mod_php\nsudo systemctl restart php8.3-fpm   # PHP-FPM'));
  }
});

// ── 3. RHEL family ──────────────────────────────────────────────────

test('3. RHEL module stream: the advisory, dnf updateinfo and upgrade with the detected names, the stream, the changelog', () => {
  const [en, ko] = both(F.rockyModule);
  for (const r of [en, ko]) {
    const upgrade = stepWith(r, `sudo dnf updateinfo list --cve ${CVES}\nsudo dnf upgrade --refresh php-common php-fpm php-cli`);
    assert.ok(upgrade);
    assert.match(upgrade.text, /RHSA-2026:87072/);
    assert.match(upgrade.text, /RLSA/);
    assert.doesNotMatch(upgrade.text, /same number|번호는 대개/);
    assert.match(stepWith(r, 'dnf module list php').text, /php:8\.2-9080020261020145734\.9/);
    // The stream is checked before the upgrade.
    assert.ok(indexWith(r, 'dnf module list php') < indexWith(r, /^sudo dnf updateinfo/));
    assert.ok(stepWith(r, `rpm -q php-common php-fpm php-cli\nrpm -q --changelog php-common | ${GREP}`));
    assert.ok(stepWith(r, 'sudo systemctl restart php-fpm'));
    assert.ok(stepWith(r, 'sudo sh php2shell-server-check.sh'), 'the server script confirms the changelog');
  }
  assert.match(stepWith(en, 'dnf module list php').text, /^Before you update.*do not need to switch streams/);
});

test('3. a stream with no fix next to newer streams that have one: switch streams after testing', () => {
  const [en, ko] = both(F.rhel9php81);
  for (const r of [en, ko]) {
    const sw = stepWith(r, 'sudo dnf module switch-to php:8.2');
    assert.match(sw.text, /RHSA-2026:87072/);
    assert.match(sw.text, /RHSA-2026:87079/);
    assert.match(sw.text, /php:8\.2-9080020261020145734\.9/);
  }
  assert.match(stepWith(en, 'sudo dnf module switch-to php:8.2').text, /Test your application with php:8\.2/);
  assert.match(stepWith(en, /^sudo dnf updateinfo/).text, /^If you stay on php:8\.1, there is nothing to install for it yet/);
});

test('3. RHEL base package: the fixed NVR from the advisory is what rpm -q should show', () => {
  for (const r of both(F.rhel9Base)) {
    assert.match(stepWith(r, /^sudo dnf updateinfo/).text, /RHSA-2026:87151/);
    assert.ok(stepWith(r, `rpm -q php-common php\nrpm -q --changelog php-common | ${GREP}`).text.includes('8.0.30-8.el9_8.1'));
    assert.ok(stepWith(r, 'sudo systemctl restart httpd'));
  }
});

test('3. RHEL 7 uses yum and says it is out of regular support; CentOS 6 uses service and says it is end of life', () => {
  const [en7, ko7] = both(F.rhel7Probe);
  for (const r of [en7, ko7]) {
    assert.match(r.actions[0].code, /\nsudo sh php2shell-server-check\.sh$/, 'the probe alone cannot read the changelog');
    assert.ok(stepWith(r, `sudo yum updateinfo list --cve ${CVES}\nsudo yum update 'php*'`));
    assert.ok(stepWith(r, 'sudo systemctl restart httpd'));
    assert.doesNotMatch(all(r), /dnf/);
    // Red Hat lists CVE-2026-109619 as not affected for RHEL 7: no changelog line is expected for it.
    assert.ok(stepWith(r, "rpm -qa 'php*'\nrpm -q --changelog php-common | grep -e CVE-2026-109618"));
  }
  assert.match(all(en7), /RHEL 7 is past the end of its regular support/);
  assert.match(all(ko7), /RHEL 7 릴리스는 정규 지원이 끝났습니다/);
  assert.match(stepWith(en7, /grep -e CVE-2026-109618$/).text, /CVE-2026-109619 as not affected for RHEL 7, so no line is expected/);
  const [en6, ko6] = both(F.centos6);
  for (const r of [en6, ko6]) {
    assert.ok(stepWith(r, "sudo yum update 'php*'"));
    assert.ok(stepWith(r, 'sudo service httpd restart'));
    assert.match(all(r), /sudo service httpd reload/);
    assert.doesNotMatch(all(r), /systemctl|dnf/);
  }
  assert.match(all(en6), /CentOS 6 has reached end of life/);
  assert.match(all(en6), /RHEL 9, Rocky Linux 9 or AlmaLinux 9/);
  assert.match(all(ko6), /CentOS 6 릴리스는 지원이 종료/);
  // No updates come any more: the mitigation follows the steps that explain that, before the update steps.
  for (const r of [en6, ko6, ...both(F.centos7srv)]) {
    const watch = indexWith(r, /^https:\/\/access\.redhat\.com/);
    assert.match(r.actions[watch + 1].code, /php2shell-mitigation\.conf/);
    assert.ok(watch + 1 < indexWith(r, /yum update/));
  }
  assert.match(stepWith(en6, /php2shell-mitigation/).text, /^Until this server runs a supported release/);
  assert.match(stepWith(ko6, /php2shell-mitigation/).text, /^지원되는 릴리스로 옮길 때까지는/);
});

test('3. no Red Hat fix for this stream yet: the state and where to watch, the mitigation now, and an update step that says it has nothing yet', () => {
  const [en, ko] = both(F.alma84);
  for (const r of [en, ko]) {
    const watch = stepWith(r, 'https://access.redhat.com/security/cve/CVE-2026-109618\nhttps://access.redhat.com/security/cve/CVE-2026-109619');
    assert.match(watch.text, /Affected|영향받음/);
    assert.doesNotMatch(all(r), /ALSA/);
    assert.equal(r.actions.indexOf(watch), 0);
    assert.match(r.actions[1].code, /zz-php2shell-mitigation\.conf/);
    assert.match(stepWith(r, /^sudo dnf updateinfo/).text, /nothing to install for this yet|아직 설치할 수정이 없습니다/);
    assert.match(stepWith(r, 'sudo sh php2shell-server-check.sh').text, /^Once the update is installed|^업데이트를 설치한 뒤/);
  }
  assert.match(en.actions[1].text, /^Until the fixed package is published/);
});

test('3. a RHEL release that is not known: the advisories of every release for this branch, never "RHEL ?"', () => {
  const [en, ko] = both(F.rockyHeader);
  for (const r of [en, ko]) assert.doesNotMatch(all(r), /RHEL \?|RHEL \{/);
  assert.match(stepWith(en, /^sudo dnf updateinfo/).text, /The RHEL release of this server is not known\. Red Hat has fixed PHP 8\.2 on RHEL 8 in RHSA-2026:87073 and on RHEL 9 in RHSA-2026:87072/);
  assert.match(stepWith(ko, /^sudo dnf updateinfo/).text, /RHEL 8\(RHSA-2026:87073\), RHEL 9\(RHSA-2026:87072\)의 PHP 8\.2를 수정했으며/);
});

test('3. Amazon Linux: its own ALAS pages, never "RHEL 2023", and Amazon Linux 2 is out of support', () => {
  for (const name of ['amzn2023', 'amzn2']) {
    const [en, ko] = both(F[name]);
    for (const r of [en, ko]) {
      assert.ok(stepWith(r, 'https://explore.alas.aws.amazon.com/CVE-2026-109618.html\nhttps://explore.alas.aws.amazon.com/CVE-2026-109619.html'));
      assert.doesNotMatch(all(r), /RHEL 20|RHEL 2\b|access\.redhat\.com/);
    }
    assert.match(all(en), /ALAS advisories, not in Red Hat ones/);
  }
  assert.ok(stepWith(run(F.amzn2023), `sudo dnf updateinfo list --cve ${CVES}\nsudo dnf upgrade --refresh php8.3-common php8.3-fpm`));
  assert.match(all(run(F.amzn2)), /Amazon Linux 2 reached the end of its support on 30 June 2026/);
  assert.match(all(run(F.amzn2, 'ko')), /Amazon Linux 2는 2026년 6월 30일에 지원이 종료/);
  assert.doesNotMatch(all(run(F.amzn2023)), /end of its support/);
});

test('3. RHEL 10 php8.4 packages the server script did not list are still Red Hat\'s: the dnf route, not a source build', () => {
  for (const r of both(F.rhel10)) {
    assert.doesNotMatch(all(r), /php\.net\/distributions|make install/);
    assert.ok(stepWith(r, `sudo dnf updateinfo list --cve ${CVES}\nsudo dnf upgrade --refresh 'php*'`));
    assert.match(stepWith(r, /^sudo dnf updateinfo/).text, /RHSA-2026:87071/);
    // RHSA-2026:87071 is a rebase to 8.4.27, whose changelog entry names the version, not the CVEs (round 3).
    assert.ok(stepWith(r, "rpm -qa 'php*'").text.includes('8.4.27-1.el10_2'));
    assert.doesNotMatch(all(r), /rpm -q --changelog/);
    assert.ok(stepWith(r, 'sudo systemctl restart php-fpm'));
  }
});

test('3. a Remi collection is updated by its own names, restarted by its own service, and its pool file is tested first', () => {
  for (const r of both(F.remiScl)) {
    const upgrade = stepWith(r, 'sudo dnf upgrade --refresh php82-php-common php82-php-fpm');
    assert.match(upgrade.text, /8\.2\.35/);
    assert.ok(stepWith(r, 'sudo systemctl restart php82-php-fpm'));
    assert.match(stepWith(r, /\/etc\/opt\/remi\/php82\/php-fpm\.d\/zz-php2shell-mitigation\.conf/).code, /\nsudo \/opt\/remi\/php82\/root\/usr\/sbin\/php-fpm -t && sudo systemctl reload php82-php-fpm$/);
  }
  // An end-of-life Remi collection gets Remi's own backport, and no self-built php-src branch next to it.
  for (const r of both(F.remi74)) {
    assert.ok(stepWith(r, 'sudo dnf upgrade --refresh php74-php-common php74-php-fpm'));
    assert.doesNotMatch(all(r), /git clone|7\.4\.33-20\.el9\.remi, so|7\.4\.33-20\.el9\.remi 그대로/);
  }
});

// ── 4. Self-built or upstream builds on a supported branch ─────────

test('4. self-built PHP: the fixed release from php.net, the same configure options, and the SAPI binary to confirm', () => {
  const [en, ko] = both(F.selfFpm);
  for (const r of [en, ko]) {
    const get = stepWith(r, 'curl -fsSLO https://www.php.net/distributions/php-8.3.36.tar.xz\nsha256sum php-8.3.36.tar.xz');
    assert.ok(get.text.includes('8.3.20') && get.text.includes('8.3.36'));
    assert.ok(stepWith(r, /^php-fpm -i \| grep -i 'configure command'\ntar -xf php-8\.3\.36\.tar\.xz\ncd php-8\.3\.36\n\.\/configure <current-options>\nmake -j"\$\(nproc\)"\nsudo make install$/));
    assert.ok(stepWith(r, 'sudo systemctl restart <php-fpm-service>'));
    assert.ok(stepWith(r, 'php-fpm -v').text.includes('8.3.36'));
    assert.ok(!r.actions.some((a) => a.code === 'php -v'), 'never the command-line php');
  }
  assert.match(stepWith(en, 'php-fpm -v').text, /not the command-line php/);
  // mod_php has no binary of its own: the probe confirms, and Apache keeps the distribution's service name.
  for (const r of both(F.selfApache)) {
    assert.ok(stepWith(r, 'sudo systemctl restart apache2'));
    const last = r.actions.findIndex((a) => /8\.4\.27/.test(a.text) && !a.code);
    assert.ok(last >= 0, 'a probe-based confirm step');
  }
  // The mitigation goes into the php.ini of the configuration directory this PHP reports.
  for (const r of both(F.selfFpm)) {
    assert.equal(stepWith(r, /php\.ini/).code, "echo 'session.upload_progress.enabled = 0' | sudo tee -a /usr/local/lib/php.ini >/dev/null\nsudo systemctl restart <php-fpm-service>");
  }
});

test('4. -v output or a bare version: the probe first, no claim about where PHP comes from, and never php -v as proof', () => {
  const [en, ko] = both(F.cliVersion);
  for (const r of [en, ko]) {
    assert.match(r.actions[0].code, /php2shell-selfcheck\.php\ncurl -s 'https:\/\/<site>\/<file>\.php\?k=<TOKEN>'$/);
    assert.ok(!r.actions.some((a) => a.code === 'php -v'));
    assert.doesNotMatch(all(r), /is not a distribution package/);
  }
  assert.match(en.actions[1].text, /^Nothing in this input shows where PHP 8\.4\.20 comes from/);
  assert.match(ko.actions[1].text, /^이 입력만으로는 PHP 8\.4\.20 버전을 어디서 설치했는지 알 수 없습니다/);
  assert.match(all(en), /Do not rely on php -v/);
  // With the probe, the step says the version matches no distribution package in the data, not that it is none.
  assert.match(all(run(F.selfFpm)), /does not match a distribution package in the data of this check/);
});

test('4. other systems: service names and package commands where the distribution fixes them, root shells on Alpine', () => {
  for (const r of both(F.fedora)) {
    assert.ok(stepWith(r, "sudo dnf upgrade --refresh 'php*'"));
    assert.ok(stepWith(r, 'sudo systemctl restart php-fpm'));
    assert.match(stepWith(r, /zz-php2shell/).code, /^sudo tee \/etc\/php-fpm\.d\/zz-php2shell-mitigation\.conf[\s\S]*\nsudo php-fpm -t && sudo systemctl reload php-fpm$/);
  }
  for (const r of both(F.suse)) {
    assert.ok(stepWith(r, 'sudo systemctl restart apache2'));
    assert.doesNotMatch(all(r), /<apache-service>|<php-fpm-service>/);
  }
  for (const r of both(F.alpine)) {
    assert.ok(stepWith(r, "apk update\napk upgrade $(apk info | grep '^php83')"));
    assert.ok(stepWith(r, 'rc-service php-fpm83 restart'));
    assert.ok(stepWith(r, 'sh php2shell-server-check.sh'));
    assert.doesNotMatch(all(r), /sudo/);
  }
  // CGI: whatever starts php-cgi is restarted, and the processes left are listed; the ini goes in the CGI scan dir.
  for (const r of both(F.cgi)) {
    assert.ok(stepWith(r, "sudo systemctl restart apache2   # Apache mod_fcgid\nps -eo pid,lstart,args | grep -E '[p]hp-cgi|[c]gi-bin/php'"));
    assert.doesNotMatch(all(r), /php8\.2-fpm|# PHP-FPM/);
    assert.match(stepWith(r, /99-php2shell-mitigation\.ini/).code, /^echo 'session\.upload_progress\.enabled = 0' \| sudo tee \/etc\/php\/8\.2\/cgi\/conf\.d\/99-php2shell-mitigation\.ini >\/dev\/null\n/);
  }
});

// ── 5. End-of-life branches ─────────────────────────────────────────

test('5. end of life: supported branches with their fixed releases, packages that carry the backport, the php-src branch', () => {
  const [en, ko] = both(F.eol81);
  for (const r of [en, ko]) {
    const move = r.actions[0];
    for (const v of ['8.4', '8.4.27', '8.3', '8.3.36']) assert.ok(move.text.includes(v), v);
    // The mitigation is the only thing that helps tonight, so it comes right after the explanation.
    assert.match(r.actions[1].code, /^echo 'session\.upload_progress\.enabled = 0' \| sudo tee -a \/usr\/local\/lib\/php\.ini >\/dev\/null/);
    // The closest fixed PHP on this very server comes first, the other carriers after it.
    const host = stepWith(r, 'sudo apt-get update\nsudo apt-get install php8.2-fpm');
    assert.match(host.text, /Debian 12/);
    assert.match(host.text, /8\.2\.35-1~deb12u1/);
    assert.match(host.text, /Ubuntu 22\.04 \(php8\.1 8\.1\.2-1ubuntu2\.28\)/);
    const backport = stepWith(r, /git clone/);
    assert.equal(backport.code, [
      "php-fpm -i | grep -i 'configure command'",
      'git clone --depth 1 --branch PHP-8.1-CVE-2026-109618-109619 https://github.com/php/php-src.git',
      'cd php-src',
      './buildconf --force',
      './configure <current-options>',
      'make -j"$(nproc)"',
      'sudo make install',
    ].join('\n'));
    assert.ok(backport.text.includes('8.1.30'));
    assert.match(backport.text, /autoconf, bison/);
  }
  assert.match(en.actions[0].text, /test your application/);
  assert.match(ko.actions[0].text, /애플리케이션을 테스트하세요/);
  assert.match(en.actions[1].text, /^Until this site runs on a supported branch/);
  assert.match(ko.actions[1].text, /^지원되는 브랜치로 옮길 때까지는/);
  assert.match(stepWith(en, /git clone/).text, /still say Vulnerable/);
  assert.match(stepWith(ko, /git clone/).text, /계속 취약으로/);
  // 8.0: the RHEL 9 package carries it; 7.3 has neither a carrier nor a backport branch.
  for (const r of both(F.eol80)) assert.match(all(r), /RHEL 9 \(php-0:8\.0\.30-8\.el9_8\.1, RHSA-2026:87151\)/);
  for (const r of both(F.eol73)) {
    assert.doesNotMatch(all(r), /git clone/);
    assert.match(all(r), /long-term support|장기 지원/);
  }
  // Installing the Apache module package next to a loaded PHP module would clash, so no command is given for it.
  for (const r of both(F.eol74apache)) {
    assert.match(all(r), /libapache2-mod-php8\.2/);
    assert.doesNotMatch(codes(r).join('\n'), /apt-get install libapache2-mod-php/);
  }
  // An end-of-life official image also gets the mitigation right after the step that moves it.
  for (const r of both(F.dockerEol)) assert.match(r.actions[1].code, /PHP_INI_DIR/);
});

// ── 6. Patched on disk, still old in memory ─────────────────────────

test('6. restart: why the old build is still loaded, the full restart for the SAPI and distribution, and how to confirm', () => {
  const [en, ko] = both(F.jammyRestart);
  for (const r of [en, ko]) {
    assert.equal(r.actions.length, 3);
    assert.equal(r.actions[0].code, 'sudo systemctl restart apache2');
    // The old build served requests until now, so the compromise check applies.
    assert.equal(r.actions[2].code, 'sudo sh php2shell-server-check.sh --logs --webroot <webroot>');
  }
  assert.match(en.actions[0].text, /loaded the old build before the update/);
  assert.match(en.actions[0].text, /mod_php.*full restart of Apache, not a reload or a graceful restart/);
  assert.match(ko.actions[0].text, /업데이트 전에 이전 빌드를 로드했고/);
  assert.match(en.actions[1].text, /Run check.*Restart needed/);
  assert.match(ko.actions[1].text, /결과확인.*재시작 필요/);
  // From the server script: the service of the stale processes, and the script again to see none left.
  const [enD, koD] = both(F.debianStale);
  for (const r of [enD, koD]) {
    assert.equal(r.actions[0].code, 'sudo systemctl restart php8.2-fpm');
    assert.equal(r.actions[1].code, 'sudo sh php2shell-server-check.sh');
  }
  // A PHP-FPM reload re-executes the master from disk; only mod_php keeps the old build through a reload.
  for (const r of [enD, koD, ...both(F.jammyFpm), ...both(F.rockyModule)]) {
    assert.doesNotMatch(all(r), /keeps the old PHP build loaded|graceful|이전 PHP 빌드가 메모리에 그대로 남습니다/);
  }
  for (const r of both(F.rockyStale)) assert.equal(r.actions[0].code, 'sudo systemctl restart httpd');
  for (const r of [en, ko, enD, koD, ...both(F.rockyStale)]) {
    for (const c of codes(r)) assert.doesNotMatch(c, /reload|graceful/);
  }
  // Processes no checked build accounts for: a way to find what started them.
  for (const r of both(F.staleOther)) assert.equal(r.actions[0].code, 'ps -o pid,user,cgroup,args -C php-fpm8.3');
  assert.match(run(F.staleOther).actions[0].text, /CGROUP column.*\.service.*docker-<id>\.scope/);
});

// ── 7. Distribution fix pending ─────────────────────────────────────

test('7. pending: what it means, where to watch, how to see the fix arrive, and the mitigation as an Apache snippet', () => {
  const [en, ko] = both(F.forkyApache);
  for (const r of [en, ko]) {
    assert.equal(r.actions[0].code, 'https://security-tracker.debian.org/tracker/CVE-2026-109618\nhttps://security-tracker.debian.org/tracker/CVE-2026-109619');
    assert.ok(stepWith(r, 'sudo apt-get update\napt list --upgradable 2>/dev/null | grep php8.4\nsudo apt-get install --only-upgrade libapache2-mod-php8.4 php8.4-common'));
    const mit = stepWith(r, /php2shell-mitigation\.conf/);
    assert.equal(mit.code, [
      "sudo tee /etc/apache2/conf-available/php2shell-mitigation.conf >/dev/null <<'EOF'",
      '<IfModule php_module>',
      '    php_admin_flag session.upload_progress.enabled off',
      '    # php_admin_value memory_limit -1',
      '</IfModule>',
      'EOF',
      'sudo a2enconf php2shell-mitigation',
      'sudo apachectl configtest && sudo systemctl reload apache2',
    ].join('\n'));
    assert.match(r.actions[r.actions.length - 1].text, /compromise|침해 지표/);
    // Nothing can be installed yet, so the mitigation comes straight after the explanation, before the steps
    // that wait for the fix.
    assert.match(r.actions[1].code, /php2shell-mitigation\.conf/);
  }
  const mitEn = stepWith(en, /php2shell-mitigation/).text;
  assert.match(en.actions[0].text, /no fixed php8\.4 package yet/);
  assert.match(mitEn, /^Until the fixed package is published/);
  assert.match(mitEn, /does not replace the patch/);
  assert.match(mitEn, /only with a memory cap outside PHP, such as MemoryMax=/);
  assert.match(mitEn, /uploads keep working/);
  assert.doesNotMatch(mitEn, /pm\.max_children|MaxRequestWorkers/);
  const mitKo = stepWith(ko, /php2shell-mitigation/).text;
  assert.match(mitKo, /^수정 패키지가 공개될 때까지는/);
  assert.match(mitKo, /패치를 대신하지 않습니다/);
});

test('7. the PHP-FPM pool snippet uses the pool directory, binary and service of the distribution', () => {
  const [enFpm] = both(F.forkyFpm);
  assert.match(stepWith(enFpm, /zz-php2shell/).text, /"\[pool www\] user has not been defined".*put your pool's name in the brackets/);
  for (const r of both(F.forkyFpm)) {
    assert.equal(stepWith(r, /zz-php2shell-mitigation/).code, [
      "sudo tee /etc/php/8.4/fpm/pool.d/zz-php2shell-mitigation.conf >/dev/null <<'EOF'",
      '[www]',
      'php_admin_flag[session.upload_progress.enabled] = off',
      '; php_admin_value[memory_limit] = -1',
      'EOF',
      'sudo php-fpm8.4 -t && sudo systemctl reload php8.4-fpm',
    ].join('\n'));
  }
  for (const r of both(F.rockyModule)) assert.match(stepWith(r, /zz-php2shell/).code, /^sudo tee \/etc\/php-fpm\.d\/zz-php2shell-mitigation\.conf[\s\S]*\nsudo php-fpm -t && sudo systemctl reload php-fpm$/);
  // PHP 7 names its Apache module php7_module; PHP 8.5 also turns off fatal_error_backtraces.
  for (const r of both(F.focalPro)) assert.match(stepWith(r, /php2shell-mitigation/).code, /<IfModule php7_module>/);
  for (const r of both(F.resolute85)) {
    const mit = stepWith(r, /php2shell-mitigation/);
    assert.match(mit.code, /php_admin_flag fatal_error_backtraces off/);
    assert.match(mit.text, /fatal_error_backtraces/);
  }
});

test('7. Ubuntu points to its own CVE pages, and a mitigation already in place is not repeated as a snippet', () => {
  const data = JSON.parse(JSON.stringify(distro));
  data.ubuntu['24.04'].packages['php8.3'].fixed = { 'CVE-2026-109618': null, 'CVE-2026-109619': null };
  const text = probe({ php_version: '8.3.6-0ubuntu0.24.04.4', sapi: 'fpm-fcgi', config_path: '/etc/php/8.3/fpm', os_release: { ID: 'ubuntu', VERSION_ID: '24.04' }, dpkg_packages: [{ name: 'php8.3-fpm', version: '8.3.6-0ubuntu0.24.04.4', source: 'php8.3' }], ini: INI });
  for (const r of both(text, data)) {
    assert.equal(r.verdict, 'pending');
    assert.equal(r.actions[0].code, 'https://ubuntu.com/security/CVE-2026-109618\nhttps://ubuntu.com/security/CVE-2026-109619');
  }
  const off = probe({ php_version: '8.4.26', sapi: 'fpm-fcgi', config_path: '/etc/php/8.4/fpm', os_release: { ID: 'debian', VERSION_CODENAME: 'forky' }, dpkg_packages: [{ name: 'php8.4-fpm', version: '8.4.26-1', source: 'php8.4' }], ini: { ...INI, 'session.upload_progress.enabled': '0' } });
  for (const r of both(off)) {
    assert.doesNotMatch(all(r), /zz-php2shell-mitigation/);
    assert.match(all(r), /listed in this result|이 결과에 나온/);
  }
});

// ── 8. Undetermined: what to collect next ───────────────────────────

test('8. an unread OS release asks for the server script as root, or the distribution in the list, and nothing else to run', () => {
  const [en, ko] = both(F.osUnread);
  for (const r of [en, ko]) {
    assert.equal(r.actions[0].code, `${FETCH}\nsudo sh php2shell-server-check.sh`);
    assert.equal(r.actions[1].code, undefined);
    assert.doesNotMatch(all(r), /apt-get|dnf|yum|FROM php|zz-php2shell/);
  }
  assert.match(en.actions[0].text, /as root/);
  assert.match(en.actions[0].text, /compare the hash with the one on the Server script tab/);
  assert.match(en.actions[1].text, /Distribution list next to Run check/);
  assert.match(ko.actions[1].text, /배포판 목록/);
  assert.match(ko.actions[1].text, /결과확인/);
});

test('8. each open question gets its own next step', () => {
  // Processes hidden without root: run as root; the package already has the fix, so restart if unsure.
  for (const r of both(F.hidden)) {
    assert.equal(r.actions[0].code, 'sudo sh php2shell-server-check.sh');
    assert.equal(r.actions[1].code, 'sudo systemctl restart php8.3-fpm');
    assert.doesNotMatch(all(r), /apt-get|zz-php2shell/);
  }
  assert.match(run(F.hidden).actions[0].text, /again as root/);
  // A cut-off server script output: copy it again. The package already records both fixes, so no mitigation.
  for (const r of both(F.truncated)) {
    assert.match(r.actions[0].text, /BEGIN.*END/);
    assert.doesNotMatch(all(r), /interim mitigation|임시 완화|memory_limit/);
  }
  // PHP processes no checked build accounts for: check them where they run (as root in a container), without
  // naming a service of this build.
  for (const r of both(F.unaccounted)) {
    assert.equal(r.actions[0].code, 'docker cp php2shell-server-check.sh <container>:/tmp/\ndocker exec -u 0 <container> sh /tmp/php2shell-server-check.sh');
    assert.doesNotMatch(all(r), /php8\.1-fpm|zz-php2shell/);
  }
  assert.match(run(F.unaccounted).actions[0].text, /-u 0 runs it as root inside the container/);
  // Probe and server script from different moments: run both together.
  for (const r of both(F.conflict)) assert.match(r.actions[0].text, /together|함께/);
  // A revision Ubuntu does not build: find its repository.
  for (const r of both(F.foreign)) assert.equal(r.actions[0].code, 'apt-cache policy php8.3-fpm');
  // The server script ran but the release is unknown: the distribution list, not the script again, as the only
  // way forward (no "Or"); an unknown Debian release is a systemd one.
  const [enN, koN] = both(F.debianNoRelease);
  for (const r of [enN, koN]) {
    assert.equal(r.actions[0].code, undefined);
    assert.match(r.actions[0].text, /Distribution list|배포판 목록/);
    assert.doesNotMatch(codes(r).join('\n'), /sudo service /);
    assert.ok(stepWith(r, 'sudo systemctl restart php8.2-fpm'));
  }
  assert.match(enN.actions[0].text, /^The server script output does not name the release of this system\./);
  assert.match(koN.actions[0].text, /^서버 스크립트 출력에 이 시스템의 릴리스가 나오지 않습니다\./);
  assert.doesNotMatch(koN.actions[0].text, /눌러도 됩니다/);
  // Nothing readable: the probe through the web server, then the server script.
  const [enV, koV] = both(F.noVersion);
  for (const r of [enV, koV]) assert.deepEqual(codes(r), [PROBE, `${FETCH}\nsudo sh php2shell-server-check.sh`]);
  assert.match(enV.actions[0].text, /PHP probe tab.*set \$TOKEN at the top of the file to 12 or more random letters and digits/);
  assert.match(koV.actions[0].text, /\$TOKEN을 영문자와 숫자로 된 12자 이상의 임의 문자열로/);
  // A bare version that may be a distribution package: the probe, the server script, or the distribution list.
  for (const r of both('8.0.30')) {
    assert.equal(r.verdict, 'unknown');
    assert.deepEqual(codes(r).slice(0, 3), [PROBE, `${FETCH}\nsudo sh php2shell-server-check.sh`, '']);
    assert.match(r.actions[2].text, /Distribution list|배포판 목록/);
  }
  // RHEL from the probe alone: the server script first, then the update steps.
  for (const r of both(F.rhelProbe)) {
    assert.equal(r.actions[0].code, `${FETCH}\nsudo sh php2shell-server-check.sh`);
    assert.ok(stepWith(r, `sudo dnf updateinfo list --cve ${CVES}\nsudo dnf upgrade --refresh 'php*'`));
  }
  // The compromise check says how to run it.
  for (const r of both(F.jammyFpm)) assert.equal(r.actions[r.actions.length - 1].code, 'sudo sh php2shell-server-check.sh --logs --webroot <webroot>');
  assert.match(run(F.jammyFpm).actions.at(-1).text, /--webroot pointing at the site's directory \(for example \/var\/www\)/);
});

// ── 9. Patched ──────────────────────────────────────────────────────

test('9. patched: other sites and pools, optional expose_php hardening for the SAPI, upload progress can stay off', () => {
  const [en, ko] = both(F.patchedFpm);
  for (const r of [en, ko]) {
    assert.equal(r.actions.length, 3);
    assert.equal(r.actions[1].code, "echo 'expose_php = Off' | sudo tee /etc/php/8.3/fpm/conf.d/99-hardening.ini\nsudo systemctl restart php8.3-fpm");
    assert.doesNotMatch(all(r), /compromise|침해 지표|php2shell-mitigation/);
  }
  assert.match(en.actions[0].text, /vhost.*pool/);
  assert.match(en.actions[1].text, /^Optional hardening/);
  assert.match(en.actions[2].text, /session\.upload_progress\.enabled/);
  for (const r of both(F.patchedDocker)) {
    assert.equal(r.actions[1].code, 'RUN echo \'expose_php = Off\' > "$PHP_INI_DIR/conf.d/zz-hardening.ini"');
    assert.match(r.actions[2].text, /keep it off|꺼 두세요/);
    // In a container, the other containers and images matter, not vhosts.
    assert.match(r.actions[0].text, /other container|다른 컨테이너/);
    assert.doesNotMatch(r.actions[0].text, /vhost/);
  }
  // A hardening step only changes a setting: no "new build" sentence borrowed from the update path.
  for (const r of both(F.patchedApache)) {
    const expose = stepWith(r, /expose_php = Off/);
    assert.equal(expose.code, "echo 'expose_php = Off' | sudo tee /etc/php/8.2/apache2/conf.d/99-hardening.ini\nsudo systemctl restart apache2");
    assert.doesNotMatch(expose.text, /new build|새 빌드/);
  }
  // expose_php already off: no hardening step for it. A header shows it on, with no layout to name a file.
  for (const r of both(F.patchedQuiet)) assert.doesNotMatch(all(r), /expose_php/);
  for (const r of both(F.patchedHeader)) {
    assert.match(r.actions[1].text, /expose_php = Off/);
    assert.equal(r.actions[1].code, undefined);
  }
});

// ── Every result ────────────────────────────────────────────────────

const PLACEHOLDERS = new Set(['container', 'your-image', 'token', 'variant', 'current-options', 'php-fpm-service', 'apache-service', 'site', 'file', 'TOKEN', 'webroot']);

test('every step: same commands in both languages, nothing destructive, only marked placeholders, plain text', () => {
  for (const [name, text] of Object.entries(F)) {
    const [en, ko] = both(text);
    assert.deepEqual(codes(ko), codes(en), `${name}: the same commands in both languages`);
    for (const r of [en, ko]) {
      for (const a of r.actions) {
        assert.deepEqual(Object.keys(a).sort(), a.code ? ['code', 'text'] : ['text'], name);
        assert.equal(typeof a.text, 'string');
        assert.doesNotMatch(a.text, /\{\w+\}|undefined|NaN|\bnull\b/, `${name}: ${a.text}`);
        const code = a.code || '';
        assert.doesNotMatch(code, /\brm\b|\bremove\b|\bpurge\b|\berase\b|--allowerasing|docker rmi?\b|prune|autoremove|\bkill\b/, `${name}: ${code}`);
        assert.doesNotMatch(code.replaceAll('/dev/null', ''), /undefined|NaN|\bnull\b/, name);
        for (const m of code.replace(/<<'EOF'/g, '').matchAll(/<([A-Za-z-]+)>/g)) assert.ok(PLACEHOLDERS.has(m[1]), `${name}: placeholder <${m[1]}>`);
        // A reload only applies a configuration change; restarts that load a new build never reload.
        if (/\breload\b/.test(code)) assert.match(a.text, /a reload is enough for a configuration change|설정 변경에는 reload로 충분합니다/, name);
      }
      for (const a of ko.actions) {
        assert.match(a.text, /[가-힣]/, `${name}: Korean text`);
        assert.doesNotMatch(a.text, /\uD310\uC815/, name);
      }
      for (const a of en.actions) assert.doesNotMatch(a.text, /recogniz|behavior|initializ|analyz|\bcolor/, `${name}: British spelling`);
    }
    // A mitigation never claims to fix the bug.
    for (const a of [...en.actions, ...ko.actions].filter((x) => /interim mitigation|임시 완화/.test(x.text))) {
      assert.match(a.text, /not replace|대신하지 않습니다/, `${name}: ${a.text}`);
    }
  }
});
