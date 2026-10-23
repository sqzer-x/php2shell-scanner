import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { LANGS, MESSAGES, translator } from '../site/lib/messages.js';
import { parseInput } from '../site/lib/parse.js';
import {
  judge, VERDICT_TITLES, VERDICT_LABELS, verdictTitles, verdictLabels, sapiLabel, sapiExposure, evaluateMitigations,
} from '../site/lib/judge.js';

const upstream = JSON.parse(readFileSync(new URL('../site/data/upstream.json', import.meta.url), 'utf8'));
const distro = JSON.parse(readFileSync(new URL('./fixtures/distro.json', import.meta.url), 'utf8'));

const HANGUL = /[가-힣]/;
const LEFTOVER = /\{\w+\}|undefined|NaN/;
const placeholders = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

const KO_TITLES = {
  patched: '수정이 적용된 PHP입니다',
  vulnerable: '취약한 PHP입니다',
  pending: '취약하며, 배포판의 수정 패키지가 아직 없습니다',
  restart: '설치된 PHP는 수정됐지만 실행 중인 PHP는 여전히 취약합니다',
  unknown: '판단할 근거가 부족합니다',
};
const KO_LABELS = {
  patched: '패치됨',
  vulnerable: '취약',
  pending: '수정 대기',
  restart: '재시작 필요',
  unknown: '판단 불가',
};

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
const servercheck = (lines) => `-----BEGIN PHP2SHELL SERVERCHECK-----\n${lines.join('\n')}\n-----END PHP2SHELL SERVERCHECK-----`;

const run = (text, lang, options = {}) => judge(parseInput(text, { lang }), upstream, distro, { ...options, lang });

test('the supported languages are English and Korean', () => {
  assert.deepEqual(LANGS, ['en', 'ko']);
  assert.deepEqual(Object.keys(MESSAGES).sort(), [...LANGS].sort());
});

test('English and Korean have the same keys, each of the same kind', () => {
  const en = Object.keys(MESSAGES.en).sort();
  const ko = Object.keys(MESSAGES.ko).sort();
  assert.deepEqual(ko.filter((k) => !en.includes(k)), [], 'keys only in ko');
  assert.deepEqual(en.filter((k) => !ko.includes(k)), [], 'keys only in en');
  for (const key of en) {
    assert.equal(typeof MESSAGES.ko[key], typeof MESSAGES.en[key], `kind of ${key}`);
    assert.ok(['string', 'function'].includes(typeof MESSAGES.en[key]), `kind of ${key}`);
  }
});

test('string messages use the same placeholders in both languages', () => {
  for (const [key, en] of Object.entries(MESSAGES.en)) {
    if (typeof en !== 'string') continue;
    assert.deepEqual(placeholders(MESSAGES.ko[key]), placeholders(en), `placeholders of ${key}`);
  }
});

test('function messages produce clean text for singular and plural counts', () => {
  for (const lang of LANGS) {
    const t = translator(lang);
    for (const [key, msg] of Object.entries(MESSAGES[lang])) {
      if (typeof msg !== 'function') continue;
      for (const n of [1, 3, '1', '4']) {
        const out = t(key, { n });
        assert.equal(typeof out, 'string');
        assert.ok(out.includes(String(n)), `${lang} ${key} shows the count ${n}`);
        assert.doesNotMatch(out, LEFTOVER, `${lang} ${key}`);
      }
    }
  }
  const en = translator('en');
  assert.match(en('finding.recentPhp', { n: 1 }), /^Found 1 PHP file changed/);
  assert.match(en('finding.recentPhp', { n: 2 }), /^Found 2 PHP files changed/);
  assert.match(en('parse.procUnreadable', { n: '1' }), /check 1 PHP process for/);
  assert.match(en('parse.procUnreadable', { n: '4' }), /check 4 PHP processes for/);
});

test('the translator falls back to English and rejects unknown keys and missing values', () => {
  for (const lang of ['xx', 'kr', '', undefined, null]) {
    assert.equal(translator(lang)('verdict.title.patched'), 'This PHP has the fix', `lang ${lang}`);
  }
  assert.equal(translator('ko')('verdict.title.patched'), KO_TITLES.patched);
  assert.throws(() => translator('ko')('no.such.key'), { message: 'Missing message: no.such.key' });
  assert.throws(() => translator('xx')('no.such.key'), { message: 'Missing message: no.such.key' });
  assert.throws(() => translator('ko')('toString'), { message: 'Missing message: toString' });
  assert.throws(() => translator('en')('reason.eol'), /\{branch\}/);

  MESSAGES.en['test.onlyInEnglish'] = 'Only {what}';
  try {
    assert.equal(translator('ko')('test.onlyInEnglish', { what: 'English' }), 'Only English');
  } finally {
    delete MESSAGES.en['test.onlyInEnglish'];
  }
});

test('placeholder values are inserted as they are, without being read as placeholders', () => {
  assert.equal(translator('en')('reason.eol', { branch: '{x}' }), 'PHP {x} has reached end of life (EOL) and has no official fix release, so an upstream build of it is vulnerable. Only a distribution package with the fixes backported can have them.');
  assert.equal(translator('ko')('advisory.fixedIn', { version: '8.2.35-1~deb12u1' }), '8.2.35-1~deb12u1에서 수정됨');
});

test('verdict titles and labels are available in both languages', () => {
  assert.deepEqual(verdictTitles('ko'), KO_TITLES);
  assert.deepEqual(verdictLabels('ko'), KO_LABELS);
  assert.deepEqual(verdictTitles('en'), VERDICT_TITLES);
  assert.deepEqual(verdictLabels('en'), VERDICT_LABELS);
  assert.deepEqual(verdictTitles(), VERDICT_TITLES);
  assert.deepEqual(verdictLabels('xx'), VERDICT_LABELS);
  assert.notEqual(verdictLabels('en'), VERDICT_LABELS, 'a fresh object every call');
});

test('exported helpers keep English by default and accept a language', () => {
  assert.equal(sapiLabel('cli'), 'Command line (CLI) (cli)');
  assert.equal(sapiLabel('cli', 'ko'), '명령줄(CLI) (cli)');
  assert.equal(sapiLabel('fpm-fcgi', 'ko'), 'PHP-FPM (fpm-fcgi)');
  assert.equal(sapiExposure('apache2handler').level, sapiExposure('apache2handler', 'ko').level);
  assert.match(sapiExposure('embed', 'ko').text, /embed/);
  assert.match(sapiExposure('embed', 'ko').text, HANGUL);
  const ini = { memory_limit: null, 'session.upload_progress.enabled': '' };
  const en = evaluateMitigations(ini, null, null);
  const ko = evaluateMitigations(ini, null, null, false, 'ko');
  assert.deepEqual(en.map((m) => m.value), ['(not set)', '(empty = Off)', '(not set)']);
  assert.deepEqual(ko.map((m) => m.value), ['(설정 안 됨)', '(빈 값 = Off)', '(설정 안 됨)']);
  assert.deepEqual(ko.map((m) => [m.name, m.status]), en.map((m) => [m.name, m.status]));
});

test('parseInput writes its notes in the requested language', () => {
  assert.match(parseInput('hello world').notes[0], /^No PHP version was found/);
  assert.match(parseInput('hello world', { lang: 'ko' }).notes[0], /^PHP 버전을 찾지 못했습니다/);
  assert.match(parseInput('PHP 8.3.6 (cli) (built: Mar 1 2026) (NTS)', { lang: 'ko' }).notes[0], /명령줄/);
  assert.deepEqual(parseInput('8.2.26', { lang: 'ko' }), parseInput('8.2.26'));
});

const SCENARIOS = {
  'upstream vulnerable (Docker)': [selfcheck({ php_version: '8.4.26', container: true, config_path: '/usr/local/etc/php', os_release: { ID: 'debian', VERSION_ID: '13' } })],
  'upstream patched': [selfcheck({ php_version: '8.4.27' })],
  'Ubuntu backport': [selfcheck({
    php_version: '8.1.2-1ubuntu2.28',
    os_release: { ID: 'ubuntu', VERSION_ID: '22.04', VERSION_CODENAME: 'jammy' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.1', version: '8.1.2-1ubuntu2.28', source: 'php8.1' }],
  })],
  'Ubuntu restart': [selfcheck({
    php_version: '8.1.2-1ubuntu2.20',
    os_release: { ID: 'ubuntu', VERSION_ID: '22.04' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.1', version: '8.1.2-1ubuntu2.28', source: 'php8.1' }],
  })],
  'Ubuntu vulnerable from a header': ['X-Powered-By: PHP/8.3.6-0ubuntu0.24.04.4'],
  'Ubuntu Pro': [selfcheck({
    php_version: '7.4.3-4ubuntu2.29+esm5',
    os_release: { ID: 'ubuntu', VERSION_ID: '20.04' },
    dpkg_packages: [{ name: 'libapache2-mod-php7.4', version: '7.4.3-4ubuntu2.29+esm5', source: 'php7.4' }],
  })],
  'Debian pending': [selfcheck({
    php_version: '8.4.26',
    os_release: { ID: 'debian', VERSION_CODENAME: 'forky' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.4', version: '8.4.26-1', source: 'php8.4' }],
  })],
  'Debian release unknown': [servercheck(['os|ID|debian', 'pkg|dpkg|php8.2-common|8.2.26-1~deb12u1|php8.2'])],
  'Sury build': [selfcheck({
    php_version: '8.3.14',
    os_release: { ID: 'debian', VERSION_ID: '12' },
    dpkg_packages: [{ name: 'libapache2-mod-php8.3', version: '8.3.14-1+0~20241122.43+debian12~1.gbp9f1e3a', source: 'php8.3' }],
  })],
  'EOL with a backport branch': ['8.1.30'],
  'PHP 5.3': ['5.3.29'],
  'PHP 8.6 RC': ['8.6.0RC3'],
  'CLI': ['PHP 8.3.6 (cli) (built: Mar 1 2026) (NTS)'],
  'RHEL changelog fixed': [servercheck(['os|ID|rocky', 'os|ID_LIKE|rhel centos fedora', 'os|VERSION_ID|9.6', 'pkg|rpm|php-common|8.0.30-8.el9_8.1|', 'changelog|php-common|CVE-2026-109618|2', 'changelog|php-common|CVE-2026-109619|2'])],
  'RHEL changelog missing': [servercheck(['os|ID|rocky', 'os|VERSION_ID|9.6', 'pkg|rpm|php-common|8.0.30-8.el9_8.1|', 'changelog|php-common|CVE-2026-109618|1', 'changelog|php-common|CVE-2026-109619|0'])],
  'server script findings': [servercheck(['os|ID|debian', 'os|VERSION_ID|12', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2', 'webuser_proc|2', 'log|oom|5', 'log|crash|1', 'log|bigsession|0', 'webroot|recent_php|3', 'proc|unreadable|4|unknown', 'proc|php-fpm8.2|812|stale'])],
  'server script clean': [servercheck(['os|ID|debian', 'os|VERSION_ID|12', 'pkg|dpkg|php8.2-fpm|8.2.35-1~deb12u1|php8.2', 'webuser_proc|0', 'log|oom|0'])],
  'mitigations unpatched': [selfcheck({ php_version: '8.5.11', ini: { memory_limit: '-1', 'session.upload_progress.enabled': '', 'session.auto_start': '1', fatal_error_backtraces: '1', max_input_nesting_level: '64', post_max_size: '8M', expose_php: '' } })],
  'mitigations patched': [selfcheck({ php_version: '8.5.12', ini: { memory_limit: '-1', 'session.upload_progress.enabled': '1', 'session.auto_start': '1', fatal_error_backtraces: '1', expose_php: 'On' } })],
  'manual distribution': ['X-Powered-By: PHP/8.1.2-1ubuntu2.28', { distro: 'ubuntu:22.04' }],
  'unknown input': ['hello world'],
};

for (const [name, [text, options]] of Object.entries(SCENARIOS)) {
  test(`Korean result: ${name}`, () => {
    const en = run(text, 'en', options);
    const ko = run(text, 'ko', options);
    assert.equal(ko.verdict, en.verdict, 'same verdict in both languages');
    assert.equal(ko.title, KO_TITLES[ko.verdict]);
    assert.equal(en.title, VERDICT_TITLES[en.verdict]);

    // Same shape: the same number of entries everywhere, the same data fields.
    for (const k of ['reasons', 'notes', 'actions', 'facts', 'mitigations', 'findings', 'advisories']) {
      assert.equal(ko[k].length, en[k].length, `${k} count`);
    }
    assert.deepEqual(ko.actions.map((a) => Boolean(a.code)), en.actions.map((a) => Boolean(a.code)));
    assert.deepEqual(ko.mitigations.map((m) => [m.name, m.status]), en.mitigations.map((m) => [m.name, m.status]));
    assert.deepEqual(ko.findings.map((f) => f.level), en.findings.map((f) => f.level));
    assert.equal(ko.exposure?.level, en.exposure?.level);
    assert.equal(ko.eol, en.eol);

    const prose = [
      ...ko.reasons, ...ko.notes, ...ko.actions.map((a) => a.text), ...ko.mitigations.map((m) => m.note),
      ...ko.findings.map((f) => f.text), ...(ko.exposure ? [ko.exposure.text] : []),
    ];
    assert.ok(prose.length > 0);
    for (const s of prose) assert.match(s, HANGUL, s);

    const everything = [
      ko.title, ...prose, ...ko.facts.flatMap((f) => [f.label, f.value]), ...ko.advisories.flatMap((a) => [a.label, a.value]),
      ...ko.mitigations.map((m) => String(m.value)), ...ko.actions.map((a) => a.code || ''),
    ];
    for (const s of everything) assert.doesNotMatch(s, LEFTOVER, s);
  });
}

test('Korean results keep data values and commands as they are', () => {
  const vulnerable = run(SCENARIOS['Ubuntu vulnerable from a header'][0], 'ko');
  assert.match(vulnerable.reasons.join(' '), /8\.3\.6-0ubuntu0\.24\.04\.13/);
  assert.ok(vulnerable.actions.some((a) => /^sudo apt-get update\nsudo apt-get install --only-upgrade \$\(dpkg -l 'php8\.3-\*'/.test(a.code || '')));
  assert.ok(vulnerable.actions.some((a) => a.code === 'sudo systemctl restart apache2   # Apache mod_php\nsudo systemctl restart php8.3-fpm   # PHP-FPM'));

  const restart = run(SCENARIOS['Ubuntu restart'][0], 'ko');
  assert.ok(restart.actions.some((a) => a.code === 'sudo systemctl restart apache2'));
  assert.match(restart.reasons[0], /8\.1\.2-1ubuntu2\.28.*8\.1\.2-1ubuntu2\.20/);

  const eol = run('8.1.30', 'ko');
  assert.match(eol.notes.join(' '), /PHP-8\.1-CVE-2026-109618-109619/);
  assert.match(eol.notes.join(' '), /백포트/);

  const rhel = run(SCENARIOS['RHEL changelog fixed'][0], 'ko');
  assert.ok(rhel.advisories.some((a) => /RHSA-2026:87151/.test(a.value)));
  assert.equal(rhel.facts.find((f) => f.label === '배포판').value, 'RHEL 9 계열');

  const inferred = run(servercheck(['os|ID|ubuntu', 'os|VERSION_ID|22.04', 'pkg|dpkg|libapache2-mod-php8.1|8.1.2-1ubuntu2.28|php8.1', 'proc|apache2|1|stale']), 'ko');
  assert.equal(inferred.facts.find((f) => f.label === 'SAPI').value, 'Apache mod_php (apache2handler) (실행 중인 프로세스로 추정)');

  const pending = run(SCENARIOS['Debian pending'][0], 'ko');
  assert.deepEqual(pending.advisories.map((a) => a.value), ['수정 대기', '수정 대기']);
});

test('English and Korean give the same commands, and English keeps the raw Red Hat fix states', () => {
  const en = run(SCENARIOS['Ubuntu vulnerable from a header'][0], 'en');
  const ko = run(SCENARIOS['Ubuntu vulnerable from a header'][0], 'ko');
  assert.deepEqual(ko.actions.map((a) => a.code || null), en.actions.map((a) => a.code || null));
  assert.ok(en.actions.some((a) => a.code === 'sudo systemctl restart apache2   # Apache mod_php\nsudo systemctl restart php8.3-fpm   # PHP-FPM'));
  const t = translator('en');
  for (const [state, key] of [['Affected', 'rhelState.affected'], ['Under investigation', 'rhelState.underInvestigation'], ['Fix deferred', 'rhelState.fixDeferred'], ['Will not fix', 'rhelState.willNotFix'], ['Not affected', 'rhelState.notAffected'], ['Out of support scope', 'rhelState.outOfSupportScope']]) {
    assert.equal(t(key), state);
  }
});

test('Korean mitigation notes never present a mitigation as a fix', () => {
  const unpatched = run(SCENARIOS['mitigations unpatched'][0], 'ko');
  const patched = run(SCENARIOS['mitigations patched'][0], 'ko');
  for (const r of [unpatched, patched]) {
    for (const s of [...r.mitigations.map((m) => m.note), ...r.actions.map((a) => a.text)]) {
      assert.doesNotMatch(s, /안전/, s);
    }
  }
  assert.ok(unpatched.actions.some((a) => /패치를 대신하지 않습니다/.test(a.text)));
  assert.ok(patched.mitigations.every((m) => m.status !== 'warn'));
});
