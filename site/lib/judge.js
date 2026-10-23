// Computes the verdict from an observation (parse.js) and the fixed-version data.
// Rule: when the evidence is not enough, never call it "safe". Leave the verdict as "unknown".
// All user-facing text comes from messages.js, in the language given by options.lang.
//
// Guards that keep a vulnerable PHP from being reported as patched:
// - A distribution package vouches for the running PHP only when its upstream version matches.
// - A release inferred from the version string is accepted only when it ships that upstream version.
// - A backport under the same upstream version counts only for the distribution's own revisions (ubuntu,
//   ~debNNuN): a PPA's or another vendor's build that merely sorts above the fixed version does not.
// - Changelog evidence counts only for the package of the PHP being judged, at the version that was read.
// - A PHP whose configuration lives outside /etc is not a distribution package.
// - A container probe is never judged by host packages, and outputs of different systems or moments are not
//   mixed (parse.js keeps the server script's system data out then).
// - -dev, alpha, beta, RC and pre builds are pre-releases.
// - Every PHP in the input counts: several outputs, and the other installed builds next to the probe's PHP, give
//   the worst verdict. A running PHP process that no checked build accounts for rules out Patched.
// - Patched on the installed package alone needs the running processes to have been checked: as root, readable,
//   and not cut off.
// - A Distribution list choice that contradicts the OS release or the version string is not used.

import { parsePhpVersion, comparePhp, compareDebian, compareRpm, splitDebian, debUpstream, debComparable, isSuryBuild, suryBuildDate } from './version.js';
import { translator, formatDate } from './messages.js';

// table[key] for a key that comes from the input (a SAPI name, an OS id): only the table's own entries, never a
// member of Object.prototype such as "constructor" or "toString".
function own(table, key) {
  return table && typeof key === 'string' && Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

const RHEL_IDS = ['rhel', 'centos', 'rocky', 'almalinux', 'ol', 'cloudlinux', 'eurolinux', 'amzn'];
const VERDICTS = ['patched', 'vulnerable', 'pending', 'restart', 'unknown'];
// When several PHP builds are judged, the worst one is reported.
const SEVERITY = { patched: 0, unknown: 1, restart: 2, pending: 3, vulnerable: 4 };

// Red Hat fix_state values that have a message; any other value is shown as it is.
const RHEL_STATES = {
  Affected: 'rhelState.affected',
  'Under investigation': 'rhelState.underInvestigation',
  'Fix deferred': 'rhelState.fixDeferred',
  'Will not fix': 'rhelState.willNotFix',
  'Not affected': 'rhelState.notAffected',
  'Out of support scope': 'rhelState.outOfSupportScope',
};

// The branch of Red Hat's own php package in releases whose advisories do not name it. A Red Hat state for the
// plain "php" package describes that branch only.
const RHEL_BASE_BRANCH = { 6: '5.3', 7: '5.4' };

// Which source of compromise indicators each server script count comes from.
const FINDING_SOURCE = { oom: 'logs', crash: 'logs', bigsession: 'sessions', webuser_proc: 'processes', recent_php: 'webroot' };

export function verdictTitles(lang = 'en') {
  const t = translator(lang);
  return Object.fromEntries(VERDICTS.map((v) => [v, t(`verdict.title.${v}`)]));
}

export function verdictLabels(lang = 'en') {
  const t = translator(lang);
  return Object.fromEntries(VERDICTS.map((v) => [v, t(`verdict.label.${v}`)]));
}

export const VERDICT_TITLES = verdictTitles('en');

export const VERDICT_LABELS = verdictLabels('en');

export function judge(obs, upstream, distro, options = {}) {
  try {
    const r = Array.isArray(obs.parts) && obs.parts.length > 1 ? judgeParts(obs, upstream, distro, options) : judgeOne(obs, upstream, distro, options);
    // Part of the input was not read (it was too long, or held too many outputs): what was left out may be worse.
    if (obs.inputCut && r.verdict === 'patched') {
      const t = translator(options.lang || 'en');
      r.verdict = 'unknown';
      r.title = t('verdict.title.unknown');
      r.reasons.push(t('reason.inputCut'));
      r.actions = [{ text: t('step.collect.shorter') }];
    }
    return r;
  } catch {
    // Never leave the page without a result. Nothing is concluded from an input the engine could not handle.
    const t = translator(options.lang || 'en');
    return {
      verdict: 'unknown',
      title: t('verdict.title.unknown'),
      reasons: [t('reason.notRead')],
      actions: [],
      facts: [],
      mitigations: [],
      notes: [],
      advisories: [],
      findings: [],
      family: null,
    };
  }
}

// Several separate outputs in one paste: each is judged on its own, and the worst result is reported.
function judgeParts(obs, upstream, distro, options) {
  const lang = options.lang || 'en';
  const t = translator(lang);
  const labels = verdictLabels(lang);
  const results = obs.parts.map((part) => ({ part, r: judgeOne(part, upstream, distro, options) }));
  const worst = results.reduce((w, x) => (SEVERITY[x.r.verdict] > SEVERITY[w.r.verdict] ? x : w));
  const notes = [t('note.severalOutputs', { n: results.length })];
  // Notes about the input as a whole (part of it was cut, too many outputs) come with the combined observation.
  for (const n of obs.notes || []) if (!notes.includes(n)) notes.push(n);
  const advisories = [];
  const findings = [];
  for (const { r } of results) {
    for (const n of r.notes) if (!notes.includes(n)) notes.push(n);
    for (const x of r.advisories) if (!advisories.some((y) => y.label === x.label && y.value === x.value)) advisories.push(x);
    for (const f of r.findings) if (!findings.some((g) => g.level === f.level && g.text === f.text)) findings.push(f);
  }
  // "Nothing suspicious" from one output must not stand next to a finding, or a source another output could not read.
  const clear = findings.every((f) => f.level === 'ok');
  const r = {
    verdict: worst.r.verdict,
    title: worst.r.title,
    reasons: results.map(({ part, r: x }) => t('reason.forPart', { part: partLabel(t, part), verdict: labels[x.verdict], reasons: x.reasons.join(' ') })),
    actions: worst.r.actions,
    facts: worst.r.facts,
    mitigations: worst.r.mitigations,
    notes,
    advisories,
    findings: clear ? findings : findings.filter((f) => f.level !== 'ok'),
    family: worst.r.family,
  };
  if (worst.r.exposure) r.exposure = worst.r.exposure;
  if (worst.r.eol) r.eol = true;
  return r;
}

function partLabel(t, part) {
  const version = part.phpVersion;
  if (part.sources.includes('selfcheck')) return version ? t('part.probe', { version }) : t('part.probeNoVersion');
  if (part.sources.includes('header')) return t('part.header', { version });
  if (part.sources.includes('cli')) return t('part.cli', { version, sapi: part.sapi });
  if (part.sources.includes('servercheck')) {
    const os = part.os || {};
    return t('part.server', { system: os.pretty || [os.id, os.versionId].filter(Boolean).join(' ') || t('distro.unknown') });
  }
  return version ? t('part.version', { version }) : t('part.probeNoVersion');
}

function judgeOne(obs, upstream, distro, options) {
  const lang = options.lang || 'en';
  const t = translator(lang);
  const r = {
    verdict: 'unknown',
    reasons: [],
    actions: [],
    facts: [],
    mitigations: [],
    notes: [...(obs.notes || [])],
    advisories: [],
  };
  // With only the server script output, infer the SAPI from running processes (the script reports Apache only when it has libphp loaded).
  const inferredSapi = obs.sapi ? null : inferSapi(obs.processes);
  const ctx = {
    t,
    lang,
    upstream,
    distro: distro || {},
    cves: upstream.cves.map((c) => c.id),
    sapi: obs.sapi || inferredSapi,
  };

  // The running PHP comes from the probe, a header, -v output or a version string. With server script output,
  // every installed PHP build is judged as well (one per Debian source package, rpm collection or apk prefix),
  // and the worst verdict is reported.
  const running = parsePhpVersion(obs.phpVersion);
  const installed = running && !obs.serverData ? [] : installedBuilds(obs);
  if (!running && !installed.length) {
    r.reasons.push(t('reason.noVersion'));
    r.family = null;
    return finish(ctx, r, obs, {}, null, { noVersion: true });
  }
  const results = [];
  if (running) {
    const d = detectDistro(obs, running, ctx.distro, options.distro);
    results.push({ ver: running, build: null, d, a: assess(ctx, obs, running, null, d) });
  }
  // The installed build the running PHP was judged with is not judged a second time.
  const used = running ? results[0].a.usedKeys : [];
  for (const b of installed) {
    if (running && (used.includes(b.key) || (!used.length && b.ver.upstream === running.upstream))) continue;
    const d = detectDistro(obs, b.ver, ctx.distro, options.distro, b);
    results.push({ ver: b.ver, build: b, d, a: assess(ctx, obs, b.ver, b, d) });
  }

  // The PHP processes each of them may run. A process none of them can run is a PHP that was not checked.
  const procs = obs.processes || [];
  for (const x of results) {
    x.mine = procs.filter((p) => mayRun(p, x, installed));
    if (x.a.path !== 'prerelease') checkRunning(ctx, x.a, obs, x.ver, x.build, x.mine);
  }
  const orphans = procs.filter((p) => !results.some((x) => x.mine.includes(p)));
  const main = results.reduce((worst, x) => (SEVERITY[x.a.verdict] > SEVERITY[worst.a.verdict] ? x : worst));

  if (running) r.facts.push({ label: t('fact.phpVersion'), value: running.raw });
  const others = results.filter((x) => x.build);
  if (others.length) {
    r.facts.push({ label: t(running ? 'fact.otherBuilds' : 'fact.installedVersion'), value: others.map((x) => pkgLabel(x.build.main)).join(', ') });
  }
  if (ctx.sapi) {
    const label = sapiLabel(ctx.sapi, lang);
    r.facts.push({ label: t('fact.sapi'), value: inferredSapi ? t('fact.sapiInferred', { sapi: label }) : label });
  }
  r.facts.push({ label: t('fact.distribution'), value: distroLabel(t, main.d, obs) });
  if (obs.serverSoftware) r.facts.push({ label: t('fact.webServer'), value: obs.serverSoftware });

  r.verdict = main.a.verdict;
  r.family = dataFamily(main.d, main.a.path);
  if (main.a.eol) r.eol = true;
  const labels = verdictLabels(lang);
  for (const x of results) {
    const reasons = x.a.reasons.join(' ');
    if (results.length === 1) r.reasons.push(...x.a.reasons);
    else if (x.build) r.reasons.push(t('reason.forBuild', { build: pkgLabel(x.build.main), verdict: labels[x.a.verdict], reasons }));
    else r.reasons.push(t('reason.forRunning', { version: x.ver.raw, verdict: labels[x.a.verdict], reasons }));
    for (const n of x.a.notes) if (!r.notes.includes(n)) r.notes.push(n);
    for (const y of x.a.advisories) if (!r.advisories.some((z) => z.label === y.label && z.value === y.value)) r.advisories.push(y);
    r.facts.push(...x.a.facts);
  }

  // What the remediation steps work from: the worst result's assessment, the processes of it that still use files
  // from before an update, and all of its processes (their names give the services to restart and configure).
  const info = {
    path: main.a.path,
    build: main.build,
    a: main.a,
    stale: [...new Set(main.mine.filter((p) => p.status === 'stale').map((p) => p.comm))],
    running: [...new Set(main.mine.map((p) => p.comm))],
  };
  // Stale processes of another PHP than the probe's: what started them is not known, so their names are given.
  if (main.a.staleOther && info.stale.length) info.genericRestart = info.stale.join(', ');
  const stale = orphans.filter((p) => p.status === 'stale');
  const unaccounted = orphans.filter((p) => p.status !== 'stale');
  if (stale.length) {
    r.reasons.push(t('reason.staleUnaccounted', { names: commNames(stale) }));
    if (r.verdict === 'patched') {
      r.verdict = 'restart';
      info.genericRestart = commNames(stale);
    }
  }
  // A Debian or Ubuntu PHP-FPM or CGI process of a branch whose other packages are installed but whose own package is
  // not listed: an interrupted update may have left that package half-installed (dpkg lists only installed ones).
  const halfInstalled = unaccounted.map((p) => {
    const m = /^php-(fpm|cgi)(\d+\.\d+)$/.exec(p.comm);
    const b = m && installed.find((x) => x.packages[0]?.manager === 'dpkg' && x.ver.branch === m[2]);
    return b ? { comm: p.comm, pkg: `php${m[2]}-${m[1]}`, src: debSource(b.main) } : null;
  }).filter(Boolean);
  if (unaccounted.length) {
    r.reasons.push(t('reason.unaccountedProcesses', { names: commNames(unaccounted) }));
    if (r.verdict === 'patched' && halfInstalled.length) {
      const h = halfInstalled[0];
      r.verdict = 'unknown';
      r.reasons.push(t('reason.sapiPackageMissingProc', { comm: h.comm, pkg: h.pkg, src: h.src }));
      info.need = 'sapiPackage';
      info.sapiPackage = h.pkg;
    } else if (r.verdict === 'patched') {
      r.verdict = 'unknown';
      info.path = 'undetermined';
      info.need = 'elsewhere';
      info.genericRestart = commNames(unaccounted);
    }
  }
  // PHP processes the server script could not check (unreadable, or a status line cut off) may be any PHP, also one
  // that was not restarted after an update. A PHP_VERSION that shows the fix vouches only for the probe's own PHP.
  if (obs.serverData && obs.procUnreadable > 0 && r.verdict === 'patched') {
    r.verdict = 'unknown';
    r.reasons.push(t(obs.root === true ? 'reason.processesUnreadableRoot' : 'reason.processesUnreadable', { n: obs.procUnreadable }));
    info.path = 'undetermined';
    info.need = 'unreadable';
  }
  // The probe and the server script describe different moments (see parse.js): which one is current is unknown, so
  // neither the probe's PHP_VERSION nor the installed packages settle it.
  if (obs.serverConflict && r.verdict === 'patched') {
    r.verdict = 'unknown';
    if (!r.reasons.includes(t('reason.serverConflict'))) r.reasons.push(t('reason.serverConflict'));
    info.path = 'undetermined';
    info.need = 'together';
  }
  if ((obs.truncated || obs.headCut) && r.verdict === 'patched') {
    r.verdict = 'unknown';
    r.reasons.push(t(obs.truncated ? 'reason.serverTruncated' : 'reason.serverHeadCut'));
    info.path = 'undetermined';
    info.need = 'whole';
  }
  // A probe that could not tell whether it runs in a container, next to server script output nothing ties to it: the
  // next step is the one that ties them, not the same server script output again.
  if (obs.unlinkedHidden && r.verdict === 'unknown') {
    info.path = 'undetermined';
    info.need = 'hiddenLink';
  }
  return finish(ctx, r, obs, main.d, main.ver, info);
}

// Judges one PHP build. build is null for the running PHP, or an installed build (server script output).
function assess(ctx, obs, ver, build, d) {
  const { t, upstream } = ctx;
  const a = {
    verdict: 'unknown',
    reasons: [],
    notes: [],
    advisories: [],
    facts: [],
    eol: false,
    // How the verdict was reached; it picks the update advice.
    path: 'upstream',
    // The running version string itself shows the fix (upstream release, or a fixed distribution revision).
    proven: false,
    // A Patched verdict rests on the installed package, not on what is loaded in memory.
    restsOnPackage: false,
    // Keys of the installed builds (see installedBuilds) this verdict was reached with.
    usedKeys: [],
    // When the verdict stays open: what to collect next (see collectSteps).
    need: null,
  };
  if (d.overridden) a.notes.push(overrideNote(t, d, obs, ver));
  const branches = Object.keys(upstream.fixed).sort(compareBranch);
  const fixedUp = upstream.fixed[ver.branch];

  if (ver.pre) {
    a.path = 'prerelease';
    a.reasons.push(t('reason.preRelease', { version: ver.raw }));
    return a;
  }
  if (!fixedUp && compareBranch(ver.branch, branches[branches.length - 1]) > 0) {
    a.path = 'prerelease';
    a.reasons.push(t('reason.newerBranch', { branch: ver.branch, branches: branches.join(', ') }));
    return a;
  }
  if (fixedUp && comparePhp(ver, fixedUp) >= 0) {
    a.verdict = 'patched';
    a.reasons.push(t('reason.upstreamPatched', { version: ver.upstream, fixed: fixedUp }));
    a.proven = !build;
    a.restsOnPackage = Boolean(build);
    if (!build) checkDowngrade(ctx, a, obs, ver, d);
  } else {
    judgeBuild(ctx, a, obs, ver, build, d);
  }
  return a;
}

// The running PHP has the fix, but the package that provides it on disk is older: it was downgraded (or replaced by
// another repository's build) after the service started, and the next restart loads that package's build. On
// Debian and Ubuntu the package of a SAPI (php8.2-fpm, libapache2-mod-php8.2) carries the whole PHP engine, and
// the configuration directory of the branch (/etc/php/8.2/fpm) ties the running PHP to it.
function checkDowngrade(ctx, a, obs, ver, d) {
  const { t } = ctx;
  if (d.family !== 'debian' && d.family !== 'ubuntu') return;
  if (obs.configPath && !debLayoutPath(obs.configPath, ver)) return;
  const pkg = sapiPackage(obs.packages, ver, ctx.sapi);
  if (!pkg || cmpUp(debUpstream(pkg.version), ver.upstream) >= 0) return;
  a.usedKeys.push(buildKey(pkg));
  a.path = isSuryBuild(pkg.version) ? 'sury' : 'deb';
  a.facts.push({ label: t('fact.packageChecked'), value: pkgLabel(pkg) });
  if (debPackageFixed(ctx, d, pkg, ver)) {
    a.notes.push(t('note.olderPackageFixed', { pkg: pkgLabel(pkg), version: ver.raw }));
    return;
  }
  a.verdict = 'vulnerable';
  a.downgraded = true;
  a.reasons = [t('reason.installedOlderUnfixed', { installed: pkgLabel(pkg), running: ver.raw })];
}

// Whether a Debian or Ubuntu package version has both fixes: by the release's fixed version when the data has one
// (and the revision is the distribution's own), otherwise by its upstream version.
function debPackageFixed(ctx, d, pkg, ver) {
  const { cves, upstream } = ctx;
  const fixedUp = upstream.fixed[ver.branch];
  if (fixedUp && cmpUp(debUpstream(pkg.version), fixedUp) >= 0) return true;
  if (isSuryBuild(pkg.version)) return false;
  const entry = own(own(ctx.distro[d.family], d.release)?.packages, debSource(pkg));
  const fixed = cves.map((c) => entry?.fixed?.[c]);
  if (!fixed.every(Boolean)) return false;
  // Below the upstream fix, only the release's own backport has the fixes: the same upstream version as its fixed
  // package, at or above its fixed revision, and a revision the distribution builds itself.
  if (cmpUp(debUpstream(pkg.version), debUpstream(fixed[0])) !== 0) return false;
  return fixed.every((f) => debAtLeast(pkg.version, f)) && vendorBuild(d.family, pkg.version);
}

// The configuration directory of a Debian or Ubuntu PHP package of this branch: /etc/php/8.2/..., /etc/php5/...
function debLayoutPath(path, ver) {
  const base = ver.major >= 7 ? `/etc/php/${ver.branch}` : '/etc/php5';
  return path === base || path.startsWith(`${base}/`);
}

// The Debian or Ubuntu package that provides this SAPI of this branch: php8.2-fpm, libapache2-mod-php8.2, php8.2-cgi.
function sapiPackageName(ver, sapi) {
  const src = srcFor(ver);
  return own({ apache2handler: `libapache2-mod-${src}`, 'fpm-fcgi': `${src}-fpm`, 'cgi-fcgi': `${src}-cgi`, cgi: `${src}-cgi`, cli: `${src}-cli` }, sapi) || null;
}

function sapiPackage(packages, ver, sapi) {
  const name = sapiPackageName(ver, sapi);
  return name ? packages.find((p) => p.manager === 'dpkg' && p.name === name) || null : null;
}

function judgeBuild(ctx, a, obs, ver, build, d) {
  const { t } = ctx;
  const debLike = d.family === 'debian' || d.family === 'ubuntu';
  const pkg = debLike ? pickDebPackage(obs, ver, ctx.sapi, build) : null;
  if (isSuryBuild(ver.raw) || (pkg && isSuryBuild(pkg.version))) {
    judgeSury(ctx, a, obs, ver, build, pkg && isSuryBuild(pkg.version) ? pkg : null);
    return;
  }
  // Debian, Ubuntu and RHEL packages keep their configuration under /etc. A PHP configured elsewhere
  // (/usr/local/etc/php in the official Docker images, a control panel's or a self-built prefix) is not
  // a distribution package, so installed packages say nothing about it.
  if (!build && obs.configPath && !/^\/etc(\/|$)/.test(obs.configPath) && (debLike || d.family === 'rhel' || !d.family)) {
    a.notes.push(t('note.configOutsideEtc', { path: obs.configPath }));
    judgeUpstream(ctx, a, ver);
    return;
  }
  if (debLike) {
    judgeDeb(ctx, a, obs, ver, build, d, pkg);
    return;
  }
  if (d.family === 'rhel') {
    judgeRhel(ctx, a, obs, ver, build, d);
    return;
  }
  if (d.family === 'alpine') {
    a.notes.push(t('note.alpine'));
    judgeUpstream(ctx, a, ver);
    a.path = 'alpine';
    return;
  }
  if (d.family === 'other') {
    if (BACKPORTING_VENDORS.test(d.vendor || '')) {
      // SUSE keeps the upstream version of its PHP packages and backports fixes into them: a version below the
      // upstream fix may have them, and only the vendor's advisories or the package changelog can tell.
      a.path = 'other';
      a.need = 'vendor';
      a.reasons.push(t('reason.vendorBackports', { vendor: obs.os?.pretty || d.vendor, version: ver.raw }));
      return;
    }
    a.notes.push(t('note.otherDistro', { vendor: d.vendor || 'other' }));
    judgeUpstream(ctx, a, ver);
    a.path = 'other';
    return;
  }
  if (!d.family) {
    // The probe could not read the OS release: this may be a RHEL-family or other distribution package whose
    // version number stays the same when a fix is backported, so an upstream-looking version is not Vulnerable.
    // The distribution is unknown. Do not judge on the upstream version when this could be a
    // distribution package that has the fix backported under the same version number.
    const releases = sameUpstreamReleases(ctx, ver);
    if (obs.osBlocked || releases.length) {
      a.path = 'undetermined';
      a.need = 'serverOrDistro';
      if (obs.osBlocked) a.reasons.push(t(obs.openBasedir ? 'reason.osBlocked' : 'reason.osUnread', { version: ver.raw }));
      if (releases.length) a.reasons.push(t('reason.couldBeDistro', { version: ver.raw, releases: releases.join(', ') }));
      return;
    }
  }
  judgeUpstream(ctx, a, ver);
}

// Distributions outside the data that keep the upstream version of their PHP packages and backport fixes into them.
const BACKPORTING_VENDORS = /^(sles|sled|sles_sap|opensuse-leap)$/;

// deb.sury.org follows upstream releases on supported branches. For end-of-life branches it ships backported fixes
// under the same upstream version (the 8.1.34-9 changelog has "Backported from 8.2.35"), so there the changelog of
// exactly the installed build decides. A Debian build dated before the upstream fix release cannot have them.
function judgeSury(ctx, a, obs, ver, build, pkg) {
  const { t, cves, upstream } = ctx;
  const version = pkg ? pkg.version : ver.raw;
  if (pkg) a.usedKeys.push(buildKey(pkg));
  if (upstream.fixed[ver.branch] || comparePhp(ver, '5.4.0') < 0) {
    a.notes.push(t('note.sury', { version }));
    judgeUpstream(ctx, a, ver);
    a.path = 'sury';
    return;
  }
  a.path = 'sury';
  a.notes.push(t('note.suryEol', { version, branch: ver.branch }));
  const evidence = obs.packages.filter((p) => p.manager === 'dpkg' && debSource(p) === srcFor(ver) && sameDeb(p.version, version));
  const logs = evidence.filter((p) => p.changelog);
  const found = changelogFound(evidence, cves);
  if (found && found.length === cves.length) {
    a.verdict = 'patched';
    a.reasons.push(t('reason.suryChangelogFixed', { pkg: pkgLabel(logs[0]), cves: cves.join(', ') }));
    // PHP_VERSION with the deb.sury.org revision is exactly that build; a plain one rests on the installed package.
    a.proven = !build && Boolean(ver.revision) && sameDeb(ver.raw, version);
    a.restsOnPackage = !a.proven;
    return;
  }
  const missing = cves.filter((c) => logs.some((p) => p.changelog[c] === 0));
  const date = suryBuildDate(version);
  if (missing.length || (date && upstream.released && date < upstream.released)) {
    judgeUpstream(ctx, a, ver);
    a.path = 'sury';
    a.reasons.push(missing.length ? t('reason.suryChangelogMissing', { pkg: pkgLabel(logs[0]), cves: missing.join(', ') })
      : t('reason.suryBuiltBefore', { version, date: formatDate(date, ctx.lang), released: formatDate(upstream.released, ctx.lang) }));
    return;
  }
  a.verdict = 'unknown';
  a.need = logs.length ? 'whole' : 'server';
  a.reasons.push(t('reason.suryEolUnread', { version, branch: ver.branch }));
}

function judgeUpstream(ctx, a, ver) {
  const { t, upstream } = ctx;
  a.path = 'upstream';
  const fixedUp = upstream.fixed[ver.branch];
  if (fixedUp) {
    a.verdict = 'vulnerable';
    a.reasons.push(t('reason.upstreamVulnerable', { version: ver.upstream, fixed: fixedUp }));
    return;
  }
  if (comparePhp(ver, '5.4.0') < 0) {
    a.verdict = 'unknown';
    a.reasons.push(t('reason.predates54', { version: ver.upstream }));
    return;
  }
  a.verdict = 'vulnerable';
  a.eol = true;
  a.reasons.push(t('reason.eol', { branch: ver.branch }));
  const branch = upstream.backport_branches?.[ver.branch];
  if (branch) a.notes.push(t('note.backportBranch', { branch }));
}

function judgeDeb(ctx, a, obs, ver, build, d, pkg) {
  const { t, distro, cves, upstream } = ctx;
  const family = d.family === 'debian' ? 'Debian' : 'Ubuntu';
  a.path = 'deb';
  // PHP_VERSION with a distribution revision identifies the running build exactly.
  const running = !build && ver.revision ? ver.raw : null;
  // A package older than the running PHP is not what runs (a self-built, panel or container PHP next to it).
  if (pkg && !build && cmpUp(debUpstream(pkg.version), ver.upstream) < 0) {
    a.notes.push(t('note.packageNotRunning', { pkg: pkgLabel(pkg), version: ver.raw }));
    pkg = null;
  }
  if (!pkg && !running) {
    judgeDebVersionOnly(ctx, a, ver, d, family);
    return;
  }
  if (pkg) a.usedKeys.push(buildKey(pkg));

  const src = pkg ? debSource(pkg) : srcFor(ver);
  const installed = pkg ? pkg.version : null;
  const judged = running || installed;
  const fixedUp = upstream.fixed[ver.branch];

  // When the distribution data cannot decide, an installed package that already has the upstream fix shows a
  // missed restart; otherwise fall back to the changelog of exactly the build being judged.
  const evidence = obs.packages.filter((p) => p.manager === 'dpkg' && debSource(p) === src && sameDeb(p.version, judged));
  const noData = (reason) => {
    if (!build && installed && fixedUp && cmpUp(debUpstream(installed), fixedUp) >= 0) {
      a.verdict = 'restart';
      a.reasons.push(t('reason.restartInstalledFixed', { installed, running: running || ver.upstream }));
      return;
    }
    const found = changelogFound(evidence, cves);
    if (found && found.length === cves.length) {
      a.verdict = 'patched';
      a.reasons.push(t('reason.noDataChangelogFixed', { reason }));
      a.proven = Boolean(running);
      a.restsOnPackage = !running;
    } else {
      a.verdict = 'unknown';
      a.reasons.push(reason);
    }
  };
  if (!d.release) {
    a.need = 'serverOrDistro';
    noData(t('reason.debReleaseUnknown', { family }));
    return;
  }
  const rel = own(distro[d.family], d.release);
  if (!rel) {
    a.need = 'advisories';
    noData(t('reason.debNoRelease', { family, release: d.release }));
    return;
  }
  const entry = rel.packages?.[src];
  if (!entry) {
    a.need = 'advisories';
    noData(t('reason.debNoPackage', { src, family, release: d.release }));
    return;
  }

  // A build newer upstream than the release's fixed package (and still below the upstream fix) is not
  // that release's package: another repository, a PPA, or a package from another release.
  const distroUp = entryUpstream(entry, cves);
  const judgedUp = debUpstream(judged);
  if (distroUp && cmpUp(judgedUp, distroUp) > 0 && !(fixedUp && cmpUp(judgedUp, fixedUp) >= 0)) {
    a.notes.push(t('note.notDistroBuild', { version: judged, family, release: d.release, src, shipped: distroUp }));
    judgeUpstream(ctx, a, ver);
    return;
  }

  if (pkg) a.facts.push({ label: t('fact.packageChecked'), value: pkgLabel(pkg) });
  const states = cves.map((cve) => {
    const fixed = entry.fixed?.[cve];
    if (fixed === undefined) return { cve, state: 'nodata' };
    if (fixed === null) return { cve, state: 'pending' };
    return { cve, fixed, state: debAtLeast(judged, fixed) ? 'fixed' : 'vulnerable' };
  });
  pushDebAdvisories(t, a, family, d.release, src, entry, cves);
  if (entry.pro) a.notes.push(t(UBUNTU_LEGACY.includes(d.release) ? 'note.ubuntuProLegacy' : 'note.ubuntuPro'));

  // The same upstream version as the release's fixed package, below the upstream fix: the fix is a backport,
  // which only the distribution's own builds carry. A revision of another vendor that merely sorts above the
  // fixed one ("8.3.6-1+ppa1", "8.1.2-2", a Debian "+deb9u12" judged as Ubuntu) is not that backport.
  const backport = distroUp && cmpUp(judgedUp, distroUp) === 0 && !(fixedUp && cmpUp(judgedUp, fixedUp) >= 0);
  if (backport && states.every((s) => s.state === 'fixed') && !vendorBuild(d.family, judged)) {
    a.verdict = 'unknown';
    a.need = 'supplier';
    a.reasons.push(t('reason.foreignRevision', { version: judged, family, release: d.release, src }));
    return;
  }

  if (states.every((s) => s.state === 'fixed')) {
    a.verdict = 'patched';
    a.reasons.push(t('reason.debBackported', { family, src, version: judged, upstream: ver.upstream }));
    a.proven = Boolean(running);
    a.restsOnPackage = !running;
  } else if (states.some((s) => s.state === 'vulnerable')) {
    a.verdict = 'vulnerable';
    a.reasons.push(t('reason.debOlder', { src, version: judged, family, fixed: maxFixed(states) }));
  } else if (states.some((s) => s.state === 'pending')) {
    a.verdict = 'pending';
    a.reasons.push(t('reason.debPending', { src, family, release: d.release }));
  } else {
    a.verdict = 'unknown';
    a.need = 'advisories';
    a.reasons.push(t('reason.debNoCveData'));
  }

  // Running and installed versions differ.
  const fixedFor = (v) => states.every((s) => s.fixed && debAtLeast(v, s.fixed));
  const order = running && installed ? compareDebian(debComparable(installed), debComparable(running)) : 0;
  if (order > 0) {
    // A newer package is installed: the service was not restarted after an update.
    if (fixedFor(running)) {
      // The running build already has the fix; the newer package only waits for a restart.
      a.notes.push(t('note.newerPackageWaiting', { installed, running }));
    } else if (fixedFor(installed)) {
      a.verdict = 'restart';
      a.reasons = [t('reason.restartInstalledFixed', { installed, running })];
    } else {
      a.reasons.push(t('reason.installedNewer', { installed, running }));
    }
  } else if (order < 0 && a.verdict === 'patched' && !fixedFor(installed)) {
    // An older package is installed (a downgrade): the next restart loads the vulnerable build.
    a.verdict = 'vulnerable';
    a.downgraded = true;
    a.reasons.push(t('reason.installedOlderUnfixed', { installed: pkgLabel(pkg), running }));
  } else if (!running && installed && !build && cmpUp(debUpstream(installed), ver.upstream) > 0) {
    // PHP_VERSION without a revision: only the upstream parts can be compared.
    a.reasons.push(t('reason.installedNewer', { installed, running: ver.upstream }));
    if (a.verdict === 'patched') {
      a.verdict = 'restart';
      a.restsOnPackage = false;
    }
  }
  if (!build && !running && pkg && a.verdict === 'patched') checkPlainVersion(ctx, a, obs, ver, d, family, pkg);
}

// The PHP probe's PHP_VERSION has no revision, and the verdict rests on the installed package of its branch.
// - Debian and Ubuntu build the PHP engine into each SAPI's own binary, so the package of the SAPI that runs
//   (php8.3-fpm, libapache2-mod-php8.3) must be installed: the other packages of the branch do not show which build
//   that binary is. dpkg lists only fully installed packages, so one that an interrupted update left half-configured
//   is missing from the list.
// - On Ubuntu 22.04 and older, the security updates report their revision in PHP_VERSION (8.1.2-1ubuntu2.28); only
//   the release's original build reports the plain version. A plain version next to an updated package is therefore
//   the original build, loaded before the update.
function checkPlainVersion(ctx, a, obs, ver, d, family, pkg) {
  const { t } = ctx;
  const sapiName = sapiPackageName(ver, ctx.sapi);
  const complete = obs.serverData || (obs.probeDpkg !== null && obs.probeDpkg.length < PROBE_DPKG_MAX);
  if (sapiName && ctx.sapi !== 'cli' && complete && !obs.packages.some((p) => p.manager === 'dpkg' && p.name === sapiName)) {
    a.verdict = 'unknown';
    a.restsOnPackage = false;
    a.need = 'sapiPackage';
    a.sapiPackage = sapiName;
    a.reasons = [t('reason.sapiPackageMissing', { sapi: sapiLabel(ctx.sapi, ctx.lang), pkg: sapiName, src: srcFor(ver) })];
    return;
  }
  if (d.family === 'ubuntu' && UBUNTU_REVISION_IN_VERSION.includes(d.release) && /ubuntu\d+\./.test(splitDebian(debComparable(pkg.version)).revision)) {
    a.verdict = 'restart';
    a.restsOnPackage = false;
    a.reasons = [t('reason.revisionMissing', { version: ver.raw, family, release: d.release, installed: pkgLabel(pkg), expected: debComparable(pkg.version) })];
  }
}

// A revision the distribution itself builds: Ubuntu's carry "ubuntu", Debian's stable updates "debNNuN".
function vendorBuild(family, version) {
  const { revision } = splitDebian(debComparable(version));
  return family === 'ubuntu' ? /ubuntu/.test(revision) : /deb\d+u\d+/.test(revision);
}

// Debian or Ubuntu, with no distribution revision in PHP_VERSION and no package of this branch to compare.
function judgeDebVersionOnly(ctx, a, ver, d, family) {
  const { t, distro, cves } = ctx;
  const src = srcFor(ver);
  if (!d.release) {
    const releases = Object.keys(distro[d.family] || {}).filter((rel) => entryUpstream(distro[d.family][rel].packages?.[src], cves) === ver.upstream);
    if (releases.length) {
      a.need = 'serverOrDistro';
      a.reasons.push(t('reason.debReleaseUnknown', { family }));
      return;
    }
    a.notes.push(t('note.upstreamBuild'));
    judgeUpstream(ctx, a, ver);
    return;
  }
  const rel = own(distro[d.family], d.release);
  if (!rel) {
    a.need = 'advisories';
    a.reasons.push(t('reason.debNoRelease', { family, release: d.release }));
    return;
  }
  const entry = rel.packages?.[src];
  if (!entry) {
    // The release does not ship this source package, so this PHP comes from somewhere else.
    a.notes.push(t('note.upstreamBuild'));
    judgeUpstream(ctx, a, ver);
    return;
  }
  const distroUp = entryUpstream(entry, cves);
  if (distroUp && cmpUp(ver.upstream, distroUp) > 0) {
    a.notes.push(t('note.notDistroBuild', { version: ver.raw, family, release: d.release, src, shipped: distroUp }));
    judgeUpstream(ctx, a, ver);
    return;
  }
  pushDebAdvisories(t, a, family, d.release, src, entry, cves);
  if (entry.pro) a.notes.push(t(UBUNTU_LEGACY.includes(d.release) ? 'note.ubuntuProLegacy' : 'note.ubuntuPro'));
  if (!distroUp) {
    const pending = cves.some((c) => entry.fixed?.[c] === null);
    a.verdict = pending ? 'pending' : 'unknown';
    if (!pending) a.need = 'advisories';
    a.reasons.push(pending ? t('reason.debPending', { src, family, release: d.release }) : t('reason.debNoCveData'));
    return;
  }
  const fixed = cves.map((c) => entry.fixed?.[c]).filter(Boolean).sort(compareDebian).pop();
  if (cmpUp(ver.upstream, distroUp) < 0) {
    a.verdict = 'vulnerable';
    a.reasons.push(t('reason.debOlderUpstream', { version: ver.raw, family, release: d.release, src, fixed }));
    return;
  }
  // Same upstream version before and after the fix: only the package version can tell.
  a.need = 'server';
  a.reasons.push(t('reason.debNeedPackage', { version: ver.raw, family, release: d.release, src }));
}

function pushDebAdvisories(t, a, family, release, src, entry, cves) {
  for (const cve of cves) {
    const fixed = entry.fixed?.[cve];
    a.advisories.push({
      label: `${family} ${release} ${src} · ${cve}`,
      value: fixed ? t('advisory.fixedIn', { version: fixed }) : fixed === null ? t('advisory.pending') : t('advisory.noData'),
    });
  }
}

function judgeRhel(ctx, a, obs, ver, build, d) {
  const { t, distro, cves } = ctx;
  a.path = 'rhel';
  const rh = d.release ? own(distro.redhat, d.release) : null;
  for (const x of rh?.advisories || []) {
    if (!x?.cve || !x.advisory) continue;
    a.advisories.push({ label: `RHEL ${d.release} · ${x.cve}`, value: x.package ? `${x.advisory} (${x.package})` : String(x.advisory) });
  }
  for (const s of rh?.states || []) {
    if (!s?.cve || !s.state) continue;
    const state = own(RHEL_STATES, s.state) ? t(RHEL_STATES[s.state]) : String(s.state);
    a.advisories.push({ label: `RHEL ${d.release} · ${s.cve}`, value: s.package ? `${s.package}: ${state}` : state });
  }
  if (d.vendor && d.vendor !== 'rhel') a.notes.push(t('note.rhelCompatible'));

  // Remi's software collections live under /etc/opt/remi.
  const remiPath = !build && /^\/etc\/opt\/remi\//.test(obs.configPath || '');
  const rpms = obs.packages.filter((p) => p.manager === 'rpm');
  // The packages of the PHP being judged: the same upstream version, and the same layout as the probe's config path.
  let candidates = build ? build.packages : rpms.filter((p) => debUpstream(p.version) === ver.upstream);
  if (!build && obs.configPath && candidates.length > 1) {
    const scl = /^\/etc\/opt\/remi\/(php\d+)(\/|$)/.exec(obs.configPath);
    const narrowed = candidates.filter((p) => (scl ? p.name.startsWith(`${scl[1]}-`) : !/^php\d+-php(-|$)/.test(p.name)));
    if (narrowed.length) candidates = narrowed;
  }
  if (candidates.length) a.usedKeys.push(...new Set(candidates.map(buildKey)));
  // Every package of this PHP whose changelog was read must record the fix. A package with no changelog lines was
  // not checked, which is not the same as a count of 0; it is covered only by a package of exactly the same version,
  // whose changelog is the same (every package built from one source package carries its changelog).
  const logged = candidates.filter((p) => p.changelog);
  const unlogged = candidates.filter((p) => !p.changelog && !logged.some((q) => q.version === p.version));
  const status = Object.fromEntries(cves.map((cve) => [cve, changelogStatus(logged, unlogged, cve)]));
  const found = cves.filter((cve) => status[cve] === 'found');
  const names = logged.map(pkgLabel).join(', ');

  if (remiPath || (candidates.length && candidates.every(isRemi))) {
    a.path = 'remi';
    const pkg = candidates.length ? pkgLabel(candidates[0]) : obs.configPath;
    // Remi follows upstream releases, but its collections of end-of-life branches (php74, php80, php81) carry
    // backported fixes under the same version number, and their changelogs record them.
    if (found.length === cves.length) {
      a.verdict = 'patched';
      a.restsOnPackage = true;
      a.reasons.push(t('reason.remiChangelogFixed', { pkg: names, cves: found.join(', ') }));
      return;
    }
    if (!ctx.upstream.fixed[ver.branch] && comparePhp(ver, '5.4.0') >= 0) {
      // An end-of-life collection: only its changelog can show the backport. A changelog that was read and has no
      // entry (a count of 0) shows a build without it; a changelog that was not read shows nothing.
      a.notes.push(t('note.remiEol', { pkg }));
      const missing = cves.filter((cve) => status[cve] === 'missing');
      if (missing.length) {
        judgeUpstream(ctx, a, ver);
        a.path = 'remi';
        a.reasons.push(t('reason.remiChangelogMissing', { pkg: names, cves: missing.join(', ') }));
        return;
      }
      a.verdict = 'unknown';
      a.need = logged.length ? 'whole' : 'server';
      if (logged.length) {
        a.reasons.push(t('reason.rhelChangelogUnread', { pkg: (unlogged.length ? unlogged : logged).map(pkgLabel).join(', '), cves: cves.filter((c) => status[c] !== 'found').join(', ') }));
      } else {
        a.reasons.push(obs.serverData && candidates.length ? t('reason.rhelChangelogNotChecked', { pkg }) : t('reason.remiEolUnread', { pkg, branch: ver.branch }));
      }
      return;
    }
    a.notes.push(t('note.remi', { pkg }));
    judgeUpstream(ctx, a, ver);
    a.path = 'remi';
    return;
  }
  if (!obs.serverData) {
    a.need = 'server';
    a.reasons.push(t('reason.rhelNeedServerScript'));
    return;
  }
  if (!rpms.length) {
    // No PHP installed with rpm at all: this PHP was built from source or comes from a panel.
    a.notes.push(t('note.noRpmPackage'));
    judgeUpstream(ctx, a, ver);
    return;
  }
  if (!candidates.length) {
    a.need = 'elsewhere';
    a.reasons.push(t('reason.rhelNoMatchingPackage', { version: ver.upstream, packages: rpms.map(pkgLabel).join(', ') }));
    return;
  }
  if (!logged.length) {
    a.need = 'server';
    a.reasons.push(t('reason.rhelChangelogNotChecked', { pkg: pkgLabel(candidates[0]) }));
    return;
  }
  const notAffected = cves.filter((cve) => !found.includes(cve) && rhelNotAffected(rh, d.release, cve, ver));
  const missing = cves.filter((cve) => status[cve] === 'missing' && !notAffected.includes(cve));
  const unread = cves.filter((cve) => status[cve] === 'unread' && !notAffected.includes(cve));
  if (!missing.length && !unread.length) {
    a.verdict = 'patched';
    a.restsOnPackage = true;
    if (found.length) a.reasons.push(t('reason.rhelChangelogFixed', { pkg: names, cves: found.join(', ') }));
  } else {
    if (missing.length) a.reasons.push(t('reason.rhelChangelogMissing', { pkg: names, cves: missing.join(', ') }));
    if (unread.length) {
      if (!missing.length) a.need = 'whole';
      a.reasons.push(t('reason.rhelChangelogUnread', { pkg: (unlogged.length ? unlogged : logged).map(pkgLabel).join(', '), cves: unread.join(', ') }));
    }
    // A changelog that was read and has no entry, on a build older than the one that fixes it, is not ambiguous.
    if (missing.length) rhelOlderThanFix(ctx, a, ver, d, rh, logged);
  }
  if (notAffected.length) a.reasons.push(t('reason.rhelNotAffected', { cves: notAffected.join(', '), release: d.release }));
}

// Vulnerable when the installed build is older than the fixed build: the exact build a Red Hat advisory names for this
// branch and release (php-0:8.0.30-8.el9_8.1, php8.4-0:8.4.27-1.el10_2), or, on Amazon Linux, which ships its PHP
// fixes as upstream releases, the upstream fixed release. A module stream advisory names no package version, so a
// module build stays Undetermined.
function rhelOlderThanFix(ctx, a, ver, d, rh, logged) {
  const { t } = ctx;
  const main = logged.find((p) => /-common$/.test(p.name)) || logged[0];
  if (!main) return;
  if (d.vendor === 'amzn') {
    const fixedUp = ctx.upstream.fixed[ver.branch];
    if (fixedUp && cmpUp(debUpstream(main.version), fixedUp) < 0) {
      a.verdict = 'vulnerable';
      a.reasons.push(t('reason.amazonOlder', { pkg: pkgLabel(main), fixed: fixedUp }));
    }
    return;
  }
  const builds = (rh?.advisories || [])
    .map((x) => ({ advisory: x?.advisory, m: /^php[\d.]*-((?:\d+:)?\d+\.\d+\.\d+-.+)$/.exec(x?.package || '') }))
    .filter((x) => x.advisory && x.m && advisoryBranch(x.m[0]) === ver.branch)
    .sort((x, y) => compareRpm(x.m[1], y.m[1]));
  const fixed = builds[builds.length - 1];
  if (fixed && compareRpm(main.version, fixed.m[1]) < 0) {
    a.verdict = 'vulnerable';
    a.reasons.push(t('reason.rhelOlderThanFixed', { pkg: pkgLabel(main), fixed: fixed.m[1].replace(/^0:/, ''), advisory: fixed.advisory }));
  }
}

// What the changelogs of one PHP's rpm packages show for a CVE: 'found' (every package records the fix), 'missing'
// (a package was read and has no entry: a count of 0), or 'unread' (a count is unknown, or a package was not read).
function changelogStatus(logged, unlogged, cve) {
  if (!logged.length) return 'unread';
  const counts = logged.map((p) => (typeof p.changelog[cve] === 'number' ? p.changelog[cve] : null));
  if (counts.some((n) => n === 0)) return 'missing';
  if (counts.every((n) => n > 0)) return unlogged.length ? 'unread' : 'found';
  return 'unread';
}

// Red Hat lists the CVE as "Not affected" for this release and this PHP. A module stream state applies to its
// branch only, and a state for the plain "php" package to the branch of Red Hat's own php package in that release.
function rhelNotAffected(rh, release, cve, ver) {
  return (rh?.states || []).some((s) => {
    if (s.cve !== cve || s.state !== 'Not affected') return false;
    const stream = /^php:(\d+\.\d+)(\/|$)/.exec(s.package) || /^php(\d+\.\d+)$/.exec(s.package);
    if (stream) return stream[1] === ver.branch;
    return s.package === 'php' && rhelBaseBranch(rh, release) === ver.branch;
  });
}

// The branch of Red Hat's own php package: from an advisory for it (php-0:8.0.30-8.el9_8.1), else the table.
function rhelBaseBranch(rh, release) {
  for (const x of rh?.advisories || []) {
    const m = /^php-(?:\d+:)?(\d+\.\d+)\./.exec(x.package || '');
    if (m) return m[1];
  }
  return RHEL_BASE_BRANCH[release] || null;
}

function isRemi(p) {
  return /\.remi(\.|$)/.test(p.version) || /^php\d+-php(-|$)/.test(p.name);
}

// Was the PHP that was judged restarted after its last update, and was that checked at all?
// mine: the processes the server script saw that may run this PHP.
function checkRunning(ctx, a, obs, ver, build, mine) {
  const { t } = ctx;
  const stale = mine.filter((p) => p.status === 'stale');
  if (a.downgraded) {
    // The running build has the fix and the package on disk is older: stale processes still run that fixed build,
    // and a restart would replace it with the vulnerable one.
    if (stale.length) a.notes.push(t('note.staleDowngraded', { names: commNames(stale) }));
    return;
  }
  if (stale.length) {
    // The probe's own PHP_VERSION shows the fix, and the stale processes are that same SAPI and branch: what runs has
    // the fix, and only a newer package waits to be loaded. One PHP-FPM master and its workers share their memory
    // maps, so they are all stale or all current: a stale process next to a current one of the same name is another
    // PHP, which the probe does not vouch for.
    const procs = obs.processes || [];
    const self = a.proven && obs.sapi && stale.every((p) => commSapi(p.comm) === sapiKind(obs.sapi)
      && !procs.some((q) => q.comm === p.comm && q.status === 'ok'));
    if (a.verdict === 'patched' && self) {
      a.notes.push(t('note.staleFixed', { names: commNames(stale) }));
    } else if (a.verdict === 'patched' || a.verdict === 'restart') {
      a.reasons.push(t(a.proven ? 'reason.staleOtherProcesses' : 'reason.staleProcesses', { names: commNames(stale) }));
      if (a.proven) a.staleOther = true;
      a.verdict = 'restart';
    } else {
      // The build installed now is not shown to have the fix, so a restart alone would not help: it would load that
      // build, and if the files were replaced by a downgrade, it would replace a fixed build with it.
      a.reasons.push(t('reason.staleUnfixed', { names: commNames(stale) }));
    }
    return;
  }
  // -v output of php-fpm or php-cgi shows the binary on disk, not what the running service loaded.
  if (!build && a.verdict === 'patched' && obs.sources.includes('cli') && obs.sapi && obs.sapi !== 'cli') {
    a.reasons.push(t('reason.binaryOnDisk', { sapi: obs.sapi }));
    return;
  }
  if (a.verdict !== 'patched' || !a.restsOnPackage) return;
  if (obs.serverData) {
    const unseen = build ? unseenServices(build, mine) : [];
    if (obs.procUnreadable > 0) {
      a.verdict = 'unknown';
      a.need = 'root';
      a.reasons.push(t(obs.root === true ? 'reason.runningUncheckedRoot' : 'reason.runningUnchecked'));
    } else if (obs.root === false && (!build || servesWeb(build))) {
      // Without root, /proc mounted with hidepid hides other accounts' processes without a trace: the processes the
      // script saw, if any, are not all that may run this build.
      a.verdict = 'unknown';
      a.need = 'root';
      a.reasons.push(t(mine.length ? 'reason.runningPartlyHidden' : 'reason.runningHidden'));
    } else if (unseen.length) {
      a.verdict = 'unknown';
      a.need = 'unseen';
      a.unseen = unseen;
      a.reasons.push(t('reason.serviceUnseen', { names: unseen.join(', ') }));
    } else if (!mine.length) {
      if (obs.root === false) {
        // No proc lines without root mean the processes were not checked, not that none run. A build with no web
        // service package cannot keep an old build loaded in a web server, so the installed package decides.
        a.reasons.push(t('reason.processesNotCheckedNoService'));
      } else {
        a.reasons.push(build ? t('reason.noRunningPhpSeen') : t('reason.probeProcessNotFound', { version: ver.raw }));
      }
    }
  } else if (obs.serverConflict) {
    a.verdict = 'unknown';
    a.need = 'together';
    a.reasons.push(t('reason.serverConflict'));
  } else {
    a.reasons.push(t('reason.loadedBuildUnconfirmed', { version: ver.raw }));
  }
}

// The packages of a build whose processes the server script cannot see in /proc, when it saw none of them: php5-fpm
// and php5-cgi (Ubuntu 14.04 and Debian 8 name the processes after the package, which the script's process list
// does not include), and an Alpine Apache module (mod_php83.so, which the script's libphp test does not match).
function unseenServices(build, mine) {
  const manager = build.packages[0]?.manager;
  const out = [];
  for (const p of build.packages) {
    if (manager === 'dpkg' && /^php5-(fpm|cgi)$/.test(p.name) && !mine.some((q) => q.comm === p.name)) out.push(p.name);
    if (manager === 'apk' && /-apache2$/.test(p.name) && !mine.some((q) => q.comm === 'httpd' || q.comm === 'apache2')) out.push(p.name);
  }
  return [...new Set(out)];
}

// Whether process p may run the PHP of result x. The running PHP judged with an installed build runs what that
// build can run; otherwise any process of its branch may be it.
function mayRun(p, x, installed) {
  if (x.build) return procRunsBuild(p, x.build);
  const used = installed.filter((b) => x.a.usedKeys.includes(b.key));
  return used.length ? used.some((b) => procRunsBuild(p, b)) : procMayRun(p.comm, x.ver);
}

// Whether a process the server script saw can run this installed build, by how each packaging names it.
// Debian and Ubuntu name FPM and CGI after the branch (php-fpm8.2, from the php8.2-fpm package; php5-fpm on the
// oldest releases) and run PHP in Apache only through a libapache2-mod-php package. Each SAPI binary carries the
// whole PHP engine, so a process belongs to a build only when that build has the SAPI's own package. Alpine names
// them php-fpm83. On the RHEL family every collection runs as php-fpm or in httpd: php-fpm from a php-fpm or
// php8.4-fpm package, httpd from php or mod_php, or php8.4-modphp on Amazon Linux 2023. An unversioned php-fpm on
// Debian is a container's, a panel's or a self-built PHP.
function procRunsBuild(p, build) {
  const comm = p.comm;
  const names = build.packages.map((x) => x.name);
  const branch = build.ver.branch;
  switch (build.packages[0]?.manager) {
    case 'dpkg': {
      const m = /^php-(fpm|cgi)(\d+\.\d+)$/.exec(comm);
      if (m) return m[2] === branch && names.includes(`php${branch}-${m[1]}`);
      if (/^php5-(fpm|cgi)$/.test(comm)) return names.includes(comm);
      return comm === 'apache2' && names.some((n) => /^libapache2-mod-php/.test(n));
    }
    case 'apk': {
      const m = /^php-(fpm|cgi)(\d)(\d+)$/.exec(comm);
      if (m) return `${m[2]}.${m[3]}` === branch && names.some((n) => n.endsWith(`-${m[1]}`));
      return (comm === 'httpd' || comm === 'apache2') && names.some((n) => /-apache2$/.test(n));
    }
    case 'rpm':
      if (comm === 'php-fpm') return names.some((n) => /(^|-)php(\d+\.\d+)?-fpm$/.test(n));
      // A collection's Apache module package (php74-php) is not in the server script's list.
      if (comm === 'httpd') return names.some((n) => n === 'php' || n === 'mod_php' || /-modphp$/.test(n)) || /^rpm:php\d+$/.test(build.key);
      if (comm === 'php-cgi') return names.some((n) => /(^|-)php(\d+\.\d+)?-(cli|cgi)$/.test(n));
      return false;
    default:
      return procMayRun(comm, build.ver);
  }
}

// A process name with a version (php-fpm8.2) runs only that branch; others (apache2, httpd, php-fpm) may run any.
function procMayRun(comm, ver) {
  const m = /^php-(?:fpm|cgi)(\d+\.\d+)$/.exec(comm);
  return m ? m[1] === ver.branch : true;
}

function commSapi(comm) {
  if (/^php\d*-fpm/.test(comm)) return 'fpm';
  if (comm === 'apache2' || comm === 'httpd') return 'apache';
  if (/^lsphp/.test(comm)) return 'litespeed';
  if (comm === 'frankenphp') return 'frankenphp';
  if (/^php\d*-cgi/.test(comm)) return 'cgi';
  return comm;
}

function sapiKind(sapi) {
  return own({ 'fpm-fcgi': 'fpm', apache2handler: 'apache', litespeed: 'litespeed', frankenphp: 'frankenphp', 'cgi-fcgi': 'cgi', cgi: 'cgi' }, sapi) || sapi;
}

const commNames = (procs) => [...new Set(procs.map((p) => p.comm))].join(', ');

function inferSapi(processes) {
  const comms = (processes || []).map((p) => p.comm);
  if (comms.some((c) => /^php\d*-fpm/.test(c))) return 'fpm-fcgi';
  if (comms.some((c) => c === 'apache2' || c === 'httpd')) return 'apache2handler';
  if (comms.includes('frankenphp')) return 'frankenphp';
  if (comms.some((c) => /^lsphp/.test(c))) return 'litespeed';
  return null;
}

// Whether a build has a package that runs PHP as a service (FPM, CGI, an Apache module): only such a service can
// keep an old build loaded in a process the server script checks. A CLI-only build has none.
function servesWeb(build) {
  return build.packages.some((p) => /-(fpm|cgi|apache2|modphp)$/.test(p.name) || /^libapache2-mod-php/.test(p.name)
    || (p.manager === 'rpm' && /^(php|mod_php)$/.test(p.name)));
}

// The PHP SAPI an installed build's packages provide, for the restart command.
function buildSapi(build) {
  const names = build.packages.map((p) => p.name);
  if (names.some((n) => /-fpm$/.test(n))) return 'fpm-fcgi';
  if (names.some((n) => /^libapache2-mod-php|^mod_php$|^php$|-apache2$|-modphp$/.test(n))) return 'apache2handler';
  return null;
}

// CVEs with a fix recorded in the changelogs of the given packages. null when none of them has a changelog.
function changelogFound(packages, cves) {
  const logs = packages.map((p) => p.changelog).filter(Boolean);
  if (!logs.length) return null;
  return cves.filter((cve) => logs.some((hits) => hits[cve] > 0));
}

// The installed PHP builds in the server script output: one per Debian source package, rpm
// collection or apk prefix (php8.2 and php8.4 side by side are two builds).
function installedBuilds(obs) {
  const groups = new Map();
  for (const p of obs.packages) {
    const key = buildKey(p);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(p);
  }
  const builds = [];
  for (const [key, packages] of groups) {
    const main = packages.find((p) => /-common$/.test(p.name)) || packages[0];
    const ver = parsePhpVersion(debComparable(main.version));
    if (ver) builds.push({ key, packages, main, ver });
  }
  return builds.sort((x, y) => compareBranch(x.ver.branch, y.ver.branch) || x.key.localeCompare(y.key));
}

function buildKey(p) {
  if (p.manager === 'dpkg') return `dpkg:${debSource(p)}`;
  const scl = /^(php\d+)-php(-|$)/.exec(p.name);
  if (p.manager === 'rpm') return `rpm:${scl ? scl[1] : 'php'}`;
  const apk = /^(php\d*)/.exec(p.name);
  return `${p.manager}:${apk ? apk[1] : p.name}`;
}

// The distribution family whose data the verdict rests on, which the page names as the data source: 'debian',
// 'ubuntu' or 'rhel'. null when it rests on upstream releases (an upstream or Docker build, a PHP configured outside
// /etc, deb.sury.org, Remi, Alpine, other distributions) or on no data at all (pre-releases, undetermined builds).
function dataFamily(d, path) {
  if (path === 'deb' && (d.family === 'debian' || d.family === 'ubuntu')) return d.family;
  if (path === 'rhel' && d.family === 'rhel') return 'rhel';
  return null;
}

function finish(ctx, r, obs, d, ver, info) {
  const { t, lang } = ctx;
  r.title = t(`verdict.title.${r.verdict}`);
  if (ctx.sapi) r.exposure = sapiExposure(ctx.sapi, lang);
  if (obs.ini) r.mitigations = evaluateMitigations(obs.ini, obs.extensions, ver, r.verdict === 'patched', lang);
  r.findings = describeFindings(t, obs.findings || {}, obs.root);
  buildActions(ctx, r, obs, d || {}, ver, info);
  // The page shows these values as text: never null, a number or an object.
  r.facts = textRows(r.facts);
  r.advisories = textRows(r.advisories);
  return r;
}

function textRows(rows) {
  return rows
    .filter((x) => x && x.value !== null && x.value !== undefined && String(x.value).trim() !== '')
    .map((x) => ({ label: String(x.label), value: String(x.value) }));
}

// Results of the server script's checks for signs of compromise (--logs, --webroot).
// A count of null means the source could not be read; it is never reported as "nothing found".
function describeFindings(t, f, root) {
  const out = [];
  const keys = Object.keys(FINDING_SOURCE).filter((k) => k in f);
  if (f.oom > 0) out.push({ level: 'warn', text: t('finding.oom', { n: f.oom }) });
  if (f.crash > 0) out.push({ level: 'warn', text: t('finding.crash', { n: f.crash }) });
  if (f.bigsession > 0) out.push({ level: 'warn', text: t('finding.bigSession', { n: f.bigsession }) });
  if (f.webuser_proc > 0) out.push({ level: 'warn', text: t('finding.webUserProc', { n: f.webuser_proc }) });
  if (f.recent_php > 0) out.push({ level: 'warn', text: t('finding.recentPhp', { n: f.recent_php }) });
  // A count of null is "unknown": the source was missing or unreadable. It is never "nothing found".
  const unread = [...new Set(keys.filter((k) => f[k] === null || f[k] === undefined).map((k) => FINDING_SOURCE[k]))];
  const checked = [...new Set(keys.map((k) => FINDING_SOURCE[k]))];
  const sources = (list) => list.map((s) => t(`finding.source.${s}`)).join(', ');
  if (unread.length) {
    out.push({ level: 'info', text: t('finding.unread', { items: sources(unread) }) });
  } else if (keys.length && root === false) {
    out.push({ level: 'info', text: t('finding.notRoot') });
  }
  // Name what was checked: the server script always counts web account processes, and logs, session files and
  // the web root only with --logs and --webroot.
  if (keys.length && !out.length) out.push({ level: 'ok', text: t('finding.none', { items: sources(checked) }) });
  if (out.some((x) => x.level === 'warn' || x.level === 'bad')) {
    out.push({ level: 'info', text: t('finding.incident') });
  }
  return out;
}

// ── Remediation steps ──────────────────────────────────────────────
// r.actions is a numbered list of steps, each { text, code? }: a sentence or two of plain explanation and, where
// useful, commands to copy. Versions, package names, image tags, service names and paths come from the observation
// and the data files. A placeholder in angle brackets (<container>, <your-image>) stands only for a value the input
// cannot show. Commands never delete anything and restart only the services that run this PHP.

// Debian releases the official PHP Docker images are still built on (php:8.3.36-apache-bookworm exists,
// php:8.3.36-apache-bullseye does not), and the Alpine releases their tags name (php:8.4.27-fpm-alpine3.24).
const DOCKER_DEBIAN = [{ release: 12, codename: 'bookworm' }, { release: 13, codename: 'trixie' }];
const DOCKER_ALPINE = ['3.23', '3.24'];
const DEBIAN_RELEASES = { jessie: 8, stretch: 9, buster: 10, bullseye: 11, bookworm: 12, trixie: 13, forky: 14 };
// Ubuntu releases past their ten-year ESM window: their fixes come only with the paid Legacy Support add-on.
const UBUNTU_LEGACY = ['14.04', '16.04'];
// Ubuntu releases whose PHP security updates report their package revision in PHP_VERSION (8.1.2-1ubuntu2.28). From
// 24.04 on, PHP_VERSION is the plain upstream version before and after the fix.
const UBUNTU_REVISION_IN_VERSION = ['14.04', '16.04', '18.04', '20.04', '22.04'];
// The probe lists at most this many packages, so a list of this length may be incomplete.
const PROBE_DPKG_MAX = 40;
// Where the page publishes the probe and the server script (the download lines on its tabs).
// The published download location. The page swaps it for its own address, so a
// self-hosted copy points at its own downloads/.
export const DEFAULT_DOWNLOADS = 'https://sqzer-x.github.io/php2shell-scanner/downloads/';
const DOWNLOADS = DEFAULT_DOWNLOADS;
const FETCH_SCRIPT = `curl -fsSLO ${DOWNLOADS}php2shell-server-check.sh\nsha256sum php2shell-server-check.sh`;
const RHEL_NAMES = {
  rhel: 'RHEL', centos: 'CentOS', rocky: 'Rocky Linux', almalinux: 'AlmaLinux', ol: 'Oracle Linux',
  cloudlinux: 'CloudLinux', eurolinux: 'EuroLinux', amzn: 'Amazon Linux',
};
// Rebuilds that republish Red Hat's fixes in advisories of their own.
const REBUILD_PREFIX = { rocky: 'RLSA', almalinux: 'ALSA', ol: 'ELSA', cloudlinux: 'CLSA' };
const CVE_GREP = (cves) => cves.map((c) => `-e ${c}`).join(' ');

function buildActions(ctx, r, obs, d, ver, info) {
  const s = actionContext(ctx, r, obs, d, ver, info);
  let steps;
  if (info.noVersion) steps = collectSteps(s, 'noVersion');
  else if (r.verdict === 'patched') steps = patchedSteps(s);
  else if (r.verdict === 'restart') steps = restartSteps(s);
  else steps = fixSteps(s);
  r.actions.push(...steps.filter(Boolean));
}

function step(s, key, vars = {}, code = null) {
  const text = s.t(key, vars).trim();
  return code ? { text, code } : { text };
}

// Marks how many steps at the start explain the situation; an interim mitigation that is the only thing to do
// for now goes straight after them.
function lead(steps, n) {
  steps.lead = n;
  return steps;
}

function actionContext(ctx, r, obs, d, ver, info) {
  const a = info.a || {};
  const build = info.build || null;
  const official = obs.configPath === '/usr/local/etc/php';
  const s = {
    ctx,
    t: ctx.t,
    r,
    obs,
    d: d || {},
    ver,
    info,
    a,
    build,
    // When the worst result is another installed build next to the probe's PHP, that build's service matters.
    sapi: build && (obs.phpVersion || !ctx.sapi) ? buildSapi(build) || ctx.sapi : ctx.sapi,
    official,
    container: obs.container === true || official,
    path: info.path,
    fixed: ver ? ctx.upstream.fixed[ver.branch] || null : null,
    pkgs: build ? build.packages : obs.packages.filter((p) => (a.usedKeys || []).includes(buildKey(p))),
    need: info.need || a.need || null,
    // A header, -v output or a bare version: nothing shows where this PHP comes from.
    fromOutside: !obs.sources.includes('selfcheck') && !obs.sources.includes('servercheck'),
  };
  s.names = [...new Set(s.pkgs.map((p) => p.name))];
  // Which PHP an undetermined result is about is open, so no service or file of it is named.
  s.layout = ver && s.path !== 'undetermined' ? phpLayout(s) : null;
  // An end-of-life branch with no package that carries the fix: the move takes time, the mitigation does not.
  s.eolNoFix = Boolean(ver && a.eol && !s.fixed && s.path !== 'remi');
  return s;
}

// Alpine has no sudo, and its steps assume a root shell.
function rootShell(s) {
  return s.layout?.init === 'openrc' || s.d.family === 'alpine' || s.obs.os?.id === 'alpine';
}

function serverScript(s, args = '') {
  return `${asRootIn(s)}sh php2shell-server-check.sh${args}`;
}

// "sudo " for a command that needs root, except where the steps assume a root shell.
function asRootIn(s) {
  return rootShell(s) ? '' : 'sudo ';
}

function inContainer(args = '') {
  return `docker cp php2shell-server-check.sh <container>:/tmp/\ndocker exec -u 0 <container> sh /tmp/php2shell-server-check.sh${args}`;
}

// "a, b and c" in the language of the result.
function listText(s, items) {
  if (items.length < 2) return items.join('');
  return `${items.slice(0, -1).join(s.t('list.separator'))}${s.t('list.and')}${items[items.length - 1]}`;
}

// ── Steps by verdict ────────────────────────────────────────────────

// Vulnerable, Fix pending and Undetermined: what to collect (when open), how to update, restart and confirm,
// the interim mitigations, and the compromise check.
function fixSteps(s) {
  const out = [];
  if (s.r.verdict === 'unknown') out.push(...collectSteps(s, s.need || (s.path === 'undetermined' ? 'server' : null)));
  let body = [];
  if (s.path === 'prerelease') {
    body = [s.fixed ? step(s, 'step.prereleaseFixed', { version: s.ver.raw, fixed: s.fixed, branch: s.ver.branch })
      : step(s, 'action.checkReleaseNotes', { version: s.ver.raw }), restartAfterUpdate(s)];
  } else if (['root', 'together', 'unreadable', 'unseen'].includes(s.need)) {
    // The installed package has the fix; only the running processes (or which output is current) are open.
    if (s.need === 'root' || s.need === 'unseen') body = [restartIfUnsure(s)];
  } else if (s.need === 'sapiPackage') {
    // The package of the running SAPI is not fully installed: finishing the update (the step above) comes first.
    body = [restartAfterUpdate(s), recheckStep(s)];
  } else if (s.path !== 'undetermined') {
    body = pathSteps(s);
  }
  const timing = mitigationTiming(s, body);
  body = body.filter(Boolean);
  // With the fixed package installed (the processes, or the end of the output, are what is open), the interim
  // mitigations are not the next step. Nor are they after a downgrade: the running PHP has the fix, and the reload
  // that applies them would load the vulnerable build on disk.
  const fixedOnDisk = ['root', 'together', 'unreadable', 'unseen'].includes(s.need) || (s.need === 'whole' && s.a.verdict === 'patched')
    || Boolean(s.a.downgraded);
  if (!fixedOnDisk) body.splice(timing.at === null ? body.length : Math.min(timing.at, body.length), 0, ...mitigationSteps(s, timing.when));
  out.push(...body, compromiseStep(s));
  return out;
}

// Where the interim mitigation goes, and how it starts. When nothing can be installed yet (a pending fix, an
// end-of-life branch, a release with no Red Hat fix), it is the only thing that lowers the risk now, so it follows
// the steps that explain the situation instead of the update steps that cannot do anything yet.
function mitigationTiming(s, body) {
  const at = body.lead || 1;
  if (s.r.verdict === 'pending') return { when: 'when.pending', at };
  if (s.eolNoFix) return { when: 'when.eol', at };
  if (body.waiting) return { when: body.waiting, at };
  return { when: 'when.cannotUpdate', at: null };
}

function pathSteps(s) {
  if (s.container) return containerSteps(s);
  if (s.path === 'deb') return debSteps(s);
  if (s.path === 'sury') return surySteps(s);
  if (s.path === 'rhel') return rhelSteps(s);
  if (s.path === 'remi') return remiSteps(s);
  if (s.path === 'alpine') return alpineSteps(s);
  if (s.path === 'other') return otherSteps(s);
  // A RHEL-family PHP configured under /etc that no rpm package in the server script output accounts for (the
  // php8.4 packages of RHEL 10, for example) is still most likely Red Hat's.
  if (s.d.family === 'rhel' && /^\/etc(\/|$)/.test(s.obs.configPath || '')) return rhelSteps(s);
  return upstreamSteps(s);
}

// Restart needed: why the old build is still loaded, the restart itself, how to confirm it, and the compromise
// check (the vulnerable build has been serving requests until now).
function restartSteps(s) {
  const out = [];
  if (s.container) {
    out.push(step(s, 'step.container.restart', {}, 'docker restart <container>'));
    const run = containerRunLine(s);
    if (run) out.push(step(s, 'step.container.persist', {}, run));
  } else {
    const plan = s.info.genericRestart ? null : restartPlan(s);
    if (plan) out.push(step(s, 'action.restartNow', { extra: plan.extra }, plan.code));
    else if (s.info.genericRestart || s.info.stale?.length) {
      const names = s.info.genericRestart ? s.info.genericRestart.split(', ') : s.info.stale;
      out.push(step(s, 'action.restartProcesses', { names: names.join(', ') }, `ps -o pid,user,cgroup,args -C ${names.join(',')}`));
    } else out.push(step(s, 'action.restartGeneric'));
    out.push(s.obs.sources.includes('servercheck') ? step(s, 'step.restart.confirmServer', {}, serverScript(s)) : step(s, 'step.restart.confirm'));
  }
  out.push(compromiseStep(s));
  return out;
}

// Patched: other sites and pools, and optional hardening.
function patchedSteps(s) {
  const out = [step(s, s.container ? 'action.checkOtherContainers' : 'action.checkOtherSites')];
  const ini = s.obs.ini;
  if ((ini && isOn(ini.expose_php)) || s.obs.sources.includes('header')) out.push(exposeStep(s));
  if (!(s.obs.extensions && s.obs.extensions.session === false)) {
    out.push(step(s, ini && isOff(ini['session.upload_progress.enabled']) ? 'step.hardening.uploadOff' : 'step.hardening.uploadOn'));
  }
  return out;
}

// The server script with --logs and --webroot, which looks for signs of an attack.
function compromiseStep(s) {
  const args = ' --logs --webroot <webroot>';
  return step(s, 'action.lookForCompromise', {}, s.container ? inContainer(args) : serverScript(s, args));
}

// ── What to collect when the verdict is open ───────────────────────

function collectSteps(s, need) {
  const hostServer = () => step(s, 'step.collect.server', {}, `${FETCH_SCRIPT}\n${serverScript(s)}`);
  const server = () => (s.container ? step(s, 'step.collect.serverInContainer', {}, `${FETCH_SCRIPT}\n${inContainer()}`) : hostServer());
  const probe = (next) => probeStep(s, next);
  switch (need) {
    case 'noVersion':
      return [probe(true), hostServer()];
    case 'server':
      return s.fromOutside ? [probe(true), server()] : [server()];
    case 'serverOrDistro':
      // The server script output is already here when it is the OS release, not the packages, that is missing.
      if (s.obs.serverData) return [step(s, 'step.collect.distroOnly')];
      if (s.container) return [server()];
      return s.fromOutside ? [probe(true), server(), step(s, 'step.collect.distro')] : [server(), step(s, 'step.collect.distro')];
    case 'root':
    case 'unreadable':
      // As root, a process the script cannot read is usually in a container without CAP_SYS_PTRACE: running it
      // again with sudo gives the same output.
      if (s.obs.root === true) return [step(s, 'step.collect.unreadableAsRoot', {}, `${FETCH_SCRIPT}\n${serverScript(s)}`)];
      return [s.container ? server() : step(s, 'step.collect.root', {}, serverScript(s))];
    case 'unseen': {
      const names = s.a.unseen || [];
      const code = names.some((n) => /-apache2$/.test(n)) ? "ps -o pid,args | grep '[h]ttpd'" : `ps -o pid,lstart,args -C ${names.join(',')}`;
      return [step(s, 'step.collect.unseen', { names: names.join(', ') }, code)];
    }
    case 'sapiPackage': {
      const src = debSrc(s);
      return [step(s, 'step.collect.sapiPackage', { pkg: s.info.sapiPackage || s.a.sapiPackage || `${src}-fpm`, src },
        `dpkg -l '${src}-*' 'libapache2-mod-${src}'\nsudo dpkg --audit\nsudo apt-get update\nsudo apt-get install -f`)];
    }
    case 'vendor': {
      const vendor = s.obs.os?.pretty || s.d.vendor || s.obs.os?.id || 'other';
      return [step(s, 'step.collect.vendor', { vendor }, `rpm -qa 'php*'\nrpm -q --changelog php${s.ver.major} | grep ${CVE_GREP(s.ctx.cves)}`)];
    }
    case 'whole':
      return [step(s, 'step.collect.whole')];
    case 'together':
      return [step(s, 'step.collect.together', {}, serverScript(s))];
    case 'elsewhere':
      return [step(s, 'step.collect.elsewhere', {}, inContainer())];
    case 'hiddenLink':
      return [step(s, 'step.collect.hiddenLink', {}, `${FETCH_SCRIPT}\n${inContainer()}`)];
    case 'advisories': {
      const family = s.d.family === 'ubuntu' ? 'ubuntu' : 'debian';
      return [step(s, 'step.collect.advisories', { family: familyName(family), src: debSrc(s) }, trackerUrls(family, s.ctx.cves))];
    }
    case 'supplier': {
      const pkg = s.names[0] || `${debSrc(s)}-common`;
      return [step(s, 'step.collect.supplier', { family: familyName(s.d.family) }, `apt-cache policy ${pkg}`)];
    }
    default:
      return [];
  }
}

// The PHP probe through the web server; next adds that the server script follows in the next step.
function probeStep(s, next) {
  return step(s, 'step.collect.probe', { next: next ? s.t('collect.probeNext') : '' },
    `curl -fsSLO ${DOWNLOADS}php2shell-selfcheck.php\ncurl -s 'https://<site>/<file>.php?k=<TOKEN>'`);
}

// ── Debian and Ubuntu packages ──────────────────────────────────────

function debSteps(s) {
  const D = debInfo(s);
  if (s.r.verdict === 'pending') {
    return lead([
      step(s, 'step.pending.watch', { family: D.family, release: D.release, src: D.src }, trackerUrls(s.d.family, s.ctx.cves)),
      step(s, 'step.pending.check', { src: D.src }, `sudo apt-get update\napt list --upgradable 2>/dev/null | grep ${D.src}\nsudo apt-get install --only-upgrade ${aptList(s, D.src)}`),
      restartAfterUpdate(s),
    ], 1);
  }
  if (s.need === 'supplier') return supplierSteps(s, D);
  const out = [];
  if (D.pro) out.push(proStep(s, D));
  let fix;
  if (s.a.downgraded) fix = s.t('fix.debDowngraded', { pkg: D.installed || D.src, version: s.ver.raw, fixed: D.fixed ? `${D.src} ${D.fixed}` : `PHP ${s.fixed}` });
  else if (s.r.verdict === 'vulnerable' && D.fixed && D.installed) fix = s.t('fix.deb', { pkg: D.installed, family: D.family, release: D.release, src: D.src, fixed: D.fixed });
  else if (s.r.verdict === 'vulnerable' && D.fixed) fix = s.t('fix.debRunning', { version: s.ver.raw, family: D.family, release: D.release, src: D.src, fixed: D.fixed });
  else fix = s.t('fix.debOpen', { family: D.family, src: D.src });
  out.push(aptUpgradeStep(s, fix, D.src));
  if (s.need === 'advisories') out.push(step(s, 'step.apt.confirmCompare', { family: D.family }, dpkgVersions(s, D.src)));
  else out.push(D.fixed ? step(s, 'step.apt.confirmFixed', { fixed: D.fixed }, dpkgVersions(s, D.src)) : step(s, 'step.apt.confirm', {}, dpkgVersions(s, D.src)));
  out.push(restartAfterUpdate(s));
  // The data has no record to compare with, but the server script reads the changelog of the updated package.
  if (s.need === 'advisories') out.push(step(s, 'step.recheckChangelog', {}, serverScript(s)));
  // The server script output did not name the release, and running it again will not either.
  else if (s.need === 'serverOrDistro' && s.obs.serverData) out.push(step(s, 'step.recheckServerDistro', {}, serverScript(s)));
  else out.push(recheckStep(s));
  return out;
}

// A build from another repository with the same upstream version: apt never replaces it with the distribution's
// lower-numbered revision, so the distribution's build is installed explicitly, at its exact version.
function supplierSteps(s, D) {
  const foreign = D.installedVersion || s.ver.raw;
  return [
    step(s, 'step.apt.switchToDistro', { family: D.family, fixed: D.fixed, foreign, src: D.src }, switchToDistroCode(D.src, foreign, D.fixed)),
    step(s, 'step.apt.confirmExact', { family: D.family, fixed: D.fixed }, `dpkg -l '${D.src}-*' 'libapache2-mod-${D.src}' | grep '^ii'`),
    restartAfterUpdate(s),
    recheckStep(s),
  ];
}

// Reinstalls every package of this source that is now at the foreign version at the distribution's fixed version.
function switchToDistroCode(src, foreign, fixed) {
  const lookup = `$(dpkg-query -W -f='\${Package} \${Version}\\n' '${src}-*' 'libapache2-mod-${src}' 2>/dev/null | awk '$2 == "${foreign}" {print $1"=${fixed}"}')`;
  return `sudo apt-get update\nsudo apt-get install --allow-downgrades ${lookup}`;
}

function proStep(s, D) {
  const cmd = D.release === '14.04' ? 'sudo ua attach <token>' : 'sudo pro attach <token>';
  return step(s, UBUNTU_LEGACY.includes(D.release) ? 'step.ubuntuProLegacy' : 'step.ubuntuPro', { release: D.release }, cmd);
}

// deb.sury.org follows upstream releases: the same apt commands, with the upstream fixed release as the target.
function surySteps(s) {
  const src = debSrc(s);
  if (!s.fixed) {
    // deb.sury.org ships backported fixes for end-of-life branches: its latest build may have them, which its
    // changelog shows. The move to a supported branch, or to the distribution's own fixed package, follows.
    const fix = s.t('fix.suryEol', { branch: s.ver.branch, src });
    return lead([aptUpgradeStep(s, fix, src), restartAfterUpdate(s), step(s, 'step.recheckChangelog', {}, serverScript(s)), ...eolSteps(s, { restart: false })], 1);
  }
  const pkg = pickDebPackage(s.obs, s.ver, s.sapi, s.build);
  const fix = s.t('fix.sury', { pkg: pkg ? pkgLabel(pkg) : `PHP ${s.ver.raw}`, branch: s.ver.branch, fixed: s.fixed }) + eolSoon(s);
  return [
    aptUpgradeStep(s, fix, src),
    step(s, 'step.apt.confirmUpstream', { fixed: s.fixed, branch: s.ver.branch }, dpkgVersions(s, src)),
    restartAfterUpdate(s),
    recheckStep(s),
  ];
}

function aptUpgradeStep(s, fix, src) {
  const dpkg = s.names.length > 0;
  return step(s, dpkg ? 'step.apt.upgrade' : 'step.apt.upgradeFind', { fix, names: s.names.join(', '), src },
    `sudo apt-get update\nsudo apt-get install --only-upgrade ${aptList(s, src)}`);
}

// The installed packages of this PHP, or, when the input does not list them, a lookup of the installed ones
// (dpkg -l marks them "ii"; dpkg-query -W with a pattern also lists names that are not installed, which apt refuses).
function aptList(s, src) {
  if (s.names.length) return s.names.join(' ');
  return `$(dpkg -l '${src}-*' 'libapache2-mod-${src}' 2>/dev/null | awk '/^ii/ {print $2}')`;
}

// The command that shows the installed versions of this PHP's packages.
function dpkgVersions(s, src) {
  return s.names.length ? `dpkg-query -W ${s.names.join(' ')}` : `dpkg -l '${src}-*' 'libapache2-mod-${src}' | grep '^ii'`;
}

function debInfo(s) {
  const src = debSrc(s);
  const entry = own(own(own(s.ctx.distro, s.d.family), s.d.release)?.packages, src);
  const fixed = entry ? s.ctx.cves.map((c) => entry.fixed?.[c]).filter(Boolean).sort(compareDebian).pop() || null : null;
  const pkg = pickDebPackage(s.obs, s.ver, s.sapi, s.build);
  const mine = pkg && s.pkgs.includes(pkg);
  return {
    src,
    fixed,
    pro: Boolean(entry?.pro),
    family: familyName(s.d.family),
    release: s.d.release || '',
    installed: mine ? pkgLabel(pkg) : null,
    installedVersion: mine ? pkg.version : null,
  };
}

function debSrc(s) {
  const p = s.pkgs.find((x) => x.manager === 'dpkg');
  return p ? debSource(p) : srcFor(s.ver);
}

function familyName(family) {
  return own({ debian: 'Debian', ubuntu: 'Ubuntu' }, family) || family || '';
}

// The pages that show the fixed version of each release, one per CVE.
function trackerUrls(family, cves) {
  return cves.map((c) => (family === 'ubuntu' ? `https://ubuntu.com/security/${c}` : `https://security-tracker.debian.org/tracker/${c}`)).join('\n');
}

// ── RHEL family ─────────────────────────────────────────────────────

function rhelSteps(s) {
  const R = rhelInfo(s);
  const out = [];
  // Releases past the end of their support come first: they decide what the update steps can still bring.
  if (R.vendor === 'amzn') {
    if (R.release === '2') out.push(step(s, 'step.amazon.al2Eol'));
    else if (/^201\d/.test(R.release)) out.push(step(s, 'step.amazon.amiEol', { release: R.release }));
  } else if (R.vendor === 'centos' && R.major && R.major <= 8) {
    // CentOS Linux 6 to 8 and CentOS Stream 8 get no updates from their own repositories; the package commands
    // below help only with a third-party extended support subscription.
    out.push(step(s, 'step.rhel.centosEol', { release: R.release }));
  } else if (R.major && R.major <= 7) {
    out.push(step(s, 'step.rhel.old', { name: R.name, release: R.release }));
  }
  const context = rhelContext(s, R);
  const what = s.t(s.names.length ? 'rhel.what.names' : 'rhel.what.all', { names: s.names.join(', ') });
  const target = s.names.length ? s.names.join(' ') : R.glob;
  const check = R.cves.map((c) => `--cve ${c}`).join(' ');
  const old = R.yum && R.major <= 6;
  const update = old ? `sudo yum update ${target}` : R.yum ? `sudo yum updateinfo list ${check}\nsudo yum update ${target}`
    : `sudo dnf updateinfo list ${check}\nsudo dnf upgrade --refresh ${target}`;
  const upgradeKey = old ? 'step.rhel.update' : R.yum ? 'step.rhel.upgradeYum' : 'step.rhel.upgrade';
  const moduleCheck = R.module && !R.yum;
  if (R.vendor === 'amzn') {
    out.push(step(s, 'step.amazon.watch', { context, release: R.release }, R.cves.map((c) => `https://explore.alas.aws.amazon.com/${c}.html`).join('\n')));
    lead(out, out.length);
    out.push(step(s, upgradeKey, { context: '', what }, update));
  } else if (R.noFix) {
    // Red Hat has published nothing for this branch and release: watch for it, and say that the update steps
    // have nothing to bring yet.
    out.push(step(s, 'step.rhel.watch', { context, release: R.release }, R.cves.map((c) => `https://access.redhat.com/security/cve/${c}`).join('\n')));
    lead(out, out.length);
    if (R.switchTo) {
      out.push(step(s, 'step.rhel.switchStream', { release: R.release, branch: s.ver.branch, streams: listText(s, R.switchTo.streams), target: R.switchTo.branch, build: R.switchTo.build },
        `sudo dnf module switch-to php:${R.switchTo.branch}`));
    }
    out.push(step(s, old ? 'step.rhel.updateNone' : R.switchTo ? 'step.rhel.upgradeNoneStay' : 'step.rhel.upgradeNone', { what, branch: s.ver.branch }, update));
    if (moduleCheck && !R.switchTo) out.push(step(s, 'step.rhel.moduleNoBuild', { branch: s.ver.branch }, 'dnf module list php'));
  } else {
    if (moduleCheck && R.stream) out.push(step(s, 'step.rhel.module', { branch: s.ver.branch, build: R.stream }, 'dnf module list php'));
    out.push(step(s, upgradeKey, { context, what }, update));
    if (!R.release && !R.fixedElsewhere.length) out.push(step(s, 'step.rhel.watchAny', {}, R.cves.map((c) => `https://access.redhat.com/security/cve/${c}`).join('\n')));
  }
  const query = s.names.length ? `rpm -q ${s.names.join(' ')}` : `rpm -qa ${R.glob}`;
  const grep = `rpm -q --changelog ${R.main} | grep ${CVE_GREP(R.grepCves)}`;
  if (R.rebase) {
    // The fix comes as a new upstream release (a Red Hat rebase, or an Amazon Linux update), whose changelog entry
    // names the version, not the CVEs: the installed version shows it.
    out.push(R.fixedNvr ? step(s, 'step.rpm.confirmVersion', { fixed: R.fixedNvr }, query)
      : step(s, 'step.rpm.confirmUpstream', { fixed: s.fixed, branch: s.ver.branch }, query));
  } else if (R.notAffected.length) {
    out.push(step(s, 'step.rhel.confirmSome', { pkg: R.main, cves: R.grepCves.join(', '), notAffected: R.notAffected.join(', '), release: R.release }, `${query}\n${grep}`));
  } else {
    out.push(R.fixedNvr ? step(s, 'step.rhel.confirmFixed', { pkg: R.main, fixed: R.fixedNvr }, `${query}\n${grep}`)
      : step(s, 'step.rhel.confirm', { pkg: R.main }, `${query}\n${grep}`));
  }
  out.push(restartAfterUpdate(s));
  out.push(step(s, R.noFix ? 'step.recheckServerLater' : 'step.recheckServer', {}, serverScript(s)));
  // With no fix to install (or no support left), the interim mitigation is what to do now.
  if (R.eolRelease) out.waiting = 'when.eolRelease';
  else if (R.noFix) out.waiting = 'when.pending';
  if (!out.lead) out.lead = 1;
  return out;
}

function rhelInfo(s) {
  const { d, ver, ctx } = s;
  const major = rhelMajor(d);
  const release = d.release || '';
  const rh = release ? ctx.distro.redhat?.[release] : null;
  const scl = sclName(s);
  const vendor = d.vendor || 'rhel';
  const branchOf = (x) => x?.advisory && advisoryBranch(x.package) === ver.branch;
  const advisories = vendor === 'amzn' ? [] : (rh?.advisories || []).filter(branchOf);
  const stream = advisories.map((x) => x.package).find((p) => /^php:\d+\.\d+-/.test(p)) || null;
  const nvr = advisories.map((x) => /^php[\d.]*-(?:\d+:)?(\d+\.\d+\.\d+-.+)$/.exec(x.package || '')).find(Boolean);
  // The package name prefix of the fixed build when no package was listed: php8.4 on RHEL 10, php elsewhere.
  const prefix = advisories.map((x) => /^(php[\d.]*)-\d+:/.exec(x.package || '')).find(Boolean)?.[1] || 'php';
  const versions = [ver.raw, ...s.pkgs.map((p) => p.version)].join(' ');
  const main = s.names.find((n) => /-common$/.test(n)) || s.names[0] || (scl ? `${scl}-php-common` : `${prefix}-common`);
  const module = Boolean(stream) || /\.module[+_]/.test(versions);
  const notAffected = release ? ctx.cves.filter((c) => rhelNotAffected(rh, release, c, ver)) : [];
  // Red Hat advisories for this branch on the other releases, for a server whose release is unknown.
  const fixedElsewhere = release ? [] : Object.entries(ctx.distro.redhat || {})
    .map(([rel, x]) => ({ release: rel, ids: [...new Set((x?.advisories || []).filter(branchOf).map((y) => y.advisory))] }))
    .filter((x) => x.ids.length);
  const noFix = Boolean(release) && vendor !== 'amzn' && !advisories.length;
  // Newer module streams of this release that have the fix, when this branch has none.
  let switchTo = null;
  if (noFix && module && !(major && major < 8)) {
    const byBranch = new Map();
    for (const x of rh?.advisories || []) {
      const m = /^php:(\d+\.\d+)-/.exec(x?.package || '');
      if (m && x.advisory && compareBranch(m[1], ver.branch) > 0 && !byBranch.has(m[1])) byBranch.set(m[1], { branch: m[1], advisory: x.advisory, build: x.package });
    }
    const list = [...byBranch.values()].sort((a, b) => compareBranch(a.branch, b.branch));
    if (list.length) switchTo = { branch: list[0].branch, build: list[0].build, streams: list.map((x) => `php:${x.branch} (${x.advisory})`) };
  }
  return {
    major,
    release,
    vendor,
    name: own(RHEL_NAMES, vendor) || 'RHEL',
    yum: Boolean(major && major < 8),
    cves: ctx.cves,
    grepCves: ctx.cves.filter((c) => !notAffected.includes(c)),
    notAffected,
    advisories,
    fixedElsewhere,
    noFix,
    switchTo,
    eolRelease: (vendor === 'centos' && Boolean(major) && major <= 8) || (vendor === 'amzn' && (release === '2' || /^201\d/.test(release))),
    stream,
    fixedNvr: nvr ? nvr[1] : null,
    // The fix is an upstream release at or above the upstream fixed version: a Red Hat rebase (php8.4 8.4.27 on
    // RHEL 10), or Amazon Linux, which ships its PHP fixes as upstream releases.
    rebase: Boolean(ctx.upstream.fixed[ver.branch]) && (vendor === 'amzn'
      || Boolean(nvr && cmpUp(nvr[1].split('-')[0], ctx.upstream.fixed[ver.branch]) >= 0)),
    module,
    glob: scl ? `'${scl}-php*'` : "'php*'",
    main,
    rh,
  };
}

// What Red Hat (or Amazon) has published for this branch and release, as one or two sentences.
function rhelContext(s, R) {
  if (R.vendor === 'amzn') return s.t('rhel.context.amazon', { release: R.release || '' }).trim();
  const vars = { branch: s.ver.branch, release: R.release };
  if (!R.release) {
    if (!R.fixedElsewhere.length) return s.t('rhel.context.noReleaseNone', { branch: s.ver.branch });
    const fixes = R.fixedElsewhere.map((x) => s.t('rhel.context.noReleaseItem', { release: x.release, advisories: x.ids.join(', ') }));
    return s.t('rhel.context.noRelease', { branch: s.ver.branch, fixes: listText(s, fixes) });
  }
  let text;
  if (R.advisories.length) {
    const ids = [...new Set(R.advisories.map((x) => `${x.advisory}${x.package ? ` (${x.package})` : ''}`))];
    text = s.t('rhel.context.advisory', { ...vars, advisories: ids.join(', ') });
  } else {
    const states = (R.rh?.states || []).filter((x) => x?.cve && x.state && stateBranch(R.rh, R.release, x.package) === s.ver.branch)
      .map((x) => `${x.cve}: ${own(RHEL_STATES, x.state) ? s.t(RHEL_STATES[x.state]) : x.state}`);
    text = states.length ? s.t('rhel.context.state', { ...vars, states: states.join(', ') }) : s.t('rhel.context.none', vars);
  }
  if (own(REBUILD_PREFIX, R.vendor) && R.advisories.length) text += ` ${s.t('rhel.rebuild', { name: R.name, prefix: REBUILD_PREFIX[R.vendor] })}`;
  return text;
}

// The PHP branch of a Red Hat package or module stream name: php:8.2-9080020261020145734.9, php-0:8.0.30-8.el9_8.1,
// php8.4-0:8.4.27-1.el10_2.
function advisoryBranch(pkg) {
  const m = /^php:(\d+\.\d+)-/.exec(pkg || '') || /^php[\d.]*-(?:\d+:)?(\d+\.\d+)\.\d+-/.exec(pkg || '');
  return m ? m[1] : null;
}

// The branch a Red Hat state applies to: a module stream (php:8.4/php) names it, the plain php package is the
// release's own branch.
function stateBranch(rh, release, pkg) {
  const m = /^php:(\d+\.\d+)(\/|$)/.exec(pkg || '') || /^php(\d+\.\d+)$/.exec(pkg || '');
  if (m) return m[1];
  return pkg === 'php' ? rhelBaseBranch(rh, release) : null;
}

// Remi's software collection of this PHP (php82), from the build or the configuration path.
function sclName(s) {
  const key = /^rpm:(php\d+)$/.exec(s.build?.key || '');
  if (key) return key[1];
  const pkg = s.pkgs.map((p) => /^(php\d+)-php(-|$)/.exec(p.name)).find(Boolean);
  if (pkg) return pkg[1];
  const path = /^\/etc\/opt\/remi\/(php\d+)(\/|$)/.exec(s.obs.configPath || '');
  return path ? path[1] : null;
}

// RHEL major version, for commands: Amazon Linux 2 is EL7-like, 2023 EL9-like, the 201x releases EL6-like.
function rhelMajor(d) {
  const rel = String(d.release || '');
  if (d.vendor === 'amzn') return rel === '2' ? 7 : rel === '2023' ? 9 : /^201\d/.test(rel) ? 6 : null;
  return Number.parseInt(rel, 10) || null;
}

// ── Remi, Alpine and other distributions ────────────────────────────

function remiSteps(s) {
  const R = rhelInfo(s);
  const what = s.t(s.names.length ? 'rhel.what.names' : 'rhel.what.all', { names: s.names.join(', ') });
  const target = s.names.length ? s.names.join(' ') : R.glob;
  const upgrade = R.yum ? `sudo yum update ${target}` : `sudo dnf upgrade --refresh ${target}`;
  const pkg = s.pkgs.find((p) => p.manager === 'rpm');
  const label = pkg ? pkgLabel(pkg) : s.obs.configPath || `PHP ${s.ver.raw}`;
  const query = s.names.length ? `rpm -q ${s.names.join(' ')}` : `rpm -qa ${R.glob}`;
  const out = [];
  if (!s.fixed) {
    // Remi's collections of end-of-life branches carry backported fixes under the same version number, so a
    // self-built backport is not offered next to them.
    out.push(step(s, 'step.remi.eol', { pkg: label, branch: s.ver.branch, what }, upgrade));
    out.push(step(s, 'step.rhel.confirm', { pkg: R.main }, `${query}\nrpm -q --changelog ${R.main} | grep ${CVE_GREP(R.cves)}`));
    out.push(restartAfterUpdate(s));
    out.push(step(s, 'step.recheckServer', {}, serverScript(s)));
    out.push(...eolSteps(s, { restart: false, backport: false }));
    return out;
  }
  out.push(step(s, 'step.remi.upgrade', { fix: s.t('fix.remi', { pkg: label, branch: s.ver.branch, fixed: s.fixed }) + eolSoon(s), what }, upgrade));
  out.push(step(s, 'step.rpm.confirmUpstream', { fixed: s.fixed, branch: s.ver.branch }, query));
  out.push(restartAfterUpdate(s));
  out.push(recheckStep(s));
  return out;
}

// Every installed package of this PHP: the PHP-FPM and Apache packages depend on the plain -common package without
// a version, so updating only some of them would leave a mix of old and new.
function apkInstalled(name) {
  return `$(apk info | grep '^${name}')`;
}

function alpineSteps(s) {
  if (!s.fixed) return eolSteps(s);
  const name = alpineName(s);
  return [
    step(s, 'step.apk.upgrade', { fix: s.t('fix.alpine', { names: s.names.length ? s.names.join(', ') : name, branch: s.ver.branch, fixed: s.fixed }) + eolSoon(s), fixed: s.fixed, name },
      `apk update\napk upgrade ${apkInstalled(name)}`),
    step(s, 'step.apk.confirm', { fixed: s.fixed, branch: s.ver.branch }, `apk list --installed '${name}*'`),
    restartAfterUpdate(s),
    recheckStep(s),
  ];
}

// Package update commands for distributions the data does not cover, when the command is certain.
function otherUpdateCommand(vendor, ver) {
  if (vendor === 'fedora') return "sudo dnf upgrade --refresh 'php*'";
  if (/^(opensuse|sles|sled)/.test(vendor || '')) return `sudo zypper refresh\nsudo zypper update 'php${ver.major}*'`;
  if (vendor === 'arch') return 'sudo pacman -Syu';
  return null;
}

function otherSteps(s) {
  const vendor = s.d.vendor || s.obs.os?.id || 'other';
  const cmd = otherUpdateCommand(vendor, s.ver);
  const vars = { vendor: s.obs.os?.pretty || vendor, fixed: s.fixed };
  if (!s.fixed) {
    // A distribution that backports fixes into its own PHP packages (SUSE): its update may carry them, and the move
    // to a supported branch is still the real fix. A source build over its packages is not offered.
    if (cmd && BACKPORTING_VENDORS.test(vendor)) {
      return lead([step(s, 'step.other.updateEol', { vendor: vars.vendor, branch: s.ver.branch }, cmd), restartAfterUpdate(s),
        eolSteps(s, { restart: false, backport: false })[0]], 1);
    }
    return eolSteps(s);
  }
  // A backport keeps the version, so running the probe again cannot show it there: the changelog check of the
  // first step does.
  if (BACKPORTING_VENDORS.test(vendor)) return [cmd ? step(s, 'step.other.update', vars, cmd) : step(s, 'step.other.updateNoCode', vars), restartAfterUpdate(s)];
  return [
    cmd ? step(s, 'step.other.update', vars, cmd) : step(s, 'step.other.updateNoCode', vars),
    restartAfterUpdate(s),
    recheckStep(s),
  ];
}

// ── Upstream builds: self-built, panels, other repositories ─────────

// The binary of this SAPI whose -i output shows the configure options, and whose -v shows its version: the name the
// distribution gives it where the layout is known (php-fpm8.2 on Debian and Ubuntu, php-fpm83 on Alpine).
function sapiBinary(s) {
  const L = s.layout;
  if (s.sapi === 'fpm-fcgi' && L?.fpmBinary) return L.fpmBinary;
  if ((s.sapi === 'cgi-fcgi' || s.sapi === 'cgi') && L?.kind === 'deb') return s.ver.major >= 7 ? `php-cgi${s.ver.branch}` : 'php5-cgi';
  return own({ 'fpm-fcgi': 'php-fpm', 'cgi-fcgi': 'php-cgi', cgi: 'php-cgi' }, s.sapi) || 'php';
}

function upstreamSteps(s) {
  // With only a header, -v output or a version, the probe shows whether this is a distribution package first.
  const out = s.fromOutside ? [probeStep(s, false)] : [];
  if (!s.fixed) {
    out.push(...eolSteps(s));
    return lead(out, out.length > 1 && s.fromOutside ? 2 : 1);
  }
  const fixed = s.fixed;
  out.push(step(s, s.fromOutside ? 'step.upstream.getUnknown' : 'step.upstream.get', { version: s.ver.raw, branch: s.ver.branch, fixed, extra: eolSoon(s) },
    `curl -fsSLO https://www.php.net/distributions/php-${fixed}.tar.xz\nsha256sum php-${fixed}.tar.xz`));
  out.push(step(s, 'step.upstream.build', { fixed },
    `${sapiBinary(s)} -i | grep -i 'configure command'\ntar -xf php-${fixed}.tar.xz\ncd php-${fixed}\n./configure <current-options>\nmake -j"$(nproc)"\n${asRootIn(s)}make install`));
  out.push(restartAfterUpdate(s));
  // The binary that serves the site; the command-line php may be another build, and mod_php has no binary.
  const binary = own({ 'fpm-fcgi': 'php-fpm', 'cgi-fcgi': 'php-cgi', cgi: 'php-cgi' }, s.sapi);
  out.push(binary ? step(s, 'step.upstream.confirmBinary', { fixed, binary }, `${binary} -v`) : step(s, 'step.upstream.confirmProbe', { fixed }));
  return out;
}

// An end-of-life branch with no fixed release: move to a supported branch, use a package that carries the
// backport (the closest one on this very server first), or build the php-src backport branch. A build from source is
// offered only for a PHP that is not a package: make install over a packaged PHP would overwrite the package's files
// (deb.sury.org builds use the prefix /usr), and its service would keep running the packaged binary.
function eolSteps(s, { restart = true, backport = s.path === 'upstream' } = {}) {
  const { ver, ctx } = s;
  const [target, alt] = supportedBranches(ctx);
  const out = [step(s, 'step.eol.move', { branch: ver.branch, target, targetFixed: ctx.upstream.fixed[target], alt, altFixed: ctx.upstream.fixed[alt] })];
  const host = hostPackage(s);
  const carriers = eolCarriers(ctx, ver, host ? `${host.family} ${host.release}` : null);
  if (host) {
    const others = carriers.length ? ` ${s.t('eol.others', { branch: ver.branch, carriers: carriers.join('; ') })}` : '';
    const pro = host.pro ? ` ${s.t('eol.hostPro')}` : '';
    const sury = host.sury ? ` ${s.t('eol.hostSury', { src: host.src, fixed: host.fixed })}` : '';
    const vars = { system: `${host.family} ${host.release}`, src: host.src, fixed: host.fixed, family: host.family, pkg: host.pkg, branch: ver.branch, extra: `${pro}${sury}${others}` };
    if (host.foreign) {
      // The installed packages of this very branch come from another repository: the distribution's own build of the
      // same packages replaces them, which apt does only when asked for that exact version.
      out.push(step(s, 'step.eol.hostSwitch', { ...vars, foreign: host.foreign, extra: `${pro}${others}` }, switchToDistroCode(host.src, host.foreign, host.fixed)));
    } else {
      out.push(host.code ? step(s, 'step.eol.host', vars, host.code) : step(s, 'step.eol.hostNoCode', vars));
    }
  } else {
    out.push(carriers.length ? step(s, 'step.eol.distro', { branch: ver.branch, carriers: carriers.join('; ') }) : step(s, 'step.eol.vendor', { branch: ver.branch }));
  }
  const branch = ctx.upstream.backport_branches?.[ver.branch];
  if (branch && backport) {
    out.push(step(s, 'step.eol.backport', { branch: ver.branch, name: branch, version: ver.upstream },
      `${sapiBinary(s)} -i | grep -i 'configure command'\ngit clone --depth 1 --branch ${branch} https://github.com/php/php-src.git\ncd php-src\n./buildconf --force\n./configure <current-options>\nmake -j"$(nproc)"\n${asRootIn(s)}make install`));
  }
  if (restart) out.push(restartAfterUpdate(s));
  return lead(out, 1);
}

// The fixed PHP package of this server's own Debian or Ubuntu release, on this branch or the nearest newer one.
function hostPackage(s) {
  const os = s.obs.os || {};
  const family = os.id === 'debian' || os.id === 'ubuntu' ? os.id : null;
  const release = family ? (s.d.family === family && s.d.release) || os.versionId : null;
  const rel = family && release ? own(s.ctx.distro[family], release) : null;
  if (!rel || s.container) return null;
  const list = Object.entries(rel.packages || {}).map(([src, entry]) => {
    if (!s.ctx.cves.every((c) => entry?.fixed?.[c])) return null;
    const fixed = s.ctx.cves.map((c) => entry.fixed[c]).sort(compareDebian).pop();
    const branch = parsePhpVersion(debUpstream(fixed))?.branch;
    return branch && compareBranch(branch, s.ver.branch) >= 0 ? { src, fixed, branch, pro: Boolean(entry.pro) } : null;
  }).filter(Boolean).sort((a, b) => compareBranch(a.branch, b.branch));
  if (!list.length) return null;
  const { src, fixed, pro } = list[0];
  const pkg = own({ apache2handler: `libapache2-mod-${src}`, 'cgi-fcgi': `${src}-cgi`, cgi: `${src}-cgi`, cli: `${src}-cli` }, s.sapi) || `${src}-fpm`;
  // deb.sury.org's packages carry the epoch 1:, so apt prefers them over the distribution's while that repository is
  // on: the step says to turn it off, and apt-cache policy shows which version apt would install.
  const sury = isSuryBuild(s.ver.raw) || s.obs.packages.some((p) => isSuryBuild(p.version));
  // This very branch is the distribution's fixed package, but another repository's build of it is installed.
  const mine = src === srcFor(s.ver) ? pickDebPackage(s.obs, s.ver, s.sapi, s.build) : null;
  const foreign = mine && !sameDeb(mine.version, fixed) ? mine.version : null;
  // Installing the Apache module package enables it right away, next to the PHP module loaded now, so no
  // command is given for it.
  const code = s.sapi === 'apache2handler' ? null : `sudo apt-get update${sury ? `\napt-cache policy ${pkg}` : ''}\nsudo apt-get install ${pkg}`;
  return { family: familyName(family), release, src, fixed, pro, pkg, code, sury, foreign };
}

// Two supported branches to move to: those with a fixed release and no announced end of life, newest first,
// leaving out the newest branch when there are more than two (applications usually need the most time for it).
function supportedBranches(ctx) {
  const eol = ctx.upstream.eol || {};
  let list = Object.keys(ctx.upstream.fixed).filter((b) => !eol[b]).sort(compareBranch).reverse();
  if (list.length > 2) list = list.slice(1);
  return [list[0], list[1] || list[0]];
}

// Distribution packages in the data that carry both fixes for this branch: "Ubuntu 22.04 (php8.1 8.1.2-1ubuntu2.28)".
function eolCarriers(ctx, ver, skip = null) {
  const out = [];
  const src = srcFor(ver);
  for (const [family, name] of [['debian', 'Debian'], ['ubuntu', 'Ubuntu']]) {
    for (const [release, rel] of Object.entries(ctx.distro[family] || {})) {
      const entry = rel?.packages?.[src];
      if (!entry || !ctx.cves.every((c) => entry.fixed?.[c]) || `${name} ${release}` === skip) continue;
      const fixed = ctx.cves.map((c) => entry.fixed[c]).sort(compareDebian).pop();
      if (parsePhpVersion(debUpstream(fixed))?.branch !== ver.branch) continue;
      out.push(`${name} ${release} (${src} ${fixed}${entry.pro ? ', Ubuntu Pro' : ''})`);
    }
  }
  for (const [release, rel] of Object.entries(ctx.distro.redhat || {})) {
    const advs = (rel?.advisories || []).filter((x) => x?.advisory && advisoryBranch(x.package) === ver.branch);
    if (!ctx.cves.every((c) => advs.some((x) => x.cve === c))) continue;
    out.push(`RHEL ${release} (${advs[0].package}, ${[...new Set(advs.map((x) => x.advisory))].join(', ')})`);
  }
  return out;
}

// " PHP 8.2 reaches end of life on 31 December 2026, so plan the move to 8.3 or 8.4 as well." for a branch whose
// end of life is announced in upstream.json; empty otherwise.
function eolSoon(s) {
  const date = s.ver && s.fixed ? s.ctx.upstream.eol?.[s.ver.branch] : null;
  if (!date) return '';
  const [high, low] = supportedBranches(s.ctx);
  const past = String(s.ctx.upstream.updated || '') >= date;
  return ` ${s.t(past ? 'branch.eolPast' : 'branch.eolSoon', { branch: s.ver.branch, date: formatDate(date, s.ctx.lang), low, high })}`;
}

// ── Containers ──────────────────────────────────────────────────────

function containerSteps(s) {
  // The official image keeps PHP outside the package manager, whatever its base system.
  if (s.official && !s.pkgs.length && ['upstream', 'alpine', 'other'].includes(s.path)) return dockerSteps(s);
  const out = [];
  let pro = false;
  if (['deb', 'sury', 'rhel', 'remi', 'alpine'].includes(s.path)) {
    if (s.r.verdict === 'pending') {
      const D = debInfo(s);
      out.push(step(s, 'step.pending.watch', { family: D.family, release: D.release, src: D.src }, trackerUrls(s.d.family, s.ctx.cves)));
      return lead(out, 1);
    }
    const D = s.path === 'deb' ? debInfo(s) : null;
    if (D?.pro && D.release !== '14.04') {
      // The fix is only in Ubuntu Pro, which an image build sees only while it is attached.
      pro = true;
      out.push(step(s, 'step.container.updatePro', { fix: containerFix(s) }, containerProLines(s)));
    } else {
      out.push(step(s, 'step.container.update', { fix: containerFix(s) }, containerRunLine(s)));
    }
  } else if (s.fixed && s.path === 'other') {
    out.push(step(s, 'step.container.other', { vendor: s.obs.os?.pretty || s.d.vendor || s.obs.os?.id || 'other', fixed: s.fixed }));
  } else if (s.fixed) {
    out.push(step(s, 'step.container.upstream', { version: s.ver.raw, branch: s.ver.branch, fixed: s.fixed, extra: eolSoon(s) }));
  } else {
    const [target, alt] = supportedBranches(s.ctx);
    out.push(step(s, 'step.container.eol', { version: s.ver.raw, branch: s.ver.branch, target, targetFixed: s.ctx.upstream.fixed[target], alt, altFixed: s.ctx.upstream.fixed[alt] }));
  }
  out.push(rebuildStep(s, pro));
  out.push(containerConfirm(s));
  return lead(out, 1);
}

// What fixes the PHP of a container that comes from distribution packages, as one sentence.
function containerFix(s) {
  if (s.path === 'deb') {
    const D = debInfo(s);
    if (D.fixed && D.installed) return s.t('fix.deb', { pkg: D.installed, family: D.family, release: D.release, src: D.src, fixed: D.fixed });
    if (D.fixed) return s.t('fix.debRunning', { version: s.ver.raw, family: D.family, release: D.release, src: D.src, fixed: D.fixed });
    return s.t('fix.debOpen', { family: D.family, src: D.src });
  }
  if (s.path === 'rhel') return rhelContext(s, rhelInfo(s));
  const pkg = s.pkgs[0];
  const label = pkg ? pkgLabel(pkg) : `PHP ${s.ver.raw}`;
  if (!s.fixed) return s.t('reason.eol', { branch: s.ver.branch });
  if (s.path === 'sury') return s.t('fix.sury', { pkg: label, branch: s.ver.branch, fixed: s.fixed }) + eolSoon(s);
  if (s.path === 'remi') return s.t('fix.remi', { pkg: label, branch: s.ver.branch, fixed: s.fixed }) + eolSoon(s);
  return s.t('fix.alpine', { names: s.names.join(', ') || alpineName(s), branch: s.ver.branch, fixed: s.fixed }) + eolSoon(s);
}

// The Dockerfile line that updates this PHP's packages in the image.
function containerRunLine(s) {
  if (s.path === 'deb' || s.path === 'sury') {
    return s.names.length ? `RUN apt-get update && apt-get install -y --only-upgrade ${s.names.join(' ')}` : 'RUN apt-get update && apt-get -y upgrade';
  }
  if (s.path === 'rhel' || s.path === 'remi') {
    const target = s.names.length ? s.names.join(' ') : rhelInfo(s).glob;
    return (rhelMajor(s.d) || 9) < 8 ? `RUN yum -y update ${target}` : `RUN dnf -y upgrade --refresh ${target}`;
  }
  if (s.path === 'alpine') return `RUN apk upgrade --no-cache ${apkInstalled(alpineName(s))}`;
  return null;
}

// The Dockerfile lines that attach Ubuntu Pro for the build only (the token comes in as a build secret and is
// never stored in the image), update the PHP packages, and detach again.
function containerProLines(s) {
  const names = s.names.length ? s.names.join(' ') : `$(dpkg -l '${debSrc(s)}-*' 'libapache2-mod-${debSrc(s)}' 2>/dev/null | awk '/^ii/ {print $2}')`;
  return [
    'RUN --mount=type=secret,id=pro-attach-config \\',
    '    apt-get update && apt-get install -y --no-install-recommends ubuntu-advantage-tools ca-certificates && \\',
    '    pro attach --attach-config /run/secrets/pro-attach-config && \\',
    `    apt-get update && apt-get install -y --only-upgrade ${names} && \\`,
    '    pro detach --assume-yes',
  ].join('\n');
}

function containerConfirm(s) {
  let code = null;
  if (s.path === 'deb' || s.path === 'sury') code = `docker exec <container> ${dpkgVersions(s, debSrc(s))}`;
  else if (s.path === 'remi') code = `docker exec <container> rpm -q ${s.names.length ? s.names.join(' ') : rhelInfo(s).main}`;
  else if (s.path === 'alpine') code = `docker exec <container> apk list --installed '${alpineName(s)}*'`;
  else if (s.path === 'rhel') {
    // Red Hat backports the fix without changing the upstream version, so the changelog shows it.
    const R = rhelInfo(s);
    const query = `docker exec <container> rpm -q ${s.names.length ? s.names.join(' ') : R.main}`;
    // A fix that is a new upstream release shows in the version, not in the changelog.
    if (R.rebase) return step(s, 'step.container.confirmFixed', { fixed: R.fixedNvr || s.fixed }, query);
    const grep = `docker exec <container> sh -c "rpm -q --changelog ${R.main} | grep ${CVE_GREP(R.grepCves)}"`;
    const cves = R.grepCves.join(', ');
    return R.fixedNvr ? step(s, 'step.container.confirmChangelogFixed', { pkg: R.main, fixed: R.fixedNvr, cves }, `${query}\n${grep}`)
      : step(s, 'step.container.confirmChangelog', { pkg: R.main, cves }, `${query}\n${grep}`);
  }
  if (!code) {
    const fixed = s.fixed || s.ctx.upstream.fixed[supportedBranches(s.ctx)[0]];
    return step(s, 'step.docker.confirm', { fixed }, "docker exec <container> php -r 'echo PHP_VERSION, PHP_EOL;'");
  }
  const fixed = s.path === 'deb' ? debInfo(s).fixed : s.fixed;
  return fixed ? step(s, 'step.container.confirmFixed', { fixed }, code) : step(s, 'step.container.confirm', {}, code);
}

// Rebuild with --pull and recreate: plain Docker, and Compose for services that build an image and for those
// that use one directly (image: in compose.yaml).
function rebuildStep(s, pro = false) {
  const secret = pro ? ' --secret id=pro-attach-config,src=pro-attach-config.yaml' : '';
  return step(s, 'step.docker.rebuild', {},
    `# Docker\ndocker build --pull${secret} -t <your-image> .\n# Docker Compose\ndocker compose build --pull\ndocker compose pull --ignore-buildable\ndocker compose up -d`);
}

// The official PHP image: the exact tag of the fixed release in the same variant, rebuild, confirm.
function dockerSteps(s) {
  const { ver } = s;
  const out = [];
  let expect = s.fixed;
  if (!s.fixed) {
    const [target, alt] = supportedBranches(s.ctx);
    expect = s.ctx.upstream.fixed[target];
    const v = dockerVariant(s, expect);
    out.push(step(s, 'step.docker.eol', { version: ver.raw, branch: ver.branch, targetFixed: expect, altFixed: s.ctx.upstream.fixed[alt], extra: v.extra },
      `FROM php:${expect}${v.sapi ? `-${v.sapi}` : '-<variant>'}${v.os}`));
  } else if (s.sapi === 'frankenphp') {
    out.push(step(s, 'step.docker.frankenphp', { version: ver.raw, branch: ver.branch, fixed: s.fixed }));
  } else {
    const v = dockerVariant(s, s.fixed);
    const extra = `${v.extra}${eolSoon(s)}`;
    if (v.sapi) {
      const suffix = `-${v.sapi}${v.os}`;
      out.push(step(s, 'step.docker.tag', { version: ver.raw, branch: ver.branch, fixed: s.fixed, variant: v.kept ? suffix : `-${v.sapi}`, floating: `${ver.branch}${suffix}`, extra },
        `FROM php:${s.fixed}${suffix}`));
    } else {
      out.push(step(s, 'step.docker.tagNoVariant', { version: ver.raw, branch: ver.branch, fixed: s.fixed, extra }, `FROM php:${s.fixed}-<variant>${v.os}`));
    }
  }
  out.push(rebuildStep(s));
  out.push(step(s, 'step.docker.confirm', { fixed: expect }, "docker exec <container> php -r 'echo PHP_VERSION, PHP_EOL;'"));
  return lead(out, 1);
}

// The variant part of an official PHP image tag: the SAPI (apache, fpm, cli) and the base system: the Alpine
// release or Debian codename the image uses now when tags for it are still published, otherwise the nearest newer
// one, with a sentence that says so.
function dockerVariant(s, fixed) {
  const sapi = own({ apache2handler: 'apache', 'fpm-fcgi': 'fpm', cli: 'cli' }, s.sapi) || null;
  const os = s.obs.os || {};
  let suffix = '';
  let extra = '';
  let kept = true;
  if (os.id === 'alpine') {
    const rel = /^(\d+\.\d+)/.exec(os.versionId || '')?.[1] || null;
    if (rel && DOCKER_ALPINE.includes(rel)) suffix = `-alpine${rel}`;
    else {
      suffix = '-alpine';
      if (rel) extra = ` ${s.t('docker.alpineFloating', { release: rel, example: `php:${fixed}-${sapi || 'cli'}-alpine${DOCKER_ALPINE[DOCKER_ALPINE.length - 1]}` })}`;
    }
  } else if (os.id === 'debian') {
    const known = own(s.ctx.distro.debian, os.versionId)?.codename;
    const number = Number.parseInt(os.versionId, 10) || own(DEBIAN_RELEASES, os.codename) || own(DEBIAN_RELEASES, known) || null;
    const codename = os.codename || known || Object.keys(DEBIAN_RELEASES).find((k) => DEBIAN_RELEASES[k] === number) || null;
    const hit = DOCKER_DEBIAN.find((x) => x.codename === codename || x.release === number);
    if (hit) suffix = `-${hit.codename}`;
    else if (number && number < DOCKER_DEBIAN[0].release) {
      const to = DOCKER_DEBIAN[0];
      suffix = `-${to.codename}`;
      kept = false;
      extra = ` ${s.t('docker.oldDebian', { from: number, fromName: codename || number, to: to.release, toName: to.codename })}`;
    } else if (codename) extra = ` ${s.t('docker.otherDebian', { codename })}`;
  }
  return { sapi, os: suffix, extra, kept };
}

// ── Restart ─────────────────────────────────────────────────────────

// The restart step after an update: the exact command when the service is known, a marked placeholder for a
// self-built PHP-FPM, otherwise the advice alone.
function restartAfterUpdate(s) {
  if (s.container) return null;
  const plan = restartPlan(s) || restartPlaceholder(s);
  if (plan) return step(s, 'action.restartAfterUpdate', { extra: plan.extra }, plan.code);
  return step(s, 'action.restartAfterUpdateGeneric');
}

// A restart as a precaution, when the installed package has the fix but the running processes could not be checked.
function restartIfUnsure(s) {
  const plan = s.container ? null : restartPlan(s);
  return plan ? step(s, 'step.restart.ifUnsure', { extra: plan.extra }, plan.code) : null;
}

// The services to restart, as commands for the init system of this distribution: those of the processes still
// using old files, else those of every process the server script saw running this build (Apache with mod_php and
// PHP-FPM can both run it), else the one of the SAPI. null when the layout is unknown (self-built, panels, others).
function restartPlan(s) {
  const L = s.layout;
  if (!L || L.kind === 'docker') return null;
  const stale = s.info.stale || [];
  const comms = stale.length ? stale : s.info.running || [];
  if (comms.length) {
    const services = [...new Set(comms.map((c) => serviceForComm(L, c)))];
    if (!services.includes(null)) {
      return { code: services.map((x) => serviceCommand(L, 'restart', x)).join('\n'), extra: services.includes(L.apacheService) ? s.t('restart.modPhp') : '' };
    }
    if (stale.length) return null;
  }
  if (s.sapi === 'apache2handler') return { code: serviceCommand(L, 'restart', L.apacheService), extra: s.t('restart.modPhp') };
  if (s.sapi === 'fpm-fcgi') return { code: serviceCommand(L, 'restart', L.fpmService), extra: '' };
  if (s.sapi === 'cgi-fcgi' || s.sapi === 'cgi') {
    // php-cgi is started by the web server (mod_fcgid) or a FastCGI process manager, not by a service of its own.
    return {
      code: `${serviceCommand(L, 'restart', L.apacheService)}   # Apache mod_fcgid\nps -eo pid,lstart,args | grep -E '[p]hp-cgi|[c]gi-bin/php'`,
      extra: s.t('restart.cgi'),
    };
  }
  return {
    code: `${serviceCommand(L, 'restart', L.apacheService)}   # Apache mod_php\n${serviceCommand(L, 'restart', L.fpmService)}   # PHP-FPM`,
    extra: s.t('restart.choose'),
  };
}

// The service names a distribution gives Apache and PHP-FPM, where they are fixed. A self-built PHP-FPM has a
// service of the admin's choosing.
function serviceNames(s) {
  const vendor = s.d.vendor || s.obs.os?.id || '';
  if (s.d.family === 'debian' || s.d.family === 'ubuntu') return { apache: 'apache2', fpm: null };
  if (s.d.family === 'rhel') return { apache: 'httpd', fpm: null };
  if (s.d.family === 'other' && s.path === 'other') {
    if (vendor === 'fedora' || vendor === 'arch') return { apache: 'httpd', fpm: 'php-fpm' };
    if (/^(opensuse|sles|sled)/.test(vendor)) return { apache: 'apache2', fpm: 'php-fpm' };
  }
  return { apache: null, fpm: null };
}

// A restart command for a PHP whose layout is not known: the names the distribution fixes, else a marked placeholder.
function restartPlaceholder(s) {
  const names = serviceNames(s);
  if (s.sapi === 'apache2handler') {
    const apache = names.apache || '<apache-service>';
    const cmd = s.d.family === 'rhel' && (rhelMajor(s.d) || 9) < 7 ? `sudo service ${apache} restart` : `sudo systemctl restart ${apache}`;
    return { code: cmd, extra: s.t('restart.modPhp') };
  }
  if (s.sapi === 'fpm-fcgi') return { code: `sudo systemctl restart ${names.fpm || '<php-fpm-service>'}`, extra: '' };
  return null;
}

function serviceCommand(L, action, service) {
  if (L.init === 'openrc') return `rc-service ${service} ${action}`;
  if (L.init === 'sysv') return `sudo service ${service} ${action}`;
  return `sudo systemctl ${action} ${service}`;
}

// The service that starts a process the server script saw, in this distribution's naming.
function serviceForComm(L, comm) {
  if (L.kind === 'deb') {
    const m = /^php-fpm(\d+\.\d+)$/.exec(comm);
    if (m) return `php${m[1]}-fpm`;
    if (comm === 'php5-fpm') return 'php5-fpm';
    return comm === 'apache2' ? 'apache2' : null;
  }
  if (L.kind === 'rhel' || L.kind === 'scl') {
    if (comm === 'php-fpm') return L.fpmService;
    return comm === 'httpd' ? 'httpd' : null;
  }
  if (L.kind === 'alpine') {
    const m = /^php-fpm(\d+)$/.exec(comm);
    if (m) return `php-fpm${m[1]}`;
    return comm === 'httpd' || comm === 'apache2' ? 'apache2' : null;
  }
  return null;
}

// Where this PHP keeps its files and what its services are called, for the distributions whose layout is known.
function phpLayout(s) {
  const { d, ver, path } = s;
  const cp = s.obs.configPath || '';
  const sapiDir = own({ apache2handler: 'apache2', 'fpm-fcgi': 'fpm', 'cgi-fcgi': 'cgi', cgi: 'cgi', cli: 'cli' }, s.sapi);
  if (s.official) return { kind: 'docker' };
  // A packaged build judged on upstream releases (its version already has the fix) keeps its distribution layout.
  const by = (manager) => s.pkgs.some((p) => p.manager === manager);
  const underEtc = /^\/etc(\/|$)/.test(cp);
  if ((d.family === 'debian' || d.family === 'ubuntu') && (path === 'deb' || path === 'sury' || by('dpkg') || /^\/etc\/php5?\//.test(cp))) {
    const base = ver.major >= 7 ? `/etc/php/${ver.branch}` : '/etc/php5';
    // A release that is not known (Debian testing has none) is a current, systemd one.
    const old = (d.family === 'ubuntu' && d.release === '14.04') || (d.family === 'debian' && d.release && Number(d.release) <= 7);
    return {
      kind: 'deb',
      init: old ? 'sysv' : 'systemd',
      confDir: sapiDir ? `${base}/${sapiDir}/conf.d` : null,
      poolDir: `${base}/fpm/pool.d`,
      fpmService: `${srcFor(ver)}-fpm`,
      fpmBinary: ver.major >= 7 ? `php-fpm${ver.branch}` : 'php5-fpm',
      apacheService: 'apache2',
      apacheFile: '/etc/apache2/conf-available/php2shell-mitigation.conf',
      apacheEnable: 'sudo a2enconf php2shell-mitigation',
      apacheTest: 'sudo apachectl configtest',
    };
  }
  const rhelLike = { apacheService: 'httpd', apacheFile: '/etc/httpd/conf.d/php2shell-mitigation.conf', apacheEnable: null, apacheTest: 'sudo apachectl configtest' };
  if (d.family === 'rhel' && (path === 'rhel' || path === 'remi' || by('rpm') || (path === 'upstream' && underEtc))) {
    const init = (rhelMajor(d) || 9) < 7 ? 'sysv' : 'systemd';
    const scl = sclName(s);
    if (scl) {
      return { ...rhelLike, init, kind: 'scl', confDir: `/etc/opt/remi/${scl}/php.d`, poolDir: `/etc/opt/remi/${scl}/php-fpm.d`, fpmService: `${scl}-php-fpm`, fpmBinary: `/opt/remi/${scl}/root/usr/sbin/php-fpm` };
    }
    return { ...rhelLike, init, kind: 'rhel', confDir: '/etc/php.d', poolDir: '/etc/php-fpm.d', fpmService: 'php-fpm', fpmBinary: 'php-fpm' };
  }
  // Fedora packages PHP the way RHEL does.
  if (d.family === 'other' && d.vendor === 'fedora' && path === 'other' && (!cp || underEtc)) {
    return { ...rhelLike, init: 'systemd', kind: 'rhel', confDir: '/etc/php.d', poolDir: '/etc/php-fpm.d', fpmService: 'php-fpm', fpmBinary: 'php-fpm' };
  }
  if (d.family === 'alpine' && (path === 'alpine' || by('apk'))) {
    const name = alpineName(s);
    const n = name.slice(3);
    return {
      kind: 'alpine',
      init: 'openrc',
      confDir: `/etc/${name}/conf.d`,
      poolDir: `/etc/${name}/php-fpm.d`,
      fpmService: `php-fpm${n}`,
      fpmBinary: `php-fpm${n}`,
      apacheService: 'apache2',
      apacheFile: '/etc/apache2/conf.d/php2shell-mitigation.conf',
      apacheEnable: null,
      apacheTest: 'httpd -t',
    };
  }
  return null;
}

// The Alpine package prefix of this PHP: php83 (from the installed packages, the configuration path or the version).
function alpineName(s) {
  const pkg = s.pkgs.map((p) => /^(php\d*)/.exec(p.name)).find(Boolean);
  if (pkg) return pkg[1];
  const path = /^\/etc\/(php\d+)$/.exec(s.obs.configPath || '');
  return path ? path[1] : `php${s.ver.major}${s.ver.minor}`;
}

// ── Confirmation, mitigations, hardening ────────────────────────────

function recheckStep(s) {
  return s.obs.sources.includes('servercheck') ? step(s, 'step.recheckServer', {}, serverScript(s)) : step(s, 'step.recheck');
}

// The interim mitigations of the official advisory, ready to paste where the place is known: an Apache mod_php
// configuration file and a PHP-FPM pool file (both when the server script saw both running this PHP), an ini file
// for CGI, the official image's ini directory, or a self-built PHP's php.ini; otherwise as text. They never replace
// the fix, and the text says so.
function mitigationSteps(s, whenKey) {
  const when = s.t(whenKey);
  const ini = s.obs.ini;
  const php85 = s.ver?.branch === '8.5';
  const sessionOff = s.obs.extensions && s.obs.extensions.session === false;
  const inPlace = ini && isOff(ini['session.upload_progress.enabled']) && (!php85 || isOff(ini.fatal_error_backtraces));
  const generic = [step(s, s.r.mitigations.length ? 'action.applyMitigations' : 'action.applyMitigationsAdvisory', { when })];
  if (!s.ver || sessionOff || inPlace) return generic;
  const extra = php85 ? s.t('mitigate.fatalBacktraces') : '';
  const settings = ['session.upload_progress.enabled = 0', ...(php85 ? ['fatal_error_backtraces = 0'] : [])];
  if (s.official && s.container) {
    const file = '"$PHP_INI_DIR/conf.d/zz-php2shell-mitigation.ini"';
    const lines = settings.join('\\n');
    return [step(s, 'step.mitigate.docker', { when, extra }, [
      `docker exec -u 0 <container> sh -c 'printf "${lines}\\n" > ${file}'`,
      'docker restart <container>',
      '# Dockerfile',
      `RUN printf '${lines}\\n' > ${file}`,
    ].join('\n'))];
  }
  const L = s.layout;
  if (L && L.kind !== 'docker' && !s.container) {
    const running = s.info.running || [];
    const apache = s.sapi === 'apache2handler' || running.some((c) => c === 'apache2' || c === 'httpd');
    const fpm = s.sapi === 'fpm-fcgi' || running.some((c) => /^php-fpm/.test(c));
    const out = [];
    if (apache && L.apacheFile) {
      const module = s.ver.major >= 8 ? 'php_module' : s.ver.major === 7 ? 'php7_module' : 'php5_module';
      const lines = [`<IfModule ${module}>`, '    php_admin_flag session.upload_progress.enabled off'];
      if (php85) lines.push('    php_admin_flag fatal_error_backtraces off');
      lines.push('    # php_admin_value memory_limit -1', '</IfModule>');
      const code = [`${asRoot(L, `tee ${L.apacheFile}`)} >/dev/null <<'EOF'`, ...lines, 'EOF'];
      if (L.apacheEnable) code.push(L.apacheEnable);
      code.push(`${L.apacheTest} && ${serviceCommand(L, 'reload', L.apacheService)}`);
      out.push(step(s, 'step.mitigate.apache', { when, extra }, code.join('\n')));
    }
    if (fpm && L.poolDir) {
      const lines = ['[www]', 'php_admin_flag[session.upload_progress.enabled] = off'];
      if (php85) lines.push('php_admin_flag[fatal_error_backtraces] = off');
      lines.push('; php_admin_value[memory_limit] = -1');
      const reload = serviceCommand(L, 'reload', L.fpmService);
      const code = [`${asRoot(L, `tee ${L.poolDir}/zz-php2shell-mitigation.conf`)} >/dev/null <<'EOF'`, ...lines, 'EOF',
        L.fpmBinary ? `${asRoot(L, `${L.fpmBinary} -t`)} && ${reload}` : reload];
      // A reload makes PHP-FPM run its binary from disk again. When its processes still use files from before the
      // last package change, and that change may have been a downgrade, the step says so.
      const staleFpm = (s.info.stale || []).filter((c) => /^php\d*-fpm/.test(c));
      const fpmExtra = staleFpm.length ? `${extra}${s.t('mitigate.staleReload', { names: staleFpm.join(', ') })}` : extra;
      // After the Apache step, the same text again would only repeat it.
      out.push(out.length ? step(s, 'step.mitigate.fpmAlso', { extra: fpmExtra }, code.join('\n')) : step(s, 'step.mitigate.fpm', { when, extra: fpmExtra }, code.join('\n')));
    }
    if (!out.length && (s.sapi === 'cgi-fcgi' || s.sapi === 'cgi') && L.confDir) {
      const plan = restartPlan(s);
      const file = `${L.confDir}/99-php2shell-mitigation.ini`;
      const code = settings.map((x, i) => `echo '${x}' | ${asRoot(L, `tee ${i ? '-a ' : ''}${file}`)} >/dev/null`);
      out.push(plan ? step(s, 'step.mitigate.ini', { when, extra, file }, [...code, plan.code].join('\n'))
        : step(s, 'step.mitigate.iniNoRestart', { when, extra, file }, code.join('\n')));
    }
    if (out.length) return out;
  }
  // A self-built PHP reads php.ini in its own configuration directory.
  if (!s.container && s.path === 'upstream' && s.obs.configPath && !/^\/etc(\/|$)/.test(s.obs.configPath)) {
    const file = `${s.obs.configPath.replace(/\/+$/, '')}/php.ini`;
    const plan = restartPlaceholder(s);
    const code = settings.map((x) => `echo '${x}' | ${asRootIn(s)}tee -a ${file} >/dev/null`);
    return [plan ? step(s, 'step.mitigate.ini', { when, extra, file }, [...code, plan.code].join('\n'))
      : step(s, 'step.mitigate.iniNoRestart', { when, extra, file }, code.join('\n'))];
  }
  return generic;
}

function asRoot(L, cmd) {
  return L.init === 'openrc' ? cmd : `sudo ${cmd}`;
}

// expose_php = Off for this PHP: an ini file in the directory this SAPI reads, then a restart of its service.
function exposeStep(s) {
  if (s.official) return step(s, 'step.hardening.exposeDocker', {}, 'RUN echo \'expose_php = Off\' > "$PHP_INI_DIR/conf.d/zz-hardening.ini"');
  const L = s.layout;
  const plan = L && L.confDir ? restartPlan(s) : null;
  if (plan && !s.container) {
    return step(s, 'step.hardening.expose', {}, `echo 'expose_php = Off' | ${asRoot(L, `tee ${L.confDir}/99-hardening.ini`)}\n${plan.code}`);
  }
  if (s.obs.configPath) return step(s, 'step.hardening.exposePath', { path: s.obs.configPath });
  return step(s, 'step.hardening.exposeManual');
}

// When patched is true, the interim mitigations meant for unpatched servers are shown for reference only.
export function evaluateMitigations(ini, extensions, ver, patched = false, lang = 'en') {
  const t = translator(lang);
  const items = [];
  const sessionLoaded = !extensions || extensions.session !== false;
  const add = (name, value, status, note) => items.push({
    name,
    value: value === null || value === undefined ? t('mit.value.notSet') : value === '' ? t('mit.value.emptyOff') : String(value),
    status,
    note: t(note),
  });

  const mem = ini.memory_limit;
  if (patched) {
    add('memory_limit', mem, 'info', mem === '-1' ? 'mit.memoryLimit.patchedUnlimited' : 'mit.noChangeNeeded');
  } else {
    add('memory_limit', mem, mem === '-1' ? 'ok' : 'warn', mem === '-1' ? 'mit.memoryLimit.unlimited' : 'mit.memoryLimit.suggest');
  }

  const up = ini['session.upload_progress.enabled'];
  if (!sessionLoaded) {
    add('session.upload_progress.enabled', up, 'ok', 'mit.uploadProgress.noSession');
  } else {
    add('session.upload_progress.enabled', up, isOff(up) ? 'ok' : patched ? 'info' : 'warn',
      isOff(up)
        ? 'mit.uploadProgress.off'
        : patched
          ? 'mit.uploadProgress.patchedOn'
          : 'mit.uploadProgress.suggest');
    const auto = ini['session.auto_start'];
    if (!patched || !isOff(auto)) {
      add('session.auto_start', auto, isOff(auto) ? 'ok' : patched ? 'info' : 'warn',
        isOff(auto)
          ? 'mit.autoStart.off'
          : patched
            ? 'mit.noChangeNeeded'
            : 'mit.autoStart.suggest');
    }
  }

  const fb = ini.fatal_error_backtraces;
  if (!patched && fb !== null && fb !== undefined && ver && ver.branch === '8.5') {
    add('fatal_error_backtraces', fb, isOff(fb) ? 'ok' : 'warn', isOff(fb) ? 'mit.fatalBacktraces.off' : 'mit.fatalBacktraces.suggest');
  }

  const nest = ini.max_input_nesting_level;
  if (nest !== null && nest !== undefined) {
    add('max_input_nesting_level', nest, 'info', 'mit.nestingLevel');
  }
  if (ini.post_max_size !== null && ini.post_max_size !== undefined) {
    add('post_max_size', ini.post_max_size, 'info', 'mit.postMaxSize');
  }
  if (ini.expose_php !== null && ini.expose_php !== undefined) {
    add('expose_php', ini.expose_php, isOff(ini.expose_php) ? 'ok' : 'info', isOff(ini.expose_php) ? 'mit.exposePhp.off' : 'mit.exposePhp.on');
  }
  return items;
}

export function sapiExposure(sapi, lang = 'en') {
  const t = translator(lang);
  switch (sapi) {
    case 'apache2handler':
      return { level: 'high', text: t('exposure.apache2handler') };
    case 'frankenphp':
      return { level: 'high', text: t('exposure.frankenphp') };
    case 'fpm-fcgi':
      return { level: 'medium', text: t('exposure.fpm') };
    case 'litespeed':
      return { level: 'medium', text: t('exposure.litespeed') };
    case 'cli':
      return { level: 'info', text: t('exposure.cli') };
    default:
      return { level: 'medium', text: t('exposure.other', { sapi }) };
  }
}

function pickDebPackage(obs, ver, sapi, build) {
  const pool = build ? build.packages : obs.packages;
  const same = pool.filter((p) => p.manager === 'dpkg' && debSource(p) === srcFor(ver));
  const prefer = own({
    apache2handler: /^libapache2-mod-php/,
    'fpm-fcgi': /-fpm$/,
    'cgi-fcgi': /-cgi$/,
    cgi: /-cgi$/,
    cli: /-cli$/,
  }, sapi);
  return (prefer && same.find((p) => prefer.test(p.name))) || same.find((p) => /-common$/.test(p.name)) || same[0] || null;
}

function debSource(p) {
  return p.source || p.name.replace(/^libapache2-mod-/, '').replace(/-(common|fpm|cli|cgi)$/, '');
}

// The Debian/Ubuntu source package name of a PHP branch: php8.2, php7.4, php5.
function srcFor(ver) {
  return ver.major >= 7 ? `php${ver.branch}` : `php${ver.major}`;
}

// The upstream version of a release's fixed package ("8.3.6" for 8.3.6-0ubuntu0.24.04.13), or null.
function entryUpstream(entry, cves) {
  const fixed = cves.map((c) => entry?.fixed?.[c]).find(Boolean);
  return fixed ? debUpstream(fixed) : null;
}

// Releases that may ship exactly this version with the fixes backported, as labels: Debian and Ubuntu releases
// whose package has this upstream version, and RHEL releases with a fix that keeps the version number (an
// advisory for exactly this version, or a module stream fix for this branch: a stream keeps the upstream version it
// started with, which the data does not give, so any version of that branch below the upstream fix may be one).
function sameUpstreamReleases(ctx, ver) {
  const out = [];
  for (const [family, name] of [['debian', 'Debian'], ['ubuntu', 'Ubuntu']]) {
    for (const [release, rel] of Object.entries(ctx.distro[family] || {})) {
      if (entryUpstream(rel.packages?.[srcFor(ver)], ctx.cves) === ver.upstream) out.push(`${name} ${release}`);
    }
  }
  for (const [release, rel] of Object.entries(ctx.distro.redhat || {})) {
    const keeps = (rel.advisories || []).some((x) => {
      const nevra = /^php[\d.]*-(?:\d+:)?(\d+\.\d+\.\d+)-/.exec(x.package || '');
      if (nevra) return nevra[1] === ver.upstream;
      const stream = /^php:(\d+\.\d+)-/.exec(x.package || '');
      return Boolean(stream) && stream[1] === ver.branch;
    });
    if (keeps) out.push(`RHEL ${release}`);
  }
  return out;
}

function debAtLeast(version, fixed) {
  return compareDebian(debComparable(version), debComparable(fixed)) >= 0;
}

function sameDeb(a, b) {
  return compareDebian(debComparable(a), debComparable(b)) === 0;
}

function maxFixed(states) {
  return states.filter((s) => s.fixed).map((s) => s.fixed).sort(compareDebian).pop();
}

// Compares two upstream version strings; null when either cannot be read.
function cmpUp(a, b) {
  const pa = parsePhpVersion(a);
  const pb = parsePhpVersion(b);
  return pa && pb ? comparePhp(pa, pb) : null;
}

const pkgLabel = (p) => `${p.name} ${p.version}`;

// The distribution to judge against. A choice in the Distribution list is used unless the pasted output
// contradicts it: then the detected distribution is used, and d.overridden says what was chosen and why.
export function detectDistro(obs, ver, distro, override, build) {
  distro = distro || {};
  const auto = autoDistro(obs, ver, distro, build);
  if (!override || override === 'auto') return auto;
  const [family, release] = override.split(':');
  const manual = { family, release: release || null, how: 'manual' };
  const by = manualConflict(ver, auto, manual);
  return by ? { ...auto, overridden: { chosen: manual, by } } : manual;
}

// What in the pasted output contradicts a Distribution list choice: the OS release or a RHEL kernel ('os'), a
// distribution revision in the version string ('version'), or nothing (null). A distribution the data does not
// cover ('other') does not contradict a choice, nor does a release that could not be told.
function manualConflict(ver, auto, manual) {
  const revision = ver?.revision || '';
  if (manual.family === 'upstream') {
    // An upstream build never carries a distribution revision (deb.sury.org builds are judged by upstream anyway).
    return /ubuntu|[~+]deb\d+u\d+|\.el\d/.test(revision) && !isSuryBuild(revision) ? 'version' : null;
  }
  const known = ['debian', 'ubuntu', 'rhel', 'alpine'];
  if (['os', 'derived', 'kernel'].includes(auto.how) && known.includes(auto.family)) {
    if (auto.family !== manual.family) return 'os';
    return auto.release && manual.release && auto.release !== manual.release ? 'os' : null;
  }
  if (auto.how === 'suffix' && auto.family) {
    if (auto.family !== manual.family) return 'version';
    return auto.release && manual.release !== auto.release ? 'version' : null;
  }
  return null;
}

function overrideNote(t, d, obs, ver) {
  const chosen = plainDistroLabel(t, d.overridden.chosen);
  return d.overridden.by === 'os'
    ? t('note.manualConflictOs', { chosen, detected: distroLabel(t, d, obs) })
    : t('note.manualConflictVersion', { chosen, detected: plainDistroLabel(t, d), version: ver.raw });
}

function autoDistro(obs, ver, distro, build) {
  const os = obs.os || {};
  const like = `${os.id || ''} ${os.idLike || ''}`;
  // Installed package versions of this branch, which can name the release ("8.2.35-1~deb12u1").
  const pkgVersions = ver
    ? (build ? build.packages : obs.packages || []).filter((p) => p.manager === 'dpkg' && debSource(p) === srcFor(ver)).map((p) => p.version)
    : [];
  if (os.id === 'debian' || os.id === 'ubuntu') {
    const release = os.versionId || codenameToRelease(distro[os.id], os.codename);
    if (release) return { family: os.id, release, how: 'os' };
    const inferred = ver ? inferRelease(os.id, ver, distro, pkgVersions) : null;
    return { family: os.id, release: inferred, how: inferred ? 'suffix' : 'os' };
  }
  if (RHEL_IDS.includes(os.id) || (/\brhel\b/.test(like) && os.id !== 'fedora')) {
    return { family: 'rhel', release: (os.versionId || '').split('.')[0] || null, how: 'os', vendor: os.id };
  }
  if (os.id === 'alpine') return { family: 'alpine', release: os.versionId || null, how: 'os' };
  if (os.id) {
    // Derivatives (Linux Mint, LMDE, Pop!_OS, Raspbian and others) use their parent's PHP packages.
    const parent = /\bubuntu\b/.test(os.idLike || '') ? 'ubuntu' : /\bdebian\b/.test(os.idLike || '') ? 'debian' : null;
    if (parent) {
      const release = codenameToRelease(distro[parent], os.codename) || (ver ? inferRelease(parent, ver, distro, pkgVersions) : null);
      return { family: parent, release, how: 'derived', vendor: os.id };
    }
    return { family: 'other', release: os.versionId || null, how: 'os', vendor: os.id };
  }

  // A RHEL-family kernel (5.14.0-427.el9_4.x86_64). Not inside a container: it reports the host's kernel.
  const kernel = /\.el(\d+)/.exec(obs.kernel || '');
  if (kernel && obs.container !== true) return { family: 'rhel', release: kernel[1], how: 'kernel' };

  // Without os-release, infer the distribution from the distribution revision in the version string.
  const rev = ver?.revision || '';
  // deb.sury.org builds name a distribution but are not its packages: they never select a release.
  if (isSuryBuild(rev)) return { family: /ubuntu/.test(rev) ? 'ubuntu' : 'debian', release: null, how: 'suffix' };
  if (/[~+]deb\d+u\d+/.test(rev)) return { family: 'debian', release: inferRelease('debian', ver, distro), how: 'suffix' };
  if (/ubuntu/.test(rev)) return { family: 'ubuntu', release: inferRelease('ubuntu', ver, distro), how: 'suffix' };

  // A Server header that names a RHEL rebuild ("Apache/2.4.57 (Rocky Linux)") selects the RHEL family, whose
  // version numbers cannot settle the verdict. It is used for nothing else: it may come from a reverse proxy on
  // another system, and it never names the release.
  if (/\((?:Red Hat|Rocky Linux|AlmaLinux|CentOS|Oracle Linux|CloudLinux)[^)]*\)/i.test(obs.serverSoftware || '')) {
    return { family: 'rhel', release: null, how: 'server' };
  }
  return { family: null, release: null, how: 'none' };
}

// The release named in, or consistent with, the version string; null when it cannot be told.
// versions: installed package versions of the same branch, used when the version string names no release.
function inferRelease(family, ver, distro, versions = []) {
  const rev = ver.revision || '';
  if (isSuryBuild(rev)) return null;
  const named = namedRelease(family, rev);
  if (named) return named;
  const fromPackages = [...new Set(versions.filter((v) => !isSuryBuild(v)).map((v) => namedRelease(family, splitDebian(v).revision)).filter(Boolean))];
  if (fromPackages.length === 1) return fromPackages[0];
  if (family === 'debian') return null;
  // Otherwise the only release that ships this source package at the same upstream version.
  const releases = Object.entries(distro.ubuntu || {})
    .filter(([, v]) => {
      const entry = v.packages?.[srcFor(ver)];
      return entry && entryUpstream(entry, Object.keys(entry.fixed || {})) === ver.upstream;
    })
    .map(([k]) => k);
  return releases.length === 1 ? releases[0] : null;
}

// The release a revision names: "~deb12u1" names Debian 12, "0ubuntu0.24.04.13" names Ubuntu 24.04.
function namedRelease(family, revision) {
  const m = family === 'debian' ? /[~+]deb(\d+)u\d+/.exec(revision) : /ubuntu\d*\.(\d{2}\.\d{2})/.exec(revision);
  return m ? m[1] : null;
}

function codenameToRelease(table, codename) {
  if (!table || !codename) return null;
  const hit = Object.entries(table).find(([, v]) => v.codename === codename);
  return hit ? hit[0] : null;
}

// A distribution as the Distribution list names it: "Ubuntu 22.04", "RHEL family 9", "Upstream build (...)".
function plainDistroLabel(t, d) {
  if (d.family === 'upstream') return t('distro.upstream');
  if (d.family === 'rhel') return d.release ? t('distro.rhelRelease', { release: d.release }) : t('distro.rhel');
  const names = { debian: 'Debian', ubuntu: 'Ubuntu', alpine: 'Alpine' };
  return `${names[d.family] || d.family}${d.release ? ' ' + d.release : ''}`;
}

function distroLabel(t, d, obs) {
  const names = { debian: 'Debian', ubuntu: 'Ubuntu', rhel: t('distro.rhel'), alpine: 'Alpine', upstream: t('distro.upstream'), other: obs.os?.id || t('distro.other') };
  if (!d.family) return t('distro.unknown');
  const plain = `${names[d.family] || d.family}${d.release ? ' ' + d.release : ''}`;
  if (d.how === 'derived') return t('distro.derived', { label: obs.os?.pretty || d.vendor, parent: plain });
  const base = obs.os?.pretty && d.how === 'os'
    ? obs.os.pretty
    : d.family === 'rhel' && d.release
      ? t('distro.rhelRelease', { release: d.release })
      : plain;
  if (d.how === 'suffix') return t('distro.inferred', { label: base });
  if (d.how === 'kernel') return t('distro.kernel', { label: base });
  if (d.how === 'server') return t('distro.serverHeader', { label: base });
  if (d.how === 'manual') return t('distro.manual', { label: base });
  return base;
}

export function sapiLabel(sapi, lang = 'en') {
  const names = {
    apache2handler: 'Apache mod_php',
    'fpm-fcgi': 'PHP-FPM',
    'cgi-fcgi': 'CGI/FastCGI',
    cgi: 'CGI',
    litespeed: 'LiteSpeed (LSAPI)',
    frankenphp: 'FrankenPHP',
    cli: translator(lang)('sapi.cli'),
  };
  return own(names, sapi) ? `${names[sapi]} (${sapi})` : String(sapi ?? '');
}

function compareBranch(a, b) {
  const [am, an] = a.split('.').map(Number);
  const [bm, bn] = b.split('.').map(Number);
  return am - bm || an - bn;
}

export function isOff(v) {
  if (v === null || v === undefined) return false;
  return v === '' || v === '0' || /^(off|false|no|none)$/i.test(String(v).trim());
}

function isOn(v) {
  return v !== null && v !== undefined && !isOff(v);
}
