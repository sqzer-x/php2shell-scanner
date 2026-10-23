// Turns pasted text into an observation.
// Accepted formats: PHP probe output, server script output, response headers (curl -I or curl -IL), php -v output,
// a version string. Text that holds several separate outputs (two probe outputs, two server script outputs, a probe
// output and a header, several X-Powered-By headers, several -v lines) gives one observation per output in
// obs.parts, and judge.js reports the worst of them. The top-level fields then describe the first one.
// Notes for the user come from messages.js, in the language given by options.lang.
// Every value read from the input is untrusted: it is used only as text of the expected type, and never as a key
// that could reach an object's prototype.

import { translator } from './messages.js';

const MARKER = /-----(BEGIN|END) PHP2SHELL (SELFCHECK|SERVERCHECK)-----/g;
// The first line of the server script's result block, and the line kinds that follow it.
const SERVER_LINE = /^(?:tool|env|os|pkg|changelog|proc|log|webroot|webuser_proc)\|/m;
const RHEL_IDS = ['rhel', 'centos', 'rocky', 'almalinux', 'ol', 'cloudlinux', 'eurolinux', 'amzn'];
// Longer input is cut, so that a paste of several megabytes cannot keep the page busy.
const MAX_INPUT = 2000000;
// At most this many separate outputs are judged.
const MAX_PARTS = 64;

export function emptyObservation() {
  return {
    sources: [],
    phpVersion: null,
    sapi: null,
    os: {},
    // { manager, name, version, source, changelog? }. changelog (CVE -> number of changelog lines, null when the
    // count is unknown) is the server script's reading of that package at exactly that version.
    packages: [],
    ini: null,
    extensions: null,
    container: null,
    // True when the probe could not tell whether it runs in a container (open_basedir hides the markers)
    containerHidden: false,
    configPath: null,
    serverSoftware: null,
    // php_uname('r') from the probe: the kernel release, e.g. "5.14.0-427.el9_4.x86_64"
    kernel: null,
    // Whether open_basedir was set where the probe ran (true, false, or null when not reported)
    openBasedir: null,
    // True when the probe could not read the OS release at all (open_basedir, or no readable release file), so the
    // distribution and its packages are hidden from it
    osBlocked: false,
    // The probe's own dpkg package list ([{ name, version }]), or null when it could not be read or was not reported
    probeDpkg: null,
    // Whether the server script ran as root (true, false, or null when not reported)
    root: null,
    // True when the server script's OS, packages and processes describe the system this PHP runs on
    serverData: false,
    // The probe and the server script list different PHP packages: taken at different times or on different systems
    serverConflict: false,
    // The server script output ends without its END line, so its later lines are missing
    truncated: false,
    // The server script output starts without its BEGIN line and without its first lines
    headCut: false,
    // The input was longer than MAX_INPUT, or held more than MAX_PARTS outputs, so part of it was not read
    inputCut: false,
    processes: [],
    // PHP processes the server script could not check for a missed restart
    procUnreadable: 0,
    // Compromise indicator counts; null means the source could not be read ("unknown")
    findings: {},
    notes: [],
  };
}

// Every probe and server script block, in one pass over the text. A block without its END line runs to the next
// marker or to the end. An END line without its BEGIN line (the output was copied from below its first line) ends
// a block that starts where its first data line is.
function findBlocks(text) {
  const blocks = [];
  let open = null;
  let after = 0;
  const close = (end, closed, stop) => {
    blocks.push({ kind: open.kind, body: text.slice(open.from, end), closed, start: open.start, stop, headless: false });
    open = null;
    after = stop;
  };
  for (const m of text.matchAll(MARKER)) {
    const kind = m[2] === 'SELFCHECK' ? 'self' : 'server';
    const stop = m.index + m[0].length;
    if (m[1] === 'BEGIN') {
      if (open) close(m.index, false, m.index);
      open = { kind, from: stop, start: m.index };
    } else if (open) {
      // The END line of another kind of output ends the open block too, which then has no END line of its own.
      close(m.index, open.kind === kind, stop);
    } else {
      const region = text.slice(after, m.index);
      const first = kind === 'server' ? region.search(SERVER_LINE) : region.indexOf('{');
      const start = after + Math.max(first, 0);
      blocks.push({ kind, body: text.slice(start, m.index), closed: true, start, stop, headless: true });
      after = stop;
    }
  }
  if (open) close(text.length, false, text.length);
  return blocks;
}

// The same output pasted twice counts once.
function unique(blocks) {
  const seen = new Set();
  return blocks.filter((b) => {
    const key = b.body.trim();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function parseInput(text, options = {}) {
  const t = translator(options.lang || 'en');
  try {
    return parseText(t, String(text ?? ''));
  } catch {
    // Never leave the page without a result: an input this parser cannot handle gives no version.
    const obs = emptyObservation();
    obs.notes.push(t('parse.noVersion'));
    return obs;
  }
}

function parseText(t, raw) {
  let input = raw.replace(/\r\n?/g, '\n');
  if (!input.trim()) return emptyObservation();
  let cut = false;
  if (input.length > MAX_INPUT) {
    input = input.slice(0, MAX_INPUT);
    cut = true;
  }
  const finish = (obs) => {
    if (cut) {
      obs.inputCut = true;
      obs.notes.push(t('parse.inputTooLong'));
    }
    return obs;
  };

  const blocks = findBlocks(input);
  if (!blocks.length) {
    const trimmed = input.trim();
    if (trimmed.startsWith('{')) {
      const obs = emptyObservation();
      applySelfCheck(t, obs, trimmed);
      return finish(obs);
    }
    const loose = looseObservations(t, input, false);
    if (!loose.length) {
      const obs = emptyObservation();
      obs.notes.push(t('parse.noVersion'));
      return finish(obs);
    }
    return finish(combine(t, loose));
  }

  const probes = unique(blocks.filter((b) => b.kind === 'self'));
  const servers = unique(blocks.filter((b) => b.kind === 'server'));
  const parts = [];
  if (servers.length <= 1 && probes.length) {
    // One server script output next to one or more probe outputs (several sites or pools on one server).
    const sc = servers.length ? serverObservation(t, servers[0]) : null;
    let used = false;
    let otherSystem = false;
    for (const b of probes) {
      const obs = emptyObservation();
      applySelfCheck(t, obs, b.body);
      if (sc) {
        const drop = mergeServerCheck(t, obs, sc);
        if (!drop) used = true;
        else if (drop !== 'parse.serverConflict') otherSystem = true;
      }
      parts.push(obs);
    }
    // Server script output from another system (the host of a container, another server) is judged on its own:
    // the PHP it shows runs somewhere too. Output of the same system at another moment is not (see judge.js).
    if (sc && otherSystem && !used) parts.push(sc);
  } else {
    // Several server script outputs: which probe belongs to which is unknown, so each output stands alone.
    for (const b of probes) {
      const obs = emptyObservation();
      applySelfCheck(t, obs, b.body);
      parts.push(obs);
    }
    for (const b of servers) parts.push(serverObservation(t, b));
  }
  // Headers and -v lines pasted next to the blocks. Only lines that start at the left margin count, so the
  // server script's own indented text (package lists, log lines) is never read as one.
  let rest = '';
  let at = 0;
  for (const b of blocks) {
    rest += `${input.slice(at, Math.max(at, b.start))}\n`;
    at = Math.max(at, b.stop);
  }
  rest += input.slice(at);
  parts.push(...looseObservations(t, rest, true));
  return finish(combine(t, parts));
}

function combine(t, parts) {
  if (parts.length === 1) return parts[0];
  let list = parts;
  let tooMany = false;
  if (list.length > MAX_PARTS) {
    list = list.slice(0, MAX_PARTS);
    tooMany = true;
  }
  const notes = [...new Set(list.flatMap((p) => p.notes))];
  if (tooMany) notes.push(t('parse.tooManyOutputs', { n: MAX_PARTS }));
  return {
    ...list[0],
    sources: [...new Set(list.flatMap((p) => p.sources))],
    notes,
    inputCut: tooMany || list[0].inputCut,
    parts: list,
  };
}

function applySelfCheck(t, obs, jsonText) {
  let data;
  try {
    data = JSON.parse(jsonText);
  } catch {
    obs.notes.push(t('parse.badJson'));
    return;
  }
  if (!data || typeof data !== 'object' || data.tool !== 'php2shell-selfcheck') {
    obs.notes.push(t('parse.notSelfcheck'));
    return;
  }
  obs.sources.push('selfcheck');
  obs.phpVersion = field(data.php_version) || obs.phpVersion;
  obs.sapi = field(data.sapi) || obs.sapi;
  const release = isRecord(data.os_release) ? normalizeOs(data.os_release) : {};
  obs.os = { ...release, ...obs.os };
  obs.kernel = field(data.uname_release);
  obs.openBasedir = typeof data.open_basedir === 'boolean' ? data.open_basedir : null;
  // os_release is null when no release file could be read (older probes sent an empty list), and under
  // open_basedir an empty OS release means it could not be read, not that there is none.
  const unread = data.os_release === null || (Array.isArray(data.os_release) && !data.os_release.length);
  if (!Object.keys(release).length && (obs.openBasedir || unread)) {
    obs.osBlocked = true;
    obs.notes.push(t(obs.openBasedir ? 'parse.openBasedir' : 'parse.osReleaseUnread'));
  }
  if (Array.isArray(data.dpkg_packages)) {
    obs.probeDpkg = [];
    for (const p of data.dpkg_packages) {
      const name = isRecord(p) ? field(p.name) : null;
      const version = isRecord(p) ? field(p.version) : null;
      if (name && version) {
        obs.probeDpkg.push({ name, version });
        addPackage(obs, { manager: 'dpkg', name, version, source: cleanSource(p.source) });
      }
    }
  } else if (data.dpkg_packages === null && !obs.osBlocked && /debian|ubuntu/.test(`${release.id || ''} ${release.idLike || ''}`)) {
    obs.notes.push(t('parse.dpkgUnreadable'));
  }
  // An empty list is what PHP sends for an empty array: no settings were read.
  obs.ini = cleanIni(data.ini);
  obs.extensions = isRecord(data.extensions) ? data.extensions : null;
  // open_basedir also hides the container markers, so a "false" there proves nothing.
  obs.container = data.container === true ? true : data.container === false && !obs.openBasedir ? false : null;
  // The probe reported that it could not tell (null), or open_basedir hid the markers from it.
  obs.containerHidden = obs.container === null && Object.prototype.hasOwnProperty.call(data, 'container');
  obs.configPath = field(data.config_path);
  obs.serverSoftware = field(data.server_software);
  if (data.self_deleted === false) {
    obs.notes.push(t('parse.probeNotDeleted'));
  }
}

// The server script output on its own: it describes the system it ran on.
function serverObservation(t, block) {
  const sc = emptyObservation();
  applyServerCheck(t, sc, block.body);
  sc.serverData = true;
  if (!block.closed) {
    sc.truncated = true;
    sc.notes.push(t('parse.serverTruncated'));
  }
  if (block.headless) {
    // Copied from below its BEGIN line. Its first line is the tool line: without it, earlier lines are missing too.
    const whole = /^tool\|php2shell-server-check\|/m.test(block.body);
    sc.headCut = !whole;
    sc.notes.push(t(whole ? 'parse.serverNoBegin' : 'parse.serverHeadCut'));
  }
  return sc;
}

function applyServerCheck(t, obs, block) {
  obs.sources.push('servercheck');
  const os = Object.create(null);
  const changelog = new Map();
  const badStatus = [];
  let unreadable = 0;
  for (const raw of block.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const f = line.split('|');
    switch (f[0]) {
      case 'os':
        if (f[1]) os[f[1]] = f.slice(2).join('|');
        break;
      case 'env':
        if (f[1] === 'root') obs.root = f[2] === '1' ? true : f[2] === '0' ? false : null;
        break;
      case 'pkg':
        if (f[2] && f[3]) {
          addPackage(obs, { manager: f[1], name: f[2], version: f[3], source: cleanSource(f[4]) });
        }
        break;
      case 'changelog':
        if (f[1] && /^CVE-\d{4}-\d+$/.test(f[2] || '')) {
          if (!changelog.has(f[1])) changelog.set(f[1], new Map());
          changelog.get(f[1]).set(f[2], count(f[3]));
        }
        break;
      case 'proc':
        if (f[1] === 'unreadable') {
          unreadable += count(f[2]) ?? 1;
          obs.procUnreadable += count(f[2]) ?? 1;
        } else if (f[1] && (f[3] === 'ok' || f[3] === 'stale')) {
          obs.processes.push({ comm: f[1], count: Number(f[2]) || 0, status: f[3] });
        } else if (f[1]) {
          // A status other than ok or stale (a line cut off while copying): this process was not checked.
          obs.procUnreadable += count(f[2]) || 1;
          badStatus.push(f[1]);
        }
        break;
      case 'log':
      case 'webroot':
        if (f[1] && f[1] !== '__proto__') obs.findings[f[1]] = count(f[2]);
        break;
      case 'webuser_proc':
        obs.findings.webuser_proc = count(f[1]);
        break;
      default:
        break;
    }
  }
  // As root, a process the script cannot read is usually in a container without CAP_SYS_PTRACE: running it again as
  // root does not help there.
  if (unreadable) obs.notes.push(t(obs.root === true ? 'parse.procUnreadableRoot' : 'parse.procUnreadable', { n: String(unreadable) }));
  if (badStatus.length) obs.notes.push(t('parse.procBadStatus', { names: [...new Set(badStatus)].join(', ') }));
  // The script reads the changelog of each installed package, so a changelog belongs to the version listed with
  // it. A name listed with two versions is ambiguous, and its changelog is not used.
  for (const [name, hits] of changelog) {
    const pkgs = obs.packages.filter((p) => p.name === name && (p.manager === 'dpkg' || p.manager === 'rpm'));
    if (pkgs.length === 1) pkgs[0].changelog = Object.fromEntries(hits);
  }
  obs.os = normalizeOs(os);
}

// Adds the server script's observation to the probe's, and returns null, or the message key of the reason it was
// not used. Its compromise indicators are always kept. Its OS, packages, changelogs and processes are used only
// when nothing shows that the two outputs come from different systems or different moments (see unlinked).
function mergeServerCheck(t, obs, sc) {
  obs.sources.push('servercheck');
  obs.root = sc.root;
  obs.findings = { ...obs.findings, ...sc.findings };
  const drop = obs.sources.includes('selfcheck') ? unlinked(obs, sc) : null;
  if (drop) {
    obs.notes.push(t(drop, { os: osLabel(t, sc.os), probe: osLabel(t, obs.os) }));
    if (drop === 'parse.serverConflict') obs.serverConflict = true;
    if (drop === 'parse.serverUnlinkedHidden') obs.unlinkedHidden = true;
    return drop;
  }
  obs.serverData = true;
  obs.truncated = sc.truncated;
  obs.headCut = sc.headCut;
  // The server script read the OS release and the packages the probe could not see.
  if (obs.osBlocked && Object.keys(sc.os || {}).length) {
    obs.osBlocked = false;
    const hidden = [t('parse.openBasedir'), t('parse.osReleaseUnread')];
    obs.notes = obs.notes.filter((n) => !hidden.includes(n));
  }
  obs.os = { ...obs.os, ...sc.os };
  for (const p of sc.packages) addPackage(obs, p);
  obs.processes.push(...sc.processes);
  obs.procUnreadable += sc.procUnreadable;
  for (const n of sc.notes) if (!obs.notes.includes(n)) obs.notes.push(n);
  return null;
}

// Why the server script output does not describe the probe's system, as a message key, or null:
// - both report an OS release, and they differ: another system (the host of a container, or another server);
// - the probe ran in a container, and its own OS release and dpkg package list do not tie the server script
//   output to that container (the script may have run on the host);
// - the probe could not tell whether it runs in a container (open_basedir hides the markers), and its dpkg package
//   list does not tie the two together;
// - the probe read its dpkg package list and it differs from the server script's: different times or systems.
function unlinked(obs, sc) {
  const probeOs = obs.os || {};
  const serverOs = sc.os || {};
  const probeHasOs = Object.keys(probeOs).length > 0;
  if (probeHasOs && Object.keys(serverOs).length > 0 && !sameOs(probeOs, serverOs)) {
    return obs.container === true ? 'parse.serverOtherSystem' : 'parse.serverOtherOs';
  }
  const serverDpkg = sc.packages.filter((p) => p.manager === 'dpkg');
  const agree = obs.probeDpkg !== null && samePackages(obs.probeDpkg, serverDpkg);
  if (obs.container === true && (!probeHasOs || !agree)) return 'parse.serverUnlinked';
  if (obs.containerHidden && !agree) return 'parse.serverUnlinkedHidden';
  if (obs.probeDpkg !== null && !agree) return 'parse.serverConflict';
  return null;
}

// Whether two OS releases are the same. Without os-release the server script writes "rhel" and the major version for
// every /etc/redhat-release, where the probe names the vendor from the file's text (CentOS, CloudLinux, Oracle Linux).
function sameOs(a, b) {
  if (a.id === b.id) return (a.versionId || '') === (b.versionId || '');
  const legacy = (o) => o.id === 'rhel' && !o.idLike && /^\d+$/.test(o.versionId || '');
  const rhelish = (o) => RHEL_IDS.includes(o.id) || /\brhel\b/.test(o.idLike || '');
  if ((legacy(a) && rhelish(b)) || (legacy(b) && rhelish(a))) {
    const major = (o) => String(o.versionId || '').split('.')[0];
    return major(a) !== '' && major(a) === major(b);
  }
  return false;
}

// The probe lists at most 40 packages; a full list only has to be part of the server script's.
const PROBE_DPKG_MAX = 40;

function samePackages(probeList, serverList) {
  const key = (p) => `${p.name} ${p.version}`;
  const sa = new Set(probeList.map(key));
  const sb = new Set(serverList.map(key));
  return (sa.size === sb.size || probeList.length >= PROBE_DPKG_MAX) && [...sa].every((k) => sb.has(k));
}

function osLabel(t, os) {
  return os?.pretty || [os?.id, os?.versionId].filter(Boolean).join(' ') || t('distro.unknown');
}

function addPackage(obs, p) {
  const same = obs.packages.find((q) => q.manager === p.manager && q.name === p.name && q.version === p.version);
  if (!same) obs.packages.push({ ...p });
  else if (p.changelog && !same.changelog) same.changelog = p.changelog;
}

const isRecord = (value) => Boolean(value) && typeof value === 'object' && !Array.isArray(value);

// A string field of the probe output, trimmed, or null when it is missing, empty or not a string.
function field(value) {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

// A text field of an OS release: a string, or a number written as text; anything else (an object, a list) is not used.
function osField(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return field(value);
}

// The probe's ini settings: text values only. A value of another type (an object, a list) is left out, as if the
// setting had not been read.
function cleanIni(ini) {
  if (!isRecord(ini)) return null;
  const out = {};
  for (const [name, value] of Object.entries(ini)) {
    if (name === '__proto__') continue;
    if (value === null || typeof value === 'string') out[name] = value;
    else if (typeof value === 'number' || typeof value === 'boolean') out[name] = String(value);
  }
  return out;
}

// A count from the server script: a non-negative integer, or null for "unknown" (the source could not be read).
function count(value) {
  const s = String(value ?? '').trim();
  return /^\d{1,9}$/.test(s) ? Number(s) : null;
}

// A PHP version, as it appears in headers, -v output and version strings. The lengths are bounded, so that a long
// run of digits cannot make the search slow.
const VERSION = '(\\d{1,2}\\.\\d{1,3}\\.\\d{1,5}[^\\s,;()]{0,100})';

// X-Powered-By and Server headers, -v output lines and, when nothing else is found and strict is false, version
// strings. One observation per distinct PHP version. strict: only lines that start at the left margin count.
function looseObservations(t, text, strict) {
  const out = [];
  const lead = strict ? '' : '[ \\t]*';
  // curl -IL prints one header block per redirect hop, each starting with a status line.
  const headers = new Map();
  for (const response of text.split(/^(?=[ \t]*HTTP\/\d)/m)) {
    const serverLine = new RegExp(`^${lead}Server:[ \\t]*([^\\n]*)$`, 'im').exec(response);
    const server = serverLine && serverLine[1].trim() ? serverLine[1].trim().slice(0, 200) : null;
    // A PHP version anywhere in an X-Powered-By or Server header line: a proxy may merge several values into one
    // line ("PleskLin, PHP/8.2.20", "PHP/8.4.27, PHP/8.2.20"), and some servers name PHP in the Server header.
    for (const line of response.matchAll(new RegExp(`^${lead}(?:X-Powered-By|Server):[ \\t]*([^\\n]*)$`, 'gim'))) {
      for (const m of line[1].matchAll(new RegExp(`\\bPHP\\/${VERSION}`, 'gi'))) {
        if (!headers.has(m[1]) || (!headers.get(m[1]) && server)) headers.set(m[1], server);
      }
    }
  }
  for (const [version, server] of headers) {
    const obs = emptyObservation();
    obs.sources.push('header');
    obs.phpVersion = version;
    obs.serverSoftware = server;
    obs.notes.push(t('parse.headerOnly'));
    out.push(obs);
  }
  // php -v, php-fpm8.2 -v, php-cgi -v: "PHP 8.2.20 (fpm-fcgi) (built: ...)"
  const seen = new Set();
  const cli = `^${lead}PHP[ \\t]+(\\d{1,2}\\.\\d{1,3}\\.\\d{1,5}\\S{0,100})[ \\t]+\\(([A-Za-z0-9-]{1,40})\\)`;
  for (const m of text.matchAll(new RegExp(cli, 'gim'))) {
    const sapi = m[2].toLowerCase();
    if (seen.has(`${m[1]} ${sapi}`)) continue;
    seen.add(`${m[1]} ${sapi}`);
    const obs = emptyObservation();
    obs.sources.push('cli');
    obs.phpVersion = m[1];
    obs.sapi = sapi;
    if (sapi === 'cli') obs.notes.push(t('parse.cliVersion'));
    out.push(obs);
  }
  if (!strict && !out.length) {
    // Version strings: at the start of the input, on a line of their own, or after "PHP" ("PHP/8.2.20", "PHP 8.2.20").
    const versions = new Set();
    const trimmed = text.trim();
    const first = new RegExp(`^${VERSION}`).exec(trimmed);
    if (first) versions.add(first[1]);
    for (const m of trimmed.matchAll(new RegExp(`^[ \\t]*${VERSION}[ \\t]*$|\\bPHP\\/?[ \\t]*${VERSION}`, 'gim'))) {
      versions.add(m[1] || m[2]);
    }
    for (const version of versions) {
      const obs = emptyObservation();
      obs.sources.push('version');
      obs.phpVersion = version;
      out.push(obs);
    }
  }
  return out;
}

function normalizeOs(o) {
  const out = {};
  const id = osField(o.ID);
  const idLike = osField(o.ID_LIKE);
  const versionId = osField(o.VERSION_ID);
  const codename = osField(o.VERSION_CODENAME);
  const pretty = osField(o.PRETTY_NAME);
  if (id) out.id = id.toLowerCase();
  if (idLike) out.idLike = idLike.toLowerCase();
  if (versionId) out.versionId = versionId;
  if (codename) out.codename = codename.toLowerCase();
  if (pretty) out.pretty = pretty;
  // The probe names the legacy keys after the file: LEGACY_REDHAT-RELEASE, LEGACY_DEBIAN_VERSION.
  const redhat = osField(o['LEGACY_REDHAT-RELEASE']) || osField(o.LEGACY_REDHAT_RELEASE);
  if (!out.pretty && redhat) out.pretty = redhat;
  if (!out.id && redhat) {
    // Fedora writes the same file but is not part of the RHEL family.
    out.id = /centos/i.test(redhat) ? 'centos' : /rocky/i.test(redhat) ? 'rocky' : /alma/i.test(redhat) ? 'almalinux'
      : /cloudlinux/i.test(redhat) ? 'cloudlinux' : /oracle/i.test(redhat) ? 'ol' : /amazon/i.test(redhat) ? 'amzn'
        : /fedora/i.test(redhat) ? 'fedora' : 'rhel';
    const m = /release (\d+)/.exec(redhat);
    if (m) out.versionId = m[1];
  }
  const debian = osField(o['LEGACY_DEBIAN-VERSION']) || osField(o.LEGACY_DEBIAN_VERSION);
  if (!out.id && debian) {
    out.id = 'debian';
    const m = /^(\d+)/.exec(debian);
    if (m) out.versionId = m[1];
  }
  return out;
}

// The dpkg Source field sometimes carries a version, as in "php8.1 (8.1.2-1ubuntu2.28)".
function cleanSource(source) {
  return (typeof source === 'string' ? source : '').replace(/\s*\(.*\)\s*$/, '').trim();
}
