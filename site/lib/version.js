// Compares upstream PHP versions and Debian/Ubuntu package versions.

export function parsePhpVersion(text) {
  const m = /^(\d+)\.(\d+)\.(\d+)(.*)$/.exec(String(text || '').trim());
  if (!m) return null;
  const suffix = m[4];
  // Pre-releases: "8.6.0RC3", "8.5.12-dev" (a branch snapshot before that release), "8.2.0~rc1-1" (a Debian package of one),
  // "8.5.12_rc1-r0" and "8.5.0_pre1" (Alpine writes them with an underscore; its "_p1" is a patch level, not a pre-release).
  // In a Debian version any other "~" suffix of the upstream part ("8.4.27~git20261001-1") sorts before the release as
  // well: it is a snapshot taken before it. Repack markers ("~dfsg") are not pre-releases.
  const pre = /^[-.~_]?((?:alpha|beta|RC|dev|pre)\d*)/i.exec(suffix)
    || /^~(?!(?:dfsg|ds|repack)\d*(?:$|[-+~]))([^-+~]+)/i.exec(suffix);
  const rest = pre ? suffix.slice(pre[0].length) : suffix;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    branch: `${m[1]}.${m[2]}`,
    upstream: `${m[1]}.${m[2]}.${m[3]}`,
    pre: pre ? pre[1] : '',
    // The distribution revision, if one is attached, as in "-1ubuntu2.20" or "-1~deb12u1"
    revision: rest.startsWith('-') ? rest.slice(1) : '',
    raw: String(text).trim(),
  };
}

// Compares major.minor.patch only. For the same numbers, a pre-release such as RC sorts lower.
export function comparePhp(a, b) {
  const pa = typeof a === 'string' ? parsePhpVersion(a) : a;
  const pb = typeof b === 'string' ? parsePhpVersion(b) : b;
  if (!pa || !pb) throw new Error(`Cannot parse PHP version: ${a} / ${b}`);
  for (const k of ['major', 'minor', 'patch']) {
    if (pa[k] !== pb[k]) return pa[k] < pb[k] ? -1 : 1;
  }
  if (pa.pre && !pb.pre) return -1;
  if (!pa.pre && pb.pre) return 1;
  return 0;
}

// A direct port of dpkg's version comparison (lib/dpkg/version.c).
export function compareDebian(a, b) {
  const pa = splitDebian(a);
  const pb = splitDebian(b);
  if (pa.epoch !== pb.epoch) return pa.epoch < pb.epoch ? -1 : 1;
  const c = verrevcmp(pa.upstream, pb.upstream);
  if (c !== 0) return c;
  return verrevcmp(pa.revision, pb.revision);
}

export function splitDebian(version) {
  let v = String(version || '').trim();
  let epoch = 0;
  const colon = v.indexOf(':');
  if (colon >= 0) {
    epoch = Number.parseInt(v.slice(0, colon), 10) || 0;
    v = v.slice(colon + 1);
  }
  const hyphen = v.lastIndexOf('-');
  if (hyphen < 0) return { epoch, upstream: v, revision: '' };
  return { epoch, upstream: v.slice(0, hyphen), revision: v.slice(hyphen + 1) };
}

const isDigit = (ch) => ch >= '0' && ch <= '9';

function order(ch) {
  if (ch === '') return 0;
  if (isDigit(ch)) return 0;
  if (/[A-Za-z]/.test(ch)) return ch.charCodeAt(0);
  if (ch === '~') return -1;
  return ch.charCodeAt(0) + 256;
}

function verrevcmp(a, b) {
  let i = 0;
  let j = 0;
  const at = (s, k) => (k < s.length ? s[k] : '');
  while (i < a.length || j < b.length) {
    let firstDiff = 0;
    while ((i < a.length && !isDigit(a[i])) || (j < b.length && !isDigit(b[j]))) {
      const ac = order(at(a, i));
      const bc = order(at(b, j));
      if (ac !== bc) return ac < bc ? -1 : 1;
      i++;
      j++;
    }
    while (at(a, i) === '0') i++;
    while (at(b, j) === '0') j++;
    while (isDigit(at(a, i)) && isDigit(at(b, j))) {
      if (!firstDiff) firstDiff = a.charCodeAt(i) - b.charCodeAt(j);
      i++;
      j++;
    }
    if (isDigit(at(a, i))) return 1;
    if (isDigit(at(b, j))) return -1;
    if (firstDiff) return firstDiff < 0 ? -1 : 1;
  }
  return 0;
}

// Repack markers in a Debian upstream version ("5.5.9+dfsg"). PHP_VERSION never carries them.
const REPACK = /[+~](?:dfsg|ds|repack)\d*$/i;

// The upstream part of a package version or a PHP_VERSION string, without epoch and repack
// markers: "5.5.9+dfsg-1ubuntu4.29+esm18" -> "5.5.9", "1:8.2.30-1.el9_6" -> "8.2.30".
export function debUpstream(version) {
  return splitDebian(version).upstream.replace(REPACK, '');
}

// A package version or PHP_VERSION string in a form that compares like for like: the epoch
// (never in PHP_VERSION; PHP source packages do not use one) and repack markers are dropped.
export function debComparable(version) {
  const { upstream, revision } = splitDebian(version);
  const up = upstream.replace(REPACK, '');
  return revision ? `${up}-${revision}` : up;
}

// Builds from Ondřej Surý's repository (deb.sury.org) follow upstream versions directly.
export function isSuryBuild(version) {
  return /deb\.sury\.org|\+0~20\d{6}|\.gbp[0-9a-f]+/.test(String(version || ''));
}

// The build date of a deb.sury.org Debian build ("8.1.34-9+0~20261021.82+debian12~1.gbp4e430a" -> "2026-10-21"), or
// null. Its Ubuntu builds ("+ubuntu22.04.1+deb.sury.org+1") carry no date.
export function suryBuildDate(version) {
  const m = /\+0~(20\d{2})(\d{2})(\d{2})/.exec(String(version || ''));
  return m ? `${m[1]}-${m[2]}-${m[3]}` : null;
}

// rpm's version comparison (rpmvercmp in rpmio/rpmvercmp.c) of one version or release string.
function rpmvercmp(a, b) {
  if (a === b) return 0;
  const isAlnum = (ch) => /[A-Za-z0-9]/.test(ch);
  const isAlpha = (ch) => /[A-Za-z]/.test(ch);
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    while (i < a.length && !isAlnum(a[i]) && a[i] !== '~' && a[i] !== '^') i++;
    while (j < b.length && !isAlnum(b[j]) && b[j] !== '~' && b[j] !== '^') j++;
    // "~" sorts before everything, even the end of the string.
    if (a[i] === '~' || b[j] === '~') {
      if (a[i] !== '~') return 1;
      if (b[j] !== '~') return -1;
      i++;
      j++;
      continue;
    }
    // "^" sorts after the end of the string but before anything else.
    if (a[i] === '^' || b[j] === '^') {
      if (i >= a.length) return -1;
      if (j >= b.length) return 1;
      if (a[i] !== '^') return 1;
      if (b[j] !== '^') return -1;
      i++;
      j++;
      continue;
    }
    if (i >= a.length || j >= b.length) break;
    const si = i;
    const sj = j;
    const numeric = isDigit(a[i]);
    if (numeric) {
      while (i < a.length && isDigit(a[i])) i++;
      while (j < b.length && isDigit(b[j])) j++;
    } else {
      while (i < a.length && isAlpha(a[i])) i++;
      while (j < b.length && isAlpha(b[j])) j++;
    }
    let x = a.slice(si, i);
    let y = b.slice(sj, j);
    // A numeric segment is newer than an alphabetic one.
    if (!y.length) return numeric ? 1 : -1;
    if (numeric) {
      x = x.replace(/^0+/, '');
      y = y.replace(/^0+/, '');
      if (x.length !== y.length) return x.length < y.length ? -1 : 1;
    }
    if (x !== y) return x < y ? -1 : 1;
  }
  if (i >= a.length && j >= b.length) return 0;
  return i >= a.length ? -1 : 1;
}

// Compares two rpm versions "[epoch:]version-release" as rpm does. A missing epoch is 0; when one side has no release,
// only the versions are compared.
export function compareRpm(a, b) {
  const split = (s) => {
    let v = String(s || '').trim();
    let epoch = 0;
    const colon = v.indexOf(':');
    if (colon >= 0) {
      epoch = Number.parseInt(v.slice(0, colon), 10) || 0;
      v = v.slice(colon + 1);
    }
    const hyphen = v.lastIndexOf('-');
    return hyphen < 0 ? { epoch, version: v, release: '' } : { epoch, version: v.slice(0, hyphen), release: v.slice(hyphen + 1) };
  };
  const pa = split(a);
  const pb = split(b);
  if (pa.epoch !== pb.epoch) return pa.epoch < pb.epoch ? -1 : 1;
  const c = rpmvercmp(pa.version, pb.version);
  if (c !== 0 || !pa.release || !pb.release) return c;
  return rpmvercmp(pa.release, pb.release);
}
