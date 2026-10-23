import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareDebian, comparePhp, parsePhpVersion, isSuryBuild } from '../site/lib/version.js';

// [a, b, expected]: must match the result of dpkg --compare-versions.
export const DEB_CASES = [
  ['1.0', '1.0-1', -1],
  ['1.0~rc1', '1.0', -1],
  ['1.0~rc1-1', '1.0-1', -1],
  ['1:1.0', '2.0', 1],
  ['8.2.35-1~deb12u1', '8.2.34-1~deb12u1', 1],
  ['8.2.35-1~deb12u1', '8.2.35-1', -1],
  ['8.2.26-1~deb12u1', '8.2.35-1~deb12u1', -1],
  ['8.1.2-1ubuntu2.28', '8.1.2-1ubuntu2.9', 1],
  ['8.1.2-1ubuntu2.20', '8.1.2-1ubuntu2.28', -1],
  ['8.1.2-1ubuntu2.28', '8.1.2-1ubuntu2.28', 0],
  ['7.4.3-4ubuntu2.29+esm5', '7.4.3-4ubuntu2.29', 1],
  ['5.5.9+dfsg-1ubuntu4.29+esm18', '5.5.9+dfsg-1ubuntu4.29+esm9', 1],
  ['8.3.6-0ubuntu0.24.04.13', '8.3.6-0ubuntu0.24.04.4', 1],
  ['1.0a', '1.0+', -1],
  ['1.0', '1.00', 0],
  ['2.0.0', '10.0', -1],
];

test('compareDebian gives the same results as dpkg', () => {
  for (const [a, b, want] of DEB_CASES) {
    assert.equal(compareDebian(a, b), want, `${a} vs ${b}`);
    assert.equal(compareDebian(b, a), want === 0 ? 0 : -want, `${b} vs ${a}`);
  }
});

test('parsePhpVersion separates the distribution revision and pre-releases', () => {
  assert.deepEqual(
    (({ branch, upstream, revision, pre }) => ({ branch, upstream, revision, pre }))(parsePhpVersion('8.1.2-1ubuntu2.20')),
    { branch: '8.1', upstream: '8.1.2', revision: '1ubuntu2.20', pre: '' },
  );
  assert.equal(parsePhpVersion('8.6.0RC3').pre, 'RC3');
  assert.equal(parsePhpVersion('hello'), null);
});

test('comparePhp sorts pre-releases below final releases', () => {
  assert.equal(comparePhp('8.4.27', '8.4.27'), 0);
  assert.equal(comparePhp('8.4.26', '8.4.27'), -1);
  assert.equal(comparePhp('8.4.100', '8.4.27'), 1);
  assert.equal(comparePhp('8.6.0RC4', '8.6.0'), -1);
  assert.equal(comparePhp('8.2.35-1~deb12u1', '8.2.35'), 0);
});

test('isSuryBuild recognises deb.sury.org builds', () => {
  assert.ok(isSuryBuild('8.3.14-1+ubuntu22.04.1+deb.sury.org+1'));
  assert.ok(isSuryBuild('8.3.14-1+0~20241122.43+debian12~1.gbp9f1e3a'));
  assert.ok(!isSuryBuild('8.2.35-1~deb12u1'));
  assert.ok(!isSuryBuild('8.1.2-1ubuntu2.28'));
});
