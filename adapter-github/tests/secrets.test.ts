import { describe, expect, it } from 'vitest';

import { findSecretShaped, hasSecretShape } from '../src/secrets.ts';

// Secret-shaped strings are built at run time so that no tracked file ever carries one.
const ghpToken = 'ghp_' + 'a'.repeat(36);
const awsKey = 'AKIA' + 'B'.repeat(16);
const keyHeader = ['-----BEGIN', 'RSA', 'PRIVATE', 'KEY-----'].join(' ');

describe('secret shapes, ported from core (receipt.py:SECRET)', () => {
  it('matches the shapes core refuses', () => {
    expect(hasSecretShape(`token ${ghpToken} in a message`)).toBe(true);
    expect(hasSecretShape(awsKey)).toBe(true);
    expect(hasSecretShape(keyHeader)).toBe(true);
    expect(hasSecretShape('password = "' + 'x'.repeat(16) + '"')).toBe(true);
    expect(hasSecretShape('sk-ant-' + 'q'.repeat(24))).toBe(true);
  });

  it('matches every GitHub token shape, the Actions installation token (ghs_) this adapter holds first (N-05)', () => {
    for (const prefix of ['ghp_', 'ghs_', 'gho_', 'ghu_', 'ghr_']) {
      expect(hasSecretShape(`leaked ${prefix}${'Z9'.repeat(18)} here`), prefix).toBe(true);
    }
    expect(hasSecretShape('github_pat_' + 'A1_'.repeat(25))).toBe(true);
    expect(hasSecretShape('the ghs_ prefix is an installation token')).toBe(false);
  });

  it('lets ordinary gate output through', () => {
    expect(hasSecretShape('add an ownership check before the update')).toBe(false);
    expect(hasSecretShape('CVE-2026-0001: bump the package')).toBe(false);
    expect(hasSecretShape('key_secret: SB_MODEL_KEY')).toBe(false);
  });

  it('names where the first secret-shaped string is, never the string', () => {
    const where = findSecretShaped([
      ['check summary', 'clean'],
      ['comment body', `leaks ${ghpToken}`],
    ]);
    expect(where).toBe('comment body');
    expect(findSecretShaped([['x', 'clean']])).toBeNull();
  });
});
