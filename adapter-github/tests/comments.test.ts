import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { BOT_MARKER, commentBody, fixSentence, planComments, shouldPost, staleComments, type ExistingComment } from '../src/comments.ts';
import { diffLines, inDiff, parsePatch } from '../src/diff.ts';
import { readRunDir, type Finding } from '../src/run-dir.ts';

const FIXTURES = join(import.meta.dirname, 'fixtures');
const PATCH = ['@@ -1,2 +1,4 @@', ' export const a = 1;', '+export const v2 = 2;', '+export const v3 = 3;', ' export const b = 1;',
  '@@ -40,0 +42,2 @@', '+export const v42 = 42;', '+export const v43 = 43;'].join('\n');

describe('the lines a pull request changes, from its patches', () => {
  it('reads the right-hand side of every hunk: added and context lines, never removed ones', () => {
    const lines = parsePatch(['@@ -3,3 +3,3 @@', ' keep', '-old', '+new', ' keep'].join('\n'));
    expect([...lines].sort((a, b) => a - b)).toEqual([3, 4, 5]);
  });

  it('a patch that ends in a newline adds no phantom right-hand line; a blank context line inside a hunk still counts (N-04)', () => {
    const lines = parsePatch(['@@ -3,2 +3,2 @@', ' keep', '-old', '+new', ''].join('\n'));
    expect([...lines].sort((a, b) => a - b)).toEqual([3, 4]);
    const blank = parsePatch(['@@ -1,3 +1,3 @@', '+a', '', '+c'].join('\n'));
    expect([...blank].sort((a, b) => a - b)).toEqual([1, 2, 3]);
  });

  it('indexes every file with a patch; a binary file without one has no lines', () => {
    const diff = diffLines([{ filename: 'src/api/users.ts', patch: PATCH }, { filename: 'logo.png' }]);
    expect(inDiff(diff, 'src/api/users.ts', 42)).toBe(true);
    expect(inDiff(diff, 'src/api/users.ts', 43)).toBe(true);
    expect(inDiff(diff, 'src/api/users.ts', 41)).toBe(false);
    expect(inDiff(diff, 'logo.png', 1)).toBe(false);
    expect(inDiff(diff, 'other.ts', 1)).toBe(false);
  });
});

const finding = (over: Partial<Finding>): Finding => ({ severity: 'blocking', rule_id: 'AC-3', message: 'add an ownership check before the update and a test that goes red without it', path: 'src/api/users.ts', line: 42, file: null, ...over });

describe('the body of a review comment', () => {
  it('carries a severity marker, the rule id, the message, a fix sentence and the bot marker', () => {
    const body = commentBody(finding({}), 'qa');
    expect(body).toMatch(/^\*\*BLOCKING\*\*/);
    expect(body).toContain('`AC-3`');
    expect(body).toContain('Secure Builder / QA');
    expect(body).toContain('add an ownership check before the update');
    expect(body).toContain('What would fix it:');
    expect(body).toContain(BOT_MARKER);
  });

  it('marks an advisory finding differently from a blocking one', () => {
    const advisory = commentBody(finding({ severity: 'advisory' }), 'qa');
    expect(advisory).toMatch(/^_Advisory_/);
    expect(advisory).toContain('does not fail the check');
    expect(commentBody(finding({}), 'qa')).toContain('fails the check');
  });

  it("says a Sentinel finding comes from a cold reviewer with no build context, and a QA one doesn't", () => {
    expect(commentBody(finding({}), 'sentinel')).toMatch(/cold reviewer[^\n]*no build context/);
    expect(commentBody(finding({}), 'qa')).not.toMatch(/cold reviewer/);
  });

  it('gives one fix sentence per rule family', () => {
    expect(fixSentence('CVE-2026-0001')).toMatch(/version with a fix/);
    expect(fixSentence('GHSA-xxxx-yyyy-zzzz')).toMatch(/version with a fix/);
    expect(fixSentence('stale-data:grype')).toMatch(/database/);
    expect(fixSentence('scanner:trivy')).toMatch(/scan log/);
    expect(fixSentence('malware')).toMatch(/infected file/);
    expect(fixSentence('AC-3')).toMatch(/test that goes red/);
    expect(fixSentence('SI-12')).toMatch(/test that goes red/);
    expect(fixSentence('redacted-output')).toMatch(/push a new commit/);
  });
});

describe('which findings become comments', () => {
  it('plans a comment for every finding with a path and a line inside the diff, and nothing else', () => {
    const run = readRunDir(join(FIXTURES, 'run-qa-fail'));
    const diff = diffLines([{ filename: 'src/api/users.ts', patch: PATCH }]);
    const planned = planComments(run, diff);
    expect(planned).toHaveLength(1);
    expect(planned[0]).toMatchObject({ path: 'src/api/users.ts', line: 42, gate: 'qa', rule_id: 'AC-3' });
    expect(planComments(run, diffLines([]))).toHaveLength(0);
  });
});

const existing = (over: Partial<ExistingComment>): ExistingComment => ({ id: 1, path: 'src/api/users.ts', line: 42, original_line: 42, body: commentBody(finding({}), 'qa'), user: { login: 'github-actions[bot]' }, in_reply_to_id: null, ...over });

describe('the noise budget', () => {
  const candidate = planComments(readRunDir(join(FIXTURES, 'run-qa-fail')), diffLines([{ filename: 'src/api/users.ts', patch: PATCH }]))[0]!;

  it('never posts a comment whose body and line match one already posted', () => {
    expect(shouldPost([existing({})], candidate)).toBe(false);
    expect(shouldPost([], candidate)).toBe(true);
    expect(shouldPost([existing({ line: 43, original_line: 43 })], candidate)).toBe(true);
    expect(shouldPost([existing({ body: 'something else' })], candidate)).toBe(true);
    expect(shouldPost([existing({ path: 'src/other.ts' })], candidate)).toBe(true);
  });

  it('matches an outdated comment on its original line when GitHub has cleared its line', () => {
    expect(shouldPost([existing({ line: null })], candidate)).toBe(false);
  });

  it('finds the earlier comments whose finding is gone, skipping replies and ones already answered', () => {
    const gone = existing({ id: 7, line: 43, original_line: 43, body: commentBody(finding({ line: 43, rule_id: 'SA-11' }), 'qa') });
    const reply = existing({ id: 8, in_reply_to_id: 1, body: 'thanks, fixed' });
    const answered = existing({ id: 9, line: 44, original_line: 44, body: commentBody(finding({ line: 44 }), 'qa') });
    const answer = existing({ id: 10, in_reply_to_id: 9, body: 'Not found on def' });
    expect(staleComments([existing({}), gone, reply], [candidate]).map((c) => c.id)).toEqual([7]);
    expect(staleComments([answered, answer], [candidate]).map((c) => c.id)).toEqual([]);
    expect(staleComments([existing({})], [candidate])).toEqual([]);
  });
});
