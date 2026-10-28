import { cpSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { BOT_MARKER } from '../src/comments.ts';
import { GitHubClient } from '../src/github-api.ts';
import { publish, refusal } from '../src/publish.ts';
import { fakeFetch, type Canned, type RecordedCall } from './fake-fetch.ts';

const FIXTURES = join(import.meta.dirname, 'fixtures');
// The head the fixtures' receipts were written for (run-qa-yellow's is its own).
const HEAD = '7474ee10b8afabb150d67ee6bc027861b4f2a17d';
const YELLOW_HEAD = '190c6b79ad61e2507e5980c1d21d4d3885d1ae45';
const BOT = 'github-actions[bot]';
const R = '/repos/acme/widgets';
// The pull request changes src/api/users.ts lines 2..59, as the fixture's own repository did.
const PATCH = ['@@ -1,1 +1,59 @@', ' export const a = 1;', ...Array.from({ length: 58 }, (_, i) => `+export const v${i + 2} = ${i + 2};`)].join('\n');

function harness(runDir: string, over: Record<string, Canned> = {}, existing: unknown[] = []) {
  const fake = fakeFetch({
    [`POST ${R}/check-runs`]: { status: 201, json: { id: 1, name: 'x' } },
    [`GET ${R}/pulls/7/files`]: { json: [{ filename: 'src/api/users.ts', patch: PATCH }, { filename: 'README.md', patch: '@@ -1,1 +1,1 @@\n-a\n+b' }] },
    [`GET ${R}/pulls/7/comments`]: { json: existing },
    [`POST ${R}/pulls/7/comments`]: { status: 201, json: { id: 101 } },
    [`POST ${R}/pulls/7/comments/101/replies`]: { status: 201, json: { id: 102 } },
    'POST /graphql': (call: RecordedCall) => (String((call.body as { query: string }).query).includes('mutation')
      ? { json: { data: { resolveReviewThread: { thread: { id: 'T1', isResolved: true } } } } }
      : { json: { data: { repository: { pullRequest: { reviewThreads: { nodes: [{ id: 'T1', isResolved: false, comments: { nodes: [{ databaseId: 101 }] } }] } } } } } }),
    ...over,
  });
  const client = new GitHubClient({ token: 'tok', repo: 'acme/widgets', fetch: fake.fetch });
  const log: string[] = [];
  const run = (dir = runDir, pullNumber: number | null = 7, headSha = HEAD) => publish({ runDir: dir, headSha, pullNumber, botLogin: BOT, client, log: (l) => log.push(l) });
  return { fake, run, log };
}

describe('publishing a run to the pull request', () => {
  it('creates exactly one check run per gate, posts the one comment on the diff, exits 1 on a failed gate', async () => {
    const { fake, run } = harness(join(FIXTURES, 'run-qa-fail'));
    const outcome = await run();
    expect(outcome.exitCode).toBe(1);
    const checks = fake.of(`POST ${R}/check-runs`).map((c) => c.body as { name: string; conclusion: string; head_sha: string; output: { title: string; summary: string } });
    expect(checks.map((c) => [c.name, c.conclusion])).toEqual([['Secure Builder / Scan', 'success'], ['Secure Builder / QA', 'failure']]);
    expect(checks.every((c) => c.head_sha === HEAD)).toBe(true);
    expect(checks[1]!.output.title).toMatch(/^QA: FAIL — 2 blocking findings/);
    expect(checks[1]!.output.summary).toContain('the new route has no negative test; add a 401 case for it');
    const comments = fake.of(`POST ${R}/pulls/7/comments`).map((c) => c.body as { body: string; path: string; line: number; commit_id: string });
    expect(comments).toHaveLength(1);
    expect(comments[0]).toMatchObject({ path: 'src/api/users.ts', line: 42, commit_id: HEAD });
    expect(comments[0]!.body).toMatch(/^\*\*BLOCKING\*\* · `AC-3`/);
    expect(comments[0]!.body).toContain(BOT_MARKER);
    expect(outcome.posted).toBe(1);
  });

  it('run again with the same fixture: no new comment, nothing replied', async () => {
    const first = harness(join(FIXTURES, 'run-qa-fail'));
    await first.run();
    const posted = first.fake.of(`POST ${R}/pulls/7/comments`)[0]!.body as { body: string; path: string; line: number };
    const existing = [{ id: 101, path: posted.path, line: posted.line, original_line: posted.line, body: posted.body, user: { login: BOT }, in_reply_to_id: null }];
    const second = harness(join(FIXTURES, 'run-qa-fail'), {}, existing);
    const outcome = await second.run();
    expect(second.fake.of(`POST ${R}/pulls/7/comments`)).toHaveLength(0);
    expect(second.fake.of(`POST ${R}/pulls/7/comments/101/replies`)).toHaveLength(0);
    expect(second.fake.of(`POST ${R}/check-runs`)).toHaveLength(2);
    expect(outcome.posted).toBe(0);
    expect(outcome.skipped).toBe(1);
  });

  it('when the finding is gone on the new head, the earlier comment gets "Not found on <sha>" and its thread is resolved', async () => {
    const first = harness(join(FIXTURES, 'run-qa-fail'));
    await first.run();
    const posted = first.fake.of(`POST ${R}/pulls/7/comments`)[0]!.body as { body: string; path: string; line: number };
    const existing = [{ id: 101, path: posted.path, line: posted.line, original_line: posted.line, body: posted.body, user: { login: BOT }, in_reply_to_id: null }];
    const fixed = harness(join(FIXTURES, 'run-qa-fixed'), {}, existing);
    const outcome = await fixed.run();
    expect(outcome.exitCode).toBe(0);
    expect(fixed.fake.of(`POST ${R}/pulls/7/comments`)).toHaveLength(0);
    const replies = fixed.fake.of(`POST ${R}/pulls/7/comments/101/replies`);
    expect(replies).toHaveLength(1);
    expect((replies[0]!.body as { body: string }).body).toBe(`Not found on ${HEAD}`);
    expect(fixed.fake.of('POST /graphql')).toHaveLength(2);
    expect(outcome.notFound).toBe(1);
    expect(outcome.resolved).toBe(1);
  });

  it("another user's identical comment does not count as the bot's", async () => {
    const first = harness(join(FIXTURES, 'run-qa-fail'));
    await first.run();
    const posted = first.fake.of(`POST ${R}/pulls/7/comments`)[0]!.body as { body: string; path: string; line: number };
    const existing = [{ id: 55, path: posted.path, line: posted.line, body: posted.body, user: { login: 'someone' }, in_reply_to_id: null }];
    const again = harness(join(FIXTURES, 'run-qa-fail'), {}, existing);
    await again.run();
    expect(again.fake.of(`POST ${R}/pulls/7/comments`)).toHaveLength(1);
  });

  it('refuses to post anything when a finding carries a secret-shaped string: nothing reaches GitHub, exit 2', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sb-secret-'));
    cpSync(join(FIXTURES, 'run-qa-fail'), dir, { recursive: true });
    const leaked = 'ghp_' + 'z'.repeat(36);
    for (const name of ['receipt.json', 'receipt.md']) {
      const p = join(dir, name);
      writeFileSync(p, readFileSync(p, 'utf8').replace('add an ownership check', `add an ownership check (token ${leaked})`));
    }
    const { fake, run, log } = harness(dir);
    const outcome = await run();
    expect(outcome.exitCode).toBe(2);
    expect(fake.calls.filter((c) => c.method === 'POST')).toHaveLength(0);
    expect(outcome.refused).toMatch(/secret-shaped/);
    expect(log.join('\n')).not.toContain(leaked);
  });

  // CM-61 has three legs — check titles, check summaries, comment bodies — and each is proved on its
  // own: the secret reaches exactly one surface, so dropping that leg from the refusal goes red.
  const leaked = () => 'ghp_' + 'z'.repeat(36);
  function variant(edit: (files: { receiptJson: string; receiptMd: string; verdictJson: string }) => Partial<{ receiptJson: string; receiptMd: string; verdictJson: string }>): string {
    const dir = mkdtempSync(join(tmpdir(), 'sb-leg-'));
    cpSync(join(FIXTURES, 'run-qa-fail'), dir, { recursive: true });
    const files = { receiptJson: readFileSync(join(dir, 'receipt.json'), 'utf8'), receiptMd: readFileSync(join(dir, 'receipt.md'), 'utf8'), verdictJson: readFileSync(join(dir, 'verdict.json'), 'utf8') };
    const out = edit(files);
    if (out.receiptJson !== undefined) writeFileSync(join(dir, 'receipt.json'), out.receiptJson);
    if (out.receiptMd !== undefined) writeFileSync(join(dir, 'receipt.md'), out.receiptMd);
    if (out.verdictJson !== undefined) writeFileSync(join(dir, 'verdict.json'), out.verdictJson);
    return dir;
  }
  async function expectRefusedOnlyBy(dir: string, surface: RegExp) {
    const { fake, run, log } = harness(dir);
    const outcome = await run();
    expect(outcome.exitCode).toBe(2);
    expect(outcome.refused).toMatch(surface);
    expect(fake.calls.filter((c) => c.method === 'POST')).toHaveLength(0);
    expect(log.join('\n')).not.toContain(leaked());
  }

  it('CM-61 summary leg: a secret in a lineless finding, which reaches only the QA summary, is refused', async () => {
    const dir = variant(({ receiptJson }) => ({ receiptJson: receiptJson.replace('add a 401 case for it', `add a 401 case for it (token ${leaked()})`) }));
    await expectRefusedOnlyBy(dir, /^check summary: Secure Builder \/ QA /);
  });

  it('CM-61 comment leg: a secret in a finding on the diff, absent from receipt.md, reaches only the comment and is refused', async () => {
    const dir = variant(({ receiptJson }) => ({ receiptJson: receiptJson.replace('add an ownership check', `add an ownership check (token ${leaked()})`) }));
    await expectRefusedOnlyBy(dir, /^comment src\/api\/users\.ts:42 /);
  });

  it('CM-61 title leg: a secret in the gate reason that the truncated summary never reaches is refused', async () => {
    // The QA section of receipt.md is longer than a summary may be, so the summary is cut before its
    // "Reason:" line; the reason, and the secret in it, then reach only the check title.
    const filler = Array.from({ length: 800 }, (_, i) => `- note ${i}: ${'x'.repeat(90)}`).join('\n');
    const dir = variant(({ receiptMd, verdictJson }) => ({
      receiptMd: receiptMd.replace('- coverage_changed_lines: `91`', `- coverage_changed_lines: \`91\`\n${filler}`),
      verdictJson: verdictJson.replace('2 blocking findings:', `2 blocking findings (${leaked()}):`),
    }));
    await expectRefusedOnlyBy(dir, /^check title: Secure Builder \/ QA /);
  });

  it('with no pull request (a push), the checks are created and no comment endpoint is touched', async () => {
    const { fake, run } = harness(join(FIXTURES, 'run-qa-fail'));
    const outcome = await run(join(FIXTURES, 'run-qa-fail'), null);
    expect(outcome.exitCode).toBe(1);
    expect(fake.of(`POST ${R}/check-runs`)).toHaveLength(2);
    expect(fake.calls.some((c) => c.path.includes('/pulls/'))).toBe(false);
  });

  it('a run directory that cannot be read is exit 2 with the reason, nothing posted', async () => {
    const { fake, run, log } = harness(join(FIXTURES, 'nowhere'));
    const outcome = await run();
    expect(outcome.exitCode).toBe(2);
    expect(fake.calls).toHaveLength(0);
    expect(log.join('\n')).toMatch(/verdict\.json is missing/);
  });

  it('a check run GitHub refuses is exit 2 and says which; a refused comment is reported and the run goes on', async () => {
    const refusedCheck = harness(join(FIXTURES, 'run-qa-fail'), { [`POST ${R}/check-runs`]: { status: 403, json: { message: 'Resource not accessible by integration' } } });
    const a = await refusedCheck.run();
    expect(a.exitCode).toBe(2);
    expect(refusedCheck.log.join('\n')).toMatch(/checks: write/);
    const refusedComment = harness(join(FIXTURES, 'run-qa-fail'), { [`POST ${R}/pulls/7/comments`]: { status: 422, json: { message: 'line must be part of the diff' } } });
    const b = await refusedComment.run();
    expect(b.exitCode).toBe(1);
    expect(refusedComment.fake.of(`POST ${R}/check-runs`)).toHaveLength(2);
    expect(refusedComment.log.join('\n')).toMatch(/could not post/);
  });

  it('exits 0 when every gate passed, and treats a yellow gate as not red', async () => {
    const { run } = harness(join(FIXTURES, 'run-qa-yellow'));
    expect((await run(join(FIXTURES, 'run-qa-yellow'), 7, YELLOW_HEAD)).exitCode).toBe(0);
  });

  it('refuses a run whose receipt head is not the sha the checks would be posted to: exit 2, nothing reaches GitHub (B-02)', async () => {
    const { fake, run, log } = harness(join(FIXTURES, 'run-qa-fixed'));
    const outcome = await run(join(FIXTURES, 'run-qa-fixed'), 7, 'b'.repeat(40));
    expect(outcome.exitCode).toBe(2);
    expect(fake.calls).toHaveLength(0);
    expect(log.join('\n')).toMatch(/receipt\.json head is 7474ee10b8af.*not bbbbbbbbbbbb/);
  });
});

describe('the head a run is published to', () => {
  // An empty head used to match a receipt that names none (adapter-github gate run 2, N-03).
  it('refuses an empty head even when the receipt names no head either, and posts nothing', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sb-nohead-'));
    cpSync(join(FIXTURES, 'run-qa-fail'), dir, { recursive: true });
    const receipt = JSON.parse(readFileSync(join(dir, 'receipt.json'), 'utf8')) as Record<string, unknown>;
    receipt.head = '';
    writeFileSync(join(dir, 'receipt.json'), JSON.stringify(receipt));
    const { fake, run, log } = harness(dir);
    const outcome = await run(dir, 7, '');
    expect(outcome.exitCode).toBe(2);
    expect(fake.of(`POST ${R}/check-runs`)).toHaveLength(0);
    expect(log.join('\n')).toMatch(/no head sha/);
  });
});

describe('the refusal decision', () => {
  it('names the first piece that is secret-shaped and null for a clean plan', () => {
    expect(refusal([['check summary: QA', 'clean'], ['comment src/x.ts:1', 'AKIA' + 'Q'.repeat(16)]])).toMatch(/comment src\/x\.ts:1/);
    expect(refusal([['a', 'clean']])).toBeNull();
  });
});
