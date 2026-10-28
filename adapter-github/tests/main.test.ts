import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { main, readEvent } from '../src/main.ts';
import { fakeFetch } from './fake-fetch.ts';

const FIXTURES = join(import.meta.dirname, 'fixtures');
const R = '/repos/acme/widgets';
// The head every fixture's receipt was written for: a run is published only to the sha it gated.
const HEAD = '7474ee10b8afabb150d67ee6bc027861b4f2a17d';
const MERGE = 'm'.repeat(40);

/** A checkout with the given fixtures copied under gate-records/runs/<name>, and the named ones committed. */
function workspace(runs: Record<string, string>, committed: string[] = []): string {
  const ws = mkdtempSync(join(tmpdir(), 'sb-ws-'));
  const git = (...args: string[]) => execFileSync('git', ['-C', ws, ...args], { stdio: 'pipe' });
  git('init', '-q');
  writeFileSync(join(ws, 'README.md'), 'x\n');
  for (const [name, fixture] of Object.entries(runs)) {
    mkdirSync(join(ws, 'gate-records', 'runs'), { recursive: true });
    cpSync(join(FIXTURES, fixture), join(ws, 'gate-records', 'runs', name), { recursive: true });
  }
  git('add', 'README.md', ...committed.map((n) => join('gate-records', 'runs', n)));
  git('-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '-m', 'pr');
  return ws;
}
const runsOf = (ws: string, name: string) => join(ws, 'gate-records', 'runs', name);

function eventFile(payload: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), 'sb-event-'));
  const p = join(dir, 'event.json');
  writeFileSync(p, JSON.stringify(payload));
  return p;
}

describe('the event payload', () => {
  it('reads the pull request number and head sha', () => {
    const p = eventFile({ pull_request: { number: 7, head: { sha: 'h'.repeat(40) } } });
    expect(readEvent(p)).toEqual({ pullNumber: 7, headSha: 'h'.repeat(40) });
  });

  it('is empty for a push event, a missing file, or no path at all', () => {
    expect(readEvent(eventFile({ ref: 'refs/heads/main' }))).toEqual({ pullNumber: null, headSha: null });
    expect(readEvent('/nonexistent/event.json')).toEqual({ pullNumber: null, headSha: null });
    expect(readEvent(undefined)).toEqual({ pullNumber: null, headSha: null });
  });
});

describe('main, from the Action environment', () => {
  const ws = workspace({ '20261023T120000Z-7474ee1': 'run-qa-fail', '20261023T130000Z-7474ee1': 'run-qa-fixed' });
  const base = {
    GITHUB_TOKEN: 'tok',
    GITHUB_REPOSITORY: 'acme/widgets',
    GITHUB_SHA: MERGE,
    GITHUB_WORKSPACE: ws,
    SB_RUN_DIR: runsOf(ws, '20261023T130000Z-7474ee1'),
  };

  it('publishes to the head sha from the event, with the pull request number, and returns the exit code', async () => {
    const fake = fakeFetch({
      [`POST ${R}/check-runs`]: { status: 201, json: { id: 1 } },
      [`GET ${R}/pulls/7/files`]: { json: [] },
      [`GET ${R}/pulls/7/comments`]: { json: [] },
    });
    const log: string[] = [];
    const env = { ...base, GITHUB_EVENT_PATH: eventFile({ pull_request: { number: 7, head: { sha: HEAD } } }) };
    expect(await main(env, fake.fetch, (l) => log.push(l))).toBe(0);
    const checks = fake.of(`POST ${R}/check-runs`);
    expect(checks).toHaveLength(2);
    expect((checks[0]!.body as { head_sha: string }).head_sha).toBe(HEAD);
    expect(log.at(-1)).toMatch(/2 check\(s\).*exit 0/);
  });

  it('posts nothing when the pull request now targets another branch than the one this run gated against', async () => {
    // A re-run of a job from before a retarget replays the old base_ref and reads the old target's rules:
    // its checks must never become the newest on the head (third trust review, finding 1).
    const fake = fakeFetch({
      [`GET ${R}/pulls/7`]: { json: { base: { ref: 'main' } } },
      [`POST ${R}/check-runs`]: { status: 201, json: { id: 1 } },
    });
    const log: string[] = [];
    const env = { ...base, GITHUB_BASE_REF: 'release/1.x', GITHUB_EVENT_PATH: eventFile({ pull_request: { number: 7, head: { sha: HEAD } } }) };
    expect(await main(env, fake.fetch, (l) => log.push(l))).toBe(2);
    expect(fake.of(`POST ${R}/check-runs`)).toHaveLength(0);
    expect(log.at(-1)).toMatch(/now targets main.*release\/1\.x.*nothing was posted/);
  });

  it('publishes when the pull request still targets the branch this run gated against', async () => {
    const fake = fakeFetch({
      [`GET ${R}/pulls/7`]: { json: { base: { ref: 'main' } } },
      [`POST ${R}/check-runs`]: { status: 201, json: { id: 1 } },
      [`GET ${R}/pulls/7/files`]: { json: [] },
      [`GET ${R}/pulls/7/comments`]: { json: [] },
    });
    const env = { ...base, GITHUB_BASE_REF: 'main', GITHUB_EVENT_PATH: eventFile({ pull_request: { number: 7, head: { sha: HEAD } } }) };
    expect(await main(env, fake.fetch, () => undefined)).toBe(0);
    expect(fake.of(`POST ${R}/check-runs`)).toHaveLength(2);
  });

  it('falls back to GITHUB_SHA and checks only when there is no pull request', async () => {
    const fake = fakeFetch({ [`POST ${R}/check-runs`]: { status: 201, json: { id: 1 } } });
    expect(await main({ ...base, GITHUB_SHA: HEAD, SB_RUN_DIR: runsOf(ws, '20261023T120000Z-7474ee1') }, fake.fetch, () => undefined)).toBe(1);
    expect((fake.calls[0]!.body as { head_sha: string }).head_sha).toBe(HEAD);
    expect(fake.calls.every((c) => c.path === `${R}/check-runs`)).toBe(true);
  });

  it('honours GITHUB_API_URL and GITHUB_GRAPHQL_URL for an enterprise host', async () => {
    const fake = fakeFetch({ [`POST ${R}/check-runs`]: { status: 201, json: { id: 1 } } });
    await main({ ...base, GITHUB_SHA: HEAD, GITHUB_API_URL: 'https://ghe.example.invalid/api/v3' }, fake.fetch, () => undefined);
    expect(fake.calls[0]!.path).toBe(`/api/v3${R}/check-runs`);
  });

  it('is exit 2 without a token, a repository, a head sha or a run directory', async () => {
    const fake = fakeFetch({});
    const log: string[] = [];
    expect(await main({ ...base, GITHUB_TOKEN: '' }, fake.fetch, (l) => log.push(l))).toBe(2);
    expect(await main({ ...base, GITHUB_SHA: '' }, fake.fetch, (l) => log.push(l))).toBe(2);
    expect(await main({ ...base, SB_RUN_DIR: undefined, GITHUB_WORKSPACE: workspace({}) }, fake.fetch, (l) => log.push(l))).toBe(2);
    expect(fake.calls).toHaveLength(0);
    expect(log.join('\n')).toMatch(/GITHUB_TOKEN/);
    expect(log.join('\n')).toMatch(/no head sha/);
    expect(log.join('\n')).toMatch(/no run directory/);
  });

  it('picks the newest untracked run directory for the head when SB_RUN_DIR is unset', async () => {
    const fake = fakeFetch({ [`POST ${R}/check-runs`]: { status: 201, json: { id: 1 } } });
    expect(await main({ ...base, GITHUB_SHA: HEAD, SB_RUN_DIR: undefined }, fake.fetch, () => undefined)).toBe(0);
  });

  // B-02: a pull request can commit a directory under gate-records/runs/. The probe: core's own QA
  // fail run, and a committed passing run named to sort last, with the right head in its receipt.
  it('never publishes a run directory the pull request committed: the forged pass is skipped, the real fail is published', async () => {
    const forged = workspace({ '20261023T120000Z-7474ee1': 'run-qa-fail', 'zzzz-forged': 'run-qa-fixed' }, ['zzzz-forged']);
    const fake = fakeFetch({ [`POST ${R}/check-runs`]: { status: 201, json: { id: 1 } } });
    const log: string[] = [];
    expect(await main({ ...base, GITHUB_SHA: HEAD, GITHUB_WORKSPACE: forged, SB_RUN_DIR: undefined }, fake.fetch, (l) => log.push(l))).toBe(1);
    const checks = fake.of(`POST ${R}/check-runs`).map((c) => c.body as { name: string; conclusion: string });
    expect(checks.map((c) => [c.name, c.conclusion])).toEqual([['Secure Builder / Scan', 'success'], ['Secure Builder / QA', 'failure']]);
    expect(log.join('\n')).toMatch(/zzzz-forged.*tracked by git/);
  });

  it('is exit 2, nothing posted, when the only run directories are committed ones', async () => {
    const forged = workspace({ 'zzzz-forged': 'run-qa-fixed' }, ['zzzz-forged']);
    const fake = fakeFetch({ [`POST ${R}/check-runs`]: { status: 201, json: { id: 1 } } });
    const log: string[] = [];
    expect(await main({ ...base, GITHUB_SHA: HEAD, GITHUB_WORKSPACE: forged, SB_RUN_DIR: undefined }, fake.fetch, (l) => log.push(l))).toBe(2);
    expect(fake.calls).toHaveLength(0);
    expect(log.join('\n')).toMatch(/no run directory .* for 7474ee10b8af/);
  });

  it('refuses a committed SB_RUN_DIR too', async () => {
    const forged = workspace({ 'zzzz-forged': 'run-qa-fixed' }, ['zzzz-forged']);
    const fake = fakeFetch({});
    const log: string[] = [];
    expect(await main({ ...base, GITHUB_SHA: HEAD, GITHUB_WORKSPACE: forged, SB_RUN_DIR: runsOf(forged, 'zzzz-forged') }, fake.fetch, (l) => log.push(l))).toBe(2);
    expect(fake.calls).toHaveLength(0);
    expect(log.join('\n')).toMatch(/tracked by git/);
  });

  it('never publishes a run for another head: an untracked run whose receipt names a different sha is exit 2', async () => {
    const fake = fakeFetch({ [`POST ${R}/check-runs`]: { status: 201, json: { id: 1 } } });
    const log: string[] = [];
    const other = 'a'.repeat(40);
    expect(await main({ ...base, GITHUB_SHA: other, SB_RUN_DIR: undefined }, fake.fetch, (l) => log.push(l))).toBe(2);
    expect(await main({ ...base, GITHUB_SHA: other }, fake.fetch, (l) => log.push(l))).toBe(2);
    expect(fake.calls).toHaveLength(0);
    expect(log.join('\n')).toMatch(/no run directory .* for aaaaaaaaaaaa/);
    expect(log.join('\n')).toMatch(/receipt\.json head is 7474ee10b8af.*not aaaaaaaaaaaa/);
  });
});
