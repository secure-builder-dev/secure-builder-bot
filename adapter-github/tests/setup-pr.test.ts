import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { GitHubClient } from '../src/github-api.ts';
import { SetupBranchExists, openSetupPr } from '../src/setup-pr.ts';
import { BOT_ACTION, CONFIG_PATH, MODEL_KEY_SECRET, SETUP_BRANCH, WORKFLOW_PATH, configTemplate, setupFiles, setupPrBody, validateAnswers, workflowTemplate, type SetupAnswers } from '../src/templates.ts';
import { fakeFetch } from './fake-fetch.ts';
import { parseYaml } from './yaml.ts';

const CORE_RUN = resolve(import.meta.dirname, '..', '..', 'core', 'run');
const light: SetupAnswers = { profile: 'il4', gates: ['scan', 'qa'], sentinel: 'off' };
const full: SetupAnswers = { profile: 'il6', gates: ['scan', 'qa', 'sentinel'], sentinel: 'action' };

function coreConfigCheck(text: string): { status: number | null; out: string } {
  const dir = mkdtempSync(join(tmpdir(), 'sb-cfg-'));
  writeFileSync(join(dir, CONFIG_PATH), text);
  const r = spawnSync(CORE_RUN, ['config', 'check', '--config', join(dir, CONFIG_PATH)], { encoding: 'utf8' });
  return { status: r.status, out: r.stdout + r.stderr };
}

describe('.securebuilderbot.yml from the three answers', () => {
  it('for il4, scan and qa, sentinel off: parses with core/run config check and names no secret', () => {
    const text = configTemplate(light);
    const r = coreConfigCheck(text);
    expect(r.out).toMatch(/config ok: profile il4 .*gates scan, qa/);
    expect(r.status).toBe(0);
    expect(text).not.toContain('sentinel:');
    expect(text).not.toContain('key_secret');
    expect(parseYaml(text)).toEqual({ profile: 'il4', gates: ['scan', 'qa'], version: 'latest' });
  });

  it('puts a comment above every line that is not one', () => {
    const lines = configTemplate(full).split('\n').filter((l) => l.trim() !== '');
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i]!;
      if (line.trimStart().startsWith('#')) continue;
      expect(lines[i - 1]?.trimStart().startsWith('#'), `a comment above: ${line}`).toBe(true);
    }
  });

  it('with sentinel on: the sentinel block names the secret SB_MODEL_KEY, and core accepts it', () => {
    const text = configTemplate(full);
    expect(text).toContain('key_secret: SB_MODEL_KEY');
    expect(parseYaml(text)).toMatchObject({ profile: 'il6', gates: ['scan', 'qa', 'sentinel'], sentinel: { provider: 'anthropic', key_secret: MODEL_KEY_SECRET } });
    expect(coreConfigCheck(text).status).toBe(0);
  });

  it('keeps the gates and the sentinel answer consistent, and says so in a comment', () => {
    const off = configTemplate({ profile: 'il4', gates: ['scan', 'qa', 'sentinel'], sentinel: 'off' });
    expect(parseYaml(off)).toMatchObject({ gates: ['scan', 'qa'] });
    expect(off).toMatch(/#.*sentinel is off/);
    const on = configTemplate({ profile: 'il4', gates: ['scan'], sentinel: 'self-hosted' });
    expect(parseYaml(on)).toMatchObject({ gates: ['scan', 'sentinel'] });
    expect(coreConfigCheck(on).status).toBe(0);
  });

  it('warns against turning scan off, as the PRD says the setup PR does', () => {
    expect(configTemplate({ profile: 'none', gates: ['qa'], sentinel: 'off' })).toMatch(/#.*scan is off/i);
    expect(configTemplate(light)).not.toMatch(/scan is off/i);
  });

  it('pins a release when one is given', () => {
    expect(parseYaml(configTemplate({ ...light, version: '1.4.2' }))).toMatchObject({ version: '1.4.2' });
  });

  it('refuses answers that are not the three questions', () => {
    expect(() => validateAnswers({ profile: 'il9', gates: ['scan'], sentinel: 'off' } as unknown as SetupAnswers)).toThrow(/profile/);
    expect(() => validateAnswers({ profile: 'il4', gates: [], sentinel: 'off' })).toThrow(/gates/);
    expect(() => validateAnswers({ profile: 'il4', gates: ['scan', 'lint'], sentinel: 'off' } as unknown as SetupAnswers)).toThrow(/lint/);
    expect(() => validateAnswers({ profile: 'il4', gates: ['scan'], sentinel: 'maybe' } as unknown as SetupAnswers)).toThrow(/sentinel/);
    expect(() => validateAnswers({ ...light, version: 'v1' })).toThrow(/version/);
  });
});

describe('the workflow file', () => {
  type Job = { needs?: string; if?: string; 'runs-on': unknown; permissions: unknown; steps: { uses?: string; with?: Record<string, unknown>; env?: unknown }[] };
  const jobsOf = (text: string) => (parseYaml(text) as { jobs: Record<string, Job> }).jobs;

  it('runs on pull_request in two jobs: the pull request\'s code with read access only, the verdict with the write token', () => {
    const wf = parseYaml(workflowTemplate(light)) as Record<string, unknown> & { permissions: unknown; jobs: Record<string, Job> };
    // PyYAML reads the key `on` as YAML 1.1's boolean true; GitHub reads it as `on`.
    expect(wf.on ?? wf.true).toEqual({ pull_request: { types: ['opened', 'synchronize', 'reopened', 'edited'] } });
    expect(wf.permissions).toEqual({ contents: 'read' });
    expect(Object.keys(wf.jobs)).toEqual(['gates', 'verdict']);
    const { gates, verdict } = wf.jobs as { gates: Job; verdict: Job };
    expect(gates.permissions).toEqual({ contents: 'read' });
    expect(verdict.permissions).toEqual({ contents: 'read', checks: 'write', 'pull-requests': 'write' });
    expect(verdict.needs).toBe('gates');
    for (const [job, part] of [[gates, 'untrusted'], [verdict, 'trusted']] as const) {
      expect(job.steps[0]!.uses).toMatch(/^actions\/checkout@[0-9a-f]{40}$/);
      expect(job.steps[0]!.with?.['persist-credentials']).toBe(false);
      expect(job.steps[1]!.uses).toBe('secure-builder-dev/secure-builder-bot/adapter-github@v0');
      expect(job.steps[1]!.with).toMatchObject({ version: 'latest', part });
    }
  });

  it('never gives the job that runs the pull request\'s code a secret, whatever the answers', () => {
    for (const answers of [light, full, { ...full, sentinel: 'self-hosted' as const }]) {
      const gates = jobsOf(workflowTemplate(answers)).gates!;
      expect(JSON.stringify(gates)).not.toMatch(/secrets\.|model-key|token/i);
      expect(gates.permissions).toEqual({ contents: 'read' });
    }
    // GitHub-hosted unless the user chose their own runner, which is then named as having to be ephemeral:
    // a runner with no hosted pool (an air-gapped instance) must still pick the job up.
    expect(jobsOf(workflowTemplate(full)).gates!['runs-on']).toBe('ubuntu-latest');
    const selfHosted = workflowTemplate({ ...full, sentinel: 'self-hosted' });
    expect(jobsOf(selfHosted).gates!['runs-on']).toEqual(['self-hosted']);
    expect(selfHosted).toMatch(/must be ephemeral/);
  });

  it('runs one pipeline per pull request, cancelling the older run, and re-runs on an edit only when the base changed', () => {
    const wf = parseYaml(workflowTemplate(light)) as { concurrency: unknown; jobs: Record<string, { if?: string }> };
    // A retarget starts a second run on the same head sha: the older run, against the old target's
    // rules, must never finish last and post the newest checks (second trust review, finding 1).
    // A title or body edit gets a group of its own, so its skipped job can never cancel a real run.
    expect(wf.concurrency).toEqual({ group: "${{ (github.event.action == 'edited' && !github.event.changes.base) && format('secure-builder-noop-{0}', github.run_id) || format('secure-builder-{0}', github.event.pull_request.number) }}", 'cancel-in-progress': true });
    expect(Object.values(wf.jobs)[0]!.if).toBe("github.event.action != 'edited' || github.event.changes.base");
    // The verdict job runs after a red gates job (it publishes the red), but never after a cancel.
    expect(Object.values(wf.jobs)[1]!.if).toBe("${{ !cancelled() && (github.event.action != 'edited' || github.event.changes.base) }}");
  });

  it('comments every third-party pin with its version and matches the config version', () => {
    const text = workflowTemplate({ ...light, version: '1.4.2' });
    for (const line of text.split('\n').filter((l) => /uses: actions\//.test(l))) expect(line).toMatch(/@[0-9a-f]{40} # v\d+\.\d+\.\d+/);
    expect(text).toMatch(/version: 1\.4\.2/);
  });

  it('hands the model key to the verdict job only when sentinel runs in the Action, and runs that job self-hosted when asked', () => {
    expect(workflowTemplate(light)).not.toContain('SB_MODEL_KEY');
    // N-08: the key goes in as an input, never as env on the composite step, where every step of the
    // action (pip install, npm ci, the publisher) would see it; the comment claims only what is true.
    const bot = jobsOf(workflowTemplate(full)).verdict!.steps.find((st) => st.uses === BOT_ACTION)!;
    expect(bot.with).toMatchObject({ 'model-key': '${{ secrets.SB_MODEL_KEY }}' });
    expect(bot.env).toBeUndefined();
    expect(workflowTemplate(full)).toContain('model-key: ${{ secrets.SB_MODEL_KEY }}');
    expect(workflowTemplate(full)).not.toMatch(/Only Sentinel sees it/);
    expect(jobsOf(workflowTemplate({ ...full, sentinel: 'self-hosted' })).verdict!['runs-on']).toEqual(['self-hosted']);
  });
});

describe('opening the setup pull request', () => {
  const R = '/repos/acme/widgets';
  function routes(over: Record<string, unknown> = {}) {
    return fakeFetch({
      [`GET ${R}`]: { json: { default_branch: 'main' } },
      [`GET ${R}/git/ref/heads/main`]: { json: { object: { sha: 'base0' } } },
      [`GET ${R}/git/commits/base0`]: { json: { tree: { sha: 'tree0' } } },
      [`POST ${R}/git/blobs`]: (call) => ({ status: 201, json: { sha: `blob-${String((call.body as { content: string }).content.length)}` } }),
      [`POST ${R}/git/trees`]: { status: 201, json: { sha: 'tree1' } },
      [`POST ${R}/git/commits`]: { status: 201, json: { sha: 'commit1' } },
      [`GET ${R}/git/ref/heads/${SETUP_BRANCH}`]: { status: 404, json: { message: 'Not Found' } },
      [`POST ${R}/git/refs`]: { status: 201, json: { ref: `refs/heads/${SETUP_BRANCH}` } },
      [`GET ${R}/pulls`]: { json: [] },
      [`POST ${R}/pulls`]: { status: 201, json: { number: 42, html_url: 'https://example.invalid/pull/42' } },
      ...(over as Record<string, never>),
    });
  }

  it('adds a drafted control list when the default branch has none, and never replaces one that is there', async () => {
    const M = 'docs/security/CONTROL-MANIFEST.md';
    const draft = { path: M, content: '| id | control | implementation | required artifact | proving test | note |\n' };
    const none = routes({ [`GET ${R}/contents/${M}`]: { status: 404, json: { message: 'Not Found' } } });
    const added = await openSetupPr(new GitHubClient({ token: 't', repo: 'acme/widgets', fetch: none.fetch }), 'acme/widgets', light, { extraFiles: [draft] });
    expect((none.of(`POST ${R}/git/trees`)[0]!.body as { tree: { path: string }[] }).tree.map((t) => t.path)).toEqual([CONFIG_PATH, WORKFLOW_PATH, M]);
    expect(none.of(`GET ${R}/contents/${M}`)[0]!.query).toBe('ref=main');
    expect(added.files).toEqual([CONFIG_PATH, WORKFLOW_PATH, M]);
    const there = routes({ [`GET ${R}/contents/${M}`]: { json: { type: 'file' } } });
    const kept = await openSetupPr(new GitHubClient({ token: 't', repo: 'acme/widgets', fetch: there.fetch }), 'acme/widgets', light, { extraFiles: [draft] });
    expect((there.of(`POST ${R}/git/trees`)[0]!.body as { tree: { path: string }[] }).tree.map((t) => t.path)).toEqual([CONFIG_PATH, WORKFLOW_PATH]);
    expect(kept.files).toEqual([CONFIG_PATH, WORKFLOW_PATH]);
  });

  it('creates blobs, a tree on the default branch, a commit, the branch and the pull request, with the templates as content', async () => {
    const fake = routes();
    const client = new GitHubClient({ token: 't', repo: 'acme/widgets', fetch: fake.fetch });
    const result = await openSetupPr(client, 'acme/widgets', light);
    expect(result).toMatchObject({ created: true, branch: SETUP_BRANCH, commit: 'commit1', pull: { number: 42 } });
    const blobs = fake.of(`POST ${R}/git/blobs`).map((c) => (c.body as { content: string }).content);
    expect(blobs).toEqual(setupFiles(light).map((f) => f.content));
    expect(blobs[0]).toBe(configTemplate(light));
    expect(blobs[1]).toBe(workflowTemplate(light));
    const tree = fake.of(`POST ${R}/git/trees`)[0]!.body as { base_tree: string; tree: { path: string; sha: string; mode: string }[] };
    expect(tree.base_tree).toBe('tree0');
    expect(tree.tree.map((t) => t.path)).toEqual([CONFIG_PATH, WORKFLOW_PATH]);
    expect(fake.of(`POST ${R}/git/commits`)[0]!.body).toMatchObject({ tree: 'tree1', parents: ['base0'], message: expect.stringMatching(/^Enable Secure Builder/) });
    expect(fake.of(`POST ${R}/git/refs`)[0]!.body).toEqual({ ref: `refs/heads/${SETUP_BRANCH}`, sha: 'commit1' });
    const pr = fake.of(`POST ${R}/pulls`)[0]!.body as { title: string; head: string; base: string; body: string };
    expect(pr).toMatchObject({ title: 'Enable Secure Builder', head: SETUP_BRANCH, base: 'main' });
    expect(pr.body).toBe(setupPrBody(light));
    expect(pr.body).toMatch(/il4/);
    expect(pr.body).toMatch(/scan.*qa/);
    expect(pr.body).toMatch(/[Nn]othing runs until/);
  });

  it('refuses to move a setup branch that already exists, writing nothing, unless told to replace it (gate cli run 1, B-01)', async () => {
    const fake = routes({ [`GET ${R}/git/ref/heads/${SETUP_BRANCH}`]: { json: { object: { sha: 'usercommit' } } } });
    const client = new GitHubClient({ token: 't', repo: 'acme/widgets', fetch: fake.fetch });
    const refusal = openSetupPr(client, 'acme/widgets', full);
    await expect(refusal).rejects.toThrow(SetupBranchExists);
    await expect(openSetupPr(client, 'acme/widgets', full, { replaceBranch: false })).rejects.toThrow(/secure-builder\/enable already exists/);
    expect(fake.calls.filter((c) => c.method !== 'GET')).toEqual([]);
  });

  it('with replaceBranch, finds the branch and the open pull request and updates both, never duplicating', async () => {
    const fake = routes({
      [`GET ${R}/git/ref/heads/${SETUP_BRANCH}`]: { json: { object: { sha: 'old' } } },
      [`PATCH ${R}/git/refs/heads/${SETUP_BRANCH}`]: { json: { ref: `refs/heads/${SETUP_BRANCH}` } },
      [`GET ${R}/pulls`]: { json: [{ number: 42, html_url: 'https://example.invalid/pull/42' }] },
      [`PATCH ${R}/pulls/42`]: { json: { number: 42, html_url: 'https://example.invalid/pull/42' } },
    });
    const client = new GitHubClient({ token: 't', repo: 'acme/widgets', fetch: fake.fetch });
    const result = await openSetupPr(client, 'acme/widgets', full, { replaceBranch: true });
    expect(result.created).toBe(false);
    expect(fake.of(`POST ${R}/git/refs`)).toHaveLength(0);
    expect(fake.of(`POST ${R}/pulls`)).toHaveLength(0);
    expect(fake.of(`PATCH ${R}/git/refs/heads/${SETUP_BRANCH}`)[0]!.body).toEqual({ sha: 'commit1', force: true });
    expect(fake.of(`PATCH ${R}/pulls/42`)[0]!.body).toMatchObject({ title: 'Enable Secure Builder' });
    expect(fake.of(`GET ${R}/pulls`)[0]!.query).toContain(`head=acme%3A${encodeURIComponent(SETUP_BRANCH)}`);
  });

  it('refuses a repository that is not the client\'s, and answers that are not valid', async () => {
    const client = new GitHubClient({ token: 't', repo: 'acme/widgets', fetch: routes().fetch });
    await expect(openSetupPr(client, 'other/repo', light)).rejects.toThrow(/other\/repo/);
    await expect(openSetupPr(client, 'acme/widgets', { ...light, gates: [] })).rejects.toThrow(/gates/);
  });
});
