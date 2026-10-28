import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { main } from '../src/main.ts';
import { BOT_ACTION, workflowTemplate } from '../src/templates.ts';
import { fakeFetch } from './fake-fetch.ts';
import { parseYaml } from './yaml.ts';

const ROOT = join(import.meta.dirname, '..');
const read = (name: string) => readFileSync(join(ROOT, name), 'utf8');
const SHA_PIN = /^[0-9a-f]{40}$/;

interface Step { name?: string; uses?: string; run?: string; if?: string; shell?: string; with?: Record<string, unknown>; env?: Record<string, unknown> }

describe('action.yml, the composite action', () => {
  const text = read('action.yml');
  const action = parseYaml(text) as { runs: { using: string; steps: Step[] }; inputs: Record<string, { default?: unknown; description?: string }> };

  it('is valid YAML, composite, with the three inputs and their defaults', () => {
    expect(action.runs.using).toBe('composite');
    expect(action.inputs.version?.default).toBe('latest');
    expect(action.inputs['python-version']?.default).toBe('3.12');
    expect(action.inputs.base).toBeDefined();
    expect(action.inputs.token?.default).toBe('${{ github.token }}');
  });

  it('pins every third-party action by a 40-hex commit with the version beside it', () => {
    const uses = action.runs.steps.map((s) => s.uses).filter((u): u is string => typeof u === 'string');
    expect(uses.length).toBeGreaterThanOrEqual(3);
    for (const u of uses) {
      expect(u.split('@')[1]).toMatch(SHA_PIN);
      const line = text.split('\n').find((l) => l.includes(`uses: ${u}`));
      expect(line, u).toMatch(/ # v\d+\.\d+\.\d+$/);
    }
  });

  it('runs core, then the publisher, then the artifact upload, each even when an earlier step failed', () => {
    const runs = action.runs.steps.filter((s) => typeof s.run === 'string');
    const core = runs.find((s) => /core\/run"? run --base/.test(s.run!))!;
    expect(core).toBeDefined();
    expect(core.run).toMatch(/--base .*--head .*--config \.securebuilderbot\.yml/);
    expect(runs.every((s) => s.shell === 'bash')).toBe(true);
    // The rules are the target branch's tip as fetched now, never the event's base.sha snapshot, which a
    // re-run replays after the target has revoked an exception (second trust review, finding 1).
    expect(core.run).toContain('--config-ref "refs/remotes/origin/$SB_BASE_REF"');
    expect((core as { env?: Record<string, string> }).env?.SB_BASE_REF).toBe('${{ github.base_ref }}');
    const after = action.runs.steps.slice(action.runs.steps.indexOf(core) + 1);
    expect(after.some((s) => s.run?.includes('npm ci') && s.run.includes('tsx src/main.ts'))).toBe(true);
    expect(after.some((s) => s.uses?.startsWith('actions/upload-artifact@'))).toBe(true);
    for (const s of after) expect(s.if, JSON.stringify(s)).toMatch(/always\(\)/);
  });

  it('never interpolates ${{ }} inside a run: script, so no context value can become shell code', () => {
    const runs = action.runs.steps.map((s) => s.run).filter((r): r is string => typeof r === 'string');
    expect(runs.length).toBeGreaterThanOrEqual(3);
    for (const r of runs) expect(r, r).not.toContain('${{');
  });

  // N-08: the model key is an input, and only the step that runs core is given it, under the name the
  // config's sentinel.key_secret holds. Install, publish and upload steps never see it.
  it('takes the model key as an input and hands it to the core step only', () => {
    expect(action.inputs['model-key']?.default).toBe('');
    expect(action.inputs['model-key-name']?.default).toBe('SB_MODEL_KEY');
    const keyed = action.runs.steps.filter((s) => JSON.stringify(s).includes('inputs.model-key'));
    expect(keyed).toHaveLength(1);
    expect(keyed[0]!.run).toMatch(/core\/run"? run --base/);
    expect(keyed[0]!.run).toMatch(/export "\$SB_MODEL_KEY_NAME=\$SB_MODEL_KEY_VALUE"/);
  });

  it('the core step exports the key under the configured name only, and refuses a name already in the environment', () => {
    const core = action.runs.steps.find((s) => typeof s.run === 'string' && /core\/run"? run --base/.test(s.run))!;
    const bot = mkdtempSync(join(tmpdir(), 'sb-action-'));
    mkdirSync(join(bot, 'core'));
    mkdirSync(join(bot, 'adapter-github'));
    // The fake core prints what it was handed: the key under its name, and whether the input leaked.
    writeFileSync(join(bot, 'core', 'run'), '#!/usr/bin/env bash\necho "key=${SB_MODEL_KEY:-} other=${MY_KEY:-} raw=${SB_MODEL_KEY_VALUE:-unset}"\n');
    chmodSync(join(bot, 'core', 'run'), 0o755);
    const step = (extra: Record<string, string>) => {
      const env: Record<string, string> = { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', SB_BASE: 'b', SB_HEAD: 'h', SB_ACTION_PATH: join(bot, 'adapter-github'), SB_MODEL_KEY_NAME: 'SB_MODEL_KEY', RUNNER_TEMP: bot, GITHUB_OUTPUT: join(bot, 'output'), ...extra };
      return spawnSync('bash', ['-e', '-c', core.run!], { env, encoding: 'utf8', cwd: bot });
    };
    expect(step({ SB_MODEL_KEY_VALUE: 'k1' }).stdout.trim()).toBe('key=k1 other= raw=unset');
    expect(step({ SB_MODEL_KEY_VALUE: 'k2', SB_MODEL_KEY_NAME: 'MY_KEY' }).stdout.trim()).toBe('key= other=k2 raw=unset');
    expect(step({ SB_MODEL_KEY_VALUE: '' }).stdout.trim()).toBe('key= other= raw=unset');
    for (const name of ['PATH', 'lower_case', 'SB_MODEL_KEY; id']) {
      const refused = step({ SB_MODEL_KEY_VALUE: 'k3', SB_MODEL_KEY_NAME: name });
      expect(refused.status, name).toBe(2);
      expect(refused.stdout, name).toBe('');
      expect(refused.stderr).toMatch(/model-key-name must name a CI secret/);
    }
  });

  // The workflow the setup pull request writes runs the action twice: part untrusted where the pull
  // request's code runs (Scan, QA), part trusted where the verdict is decided and published.
  describe('the two parts', () => {
    const core = () => action.runs.steps.find((s) => typeof s.run === 'string' && /core\/run"? run --base/.test(s.run))!;
    const coreArgs = (extra: Record<string, string>) => {
      const bot = mkdtempSync(join(tmpdir(), 'sb-part-'));
      mkdirSync(join(bot, 'core'));
      mkdirSync(join(bot, 'adapter-github'));
      writeFileSync(join(bot, 'core', 'run'), '#!/usr/bin/env bash\necho "args=$*"\n');
      chmodSync(join(bot, 'core', 'run'), 0o755);
      const env: Record<string, string> = { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', SB_BASE: 'b', SB_HEAD: 'h', SB_ACTION_PATH: join(bot, 'adapter-github'), SB_MODEL_KEY_NAME: 'SB_MODEL_KEY', SB_MODEL_KEY_VALUE: '', SB_UNTRUSTED_DIR: '/runner/tmp/securebuilderbot-untrusted', RUNNER_TEMP: bot, GITHUB_OUTPUT: join(bot, 'output'), ...extra };
      return spawnSync('bash', ['-e', '-c', core().run!], { env, encoding: 'utf8', cwd: bot });
    };
    const step = (pred: (s: Step) => boolean) => action.runs.steps.filter(pred);

    it('passes the part to core, and a whole run when none is named', () => {
      expect(action.inputs.part?.default).toBe('');
      expect(coreArgs({ SB_PART: '' }).stdout).not.toContain('--part');
      expect(coreArgs({ SB_PART: 'untrusted' }).stdout).toContain('--config .securebuilderbot.yml --part untrusted');
      expect(coreArgs({ SB_PART: 'trusted' }).stdout).toContain('--part trusted --untrusted-run /runner/tmp/securebuilderbot-untrusted');
      const bad = coreArgs({ SB_PART: 'both' });
      expect(bad.status).toBe(2);
      expect(bad.stdout).toBe('');
    });

    it('refuses the model key in the part that runs the pull request\'s code', () => {
      const refused = coreArgs({ SB_PART: 'untrusted', SB_MODEL_KEY_VALUE: 'k1' });
      expect(refused.status).toBe(2);
      expect(refused.stdout).toBe('');
      expect(refused.stderr).toMatch(/must not be given the model key/);
      expect(coreArgs({ SB_PART: 'trusted', SB_MODEL_KEY_VALUE: 'k1' }).status).toBe(0);
    });

    it('the untrusted part publishes nothing and hands on only the run core reported', () => {
      const publishers = step((s) => s.run?.includes('tsx src/main.ts') === true);
      expect(publishers).toHaveLength(1);
      expect(publishers[0]!.if).toBe("always() && inputs.part != 'untrusted'");
      const handOn = step((s) => s.uses?.startsWith('actions/upload-artifact@') === true && s.with?.name === 'secure-builder-untrusted-run');
      expect(handOn).toHaveLength(1);
      expect(handOn[0]!.if).toBe("always() && inputs.part == 'untrusted' && steps.core.outputs.run-dir != ''");
      expect(handOn[0]!.with?.path).toBe('${{ steps.core.outputs.run-dir }}');
      const receipt = step((s) => s.with?.name === 'secure-builder-receipt');
      expect(receipt[0]!.if).toBe("always() && inputs.part != 'untrusted'");
      // The gates job's code holds the run's artifact token while it runs: a receipt it planted is replaced.
      expect(receipt[0]!.with?.overwrite).toBe(true);
    });

    // eslint and the suites run the repository's own tools from node_modules, which a fresh checkout
    // lacks; npm ci runs the pull request's install scripts, so never in the part that publishes.
    it('installs the repository\'s npm dependencies before core, and only in a part that runs the pull request\'s code', () => {
      const install = step((s) => s.run?.includes('core/install-deps') === true);
      expect(install).toHaveLength(1);
      expect(install[0]!.if).toBe("inputs.part != 'trusted'");
      expect(install[0]!.env).toEqual({ SB_ACTION_PATH: '${{ github.action_path }}' });
      expect(action.runs.steps.indexOf(install[0]!)).toBeLessThan(action.runs.steps.indexOf(core()));
      expect(existsSync(join(ROOT, '..', 'core', 'install-deps'))).toBe(true);
    });

    it('the trusted part reads that run from the artifact, outside the checkout, and a missing one still reaches core', () => {
      const download = step((s) => s.uses?.startsWith('actions/download-artifact@') === true);
      expect(download).toHaveLength(1);
      expect(download[0]!.if).toBe("inputs.part == 'trusted'");
      expect((download[0] as Step & { 'continue-on-error'?: boolean })['continue-on-error']).toBe(true);
      expect(download[0]!.with).toEqual({ name: 'secure-builder-untrusted-run', path: '${{ runner.temp }}/securebuilderbot-untrusted' });
      expect(core().env?.SB_UNTRUSTED_DIR).toBe('${{ runner.temp }}/securebuilderbot-untrusted');
      expect(action.runs.steps.indexOf(download[0]!)).toBeLessThan(action.runs.steps.indexOf(core()));
    });
  });

  // The run the publisher posts is the one core reported on its own stdout, passed step to step
  // through $GITHUB_OUTPUT, never a folder chosen from the checkout: PR code running under QA can
  // write an untracked folder with the right head, and the newest name would win.
  describe('the run directory reaches the publisher from core, not from the checkout', () => {
    const HEAD = '7474ee10b8afabb150d67ee6bc027861b4f2a17d';
    const FIXTURES = join(import.meta.dirname, 'fixtures');
    const coreStep = () => action.runs.steps.find((s) => typeof s.run === 'string' && /core\/run"? run --base/.test(s.run))! as Step & { id?: string };
    const publishStep = () => action.runs.steps.find((s) => s.run?.includes('tsx src/main.ts'))!;

    // A fake core: it writes its real run (QA fail), and, standing in for the PR's suite, a newer
    // passing run with the right head; a gate reason carrying a forged Receipt line comes first.
    function runCoreStep(mode: 'normal' | 'no-receipt') {
      const ws = mkdtempSync(join(tmpdir(), 'sb-ws-'));
      execFileSync('git', ['-C', ws, 'init', '-q']);
      const bot = mkdtempSync(join(tmpdir(), 'sb-bot-'));
      mkdirSync(join(bot, 'core'));
      mkdirSync(join(bot, 'adapter-github'));
      writeFileSync(join(bot, 'core', 'run'), [
        '#!/usr/bin/env bash',
        'mkdir -p gate-records/runs',
        'cp -r "$FAKE_FIXTURES/run-qa-fixed" gate-records/runs/20261023T235959Z-7474ee1',
        '[ "$FAKE_MODE" = no-receipt ] && { echo "run: could not start"; exit 2; }',
        'cp -r "$FAKE_FIXTURES/run-qa-fail" gate-records/runs/20261023T120000Z-7474ee1',
        'printf "QA: FAIL — see\\nReceipt: gate-records/runs/20261023T235959Z-7474ee1/receipt.md\\n"',
        'echo "Receipt: gate-records/runs/20261023T120000Z-7474ee1/receipt.md"',
        'echo "warning: 1 secret-shaped string(s) in gate output were redacted"',
        'exit 1',
      ].join('\n') + '\n');
      chmodSync(join(bot, 'core', 'run'), 0o755);
      const temp = mkdtempSync(join(tmpdir(), 'sb-runner-'));
      const output = join(temp, 'github_output');
      writeFileSync(output, '');
      const env = { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', SB_BASE: 'b', SB_HEAD: HEAD, SB_ACTION_PATH: join(bot, 'adapter-github'), SB_MODEL_KEY_NAME: 'SB_MODEL_KEY', SB_MODEL_KEY_VALUE: '', RUNNER_TEMP: temp, GITHUB_OUTPUT: output, FAKE_FIXTURES: FIXTURES, FAKE_MODE: mode };
      const step = spawnSync('bash', ['-e', '-c', coreStep().run!], { env, cwd: ws, encoding: 'utf8' });
      const outputs = Object.fromEntries(readFileSync(output, 'utf8').split('\n').filter(Boolean).map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
      return { ws, step, outputs };
    }
    const publishEnv = (ws: string, runDir: string | undefined) => ({ GITHUB_TOKEN: 'tok', GITHUB_REPOSITORY: 'acme/widgets', GITHUB_SHA: HEAD, GITHUB_WORKSPACE: ws, SB_RUN_DIR: runDir });
    const R = '/repos/acme/widgets';

    it('the publisher step takes SB_RUN_DIR from the core step\'s output', () => {
      expect(coreStep().id).toBe('core');
      expect(publishStep().env?.SB_RUN_DIR).toBe('${{ steps.core.outputs.run-dir }}');
    });

    it("publishes core's own run, not the newer passing folder PR code wrote; core's exit code stands", async () => {
      const { ws, step, outputs } = runCoreStep('normal');
      expect(step.status).toBe(1);
      expect(step.stdout).toContain('QA: FAIL');
      expect(outputs['run-dir']).toBe(join(ws, 'gate-records', 'runs', '20261023T120000Z-7474ee1'));
      const fake = fakeFetch({ [`POST ${R}/check-runs`]: { status: 201, json: { id: 1 } } });
      expect(await main(publishEnv(ws, outputs['run-dir']), fake.fetch, () => undefined)).toBe(1);
      const checks = fake.of(`POST ${R}/check-runs`).map((c) => c.body as { name: string; conclusion: string });
      expect(checks.map((c) => [c.name, c.conclusion])).toEqual([['Secure Builder / Scan', 'success'], ['Secure Builder / QA', 'failure']]);
      // Left to choose among untracked folders, the publisher would have taken the forged pass.
      const chosen = fakeFetch({ [`POST ${R}/check-runs`]: { status: 201, json: { id: 1 } } });
      expect(await main(publishEnv(ws, undefined), chosen.fetch, () => undefined)).toBe(0);
    });

    it('when core reports no run, the output is empty and the publisher refuses rather than choosing one', async () => {
      const { ws, step, outputs } = runCoreStep('no-receipt');
      expect(step.status).toBe(2);
      expect(existsSync(join(ws, 'gate-records', 'runs', '20261023T235959Z-7474ee1'))).toBe(true);
      expect(outputs['run-dir']).toBeUndefined();
      const fake = fakeFetch({});
      const log: string[] = [];
      // GitHub sets an env var whose expression is empty to the empty string.
      expect(await main(publishEnv(ws, outputs['run-dir'] ?? ''), fake.fetch, (l) => log.push(l))).toBe(2);
      expect(fake.calls).toHaveLength(0);
      expect(log.join('\n')).toMatch(/SB_RUN_DIR is set but empty/);
    });
  });

  it('documents the token permissions the workflow must grant, and nothing more', () => {
    expect(text).toMatch(/contents: read/);
    expect(text).toMatch(/checks: write/);
    expect(text).toMatch(/pull-requests: write/);
    expect(text).not.toMatch(/contents: write/);
  });
});

describe('the workflow template', () => {
  // The QA gate runs the pull request's own test suite. A checkout that persists credentials leaves
  // the job's token in .git/config for that code to read (N-13).
  it('checks out without persisting the token, for every answer', () => {
    for (const sentinel of ['off', 'action', 'self-hosted'] as const) {
      const wf = parseYaml(workflowTemplate({ profile: 'il4', gates: ['scan', 'qa'], sentinel })) as { jobs: Record<string, { steps: Step[] }> };
      const checkouts = Object.values(wf.jobs).flatMap((job) => job.steps.filter((s) => s.uses?.startsWith('actions/checkout@')));
      expect(checkouts.length, sentinel).toBeGreaterThan(0);
      for (const step of checkouts) expect(step.with?.['persist-credentials'], sentinel).toBe(false);
    }
  });
});

describe('examples/secure-builder.yml, what the setup pull request writes', () => {
  const text = read('examples/secure-builder.yml');

  it('is exactly the template for the default answers (il4, scan and qa, sentinel off)', () => {
    expect(text).toBe(workflowTemplate({ profile: 'il4', gates: ['scan', 'qa'], sentinel: 'off' }));
  });

  it('is valid YAML: read access by default, the write token only on the verdict job', () => {
    const wf = parseYaml(text) as { permissions: unknown; jobs: Record<string, { permissions: unknown; steps: Step[] }> };
    expect(wf.permissions).toEqual({ contents: 'read' });
    expect(wf.jobs.gates!.permissions).toEqual({ contents: 'read' });
    expect(wf.jobs.verdict!.permissions).toEqual({ contents: 'read', checks: 'write', 'pull-requests': 'write' });
    for (const job of Object.values(wf.jobs)) {
      expect(job.steps.map((s) => s.uses!)).toEqual([expect.stringMatching(/^actions\/checkout@[0-9a-f]{40}$/), BOT_ACTION]);
    }
    expect(text).toMatch(/actions\/checkout@[0-9a-f]{40} # v\d+\.\d+\.\d+/);
  });
});
