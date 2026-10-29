// The two files the setup pull request writes (PRD § The install experience): `.securebuilderbot.yml`
// with the three answers and a comment above every line explaining the choice, and the workflow
// that runs the bot's Action on every pull request with the least permission it needs. Exported
// as functions because the `cli` module writes the same two files from the terminal.
import { GATES, type GateName } from './run-dir.ts';

export type Profile = 'none' | 'il4' | 'il6';
export type SentinelMode = 'action' | 'self-hosted' | 'off';

export interface SetupAnswers {
  profile: Profile;
  gates: GateName[];
  sentinel: SentinelMode;
  /** `latest` (the default) or a pinned release x.y.z */
  version?: string | undefined;
}

export const SETUP_BRANCH = 'secure-builder/enable';
export const CONFIG_PATH = '.securebuilderbot.yml';
export const WORKFLOW_PATH = '.github/workflows/secure-builder.yml';
export const MODEL_KEY_SECRET = 'SB_MODEL_KEY';
/** The bot's own Action, taken by major release tag: a user's gate behaviour changes only with a release. */
export const BOT_ACTION = 'secure-builder-dev/secure-builder-bot/adapter-github@v0';
/** Third-party actions, pinned by commit; the version is the comment beside each. */
export const CHECKOUT_ACTION = { uses: 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', version: 'v7.0.1' };

const PROFILES: readonly Profile[] = ['none', 'il4', 'il6'];
const SENTINEL_MODES: readonly SentinelMode[] = ['action', 'self-hosted', 'off'];
const VERSION = /^(latest|\d+\.\d+\.\d+)$/;

const PROFILE_WHY: Readonly<Record<Profile, string>> = {
  none: 'none applies no NIST baseline: OWASP Top 10 only. Pick il4 or il6 when the system has an impact level.',
  il4: 'il4 applies the NIST SP 800-53 Rev 5 Moderate baseline (287 controls), the Application Security and Development STIG, and fails the scan on a critical or high CVE.',
  il6: 'il6 applies the NIST SP 800-53 Rev 5 High baseline (370 controls), the full STIG set with every CAT I enforced, and holds CVE data to 30 days.',
};
const GATE_WHY: Readonly<Record<GateName, string>> = {
  scan: 'scan (seven pinned scanners, CVE data live)',
  qa: 'qa (the tests prove the code, every declared control mutated)',
  sentinel: 'sentinel (a cold reviewer running the NIST checklist on the diff, with your model key)',
};

/** Refuse anything that is not an answer to the three questions. */
export function validateAnswers(a: SetupAnswers): void {
  if (!PROFILES.includes(a.profile)) throw new Error(`profile must be one of ${PROFILES.join(', ')}`);
  if (!Array.isArray(a.gates) || a.gates.length === 0) throw new Error('gates must name at least one of scan, qa, sentinel');
  for (const g of a.gates) if (!GATES.includes(g)) throw new Error(`unknown gate ${JSON.stringify(g)} — one of ${GATES.join(', ')}`);
  if (!SENTINEL_MODES.includes(a.sentinel)) throw new Error(`sentinel must be one of ${SENTINEL_MODES.join(', ')}`);
  if (a.version !== undefined && !VERSION.test(a.version)) throw new Error('version must be latest or x.y.z');
}

/** The gates as the config will carry them: in the fixed order, consistent with the sentinel answer. */
export function effectiveGates(a: SetupAnswers): GateName[] {
  const wanted = new Set<GateName>(a.gates);
  if (a.sentinel === 'off') wanted.delete('sentinel');
  else wanted.add('sentinel');
  return GATES.filter((g) => wanted.has(g));
}

export function configTemplate(a: SetupAnswers): string {
  validateAnswers(a);
  const gates = effectiveGates(a);
  const version = a.version ?? 'latest';
  const lines: string[] = [
    `# ${CONFIG_PATH} — Secure Builder Bot's one file. Three lines decide everything; the rest defaults from the profile.`,
    '# Written by the setup pull request from your three answers; edit any answer and merge. Validated on every run.',
    '',
    `# Which compliance profile (none, il4, il6). ${PROFILE_WHY[a.profile]}`,
    `profile: ${a.profile}`,
  ];
  const gateNote = [`# Which gates run on every pull request: ${gates.map((g) => GATE_WHY[g]).join('; ')}.`];
  if (!gates.includes('scan')) gateNote.push('# scan is off. The setup warns against this: the scan gate needs nothing from you and is where most real findings come from.');
  if (a.sentinel === 'off') gateNote.push('# sentinel is off until a model key is added as a CI secret; add sentinel here and the block below to turn it on.');
  if (a.sentinel !== 'off' && !a.gates.includes('sentinel')) gateNote.push(`# sentinel was added because you chose to run it (${a.sentinel}).`);
  lines.push(...gateNote, `gates: [${gates.join(', ')}]`);
  lines.push(
    '# Which release of the bot runs. latest takes each release as it ships; pin x.y.z to change only when you say so.',
    `version: ${version}`,
  );
  if (gates.includes('sentinel')) {
    lines.push(
      '',
      `# Sentinel: where it runs (${a.sentinel === 'action' ? 'in the Action, on GitHub-hosted runners' : 'on your own self-hosted runner'}) and whose key it uses.`,
      'sentinel:',
      '  # The model provider Sentinel calls with your key: anthropic, openai, or self-hosted for an air-gapped endpoint.',
      '  provider: anthropic',
      `  # The NAME of the CI secret holding the model key, never the value. Add ${MODEL_KEY_SECRET} under the repository's secrets.`,
      `  key_secret: ${MODEL_KEY_SECRET}`,
    );
  }
  return lines.join('\n') + '\n';
}

export function workflowTemplate(a: SetupAnswers): string {
  validateAnswers(a);
  const gates = effectiveGates(a);
  const version = a.version ?? 'latest';
  const sentinelOn = gates.includes('sentinel');
  const runsOn = a.sentinel === 'self-hosted' ? '[self-hosted]' : 'ubuntu-latest';
  const lines = [
    '# Secure Builder Bot on every pull request: the gates .securebuilderbot.yml turns on, as checks on the',
    '# pull request and comments on the diff. Written by the setup pull request, which it already runs on.',
    'name: Secure Builder',
    'on:',
    '  pull_request:',
    '    # edited: a pull request retargeted at another branch is gated again, against that branch\'s rules',
    '    types: [opened, synchronize, reopened, edited]',
    '# Least permission, per job (the bot asks for nothing else). Nothing below can push, merge, read other',
    '# secrets or change settings.',
    'permissions:',
    '  contents: read',
    '# One run per pull request: a retarget starts a second run on the same head, and the older one, against',
    '# the old target\'s rules, is cancelled rather than left to finish last and post the newest checks. A',
    '# title or body edit, whose job is skipped, gets a group of its own so it can never cancel a real run.',
    'concurrency:',
    "  group: ${{ (github.event.action == 'edited' && !github.event.changes.base) && format('secure-builder-noop-{0}', github.run_id) || format('secure-builder-{0}', github.event.pull_request.number) }}",
    '  cancel-in-progress: true',
    'jobs:',
    '  # Scan and QA run this pull request\'s code (its build scripts, its tests), so they run here, with',
    '  # read access only, no secret and no token that can write. Its run is handed on as an artifact.',
    '  gates:',
    '    # An edit re-runs the gates only when it changed the target branch, not on a title or body edit.',
    "    if: github.event.action != 'edited' || github.event.changes.base",
    ...(a.sentinel === 'self-hosted'
      ? ['    # Your runner, as you chose. It must be ephemeral (a fresh VM or container per job): on a reused one,',
         '    # whatever this job\'s code leaves behind is there when the verdict job, which holds the key, runs.',
         '    runs-on: [self-hosted]']
      : ['    runs-on: ubuntu-latest   # a fresh GitHub-hosted runner: nothing this job leaves behind reaches the next']),
    '    permissions: { contents: read }',
    '    steps:',
    `      - uses: ${CHECKOUT_ACTION.uses} # ${CHECKOUT_ACTION.version}`,
    '        with:',
    '          fetch-depth: 0   # the gates read the range from the base branch to the head',
    '          persist-credentials: false   # the token stays out of .git/config, where the tests could read it',
    `      - uses: ${BOT_ACTION}`,
    '        with:',
    `          version: ${version}   # the same release .securebuilderbot.yml names`,
    '          part: untrusted',
    '  # Sentinel and the verdict, in a job that runs none of the pull request\'s code: it reads the gates',
    '  # job\'s result as a claim, marks Scan and QA as that job\'s word on every check, and publishes.',
    '  verdict:',
    '    needs: gates',
    "    if: ${{ !cancelled() && (github.event.action != 'edited' || github.event.changes.base) }}",
    `    runs-on: ${runsOn}` + (a.sentinel === 'self-hosted' ? '   # sentinel: self-hosted — your own runner, so the diff never leaves it' : ''),
    '    permissions:',
    '      contents: read',
    '      checks: write',
    '      pull-requests: write',
    '    steps:',
    `      - uses: ${CHECKOUT_ACTION.uses} # ${CHECKOUT_ACTION.version}`,
    '        with:',
    '          fetch-depth: 0',
    '          persist-credentials: false',
    `      - uses: ${BOT_ACTION}`,
    '        with:',
    `          version: ${version}`,
    '          part: trusted',
  ];
  if (sentinelOn) {
    lines.push(
      `          # The model key, from the secret the config names (sentinel.key_secret). Only this job, which`,
      `          # runs none of the pull request's code, is given it, and only its gates step reads it.`,
      `          model-key: \${{ secrets.${MODEL_KEY_SECRET} }}`,
    );
  }
  return lines.join('\n') + '\n';
}

export function setupPrBody(a: SetupAnswers): string {
  validateAnswers(a);
  const gates = effectiveGates(a);
  const where = { action: 'in the Action, with your model key', 'self-hosted': 'on your own self-hosted runner, with your model key', off: 'off (no model key needed)' }[a.sentinel];
  return [
    'This pull request enables Secure Builder Bot on this repository with your three answers:',
    '',
    `1. **Compliance profile:** \`${a.profile}\` — ${PROFILE_WHY[a.profile]}`,
    `2. **Gates:** ${gates.map((g) => `\`${g}\``).join(', ')} — ${gates.map((g) => GATE_WHY[g]).join('; ')}.`,
    `3. **Sentinel runs:** ${where}.`,
    '',
    `It adds two files: \`${CONFIG_PATH}\` (every line commented, edit any answer here) and \`${WORKFLOW_PATH}\` (the Action, with`,
    'permission to read the code and write checks and review comments, nothing more).',
    '',
    '**The gates run on this pull request too**, under the config it adds. Its checks are neutral at best: a pull request that',
    'changes the CI workflow is never a clean pass. Once it is merged, every pull request gets every gate you turned on, one',
    'check per gate, with findings as review comments on the lines they concern.',
  ].join('\n') + '\n';
}

export function setupFiles(a: SetupAnswers): { path: string; content: string }[] {
  return [
    { path: CONFIG_PATH, content: configTemplate(a) },
    { path: WORKFLOW_PATH, content: workflowTemplate(a) },
  ];
}
