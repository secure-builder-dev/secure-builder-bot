import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { conclusionFor, gatesToPublish, planCheckRuns, verdictLine } from '../src/checks.ts';
import { gateSection, readRunDir, RunDirError } from '../src/run-dir.ts';

const FIXTURES = join(import.meta.dirname, 'fixtures');
const HEAD = 'a'.repeat(40);

describe('reading the run directory core wrote', () => {
  it('loads verdict.json, receipt.json and receipt.md', () => {
    const run = readRunDir(join(FIXTURES, 'run-qa-fail'));
    expect(run.verdict.overall).toBe('fail');
    expect(run.receipt.run_id).toMatch(/^20261023T120000Z-/);
    expect(run.receipt.gates.qa?.findings).toHaveLength(2);
    expect(run.receiptMd).toContain('# Receipt ');
  });

  it('refuses a directory missing one of the three files, naming it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sb-run-'));
    writeFileSync(join(dir, 'verdict.json'), '{"gates": []}');
    expect(() => readRunDir(dir)).toThrow(RunDirError);
    expect(() => readRunDir(dir)).toThrow(/receipt\.json is missing/);
  });

  it('refuses a verdict that is not the shape core writes', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sb-run-'));
    writeFileSync(join(dir, 'verdict.json'), '{"gates": "no"}');
    writeFileSync(join(dir, 'receipt.json'), '{}');
    writeFileSync(join(dir, 'receipt.md'), '');
    expect(() => readRunDir(dir)).toThrow(/verdict\.json/);
  });

  it('refuses a verdict that names a gate twice: core writes one entry per gate (N-06)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sb-run-'));
    const qa = (status: string) => ({ gate: 'qa', status, reason: '', blocking_findings: 0, advisory_findings: 0 });
    writeFileSync(join(dir, 'verdict.json'), JSON.stringify({ overall: 'pass', exit_code: 0, gates: [qa('fail'), qa('pass')] }));
    writeFileSync(join(dir, 'receipt.json'), '{"run_id": "r", "gates": {}}');
    writeFileSync(join(dir, 'receipt.md'), '');
    expect(() => readRunDir(dir)).toThrow(/verdict\.json: gate qa appears more than once/);
  });

  it('cuts one gate section out of receipt.md', () => {
    const run = readRunDir(join(FIXTURES, 'run-qa-fail'));
    const qa = gateSection(run.receiptMd, 'qa');
    expect(qa).toMatch(/^### qa: fail/);
    expect(qa).toContain('SA-11');
    expect(qa).not.toContain('### scan');
    expect(qa).not.toContain('## Sent to a model endpoint');
    expect(gateSection(run.receiptMd, 'sentinel')).toBe('');
  });
});

describe('one check run per gate that ran', () => {
  it('maps statuses to conclusions: pass green, fail and not_run red, yellow neutral', () => {
    expect(conclusionFor('pass')).toBe('success');
    expect(conclusionFor('fail')).toBe('failure');
    expect(conclusionFor('not_run')).toBe('failure');
    expect(conclusionFor('yellow')).toBe('neutral');
  });

  it("titles a check with the gate's verdict line", () => {
    const run = readRunDir(join(FIXTURES, 'run-qa-fail'));
    expect(verdictLine(run.verdict.gates[0]!)).toBe('Scan: PASS');
    expect(verdictLine(run.verdict.gates[1]!)).toMatch(/^QA: FAIL — 2 blocking findings/);
    expect(verdictLine({ gate: 'sentinel', status: 'not_run', reason: 'no key', blocking_findings: 0, advisory_findings: 0 })).toBe('Sentinel: NOT RUN — no key');
  });

  it('publishes only the gates in verdict.json: a gate the config turned off gets no check', () => {
    const run = readRunDir(join(FIXTURES, 'run-qa-fail'));
    expect(gatesToPublish(run.verdict).map((g) => g.gate)).toEqual(['scan', 'qa']);
    expect(gatesToPublish({ ...run.verdict, gates: [run.verdict.gates[1]!] }).map((g) => g.gate)).toEqual(['qa']);
  });

  it('a gate listed twice publishes its worst entry, so a fail then a pass never reads green (N-06)', () => {
    const qa = (status: 'pass' | 'fail' | 'yellow' | 'not_run') => ({ gate: 'qa' as const, status, reason: status, blocking_findings: 0, advisory_findings: 0 });
    const verdict = { overall: 'pass', exit_code: 0, relaxations: [], gates: [qa('fail'), qa('pass')] };
    expect(gatesToPublish(verdict).map((g) => g.status)).toEqual(['fail']);
    expect(gatesToPublish({ ...verdict, gates: [qa('pass'), qa('not_run'), qa('yellow')] }).map((g) => g.status)).toEqual(['not_run']);
    expect(gatesToPublish({ ...verdict, gates: [qa('yellow'), qa('pass')] }).map((g) => g.status)).toEqual(['yellow']);
  });

  it('plans exactly two check runs for the fixture, named and concluded right', () => {
    const run = readRunDir(join(FIXTURES, 'run-qa-fail'));
    const checks = planCheckRuns(run, HEAD, () => false);
    expect(checks.map((c) => [c.name, c.conclusion])).toEqual([
      ['Secure Builder / Scan', 'success'],
      ['Secure Builder / QA', 'failure'],
    ]);
    expect(checks.every((c) => c.head_sha === HEAD && c.status === 'completed')).toBe(true);
    expect(checks[1]!.output.title).toMatch(/^QA: FAIL — 2 blocking findings/);
  });

  it("puts the gate's receipt section, reason, run id, controls and the lineless findings in the summary", () => {
    const run = readRunDir(join(FIXTURES, 'run-qa-fail'));
    const onDiff = (f: { line: number | null }) => f.line === 42;
    const qa = planCheckRuns(run, HEAD, onDiff)[1]!.output.summary;
    expect(qa).toContain('### qa: fail');
    expect(qa).toContain('Reason: 2 blocking findings');
    expect(qa).toContain(`Run \`${run.receipt.run_id}\``);
    expect(qa).toContain('Controls assessed: AC-3, SA-11');
    expect(qa).toContain('the new route has no negative test; add a 401 case for it');
    expect(qa).toMatch(/Findings not placed on the diff[\s\S]*SA-11/);
    expect(qa).not.toMatch(/Findings not placed on the diff[\s\S]*AC-3 `src/);
  });

  it('a yellow gate is neutral and the summary carries its reason', () => {
    const run = readRunDir(join(FIXTURES, 'run-qa-yellow'));
    const qa = planCheckRuns(run, HEAD, () => true)[1]!;
    expect(qa.conclusion).toBe('neutral');
    expect(qa.output.title).toMatch(/^QA: YELLOW — qa\.mutation is off/);
  });

  it('a passing gate on a run with a relaxation is neutral, never green, and the summary names the relaxation', () => {
    const run = readRunDir(join(FIXTURES, 'run-qa-fail'));
    const note = 'this pull request changes the CI workflow (.github/workflows/x.yml), which decides what runs the bot';
    const relaxed = { ...run, verdict: { ...run.verdict, relaxations: [note] } };
    const scan = planCheckRuns(relaxed, HEAD, () => true)[0]!;
    expect(run.verdict.gates[0]!.status).toBe('pass');
    expect(scan.conclusion).toBe('neutral');
    expect(scan.output.summary).toContain(`- ${note}`);
    expect(planCheckRuns(run, HEAD, () => true)[0]!.conclusion).toBe('success');
  });

  it('keeps a summary under the API limit', () => {
    const run = readRunDir(join(FIXTURES, 'run-qa-fail'));
    const long = { ...run, receiptMd: run.receiptMd.replace('### qa: fail', '### qa: fail\n' + 'x'.repeat(70_000)) };
    const qa = planCheckRuns(long, HEAD, () => true)[1]!;
    expect(qa.output.summary.length).toBeLessThanOrEqual(65_535);
    expect(qa.output.summary).toMatch(/truncated/);
  });
});

describe('a gate reported by the job that ran the pull request\'s code', () => {
  it('says whose word its status is, and lists its controls as claimed, never assessed', () => {
    const run = readRunDir(join(FIXTURES, 'run-qa-fail'));
    const qa = run.receipt.gates.qa!;
    qa.attested_by = "the job that ran this pull request's code, which could have changed it: a claim, not re-derived here";
    qa.controls_claimed = ['SA-11'];
    qa.controls_assessed = [];
    const summary = planCheckRuns(run, HEAD, () => false).find((c) => c.name.endsWith('QA'))!.output.summary;
    expect(summary.startsWith("**Reported by the job that ran this pull request's code")).toBe(true);
    expect(summary).toContain('Controls that job claims, not assessed by this run: SA-11');
    expect(summary).toContain('Controls assessed: none claimed by this gate');
    const scan = planCheckRuns(run, HEAD, () => false).find((c) => c.name.endsWith('Scan'))!.output.summary;
    expect(scan).not.toContain('Reported by');
  });

  it('reads the two fields from receipt.json, ignoring a shape core does not write', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sb-run-'));
    const src = readRunDir(join(FIXTURES, 'run-qa-fail'));
    writeFileSync(join(dir, 'verdict.json'), JSON.stringify(src.verdict));
    writeFileSync(join(dir, 'receipt.md'), src.receiptMd);
    writeFileSync(join(dir, 'receipt.json'), JSON.stringify({ ...src.receipt, gates: { qa: { status: 'fail', reason: '', findings: [], attested_by: 'that job', controls_claimed: ['SA-11', 7] }, scan: { status: 'pass', attested_by: 3 } } }));
    const run = readRunDir(dir);
    expect(run.receipt.gates.qa).toMatchObject({ attested_by: 'that job', controls_claimed: ['SA-11'] });
    expect(run.receipt.gates.scan?.attested_by).toBeUndefined();
  });
});
