// The run directory core wrote (gate-records/runs/<id>/) is the only input the publisher reads:
// verdict.json is the machine-readable verdict per gate, receipt.json the contract written for an
// assessor, receipt.md its rendering. The shapes are core's (core/securebuilderbot_core/runner.py,
// verdict.py, receipt.py); the fixtures under tests/fixtures/ were produced by that runner.
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

export type GateName = 'scan' | 'qa' | 'sentinel';
export type Status = 'pass' | 'fail' | 'yellow' | 'not_run';
export const GATES: readonly GateName[] = ['scan', 'qa', 'sentinel'];

export interface Finding {
  severity: 'blocking' | 'advisory';
  rule_id: string;
  message: string;
  path: string | null;
  line: number | null;
  file: string | null;
}

export interface GateVerdict {
  gate: GateName;
  status: Status;
  reason: string;
  blocking_findings: number;
  advisory_findings: number;
}

export interface Verdict {
  overall: string;
  exit_code: number;
  relaxations: string[];
  gates: GateVerdict[];
}

export interface GateReceipt {
  status: Status;
  reason: string;
  findings: Finding[];
  controls_assessed?: string[];
  /** Set on Scan and QA when they ran in the job that ran the pull request's code: whose word the status is. */
  attested_by?: string;
  /** That job's controls: claimed, never assessed by the run that published. */
  controls_claimed?: string[];
}

export interface Receipt {
  run_id: string;
  head: string;
  gates: Partial<Record<GateName, GateReceipt>>;
  controls_assessed: string[];
}

export interface RunRecord {
  dir: string;
  verdict: Verdict;
  receipt: Receipt;
  receiptMd: string;
}

/** A run directory that cannot be published, naming the file and what is wrong with it. */
export class RunDirError extends Error {}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isGate = (v: unknown): v is GateName => typeof v === 'string' && (GATES as readonly string[]).includes(v);
const isStatus = (v: unknown): v is Status => v === 'pass' || v === 'fail' || v === 'yellow' || v === 'not_run';

function readText(dir: string, name: string): string {
  try {
    return readFileSync(join(dir, name), 'utf8');
  } catch (e) {
    throw new RunDirError(`${name} is missing from ${dir}: ${(e as Error).message}`);
  }
}

function readJson(dir: string, name: string): unknown {
  try {
    return JSON.parse(readText(dir, name));
  } catch (e) {
    if (e instanceof RunDirError) throw e;
    throw new RunDirError(`${name} in ${dir} is not valid JSON: ${(e as Error).message}`);
  }
}

function finding(raw: unknown, where: string): Finding {
  if (!isRecord(raw) || (raw.severity !== 'blocking' && raw.severity !== 'advisory') || typeof raw.rule_id !== 'string' || typeof raw.message !== 'string') {
    throw new RunDirError(`${where}: a finding is not the shape core writes (severity, rule_id, message)`);
  }
  return {
    severity: raw.severity,
    rule_id: raw.rule_id,
    message: raw.message,
    path: typeof raw.path === 'string' ? raw.path : null,
    line: typeof raw.line === 'number' ? raw.line : null,
    file: typeof raw.file === 'string' ? raw.file : null,
  };
}

function verdictOf(raw: unknown): Verdict {
  if (!isRecord(raw) || !Array.isArray(raw.gates)) {
    throw new RunDirError('verdict.json is not the shape core writes: no gates list');
  }
  const gates = raw.gates.map((g: unknown, i: number): GateVerdict => {
    if (!isRecord(g) || !isGate(g.gate) || !isStatus(g.status)) {
      throw new RunDirError(`verdict.json: gates[${i}] is not the shape core writes (gate, status)`);
    }
    return {
      gate: g.gate,
      status: g.status,
      reason: typeof g.reason === 'string' ? g.reason : '',
      blocking_findings: typeof g.blocking_findings === 'number' ? g.blocking_findings : 0,
      advisory_findings: typeof g.advisory_findings === 'number' ? g.advisory_findings : 0,
    };
  });
  const seen = new Set<GateName>();
  for (const g of gates) {
    if (seen.has(g.gate)) throw new RunDirError(`verdict.json: gate ${g.gate} appears more than once; core writes one entry per gate`);
    seen.add(g.gate);
  }
  return {
    overall: typeof raw.overall === 'string' ? raw.overall : 'fail',
    exit_code: typeof raw.exit_code === 'number' ? raw.exit_code : 1,
    relaxations: Array.isArray(raw.relaxations) ? raw.relaxations.filter((r): r is string => typeof r === 'string') : [],
    gates,
  };
}

function receiptOf(raw: unknown): Receipt {
  if (!isRecord(raw) || typeof raw.run_id !== 'string' || !isRecord(raw.gates)) {
    throw new RunDirError('receipt.json is not the shape core writes: no run_id or gates');
  }
  const gates: Partial<Record<GateName, GateReceipt>> = {};
  for (const [name, g] of Object.entries(raw.gates)) {
    if (!isGate(name) || !isRecord(g) || !isStatus(g.status)) {
      throw new RunDirError(`receipt.json: gates.${name} is not the shape core writes`);
    }
    const findings = Array.isArray(g.findings) ? g.findings.map((f) => finding(f, `receipt.json gates.${name}`)) : [];
    const controls = Array.isArray(g.controls_assessed) ? g.controls_assessed.filter((c): c is string => typeof c === 'string') : undefined;
    const claimed = Array.isArray(g.controls_claimed) ? g.controls_claimed.filter((c): c is string => typeof c === 'string') : undefined;
    gates[name] = {
      status: g.status, reason: typeof g.reason === 'string' ? g.reason : '', findings,
      ...(controls ? { controls_assessed: controls } : {}),
      ...(claimed ? { controls_claimed: claimed } : {}),
      ...(typeof g.attested_by === 'string' ? { attested_by: g.attested_by } : {}),
    };
  }
  return {
    run_id: raw.run_id,
    head: typeof raw.head === 'string' ? raw.head : '',
    gates,
    controls_assessed: Array.isArray(raw.controls_assessed) ? raw.controls_assessed.filter((c): c is string => typeof c === 'string') : [],
  };
}

/** Read and validate the three files; anything else in the directory is the gates' own. */
export function readRunDir(dir: string): RunRecord {
  const verdict = verdictOf(readJson(dir, 'verdict.json'));
  const receipt = receiptOf(readJson(dir, 'receipt.json'));
  const receiptMd = readText(dir, 'receipt.md');
  return { dir, verdict, receipt, receiptMd };
}

/**
 * True when git tracks any file under `dir`: a run directory the pull request committed, which core
 * never wrote on this runner and so is never published. A directory outside any repository holds
 * nothing a commit could have put there. When git cannot answer, the directory is refused.
 */
export function isTrackedByGit(dir: string): boolean {
  const git = (...args: string[]): string => execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    git('rev-parse', '--show-toplevel');
  } catch (e) {
    // Only git's own "not a git repository" answer means untracked. Anything else, git missing
    // from PATH included, is a question git could not answer, and the directory is refused.
    const stderr = String((e as { stderr?: unknown }).stderr ?? '');
    if (/not a git repository/i.test(stderr)) return false;
    throw new RunDirError(`could not ask git whether ${dir} is tracked: ${(e as Error).message}`);
  }
  try {
    return git('ls-files', '-z', '--', '.').length > 0;
  } catch (e) {
    throw new RunDirError(`could not ask git whether ${dir} is tracked: ${(e as Error).message}`);
  }
}

/** The head sha a run directory's receipt.json names, or '' when it has none that can be read. */
function receiptHead(dir: string): string {
  try {
    const raw: unknown = JSON.parse(readFileSync(join(dir, 'receipt.json'), 'utf8'));
    return isRecord(raw) && typeof raw.head === 'string' ? raw.head : '';
  } catch {
    return '';
  }
}

export type RunChoice = { dir: string; skipped: string[] } | { dir: null; skipped: string[]; reason: string };

/**
 * The run directory to publish for `headSha`: the newest-named directory under gate-records/runs/
 * that git does not track and whose receipt names exactly that head. A tracked directory came from
 * the pull request, not from core on this runner; a receipt for another head is another run's. Run
 * ids start with a UTC timestamp, so the name sorts. `skipped` says why each newer one was passed over.
 */
export function chooseRunDir(runsRoot: string, headSha: string): RunChoice {
  let names: string[];
  try {
    names = readdirSync(runsRoot).filter((n) => statSync(join(runsRoot, n)).isDirectory());
  } catch {
    names = [];
  }
  const skipped: string[] = [];
  for (const name of names.sort().reverse()) {
    const dir = join(runsRoot, name);
    let tracked: boolean;
    try {
      tracked = isTrackedByGit(dir);
    } catch (e) {
      skipped.push(`${name}: ${(e as Error).message}`);
      continue;
    }
    if (tracked) {
      skipped.push(`${name}: tracked by git — committed by the pull request, not written by core on this runner`);
      continue;
    }
    const head = receiptHead(dir);
    if (head !== headSha) {
      skipped.push(`${name}: receipt.json head is ${head.slice(0, 12) || 'missing'}, not ${headSha.slice(0, 12)}`);
      continue;
    }
    return { dir, skipped };
  }
  return { dir: null, skipped, reason: `no run directory under ${runsRoot} that git does not track and whose receipt is for ${headSha.slice(0, 12)} — did core/run run on this head?` };
}

/** The "### <gate>: …" block of receipt.md, up to the next heading; empty when the gate has none. */
export function gateSection(receiptMd: string, gate: GateName): string {
  const lines = receiptMd.split('\n');
  const start = lines.findIndex((l) => l.startsWith(`### ${gate}:`));
  if (start < 0) return '';
  let end = start + 1;
  while (end < lines.length && !/^##+ /.test(lines[end] ?? '')) end += 1;
  return lines.slice(start, end).join('\n').trimEnd();
}
