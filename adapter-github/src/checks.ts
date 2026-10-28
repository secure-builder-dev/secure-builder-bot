// One check run per gate that ran (PRD § What the user sees): `Secure Builder / Scan`, `/ QA`,
// `/ Sentinel`. Green for pass, red for fail and for a gate that could not run (a skip that reads
// as a pass is the failure the bot exists to prevent), neutral for yellow. A gate the config turned
// off is absent from verdict.json and gets no check at all, not a skipped-green one.
import type { Finding, GateName, GateVerdict, RunRecord, Status, Verdict } from './run-dir.ts';
import { GATES, gateSection } from './run-dir.ts';

export const CHECK_PREFIX = 'Secure Builder / ';
export const GATE_LABEL: Readonly<Record<GateName, string>> = { scan: 'Scan', qa: 'QA', sentinel: 'Sentinel' };
export type Conclusion = 'success' | 'failure' | 'neutral';
const SUMMARY_LIMIT = 65_535;
/** Worse is higher: a gate that did not run is the outcome the bot exists to keep from reading green. */
const SEVERITY: Readonly<Record<Status, number>> = { pass: 0, yellow: 1, fail: 2, not_run: 3 };

export interface CheckRunPayload {
  name: string;
  head_sha: string;
  status: 'completed';
  conclusion: Conclusion;
  output: { title: string; summary: string };
}

export function conclusionFor(status: Status): Conclusion {
  switch (status) {
    case 'pass':
      return 'success';
    case 'yellow':
      return 'neutral';
    case 'fail':
    case 'not_run':
      return 'failure';
  }
}

/** The gate's verdict line, as core prints it: `QA: FAIL — <reason>`. */
export function verdictLine(gate: GateVerdict): string {
  const status = gate.status.toUpperCase().replace('_', ' ');
  return `${GATE_LABEL[gate.gate]}: ${status}` + (gate.reason ? ` — ${gate.reason}` : '');
}

/**
 * The gates that get a check: exactly those in verdict.json, in the fixed order. A gate the config
 * turned off never appears there, so it gets no check (PRD: absent, not skipped-green).
 */
export function gatesToPublish(verdict: Verdict): GateVerdict[] {
  // A gate listed twice keeps its worst entry: a fail then a pass must never read green. readRunDir
  // refuses such a verdict outright; this holds for any other caller.
  const present = new Map<GateName, GateVerdict>();
  for (const g of verdict.gates) {
    const seen = present.get(g.gate);
    if (seen === undefined || SEVERITY[g.status] > SEVERITY[seen.status]) present.set(g.gate, g);
  }
  const out: GateVerdict[] = [];
  for (const gate of GATES) {
    const g = present.get(gate);
    if (g !== undefined) out.push(g);
  }
  return out;
}

function truncate(text: string, limit: number): string {
  if (text.length <= limit) return text;
  const note = '\n\n_(truncated: the full receipt is in the run artifact)_';
  return text.slice(0, limit - note.length) + note;
}

function summaryFor(run: RunRecord, gate: GateVerdict, commentable: (f: Finding) => boolean): string {
  const receipt = run.receipt.gates[gate.gate];
  const parts: string[] = [];
  if (run.verdict.relaxations.length) {
    parts.push(['Relaxations on this run, so no check of it reads as a clean pass:', ...run.verdict.relaxations.map((r) => `- ${r}`)].join('\n'));
  }
  if (receipt?.attested_by) parts.push(`**Reported by ${receipt.attested_by}.**`);
  const section = gateSection(run.receiptMd, gate.gate);
  if (section) parts.push(section);
  if (gate.reason) parts.push(`Reason: ${gate.reason}`);
  parts.push(`Run \`${run.receipt.run_id}\``);
  const controls = receipt?.controls_assessed ?? [];
  parts.push(`Controls assessed: ${controls.length ? controls.join(', ') : 'none claimed by this gate'}`);
  if (receipt?.controls_claimed?.length) parts.push(`Controls that job claims, not assessed by this run: ${receipt.controls_claimed.join(', ')}`);
  const elsewhere = (receipt?.findings ?? []).filter((f) => !commentable(f));
  if (elsewhere.length) {
    parts.push(
      ['Findings not placed on the diff (no line, or a line this pull request does not change):',
        ...elsewhere.map((f) => `- **${f.severity}** ${f.rule_id}${f.path ? ` \`${f.path}${f.line ? `:${f.line}` : ''}\`` : ''}: ${f.message}`)].join('\n'),
    );
  }
  return truncate(parts.join('\n\n'), SUMMARY_LIMIT);
}

/**
 * The check-run payloads for a run, one per gate present. `commentable` says which findings will
 * land as review comments on the diff; the rest are listed in the summary so nothing is lost.
 */
export function planCheckRuns(run: RunRecord, headSha: string, commentable: (f: Finding) => boolean): CheckRunPayload[] {
  return gatesToPublish(run.verdict).map((gate) => ({
    name: `${CHECK_PREFIX}${GATE_LABEL[gate.gate]}`,
    head_sha: headSha,
    status: 'completed',
    // A relaxation (a scanner off, mutation off, the CI workflow edited) is a yellow note on every check:
    // a gate that passed on such a run is neutral, never green (docs/PRD.md § Configuration).
    conclusion: gate.status === 'pass' && run.verdict.relaxations.length ? 'neutral' : conclusionFor(gate.status),
    output: { title: verdictLine(gate).slice(0, 1024), summary: summaryFor(run, gate, commentable) },
  }));
}
