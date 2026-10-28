// What the merge request shows (docs/PRD.md § What the user sees): one note with the verdict block
// and a section per gate, and one discussion per finding on a diff line. The two hidden markers are
// how the bot finds its own note and its own discussions on the next run; a human never sees them.
import type { Finding, GateName, GateRecord, RunRecord, Severity } from "./run-dir.js";

export const VERDICT_MARKER = "<!-- secure-builder:verdict -->";
export const FINDING_MARKER = "<!-- secure-builder:finding -->";

const GATE_LABEL = new Map<GateName, string>([["scan", "Scan"], ["qa", "QA"], ["sentinel", "Sentinel"]]);
const COLD_REVIEWER = "_Posted by Sentinel, a cold reviewer with no build context: it read the diff, the manifest and the checklist, not the discussion that produced them._";

export function gateLabel(name: GateName): string {
  return GATE_LABEL.get(name) ?? name;
}

export function statusLabel(status: string): string {
  return status.toUpperCase().replace("_", " ");
}

export function severityMarker(severity: Severity): string {
  return severity === "blocking" ? "**[BLOCKING]**" : "[advisory]";
}

/** A finding that lands on a diff line: a path and a positive line number. */
export function hasLine(f: Finding): f is Finding & { path: string; line: number } {
  return f.path !== null && f.line !== null;
}

/** Core's verdict block (core/securebuilderbot_core/verdict.py:verdict_block), one line per gate. */
/** One line: the note holds every gate's section, so a newline in one gate's text must never start another's heading. */
const oneLine = (text: string): string => text.split(/\r\n|[\n\r\v\f\u0085\u2028\u2029]/).join(" ");

export function verdictBlock(run: RunRecord): string[] {
  const lines = run.gates.map((g) => `${gateLabel(g.name)}: ${statusLabel(g.status)}` + (g.reason ? ` — ${oneLine(g.reason)}` : ""));
  for (const r of run.relaxations) lines.push(`Relaxed: ${r}`);
  lines.push(`Overall: ${run.overall.toUpperCase()}`);
  return lines;
}

/** One sentence on what would fix the finding, from the shape of its rule id. */
export function fixSentence(gate: GateName, ruleId: string): string {
  if (/^(CVE-|GHSA-)/i.test(ruleId)) return "Upgrade the package to a fixed version, or add an accepted-risk entry with a reason and an expiry.";
  if (ruleId.startsWith("stale-data:")) return "Refresh the scanner's vulnerability database, or point it at a current mirror.";
  if (ruleId.startsWith("scanner:")) return "Make the scanner run: a partial scan is never a pass.";
  if (ruleId === "malware") return "Remove the infected file and find out how it got in.";
  if (ruleId === "coverage") return "Add tests for the changed lines until the profile's threshold is met.";
  if (/^CM-\d+/.test(ruleId)) return "Add or change the proving test so the suite goes red when this control is disabled.";
  if (gate === "sentinel") return "Keep every caller in their lane: cite the control the checklist names, or give the reason it does not apply.";
  return "See the receipt in the job artifacts for what was checked.";
}

function section(g: GateRecord, runId: string): string[] {
  const out = [`### ${gateLabel(g.name)} — ${statusLabel(g.status)}`, ""];
  if (g.attestedBy) out.push(`- **Reported by ${oneLine(g.attestedBy)}.**`);
  if (g.line) out.push(`- Verdict: \`${oneLine(g.line)}\``);
  if (g.reason) out.push(`- Reason: ${oneLine(g.reason)}`);
  out.push(`- Controls assessed: ${g.controlsAssessed.length ? g.controlsAssessed.join(", ") : "none claimed"}`);
  if (g.controlsClaimed?.length) out.push(`- Controls that job claims, not assessed by this run: ${g.controlsClaimed.join(", ")}`);
  out.push(`- Run \`${runId}\``);
  const lineless = g.findings.filter((f) => !hasLine(f));
  if (lineless.length) {
    out.push("- Findings not on a diff line:");
    for (const f of lineless) out.push(`  - ${severityMarker(f.severity)} \`${oneLine(f.rule_id)}\` — ${oneLine(f.message)}` + (f.path ? ` (\`${oneLine(f.path)}\`)` : ""));
  }
  const lined = g.findings.filter(hasLine).length;
  if (lined) out.push(`- ${String(lined)} finding(s) on diff lines, posted as discussions`);
  out.push("");
  return out;
}

/** The one note: the verdict block, a section per gate, the findings without a line, the range. */
export function verdictNote(run: RunRecord): string {
  const out = [VERDICT_MARKER, `## Secure Builder — Overall ${run.overall.toUpperCase()}`, "", "```", ...verdictBlock(run), "```", ""];
  for (const g of run.gates) out.push(...section(g, run.runId));
  const baseline = run.profile.baseline ? `${run.profile.baseline} baseline` : "no baseline";
  out.push(`Profile \`${run.profile.name}\` (${baseline}, NIST SP 800-53 Rev 5 catalog ${run.profile.catalog_version}) · ` +
    `range \`${run.base.slice(0, 12)}..${run.head.slice(0, 12)}\` (${run.depth}) · the receipt is in this job's artifacts under \`gate-records/runs/${run.runId}/\``);
  return out.join("\n") + "\n";
}

/** A finding's discussion body: severity, rule id, message, a fix, and the cold-reviewer line for Sentinel. */
export function findingBody(gate: GateName, f: Finding): string {
  const out = [FINDING_MARKER, `${severityMarker(f.severity)} \`${f.rule_id}\` — ${gateLabel(gate)} gate`, "", f.message, "", `Fix: ${fixSentence(gate, f.rule_id)}`];
  if (gate === "sentinel") out.push("", COLD_REVIEWER);
  return out.join("\n") + "\n";
}
