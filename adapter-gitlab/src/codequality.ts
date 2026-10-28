// The code quality report GitLab's merge request widget reads (the CodeClimate shape): one entry
// per finding on a diff line. The fingerprint is what lets the widget tell a finding that moved
// from one that is new, so it is the hash of everything that identifies the finding and nothing else.
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { gateLabel, hasLine } from "./markdown.js";
import type { RunRecord, Severity } from "./run-dir.js";
import { refuseSecrets } from "./secrets.js";

export type ReportSeverity = "blocker" | "major" | "minor";

export interface CodeQualityEntry {
  description: string;
  check_name: string;
  fingerprint: string;
  severity: ReportSeverity;
  location: { path: string; lines: { begin: number } };
}

export function fingerprint(gate: string, ruleId: string, filePath: string, line: number, message: string): string {
  return createHash("sha256").update([gate, ruleId, filePath, String(line), message].join("\n")).digest("hex");
}

function reportSeverity(severity: Severity): ReportSeverity {
  return severity === "blocking" ? "blocker" : "minor";
}

export function codeQualityReport(run: RunRecord): CodeQualityEntry[] {
  const out: CodeQualityEntry[] = [];
  for (const g of run.gates) {
    for (const f of g.findings) {
      if (!hasLine(f)) continue;
      out.push({
        description: `[${gateLabel(g.name)}] ${f.message}`,
        check_name: f.rule_id,
        fingerprint: fingerprint(g.name, f.rule_id, f.path, f.line, f.message),
        severity: reportSeverity(f.severity),
        location: { path: f.path, lines: { begin: f.line } },
      });
    }
  }
  return out;
}

/**
 * Writes the report, unless its content is secret-shaped: the report is uploaded as an artifact and
 * shown in the merge request widget, so it is held to the same refusal as every body posted to
 * GitLab, and on a refusal no file is written at all.
 */
export function writeCodeQualityReport(run: RunRecord, file: string): CodeQualityEntry[] {
  const report = codeQualityReport(run);
  const text = JSON.stringify(report, null, 1) + "\n";
  refuseSecrets(text, "the code quality report");
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, text);
  return report;
}
