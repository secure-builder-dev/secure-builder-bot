// The run directory core wrote (core/securebuilderbot_core/runner.py): receipt.json is the
// contract, verdict.json the exit code. The publisher reads both into one record and refuses a
// directory that is not a run, so a missing or half-written receipt is never published as a pass.
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

export type Severity = "blocking" | "advisory";
export type Status = "pass" | "fail" | "yellow" | "not_run";
export type GateName = "scan" | "qa" | "sentinel";

export interface Finding {
  severity: Severity;
  rule_id: string;
  message: string;
  path: string | null;
  line: number | null;
  file: string | null;
}

export interface GateRecord {
  name: GateName;
  status: Status;
  reason: string;
  findings: Finding[];
  controlsAssessed: string[];
  line?: string; // the scan's one verdict line, when the gate wrote one
  attestedBy?: string; // set when the gate ran in the job that ran the merge request's code: whose word the status is
  controlsClaimed?: string[]; // that job's controls: claimed, never assessed by the run that published
}

export interface Profile {
  name: string;
  title: string;
  baseline: string | null;
  catalog_version: string;
  controls: number;
}

export interface RunRecord {
  runId: string;
  base: string;
  head: string;
  branch: string;
  depth: string;
  profile: Profile;
  relaxations: string[];
  gates: GateRecord[];
  overall: string;
  exitCode: number;
}

export class RunDirError extends Error {}

const SCHEMA_PREFIX = "securebuilderbot.receipt/";
const GATE_ORDER: readonly GateName[] = ["scan", "qa", "sentinel"];
const STATUSES: readonly string[] = ["pass", "fail", "yellow", "not_run"];
const SEVERITIES: readonly string[] = ["blocking", "advisory"];

function readJson(dir: string, name: string): Record<string, unknown> {
  const file = path.join(dir, name);
  if (!existsSync(file)) throw new RunDirError(`${dir} is not a run directory: no ${name}`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch (e: unknown) {
    // JSON.parse's own message quotes part of the input on Node 22, and this one reaches the job
    // log; only the position, a number, is kept.
    const at = /at position \d+/.exec(e instanceof Error ? e.message : "");
    throw new RunDirError(`${file} is not valid JSON${at ? ` (${at[0]})` : ""}; its content is not repeated here`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new RunDirError(`${file} is not a JSON object`);
  return parsed as Record<string, unknown>;
}

function str(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((x): x is string => typeof x === "string") : [];
}

function finding(raw: unknown, where: string): Finding {
  if (typeof raw !== "object" || raw === null) throw new RunDirError(`${where}: a finding is not an object`);
  const f = raw as Record<string, unknown>;
  if (!SEVERITIES.includes(str(f["severity"]))) throw new RunDirError(`${where}: finding severity must be blocking or advisory`);
  return {
    severity: f["severity"] as Severity,
    rule_id: str(f["rule_id"], "unknown"),
    message: str(f["message"]),
    path: typeof f["path"] === "string" ? f["path"] : null,
    line: typeof f["line"] === "number" && Number.isInteger(f["line"]) && f["line"] > 0 ? f["line"] : null,
    file: typeof f["file"] === "string" ? f["file"] : null,
  };
}

function gate(name: GateName, raw: unknown): GateRecord {
  if (typeof raw !== "object" || raw === null) throw new RunDirError(`receipt gates.${name} is not an object`);
  const g = raw as Record<string, unknown>;
  const status = str(g["status"]);
  if (!STATUSES.includes(status)) throw new RunDirError(`receipt gates.${name}.status must be one of ${STATUSES.join(", ")}`);
  const rawFindings = Array.isArray(g["findings"]) ? g["findings"] : [];
  const record: GateRecord = {
    name,
    status: status as Status,
    reason: str(g["reason"]),
    findings: rawFindings.map((f, i) => finding(f, `receipt gates.${name}.findings[${String(i)}]`)),
    controlsAssessed: strings(g["controls_assessed"]),
  };
  if (typeof g["line"] === "string") record.line = g["line"];
  if (typeof g["attested_by"] === "string") record.attestedBy = g["attested_by"];
  if (Array.isArray(g["controls_claimed"])) record.controlsClaimed = strings(g["controls_claimed"]);
  return record;
}

export function readRunDir(dir: string): RunRecord {
  const receipt = readJson(dir, "receipt.json");
  const verdict = readJson(dir, "verdict.json");
  if (!str(receipt["schema"]).startsWith(SCHEMA_PREFIX)) {
    throw new RunDirError(`${path.join(dir, "receipt.json")}: schema is not ${SCHEMA_PREFIX}*`);
  }
  const rawGates = receipt["gates"];
  if (typeof rawGates !== "object" || rawGates === null) throw new RunDirError("receipt has no gates object");
  const sections = new Map(Object.entries(rawGates));
  const gates = GATE_ORDER.filter((n) => sections.has(n)).map((n) => gate(n, sections.get(n)));
  const profile = (typeof receipt["profile"] === "object" && receipt["profile"] !== null ? receipt["profile"] : {}) as Record<string, unknown>;
  const exitCode = verdict["exit_code"];
  return {
    runId: str(receipt["run_id"], path.basename(dir)),
    base: str(receipt["base"]),
    head: str(receipt["head"]),
    branch: str(receipt["branch"]),
    depth: str(receipt["depth"]),
    profile: {
      name: str(profile["name"], "unknown"),
      title: str(profile["title"]),
      baseline: typeof profile["baseline"] === "string" ? profile["baseline"] : null,
      catalog_version: str(profile["catalog_version"]),
      controls: typeof profile["controls"] === "number" ? profile["controls"] : 0,
    },
    relaxations: strings(receipt["relaxations"]),
    gates,
    overall: str(verdict["overall"], str(receipt["overall"], "fail")),
    exitCode: typeof exitCode === "number" ? exitCode : 1,
  };
}

/**
 * Is anything under `dir` tracked by git? A run directory a branch committed is the branch author's
 * writing, not core's, so it is never published. Outside any git work tree nothing can be tracked;
 * inside one, git is asked, and an answer it cannot give is a refusal, never a "no".
 */
export function isTracked(dir: string): boolean {
  let probe = path.resolve(dir);
  for (;;) {
    if (existsSync(path.join(probe, ".git"))) break;
    const parent = path.dirname(probe);
    if (parent === probe) return false;
    probe = parent;
  }
  let listed: string;
  try {
    listed = execFileSync("git", ["-C", dir, "ls-files", "-z", "--", "."], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    throw new RunDirError(`could not ask git whether ${dir} is tracked; refusing to publish it`);
  }
  return listed.length > 0;
}

/**
 * Why this run must not be published for `sha`, or null when it may be. Only a run core wrote in
 * this job, for exactly this commit, is published: one tracked by git was committed by the branch,
 * and one whose receipt head is another commit is not this pipeline's verdict.
 */
export function runRefusal(run: RunRecord, dir: string, sha: string): string | null {
  if (isTracked(dir)) return `${dir} is tracked by git: a committed run is never published`;
  if (run.head !== sha) return `${dir} describes another commit (receipt head ${run.head || "missing"}, publishing for ${sha})`;
  return null;
}

export type RunChoice = { dir: string; run: RunRecord; passedOver: string[] } | { refused: string };

/**
 * The run to publish for `sha`: the one named, or else the one untracked run under
 * <project>/gate-records/runs whose receipt head is `sha`. Every other directory there is passed
 * over with its reason; none, or more than one, is a refusal naming each.
 */
export function selectRun(projectDir: string, sha: string, named?: string): RunChoice {
  const runs = path.join(projectDir, "gate-records", "runs");
  const dirs = named !== undefined ? [named]
    : existsSync(runs) ? readdirSync(runs).sort().map((n) => path.join(runs, n)).filter((d) => statSync(d).isDirectory()) : [];
  const valid: { dir: string; run: RunRecord }[] = [];
  const reasons: string[] = [];
  for (const dir of dirs) {
    try {
      const run = readRunDir(dir);
      const refusal = runRefusal(run, dir, sha);
      if (refusal === null) valid.push({ dir, run });
      else reasons.push(refusal);
    } catch (e: unknown) {
      if (!(e instanceof RunDirError)) throw e;
      reasons.push(e.message);
    }
  }
  const only = valid[0];
  if (valid.length === 1 && only !== undefined) return { ...only, passedOver: reasons };
  const where = named ?? runs;
  const head = valid.length > 1
    ? `more than one untracked run for ${sha} under ${where} (${valid.map((v) => path.basename(v.dir)).join(", ")}); name one with --run-dir`
    : `no run core wrote for ${sha} under ${where}${dirs.length ? "" : " — did core/run run write one?"}`;
  return { refused: [head, ...reasons.map((r) => `  passed over: ${r}`)].join("\n") };
}
