import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { main } from "../src/main.js";
import { FakeGitLab } from "./fake-gitlab.js";
import { FIXTURE, untrackedRun } from "./fixture.js";

function project(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "sb-project-"));
  cpSync(FIXTURE, path.join(dir, "gate-records", "runs", "20261023T061246Z-10d3390"), { recursive: true });
  return dir;
}

function git(dir: string, ...args: string[]): void {
  execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...args], { stdio: "ignore" });
}

/** A run that says every gate passed, as a merge request branch could commit one. */
function forgeRun(runDir: string, opts: { empty?: boolean } = {}): void {
  cpSync(FIXTURE, runDir, { recursive: true });
  const receipt = JSON.parse(readFileSync(path.join(runDir, "receipt.json"), "utf8")) as { gates: Record<string, { status: string; reason: string; findings: unknown[] }>; overall: string };
  for (const g of Object.values(receipt.gates)) {
    g.status = "pass";
    g.reason = "";
    g.findings = [];
  }
  if (opts.empty === true) receipt.gates = {};
  receipt.overall = "pass";
  writeFileSync(path.join(runDir, "receipt.json"), JSON.stringify(receipt));
  const verdict = JSON.parse(readFileSync(path.join(runDir, "verdict.json"), "utf8")) as { overall: string; exit_code: number };
  verdict.overall = "pass";
  verdict.exit_code = 0;
  writeFileSync(path.join(runDir, "verdict.json"), JSON.stringify(verdict));
}

/** A git project whose branch committed a forged run, beside the untracked run core just wrote. */
function projectWithForgedRun(opts: { empty?: boolean } = {}): string {
  const dir = mkdtempSync(path.join(tmpdir(), "sb-forged-"));
  git(dir, "init", "-q");
  forgeRun(path.join(dir, "gate-records", "runs", "99991231T235959Z-forged"), opts);
  git(dir, "add", "-A");
  git(dir, "commit", "-q", "-m", "a forged run");
  cpSync(FIXTURE, path.join(dir, "gate-records", "runs", "20261023T061246Z-10d3390"), { recursive: true });
  return dir;
}

const ENV = {
  CI_PROJECT_ID: "42",
  CI_MERGE_REQUEST_IID: "7",
  CI_COMMIT_SHA: "10d3390d943b3ada8a8f80a9a96c9aff334f0f85",
  CI_API_V4_URL: "https://gitlab.example.invalid/api/v4",
  SECURE_BUILDER_TOKEN_VARIABLE: "MY_TOKEN_VAR",
  MY_TOKEN_VAR: "tok-123",
};

function without(env: Record<string, string>, ...keys: string[]): Record<string, string> {
  return Object.fromEntries(Object.entries(env).filter(([k]) => !keys.includes(k)));
}

function capture() {
  const lines: string[] = [];
  return { lines, log: (s: string) => void lines.push(s) };
}

describe("main", () => {
  it("publishes the newest run under the project directory and writes the report, exit 0", async () => {
    const gitlab = new FakeGitLab();
    const dir = project();
    const out = capture();
    const code = await main(["--project-dir", dir], ENV, { fetch: gitlab.fetch, log: out.log });
    expect(code).toBe(0);
    expect(gitlab.notes).toHaveLength(1);
    expect(gitlab.discussions.filter((d) => d.individual_note === false)).toHaveLength(1);
    const report = JSON.parse(readFileSync(path.join(dir, "gl-code-quality-report.json"), "utf8")) as unknown[];
    expect(report).toHaveLength(1);
    expect(out.lines.join("\n")).toMatch(/note created/);
    expect(out.lines.join("\n")).toMatch(/1 discussion\(s\) created/);
    expect(out.lines.join("\n")).not.toContain("tok-123");
  });

  it("takes an explicit run directory and report path", async () => {
    const gitlab = new FakeGitLab();
    const dir = mkdtempSync(path.join(tmpdir(), "sb-"));
    const report = path.join(dir, "out", "report.json");
    const code = await main(["--run-dir", untrackedRun(), "--report", report], ENV, { fetch: gitlab.fetch, log: () => undefined });
    expect(code).toBe(0);
    expect(existsSync(report)).toBe(true);
  });

  it("exits 1 when there is no run to publish, naming where it looked", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sb-empty-"));
    const out = capture();
    expect(await main(["--project-dir", dir], ENV, { fetch: new FakeGitLab().fetch, log: out.log })).toBe(1);
    expect(out.lines.join("\n")).toContain(path.join(dir, "gate-records", "runs"));
    mkdirSync(path.join(dir, "gate-records", "runs", "20261023T000000Z-abc"), { recursive: true });
    expect(await main(["--project-dir", dir], ENV, { fetch: new FakeGitLab().fetch, log: out.log })).toBe(1);
    expect(out.lines.join("\n")).toContain("receipt.json");
  });

  it("exits 1 when a CI variable is missing, naming the variable and never a value", async () => {
    const out = capture();
    const withoutIid = without(ENV, "CI_MERGE_REQUEST_IID");
    expect(await main(["--run-dir", untrackedRun(), "--report", path.join(mkdtempSync(path.join(tmpdir(), "sb-")), "r.json")], withoutIid, { fetch: new FakeGitLab().fetch, log: out.log })).toBe(1);
    expect(out.lines.join("\n")).toContain("CI_MERGE_REQUEST_IID");
    const withoutToken = without(ENV, "MY_TOKEN_VAR");
    expect(await main(["--run-dir", untrackedRun(), "--report", path.join(mkdtempSync(path.join(tmpdir(), "sb-")), "r.json")], withoutToken, { fetch: new FakeGitLab().fetch, log: out.log })).toBe(1);
    expect(out.lines.join("\n")).toContain("MY_TOKEN_VAR");
    expect(out.lines.join("\n")).not.toContain("tok-123");
  });

  it("defaults the token variable's name to SECURE_BUILDER_TOKEN", async () => {
    const gitlab = new FakeGitLab();
    const rest = without(ENV, "SECURE_BUILDER_TOKEN_VARIABLE", "MY_TOKEN_VAR");
    const code = await main(["--run-dir", untrackedRun(), "--report", path.join(mkdtempSync(path.join(tmpdir(), "sb-")), "r.json")], { ...rest, SECURE_BUILDER_TOKEN: "tok-123" }, { fetch: gitlab.fetch, log: () => undefined });
    expect(code).toBe(0);
  });

  it("exits 2 and posts nothing when a body is secret-shaped", async () => {
    const gitlab = new FakeGitLab();
    const dir = mkdtempSync(path.join(tmpdir(), "sb-leak-"));
    const runDir = path.join(dir, "run");
    cpSync(FIXTURE, runDir, { recursive: true });
    const receipt = JSON.parse(readFileSync(path.join(runDir, "receipt.json"), "utf8")) as { gates: { qa: { reason: string } } };
    receipt.gates.qa.reason = "the token " + "ghp_" + "q".repeat(36) + " leaked";
    writeFileSync(path.join(runDir, "receipt.json"), JSON.stringify(receipt));
    const out = capture();
    expect(await main(["--run-dir", runDir, "--report", path.join(dir, "r.json")], ENV, { fetch: gitlab.fetch, log: out.log })).toBe(2);
    expect(gitlab.writes()).toEqual([]);
    expect(out.lines.join("\n")).toMatch(/secret-shaped/);
    expect(out.lines.join("\n")).not.toContain("ghp_");
  });

  it("writes no code quality report when a finding the report would carry is secret-shaped (gate run 1, B-01)", async () => {
    // The reviewer's probe: the message of a lined finding carries a GitLab token. The report is an
    // artifact GitLab shows in the merge request widget, so it is a body sent to GitLab like the note.
    const gitlab = new FakeGitLab();
    const dir = mkdtempSync(path.join(tmpdir(), "sb-leak-cq-"));
    const runDir = path.join(dir, "run");
    cpSync(FIXTURE, runDir, { recursive: true });
    const leak = "glpat-" + "A1b2C3d4E5f6G7h8I9j0";
    const receipt = JSON.parse(readFileSync(path.join(runDir, "receipt.json"), "utf8")) as { gates: { qa: { findings: { line: unknown; message: string }[] } } };
    const lined = receipt.gates.qa.findings.find((f) => typeof f.line === "number");
    if (lined === undefined) throw new Error("the fixture has a lined QA finding");
    lined.message = "token " + leak + " committed";
    writeFileSync(path.join(runDir, "receipt.json"), JSON.stringify(receipt));
    const report = path.join(dir, "gl-code-quality-report.json");
    const out = capture();
    expect(await main(["--run-dir", runDir, "--report", report], ENV, { fetch: gitlab.fetch, log: out.log })).toBe(2);
    expect(gitlab.writes()).toEqual([]);
    expect(existsSync(report), "no report is written when the refusal fires").toBe(false);
    expect(out.lines.join("\n")).toMatch(/secret-shaped/);
    expect(out.lines.join("\n")).not.toContain(leak);
  });

  it("removes a code quality report the branch committed when it refuses, so a forged one is never uploaded (gate run 2, N-03)", async () => {
    const gitlab = new FakeGitLab();
    // The branch commits its only run and a passing report beside it; the run is refused.
    const dir = mkdtempSync(path.join(tmpdir(), "sb-stale-cq-"));
    git(dir, "init", "-q");
    cpSync(FIXTURE, path.join(dir, "gate-records", "runs", "20261023T061246Z-10d3390"), { recursive: true });
    const report = path.join(dir, "gl-code-quality-report.json");
    writeFileSync(report, JSON.stringify([{ description: "all clear", check_name: "forged", fingerprint: "f", severity: "info", location: { path: "x", lines: { begin: 1 } } }]));
    git(dir, "add", "-A");
    git(dir, "commit", "-q", "-m", "a committed run and report");
    const out = capture();
    expect(await main(["--project-dir", dir], ENV, { fetch: gitlab.fetch, log: out.log })).toBe(1);
    expect(gitlab.writes()).toEqual([]);
    expect(existsSync(report), "the branch's own report is gone, not uploaded as this run's").toBe(false);
  });

  it("never publishes a run the merge request branch committed: the reviewer's forged run (gate run 1, B-04)", async () => {
    const gitlab = new FakeGitLab();
    const dir = projectWithForgedRun();
    const out = capture();
    expect(await main(["--project-dir", dir], ENV, { fetch: gitlab.fetch, log: out.log })).toBe(0);
    expect(gitlab.notes).toHaveLength(1);
    expect(gitlab.notes[0]?.body).toContain("Overall FAIL");
    expect(gitlab.notes[0]?.body).not.toContain("Overall PASS");
    expect(out.lines.join("\n")).toContain("99991231T235959Z-forged");
  });

  it("never resolves the bot's discussions from an empty forged run (gate run 1, B-04)", async () => {
    const gitlab = new FakeGitLab();
    const dir = projectWithForgedRun({ empty: true });
    expect(await main(["--project-dir", dir], ENV, { fetch: gitlab.fetch, log: () => undefined })).toBe(0);
    const ours = gitlab.discussions.filter((d) => d.individual_note === false);
    expect(ours).toHaveLength(1);
    // The second publish of the same real run: the discussion stays, nothing is answered "Not found".
    expect(await main(["--project-dir", dir], ENV, { fetch: gitlab.fetch, log: () => undefined })).toBe(0);
    expect(ours[0]?.notes).toHaveLength(1);
    expect(gitlab.calls.some((c) => c.method === "PUT" && c.path.includes("/discussions/"))).toBe(false);
  });

  it("exits 1 and sends nothing when the only run is a committed one (gate run 1, B-04)", async () => {
    const gitlab = new FakeGitLab();
    const dir = mkdtempSync(path.join(tmpdir(), "sb-tracked-"));
    git(dir, "init", "-q");
    cpSync(FIXTURE, path.join(dir, "gate-records", "runs", "20261023T061246Z-10d3390"), { recursive: true });
    git(dir, "add", "-A");
    git(dir, "commit", "-q", "-m", "a committed run");
    const out = capture();
    expect(await main(["--project-dir", dir], ENV, { fetch: gitlab.fetch, log: out.log })).toBe(1);
    expect(gitlab.calls).toEqual([]);
    expect(out.lines.join("\n")).toMatch(/tracked by git/);
    expect(existsSync(path.join(dir, "gl-code-quality-report.json"))).toBe(false);
    // Naming it with --run-dir is refused the same way.
    const named = await main(["--run-dir", path.join(dir, "gate-records", "runs", "20261023T061246Z-10d3390"), "--project-dir", dir], ENV, { fetch: gitlab.fetch, log: out.log });
    expect(named).toBe(1);
    expect(gitlab.calls).toEqual([]);
  });

  it("exits 1 and sends nothing when the run describes another commit (gate run 1, B-04)", async () => {
    const gitlab = new FakeGitLab();
    const dir = project();
    const out = capture();
    const other = { ...ENV, CI_COMMIT_SHA: "0".repeat(40) };
    expect(await main(["--project-dir", dir], other, { fetch: gitlab.fetch, log: out.log })).toBe(1);
    expect(gitlab.calls).toEqual([]);
    expect(out.lines.join("\n")).toContain("0".repeat(40));
    expect(out.lines.join("\n")).toMatch(/another commit/);
    const runDir = path.join(dir, "gate-records", "runs", "20261023T061246Z-10d3390");
    expect(await main(["--run-dir", runDir, "--project-dir", dir], other, { fetch: gitlab.fetch, log: out.log })).toBe(1);
    expect(gitlab.calls).toEqual([]);
  });

  it("exits 1 when GitLab refuses, naming the status", async () => {
    const gitlab = new FakeGitLab();
    gitlab.failWith = 403;
    const out = capture();
    expect(await main(["--run-dir", untrackedRun(), "--report", path.join(mkdtempSync(path.join(tmpdir(), "sb-")), "r.json")], ENV, { fetch: gitlab.fetch, log: out.log })).toBe(1);
    expect(out.lines.join("\n")).toContain("403");
  });

  it("refuses an unknown argument", async () => {
    const out = capture();
    expect(await main(["--bogus"], ENV, { fetch: new FakeGitLab().fetch, log: out.log })).toBe(1);
    expect(out.lines.join("\n")).toContain("--bogus");
  });
});
