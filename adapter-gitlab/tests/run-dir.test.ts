import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { RunDirError, isTracked, readRunDir, runRefusal, selectRun } from "../src/run-dir.js";
import { FIXTURE } from "./fixture.js";

const HEAD = "10d3390d943b3ada8a8f80a9a96c9aff334f0f85";

function git(dir: string, ...args: string[]): void {
  execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...args], { stdio: "ignore" });
}

function runsIn(project: string, ...ids: string[]): string[] {
  return ids.map((id) => {
    const dir = path.join(project, "gate-records", "runs", id);
    cpSync(FIXTURE, dir, { recursive: true });
    return dir;
  });
}

describe("readRunDir", () => {
  it("reads the receipt and the verdict core wrote into one record", () => {
    const run = readRunDir(FIXTURE);
    expect(run.runId).toBe("20261023T061246Z-10d3390");
    expect(run.head).toBe("10d3390d943b3ada8a8f80a9a96c9aff334f0f85");
    expect(run.base).toBe("3fd11a61f4a961faf1196681898ff723ad0e6640");
    expect(run.profile).toMatchObject({ name: "il6", baseline: "high", catalog_version: "5.2.0" });
    expect(run.overall).toBe("fail");
    expect(run.exitCode).toBe(1);
    expect(run.gates.map((g) => [g.name, g.status])).toEqual([["scan", "pass"], ["qa", "fail"]]);
    const qa = run.gates[1];
    expect(qa?.reason).toContain("1 control survived mutation");
    expect(qa?.controlsAssessed).toEqual(["SA-11", "SA-11(5)"]);
    expect(qa?.findings).toHaveLength(2);
    expect(qa?.findings[0]).toEqual({ severity: "blocking", rule_id: "CM-03", message: "add a test that fails when _check_secret_shaped is disabled",
      path: "core/securebuilderbot_core/config.py", line: 117, file: null });
    expect(qa?.findings[1]?.line).toBeNull();
    expect(run.gates[0]?.line).toMatch(/^Scan: PASS/);
  });

  it("refuses a directory without a receipt, naming what is missing", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sb-"));
    expect(() => readRunDir(dir)).toThrow(RunDirError);
    expect(() => readRunDir(dir)).toThrow(/receipt\.json/);
  });

  it("refuses a receipt of another schema or shape", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sb-"));
    writeFileSync(path.join(dir, "receipt.json"), JSON.stringify({ schema: "something-else/9", gates: {} }));
    writeFileSync(path.join(dir, "verdict.json"), JSON.stringify({ overall: "pass", exit_code: 0, gates: [] }));
    expect(() => readRunDir(dir)).toThrow(/schema/);
    writeFileSync(path.join(dir, "receipt.json"), JSON.stringify({ schema: "securebuilderbot.receipt/1", run_id: "r", gates: { scan: { status: "maybe", findings: [] } } }));
    expect(() => readRunDir(dir)).toThrow(/status/);
    writeFileSync(path.join(dir, "receipt.json"), "{not json");
    expect(() => readRunDir(dir)).toThrow(/not valid JSON/);
  });

  it("never repeats the content of a file that is not JSON (gate run 1, N-07)", () => {
    // Node 22's JSON.parse quotes part of its input in the message; that message reaches the job log.
    const dir = mkdtempSync(path.join(tmpdir(), "sb-"));
    for (const body of ["CONTENT-THAT-MUST-NOT-BE-LOGGED", '{"a": CONTENT-THAT-MUST-NOT-BE-LOGGED}']) {
      writeFileSync(path.join(dir, "receipt.json"), body);
      let message = "";
      try {
        readRunDir(dir);
      } catch (e: unknown) {
        message = (e as Error).message;
      }
      expect(message).toMatch(/receipt\.json is not valid JSON/);
      expect(message).not.toContain("CONTENT");
    }
  });
});

describe("isTracked", () => {
  it("is false outside any git work tree and for an untracked directory inside one", () => {
    const loose = mkdtempSync(path.join(tmpdir(), "sb-"));
    expect(isTracked(loose)).toBe(false);
    const repo = mkdtempSync(path.join(tmpdir(), "sb-git-"));
    git(repo, "init", "-q");
    const [run] = runsIn(repo, "20261023T061246Z-10d3390");
    expect(isTracked(run!)).toBe(false);
  });

  it("is true once any file under the directory is in git's index", () => {
    const repo = mkdtempSync(path.join(tmpdir(), "sb-git-"));
    git(repo, "init", "-q");
    const [run] = runsIn(repo, "20261023T061246Z-10d3390");
    git(repo, "add", "gate-records/runs/20261023T061246Z-10d3390/verdict.json");
    expect(isTracked(run!)).toBe(true);
  });

  it("refuses, rather than answering no, when git cannot answer", () => {
    const repo = mkdtempSync(path.join(tmpdir(), "sb-broken-"));
    mkdirSync(path.join(repo, ".git"));
    const [run] = runsIn(repo, "20261023T061246Z-10d3390");
    expect(() => isTracked(run!)).toThrow(RunDirError);
  });
});

describe("runRefusal", () => {
  it("lets through only an untracked run for exactly the commit being published", () => {
    const [dir] = runsIn(mkdtempSync(path.join(tmpdir(), "sb-")), "20261023T061246Z-10d3390");
    const run = readRunDir(dir!);
    expect(runRefusal(run, dir!, HEAD)).toBeNull();
    expect(runRefusal(run, dir!, HEAD.slice(0, 7))).toMatch(/another commit/);
    expect(runRefusal({ ...run, head: "" }, dir!, HEAD)).toMatch(/another commit \(receipt head missing/);
    expect(runRefusal(run, FIXTURE, HEAD)).toMatch(/tracked by git/);
  });
});

describe("selectRun", () => {
  it("picks the one untracked run for the commit, passing over the others with their reasons", () => {
    const project = mkdtempSync(path.join(tmpdir(), "sb-"));
    const [real] = runsIn(project, "20261023T061246Z-10d3390");
    const [other] = runsIn(project, "99991231T235959Z-other");
    writeFileSync(path.join(other!, "receipt.json"), JSON.stringify({ ...JSON.parse(readFileSync(path.join(FIXTURE, "receipt.json"), "utf8")) as object, head: "f".repeat(40) }));
    mkdirSync(path.join(project, "gate-records", "runs", "99991231T235959Z-empty"));
    const choice = selectRun(project, HEAD);
    if ("refused" in choice) throw new Error(choice.refused);
    expect(choice.dir).toBe(real);
    expect(choice.passedOver.join("\n")).toMatch(/99991231T235959Z-empty is not a run directory/);
    expect(choice.passedOver.join("\n")).toMatch(/99991231T235959Z-other describes another commit/);
  });

  it("refuses when there is no run, naming where it looked", () => {
    const project = mkdtempSync(path.join(tmpdir(), "sb-"));
    const choice = selectRun(project, HEAD);
    expect("refused" in choice && choice.refused).toMatch(new RegExp(`no run core wrote for ${HEAD} under .*gate-records/runs — did core/run run write one\\?`));
  });

  it("refuses two untracked runs for the same commit rather than guess", () => {
    const project = mkdtempSync(path.join(tmpdir(), "sb-"));
    runsIn(project, "20261023T061246Z-10d3390", "20261023T070000Z-10d3390");
    const choice = selectRun(project, HEAD);
    expect("refused" in choice && choice.refused).toMatch(/more than one untracked run .*20261023T061246Z-10d3390, 20261023T070000Z-10d3390/);
  });

  it("holds a run named with --run-dir to the same tests", () => {
    const [dir] = runsIn(mkdtempSync(path.join(tmpdir(), "sb-")), "20261023T061246Z-10d3390");
    expect("run" in selectRun("/nonexistent", HEAD, dir)).toBe(true);
    expect(selectRun("/nonexistent", "0".repeat(40), dir)).toHaveProperty("refused");
    expect(selectRun("/nonexistent", HEAD, FIXTURE)).toHaveProperty("refused");
  });
});
