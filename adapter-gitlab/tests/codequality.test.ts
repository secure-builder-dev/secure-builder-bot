import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { codeQualityReport, fingerprint, writeCodeQualityReport } from "../src/codequality.js";
import { readRunDir } from "../src/run-dir.js";
import { SecretRefused } from "../src/secrets.js";
import { FIXTURE } from "./fixture.js";

const run = readRunDir(FIXTURE);
const SEVERITIES = ["blocker", "major", "minor"];

describe("the code quality report", () => {
  it("holds one entry per finding on a diff line, in the CodeClimate shape the widget reads", () => {
    const report = codeQualityReport(run);
    expect(report).toHaveLength(1);
    const entry = report[0]!;
    expect(Object.keys(entry).sort()).toEqual(["check_name", "description", "fingerprint", "location", "severity"]);
    expect(entry.check_name).toBe("CM-03");
    expect(entry.description).toBe("[QA] add a test that fails when _check_secret_shaped is disabled");
    expect(entry.severity).toBe("blocker");
    expect(SEVERITIES).toContain(entry.severity);
    expect(entry.location).toEqual({ path: "core/securebuilderbot_core/config.py", lines: { begin: 117 } });
    expect(entry.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("fingerprints gate, rule, path, line and message with sha256, stably", () => {
    const expected = createHash("sha256").update(["qa", "CM-03", "core/securebuilderbot_core/config.py", "117", "add a test that fails when _check_secret_shaped is disabled"].join("\n")).digest("hex");
    expect(fingerprint("qa", "CM-03", "core/securebuilderbot_core/config.py", 117, "add a test that fails when _check_secret_shaped is disabled")).toBe(expected);
    expect(codeQualityReport(run)[0]!.fingerprint).toBe(expected);
    expect(fingerprint("qa", "CM-03", "core/securebuilderbot_core/config.py", 118, "x")).not.toBe(expected);
  });

  it("maps blocking to blocker and advisory to minor", () => {
    const qa = run.gates[1]!;
    const advisory = { ...run, gates: [{ ...qa, findings: [{ ...qa.findings[0]!, severity: "advisory" as const }] }] };
    expect(codeQualityReport(advisory)[0]!.severity).toBe("minor");
  });

  it("is an empty array when no finding has a line", () => {
    expect(codeQualityReport({ ...run, gates: [run.gates[0]!] })).toEqual([]);
  });

  it("is written as JSON where the component's artifacts expect it", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sb-"));
    const file = path.join(dir, "gl-code-quality-report.json");
    const written = writeCodeQualityReport(run, file);
    const parsed = JSON.parse(readFileSync(file, "utf8")) as unknown[];
    expect(parsed).toEqual(written);
    expect(parsed).toHaveLength(1);
  });

  it("refuses to write a report whose content is secret-shaped, and writes no file (gate run 1, B-01)", () => {
    const leak = "glpat-" + "A1b2C3d4E5f6G7h8I9j0";
    const leaky = { ...run, gates: run.gates.map((g) => ({ ...g, findings: g.findings.map((f) => ({ ...f, message: `token ${leak} committed` })) })) };
    const file = path.join(mkdtempSync(path.join(tmpdir(), "sb-cq-")), "gl-code-quality-report.json");
    expect(() => writeCodeQualityReport(leaky, file)).toThrow(SecretRefused);
    expect(() => writeCodeQualityReport(leaky, file)).toThrow(/the code quality report/);
    expect(existsSync(file)).toBe(false);
  });
});
