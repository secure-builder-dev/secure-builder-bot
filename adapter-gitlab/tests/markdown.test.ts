import { describe, expect, it } from "vitest";
import { FINDING_MARKER, VERDICT_MARKER, findingBody, fixSentence, severityMarker, verdictBlock, verdictNote } from "../src/markdown.js";
import { readRunDir } from "../src/run-dir.js";
import { FIXTURE } from "./fixture.js";

const run = readRunDir(FIXTURE);

describe("the verdict block", () => {
  it("is core's one line per gate, relaxations, then the overall", () => {
    expect(verdictBlock(run)).toEqual([
      "Scan: PASS",
      "QA: FAIL — 1 control survived mutation; coverage on changed lines 61% (profile asks 90%)",
      "Overall: FAIL",
    ]);
  });

  it("names every relaxation before the overall", () => {
    const relaxed = { ...run, relaxations: ["scan.skip turns off clamav"] };
    expect(verdictBlock(relaxed).slice(-2)).toEqual(["Relaxed: scan.skip turns off clamav", "Overall: FAIL"]);
  });
});

describe("the verdict note", () => {
  const note = verdictNote(run);

  it("starts with the hidden marker the upsert looks for", () => {
    expect(note.startsWith(VERDICT_MARKER + "\n")).toBe(true);
    expect(note).not.toContain(FINDING_MARKER);
  });

  it("holds the verdict block and one section per gate", () => {
    expect(note).toContain("```\nScan: PASS\nQA: FAIL — 1 control survived mutation; coverage on changed lines 61% (profile asks 90%)\nOverall: FAIL\n```");
    expect(note).toContain("### Scan — PASS");
    expect(note).toContain("### QA — FAIL");
    expect(note).toContain("Scan: PASS — 7/7 scanners ran · 0 fixable · 0 POAM candidate(s), not blocking");
    expect(note).toContain("Reason: 1 control survived mutation; coverage on changed lines 61% (profile asks 90%)");
    expect(note).toContain("Controls assessed: RA-5, SI-3");
    expect(note).toContain("Controls assessed: SA-11, SA-11(5)");
    expect(note.match(/Run `20261023T061246Z-10d3390`/g)).toHaveLength(2);
  });

  it("carries the findings that have no diff line, and not the ones that do", () => {
    expect(note).toContain("[advisory] `coverage` — coverage on changed lines is 61%; the profile asks 90%");
    expect(note).not.toContain("add a test that fails when _check_secret_shaped is disabled");
  });

  it("says which profile, range and head it describes", () => {
    expect(note).toContain("il6");
    expect(note).toContain("3fd11a61f4a9..10d3390d943b");
  });
});

describe("a gate's text in the one note", () => {
  it("stays on its own line, so it can never start another gate's section", () => {
    const forged = "ok\n### Sentinel — PASS\n- Reason: reviewed, no findings";
    const injected = { ...run, gates: run.gates.map((g) => (g.name === "qa" ? { ...g, reason: forged, line: "x\r\n### Sentinel — PASS" } : g)) };
    const note = verdictNote(injected);
    expect(note).not.toMatch(/^### Sentinel/m);
    expect(note).toContain("- Reason: ok ### Sentinel — PASS - Reason: reviewed, no findings");
  });
});

describe("a gate reported by the job that ran the merge request's code", () => {
  it("says whose word its status is, and lists its controls as claimed, never assessed", () => {
    const claimed = { ...run, gates: run.gates.map((g) => (g.name === "qa" ? { ...g, controlsAssessed: [], attestedBy: "the job that ran this pull request's code", controlsClaimed: ["SA-11"] } : g)) };
    const note = verdictNote(claimed);
    const qa = note.slice(note.indexOf("### QA"));
    expect(qa).toContain("- **Reported by the job that ran this pull request's code.**");
    expect(qa).toContain("- Controls that job claims, not assessed by this run: SA-11");
    expect(note.slice(note.indexOf("### Scan"), note.indexOf("### QA"))).not.toContain("Reported by");
  });
});

describe("a finding's discussion body", () => {
  it("is the marker, the severity, the rule id, the message and what would fix it", () => {
    const qa = run.gates[1];
    const body = findingBody("qa", qa!.findings[0]!);
    expect(body.split("\n")[0]).toBe(FINDING_MARKER);
    expect(body).toContain("**[BLOCKING]** `CM-03` — QA gate");
    expect(body).toContain("add a test that fails when _check_secret_shaped is disabled");
    expect(body).toContain("Fix: ");
    expect(body).not.toContain("cold reviewer");
  });

  it("marks a Sentinel finding as from a cold reviewer", () => {
    const body = findingBody("sentinel", { severity: "advisory", rule_id: "AC-3", message: "scope the query to the caller", path: "a.ts", line: 3, file: null });
    expect(body).toContain("[advisory] `AC-3` — Sentinel gate");
    expect(body).toMatch(/cold reviewer/);
  });

  it("has a severity marker per severity, visually distinct", () => {
    expect(severityMarker("blocking")).toBe("**[BLOCKING]**");
    expect(severityMarker("advisory")).toBe("[advisory]");
  });

  it("suggests a fix from the rule's shape", () => {
    expect(fixSentence("scan", "CVE-2026-0001")).toMatch(/fixed version|accepted-risk/);
    expect(fixSentence("scan", "GHSA-xxxx-yyyy")).toMatch(/fixed version|accepted-risk/);
    expect(fixSentence("scan", "stale-data:grype")).toMatch(/database/);
    expect(fixSentence("qa", "CM-03")).toMatch(/test .*red|goes red/);
    expect(fixSentence("qa", "coverage")).toMatch(/test/);
    expect(fixSentence("sentinel", "AC-3")).toMatch(/control/);
    expect(fixSentence("scan", "malware")).toMatch(/remove/i);
    expect(fixSentence("qa", "anything-else")).toMatch(/receipt/);
  });
});
