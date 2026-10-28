import { describe, expect, it } from "vitest";
import { mergeRequestApi } from "../src/gitlab-api.js";
import { FINDING_MARKER, VERDICT_MARKER } from "../src/markdown.js";
import { alreadyPosted, findVerdictNote, publish } from "../src/publish.js";
import type { RunRecord } from "../src/run-dir.js";
import { readRunDir } from "../src/run-dir.js";
import { SecretRefused } from "../src/secrets.js";
import { DIFF_REFS, FakeGitLab } from "./fake-gitlab.js";
import { FIXTURE } from "./fixture.js";

const run = readRunDir(FIXTURE);
const HEAD = run.head;

function api(gitlab: FakeGitLab) {
  return mergeRequestApi({ apiV4Url: "https://gitlab.example.invalid/api/v4", projectId: "42", mergeRequestIid: "7", token: "tok-123", fetch: gitlab.fetch });
}

/** The same run with the QA finding on config.py:117 fixed: it is gone on the new head. */
function fixedRun(): RunRecord {
  const qa = run.gates[1]!;
  return {
    ...run,
    head: "feedfacefeedfacefeedfacefeedfacefeedface",
    overall: "pass",
    exitCode: 0,
    gates: [run.gates[0]!, { ...qa, status: "pass", reason: "", findings: [] }],
  };
}

describe("publish: the first run on a merge request", () => {
  it("posts one note with both gates' sections and one discussion with a correct position", async () => {
    const gitlab = new FakeGitLab();
    const outcome = await publish({ api: api(gitlab), run, headSha: HEAD });

    const writes = gitlab.writes();
    expect(writes.map((w) => [w.method, w.path.replace("/api/v4/projects/42/merge_requests/7", "")])).toEqual([
      ["POST", "/notes"],
      ["POST", "/discussions"],
    ]);
    const note = gitlab.notes[0]!;
    expect(note.body.startsWith(VERDICT_MARKER)).toBe(true);
    expect(note.body).toContain("### Scan — PASS");
    expect(note.body).toContain("### QA — FAIL");
    expect(note.body).toContain("coverage on changed lines is 61%"); // the lineless finding lives in the note
    expect(note.body).not.toContain("_check_secret_shaped"); // the lined one does not

    const discussion = gitlab.discussions.find((d) => d.individual_note === false)!;
    expect(discussion.notes[0]!.position).toEqual({
      position_type: "text",
      base_sha: DIFF_REFS.base_sha,
      start_sha: DIFF_REFS.start_sha,
      head_sha: DIFF_REFS.head_sha,
      new_path: "core/securebuilderbot_core/config.py",
      old_path: "core/securebuilderbot_core/config.py",
      new_line: 117,
    });
    expect(discussion.notes[0]!.body).toContain(FINDING_MARKER);
    expect(discussion.notes[0]!.body).toContain("**[BLOCKING]** `CM-03` — QA gate");
    expect(outcome).toEqual({ note: { action: "created", id: note.id }, discussions: { created: 1, alreadyPosted: 0, resolved: 0 }, lineless: 1 });
  });
});

describe("publish: the noise budget on later runs", () => {
  it("edits its own note (PUT) and posts no second discussion when nothing changed", async () => {
    const gitlab = new FakeGitLab();
    await publish({ api: api(gitlab), run, headSha: HEAD });
    const noteId = gitlab.notes[0]!.id;
    gitlab.calls.length = 0;

    const outcome = await publish({ api: api(gitlab), run, headSha: HEAD });
    expect(gitlab.writes().map((w) => [w.method, w.path.replace("/api/v4/projects/42/merge_requests/7", "")])).toEqual([["PUT", `/notes/${String(noteId)}`]]);
    expect(gitlab.notes).toHaveLength(1);
    expect(gitlab.discussions.filter((d) => d.individual_note === false)).toHaveLength(1);
    expect(outcome).toEqual({ note: { action: "updated", id: noteId }, discussions: { created: 0, alreadyPosted: 1, resolved: 0 }, lineless: 1 });
  });

  it("replies 'Not found on <sha>' and resolves a discussion whose finding is gone, once", async () => {
    const gitlab = new FakeGitLab();
    await publish({ api: api(gitlab), run, headSha: HEAD });
    const fixed = fixedRun();
    gitlab.calls.length = 0;

    const outcome = await publish({ api: api(gitlab), run: fixed, headSha: fixed.head });
    const discussion = gitlab.discussions.find((d) => d.individual_note === false)!;
    expect(gitlab.writes().map((w) => [w.method, w.path.replace("/api/v4/projects/42/merge_requests/7", "")])).toEqual([
      ["PUT", `/notes/${String(gitlab.notes[0]!.id)}`],
      ["POST", `/discussions/${discussion.id}/notes`],
      ["PUT", `/discussions/${discussion.id}`],
    ]);
    expect(discussion.notes[1]!.body).toBe(`Not found on ${fixed.head}`);
    expect(discussion.notes.every((n) => n.resolved)).toBe(true);
    expect(outcome.discussions).toEqual({ created: 0, alreadyPosted: 0, resolved: 1 });
    expect(gitlab.notes[0]!.body).toContain("Overall PASS");

    gitlab.calls.length = 0;
    await publish({ api: api(gitlab), run: fixed, headSha: fixed.head });
    expect(gitlab.writes().map((w) => w.method)).toEqual(["PUT"]); // the note only: a resolved discussion is left alone
  });

  it("never touches a human's note or discussion, even on the same line", async () => {
    const gitlab = new FakeGitLab();
    const a = api(gitlab);
    await a.createNote("Looks fine to me, approving once the gates pass.");
    const human = await a.createDiscussion("Why is this here?", { position_type: "text", ...DIFF_REFS, new_path: "core/securebuilderbot_core/config.py", old_path: "core/securebuilderbot_core/config.py", new_line: 117 });
    gitlab.calls.length = 0;

    await publish({ api: a, run, headSha: HEAD });
    expect(gitlab.notes.map((n) => n.body.startsWith(VERDICT_MARKER))).toEqual([false, true]);
    expect(gitlab.discussions.filter((d) => d.individual_note === false)).toHaveLength(2);

    await publish({ api: a, run: fixedRun(), headSha: "feedfacefeedfacefeedfacefeedfacefeedface" });
    expect(gitlab.discussions.find((d) => d.id === human.id)!.notes.every((n) => n.resolved === false)).toBe(true);
    expect(gitlab.discussions.find((d) => d.id === human.id)!.notes).toHaveLength(1);
  });
});

describe("publish: refusals", () => {
  it("refuses a secret-shaped body before anything is sent", async () => {
    const gitlab = new FakeGitLab();
    const leak = "AKIA" + "ZZZZZZZZZZZZZZZZ";
    const qa = run.gates[1]!;
    const leaky: RunRecord = { ...run, gates: [run.gates[0]!, { ...qa, findings: [{ ...qa.findings[0]!, message: `the key ${leak} is committed` }] }] };
    await expect(publish({ api: api(gitlab), run: leaky, headSha: HEAD })).rejects.toThrow(SecretRefused);
    expect(gitlab.calls).toEqual([]);
  });
});

describe("the two decisions behind the noise budget", () => {
  const ours = [{ id: "d1", individual_note: false, notes: [{ id: 1, body: `${FINDING_MARKER}\nbody\n`, resolved: false, position: { position_type: "text" as const, ...DIFF_REFS, new_path: "a.ts", old_path: "a.ts", new_line: 3 } }] }];

  it("alreadyPosted: same path, line and body, by the bot", () => {
    expect(alreadyPosted(ours, "a.ts", 3, `${FINDING_MARKER}\nbody\n`)).toBe(true);
    expect(alreadyPosted(ours, "a.ts", 4, `${FINDING_MARKER}\nbody\n`)).toBe(false);
    expect(alreadyPosted(ours, "b.ts", 3, `${FINDING_MARKER}\nbody\n`)).toBe(false);
    expect(alreadyPosted(ours, "a.ts", 3, `${FINDING_MARKER}\nother\n`)).toBe(false);
    const human = [{ id: "d2", individual_note: false, notes: [{ id: 2, body: "body", position: ours[0]!.notes[0]!.position }] }];
    expect(alreadyPosted(human, "a.ts", 3, "body")).toBe(false);
  });

  it("findVerdictNote: the bot's own marker, never a system note or a human's", () => {
    expect(findVerdictNote([])).toBeUndefined();
    expect(findVerdictNote([{ id: 1, body: "approved" }, { id: 2, body: `${VERDICT_MARKER}\n## x`, system: true }])).toBeUndefined();
    expect(findVerdictNote([{ id: 3, body: "hi" }, { id: 4, body: `${VERDICT_MARKER}\n## x` }, { id: 5, body: `${VERDICT_MARKER}\n## y` }])?.id).toBe(4);
  });
});
