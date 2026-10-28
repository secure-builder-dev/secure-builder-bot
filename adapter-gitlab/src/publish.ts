// The merge request publisher (docs/PRD.md § What the user sees, § Noise budget). From the run
// directory core wrote: one note holding the verdict block, upserted; one discussion per finding on
// a diff line, never posted twice; a finding gone on the new head gets a reply and its discussion
// resolved. Every body is checked for secret-shaped strings before the first request is sent, so a
// refusal posts nothing at all.
import type { Discussion, MergeRequestApi, Note, Position } from "./gitlab-api.js";
import { FINDING_MARKER, VERDICT_MARKER, findingBody, hasLine, verdictNote } from "./markdown.js";
import type { Finding, GateName, RunRecord } from "./run-dir.js";
import { refuseSecrets } from "./secrets.js";

export interface PublishOptions {
  api: MergeRequestApi;
  run: RunRecord;
  headSha: string; // the commit the run describes; named in the reply when a finding is gone
}

export interface PublishOutcome {
  note: { action: "created" | "updated"; id: number };
  discussions: { created: number; alreadyPosted: number; resolved: number };
  lineless: number;
}

interface LinedFinding {
  gate: GateName;
  finding: Finding & { path: string; line: number };
  body: string;
}

/** The bot's own verdict note among the merge request's notes: the oldest non-system note carrying the marker. */
export function findVerdictNote(notes: Note[]): Note | undefined {
  return notes
    .filter((n) => n.system !== true && n.body.includes(VERDICT_MARKER))
    .sort((a, b) => a.id - b.id)[0];
}

function isOurs(d: Discussion): boolean {
  const first = d.notes[0];
  return first !== undefined && first.system !== true && first.body.includes(FINDING_MARKER) && first.position != null;
}

function sameFinding(d: Discussion, path: string, line: number, body: string): boolean {
  const first = d.notes[0];
  return first?.position?.new_path === path && first.position.new_line === line && first.body.trim() === body.trim();
}

/** Has the bot already posted this finding — same path, same line, same body — on this merge request? */
export function alreadyPosted(discussions: Discussion[], path: string, line: number, body: string): boolean {
  return discussions.some((d) => isOurs(d) && sameFinding(d, path, line, body));
}

function linedFindings(run: RunRecord): LinedFinding[] {
  const out: LinedFinding[] = [];
  for (const g of run.gates) {
    for (const f of g.findings) {
      if (hasLine(f)) out.push({ gate: g.name, finding: f, body: findingBody(g.name, f) });
    }
  }
  return out;
}

/** Every body publish would send, checked before a single request: a refusal is all or nothing. Throws SecretRefused. */
export function refuseBodies(run: RunRecord): { noteBody: string; lined: LinedFinding[] } {
  const noteBody = verdictNote(run);
  const lined = linedFindings(run);
  refuseSecrets(noteBody, "the merge request note");
  for (const l of lined) refuseSecrets(l.body, `the discussion on ${l.finding.path}:${String(l.finding.line)}`);
  return { noteBody, lined };
}

export async function publish(opts: PublishOptions): Promise<PublishOutcome> {
  const { api, run } = opts;
  const { noteBody, lined } = refuseBodies(run);

  const existing = findVerdictNote(await api.listNotes());
  const note = existing ? await api.updateNote(existing.id, noteBody) : await api.createNote(noteBody);

  const discussions = await api.listDiscussions();
  const counts = { created: 0, alreadyPosted: 0, resolved: 0 };
  let refs: Position | undefined;
  for (const l of lined) {
    if (alreadyPosted(discussions, l.finding.path, l.finding.line, l.body)) {
      counts.alreadyPosted += 1;
      continue;
    }
    if (refs === undefined) {
      const d = await api.diffRefs();
      refs = { position_type: "text", base_sha: d.base_sha, start_sha: d.start_sha, head_sha: d.head_sha, new_path: "", old_path: "", new_line: 0 };
    }
    await api.createDiscussion(l.body, { ...refs, new_path: l.finding.path, old_path: l.finding.path, new_line: l.finding.line });
    counts.created += 1;
  }

  const gone = discussions.filter((d) => isOurs(d) && !d.notes.every((n) => n.resolved === true)
    && !lined.some((l) => sameFinding(d, l.finding.path, l.finding.line, l.body)));
  for (const d of gone) {
    await api.replyToDiscussion(d.id, `Not found on ${opts.headSha}`);
    await api.resolveDiscussion(d.id);
    counts.resolved += 1;
  }

  return {
    note: { action: existing ? "updated" : "created", id: note.id },
    discussions: counts,
    lineless: run.gates.reduce((n, g) => n + g.findings.filter((f) => !hasLine(f)).length, 0),
  };
}
