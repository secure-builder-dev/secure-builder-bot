// Review comments on the diff (PRD § What the user sees, On the diff): each finding with a path and
// a line the pull request changes lands as one comment carrying its severity, the rule or control
// id, the message and one sentence on what would fix it; a Sentinel finding says it comes from a
// cold reviewer with no build context. The noise budget: a comment whose body and line match one
// the bot already posted is never posted again, and a comment whose finding is gone on the new
// head gets a "Not found on <sha>" reply.
import { CHECK_PREFIX, GATE_LABEL } from './checks.ts';
import type { DiffLines } from './diff.ts';
import { inDiff } from './diff.ts';
import type { Finding, GateName, RunRecord } from './run-dir.ts';

/** An invisible marker in every body the bot writes, so its comments are its own whatever the login. */
export const BOT_MARKER = '<!-- securebuilderbot -->';
export const NOT_FOUND_PREFIX = 'Not found on ';

export interface CommentCandidate {
  path: string;
  line: number;
  body: string;
  gate: GateName;
  rule_id: string;
}

/** The fields of a pull request review comment this module reads. */
export interface ExistingComment {
  id: number;
  path: string;
  line: number | null;
  original_line?: number | null | undefined;
  body: string;
  user: { login: string };
  in_reply_to_id?: number | null | undefined;
}

/** One sentence on what would fix a finding, by the family its rule id belongs to. */
export function fixSentence(ruleId: string): string {
  const id = ruleId.toUpperCase();
  if (id.startsWith('CVE-') || id.startsWith('GHSA-')) {
    return 'Update the affected package to a version with a fix, or record an accepted risk with a reason and an expiry.';
  }
  if (ruleId.startsWith('stale-data:')) return "Refresh the scanner's vulnerability database, or point it at a mirror that is current.";
  if (ruleId.startsWith('scanner:')) return 'Make the scanner run: check its install, its network access and the scan log in the run artifact.';
  if (ruleId === 'malware') return 'Remove the infected file and rotate anything it could have touched.';
  if (/^[A-Z][A-Z]-\d/.test(ruleId)) return 'Add the check the control requires and a test that goes red without it.';
  return 'Address the message above and push a new commit; this comment resolves itself when the finding is gone.';
}

export function commentBody(finding: Finding, gate: GateName): string {
  const check = `${CHECK_PREFIX}${GATE_LABEL[gate]}`;
  const marker = finding.severity === 'blocking'
    ? `**BLOCKING** · \`${finding.rule_id}\` · ${check} — fails the check`
    : `_Advisory_ · \`${finding.rule_id}\` · ${check} — does not fail the check`;
  const lines = [marker, '', finding.message, '', `What would fix it: ${fixSentence(finding.rule_id)}`];
  if (gate === 'sentinel') {
    lines.push('', '_From a cold reviewer with no build context: it read the diff, the control manifest and the checklist, and nothing else._');
  }
  lines.push('', BOT_MARKER);
  return lines.join('\n');
}

/** Every finding with a path and a line the pull request changes, as a comment to post. */
export function planComments(run: RunRecord, diff: DiffLines): CommentCandidate[] {
  const out: CommentCandidate[] = [];
  for (const [gate, receipt] of Object.entries(run.receipt.gates) as [GateName, NonNullable<RunRecord['receipt']['gates'][GateName]>][]) {
    for (const f of receipt.findings) {
      if (f.path !== null && f.line !== null && inDiff(diff, f.path, f.line)) {
        out.push({ path: f.path, line: f.line, body: commentBody(f, gate), gate, rule_id: f.rule_id });
      }
    }
  }
  return out;
}

const lineOf = (c: ExistingComment): number | null => c.line ?? c.original_line ?? null;
const same = (c: ExistingComment, k: { path: string; line: number; body: string }): boolean =>
  c.path === k.path && lineOf(c) === k.line && c.body.trim() === k.body.trim();

/**
 * The noise budget's decision: post only when no existing comment has this body on this line.
 * `existing` is the bot's own comments on the pull request; a comment GitHub marked outdated keeps
 * its original line, which is the line the finding named.
 */
export function shouldPost(existing: readonly ExistingComment[], candidate: CommentCandidate): boolean {
  return !existing.some((c) => same(c, candidate));
}

/**
 * The bot's earlier top-level comments whose finding is no longer among the candidates for this
 * head, and which have not been answered yet: each gets a "Not found on <sha>" reply.
 */
export function staleComments(existing: readonly ExistingComment[], candidates: readonly CommentCandidate[]): ExistingComment[] {
  const answered = new Set(existing.filter((c) => c.in_reply_to_id && c.body.startsWith(NOT_FOUND_PREFIX)).map((c) => c.in_reply_to_id));
  return existing.filter((c) => !c.in_reply_to_id && c.body.includes(BOT_MARKER) && !answered.has(c.id) && !candidates.some((k) => same(c, k)));
}
