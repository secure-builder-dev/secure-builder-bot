// The publisher: a run directory core wrote, turned into the pull request's native shape (PRD §
// Platforms, § What the user sees). Plan first, post second: every check-run payload and comment
// body is built, then checked for secret-shaped strings, and only a plan that is clean reaches
// GitHub. Exit 0 when every gate passed or was yellow, 1 when any gate failed or did not run (so
// the job is red too), 2 when nothing could be published.
import { planCheckRuns } from './checks.ts';
import { NOT_FOUND_PREFIX, planComments, shouldPost, staleComments, BOT_MARKER, type CommentCandidate, type ExistingComment } from './comments.ts';
import { diffLines, inDiff, type DiffLines } from './diff.ts';
import { GitHubApiError, type GitHubClient } from './github-api.ts';
import { readRunDir, RunDirError, type Finding } from './run-dir.ts';
import { findSecretShaped } from './secrets.ts';

export interface PublishOptions {
  runDir: string;
  headSha: string;
  /** null on an event that is not a pull request: checks only, no comments. */
  pullNumber: number | null;
  /** The login the token posts as; its comments are the ones the noise budget reads. */
  botLogin: string;
  client: GitHubClient;
  log?: (line: string) => void;
}

export interface PublishOutcome {
  exitCode: 0 | 1 | 2;
  checks: string[];
  posted: number;
  skipped: number;
  notFound: number;
  resolved: number;
  /** Set when the plan was refused: what was wrong, never the string that was. */
  refused?: string;
}

/**
 * The secrets rule on the bot's own output (PRD § Security of the bot itself): the label of the
 * first piece of the plan that carries a secret-shaped string, or null when the plan may be posted.
 */
export function refusal(pieces: ReadonlyArray<readonly [label: string, text: string]>): string | null {
  const where = findSecretShaped(pieces);
  return where === null ? null : `${where} carries a secret-shaped string; nothing was posted`;
}

const quiet = (): void => undefined;

export async function publish(options: PublishOptions): Promise<PublishOutcome> {
  const log = options.log ?? quiet;
  const { client, headSha, pullNumber } = options;
  const outcome: PublishOutcome = { exitCode: 0, checks: [], posted: 0, skipped: 0, notFound: 0, resolved: 0 };

  let run;
  try {
    run = readRunDir(options.runDir);
  } catch (e) {
    if (!(e instanceof RunDirError)) throw e;
    log(`publish: ${e.message}`);
    return { ...outcome, exitCode: 2 };
  }
  // A run is published only to the head it gated. A commit cannot know its own sha, so a receipt
  // the pull request committed can never name it; one for another head is another run's verdict.
  if (!headSha) {
    log(`publish: refused — no head sha to post the checks to; nothing was posted`);
    return { ...outcome, exitCode: 2 };
  }
  if (run.receipt.head !== headSha) {
    log(`publish: refused — ${options.runDir}: receipt.json head is ${run.receipt.head.slice(0, 12) || 'missing'}, not ${headSha.slice(0, 12)}, the sha the checks would be posted to; nothing was posted`);
    return { ...outcome, exitCode: 2 };
  }

  // The plan.
  let diff: DiffLines = new Map();
  if (pullNumber !== null) {
    try {
      diff = diffLines(await client.listPullFiles(pullNumber));
    } catch (e) {
      if (!(e instanceof GitHubApiError)) throw e;
      log(`publish: could not read the pull request's files (${e.message}); findings go into the check summaries`);
    }
  }
  const commentable = (f: Finding): boolean => pullNumber !== null && f.path !== null && f.line !== null && inDiff(diff, f.path, f.line);
  const checks = planCheckRuns(run, headSha, commentable);
  const candidates: CommentCandidate[] = pullNumber === null ? [] : planComments(run, diff);

  // The refusal (CM-61): nothing is posted when any piece is secret-shaped.
  const pieces: (readonly [string, string])[] = [
    ...checks.flatMap((c) => [[`check title: ${c.name}`, c.output.title] as const, [`check summary: ${c.name}`, c.output.summary] as const]),
    ...candidates.map((c) => [`comment ${c.path}:${c.line}`, c.body] as const),
  ];
  const refused = refusal(pieces);
  if (refused !== null) {
    log(`publish: refused — ${refused}`);
    return { ...outcome, exitCode: 2, refused };
  }

  // The checks: one per gate that ran.
  for (const check of checks) {
    try {
      await client.createCheckRun(check);
      outcome.checks.push(`${check.name}: ${check.conclusion}`);
      log(`check ${check.name} → ${check.conclusion} (${check.output.title})`);
    } catch (e) {
      if (!(e instanceof GitHubApiError)) throw e;
      log(`publish: could not create the check run ${check.name} (${e.message}); the workflow needs \`checks: write\``);
      return { ...outcome, exitCode: 2 };
    }
  }

  // The comments, within the noise budget.
  if (pullNumber !== null) {
    let existing: ExistingComment[] = [];
    try {
      existing = (await client.listReviewComments(pullNumber)).filter((c) => c.user.login === options.botLogin && (c.body.includes(BOT_MARKER) || c.body.startsWith(NOT_FOUND_PREFIX)));
    } catch (e) {
      if (!(e instanceof GitHubApiError)) throw e;
      log(`publish: could not list the bot's earlier comments (${e.message}); the workflow needs \`pull-requests: write\``);
    }
    for (const candidate of candidates) {
      if (!shouldPost(existing, candidate)) {
        outcome.skipped += 1;
        continue;
      }
      try {
        await client.createReviewComment(pullNumber, { body: candidate.body, commit_id: headSha, path: candidate.path, line: candidate.line });
        outcome.posted += 1;
        log(`comment ${candidate.path}:${candidate.line} ${candidate.rule_id} posted`);
      } catch (e) {
        if (!(e instanceof GitHubApiError)) throw e;
        log(`publish: could not post the comment at ${candidate.path}:${candidate.line} (${e.message}); it stays in the check summary`);
      }
    }
    for (const stale of staleComments(existing, candidates)) {
      try {
        await client.replyToReviewComment(pullNumber, stale.id, `${NOT_FOUND_PREFIX}${headSha}`);
        outcome.notFound += 1;
        if (await client.resolveThreadOfComment(pullNumber, stale.id)) outcome.resolved += 1;
        log(`comment ${stale.path}:${stale.line ?? stale.original_line ?? '?'} not found on ${headSha.slice(0, 12)}: replied`);
      } catch (e) {
        if (!(e instanceof GitHubApiError)) throw e;
        log(`publish: could not reply to comment ${stale.id} (${e.message})`);
      }
    }
  }

  outcome.exitCode = run.verdict.gates.some((g) => g.status === 'fail' || g.status === 'not_run') ? 1 : 0;
  return outcome;
}
