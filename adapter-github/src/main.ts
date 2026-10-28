// The entry point the Action runs: `npx tsx src/main.ts` after `core/run run` wrote the run
// directory. Everything comes from the Action's environment: the token, the repository, the head
// sha and pull request number from the event payload, and the run directory: SB_RUN_DIR when it is
// set (the Action sets it to the run core reported, and empty is refused), otherwise the newest under gate-records/runs/ that git does not track and whose receipt is for
// the head. A directory git tracks is refused either way: the pull request committed it, core did not
// write it. Prints what it did; exits 0, 1 or 2 as publish does.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { GitHubClient, type FetchLike } from './github-api.ts';
import { publish } from './publish.ts';
import { chooseRunDir, isTrackedByGit, RunDirError } from './run-dir.ts';

export interface EventContext {
  pullNumber: number | null;
  headSha: string | null;
}

/** The pull request number and head sha from GITHUB_EVENT_PATH, when the event has them. */
export function readEvent(path: string | undefined): EventContext {
  if (!path) return { pullNumber: null, headSha: null };
  let event: unknown;
  try {
    event = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return { pullNumber: null, headSha: null };
  }
  const pr = typeof event === 'object' && event !== null && 'pull_request' in event ? (event as { pull_request: unknown }).pull_request : null;
  if (typeof pr !== 'object' || pr === null) return { pullNumber: null, headSha: null };
  const { number, head } = pr as { number?: unknown; head?: { sha?: unknown } };
  return {
    pullNumber: typeof number === 'number' ? number : null,
    headSha: typeof head?.sha === 'string' ? head.sha : null,
  };
}

/**
 * Why this run must not post, or null. The run read its rules from GITHUB_BASE_REF's tip; a re-run of a
 * job from before a retarget replays the old base_ref, so its checks would gate the head against the
 * old target's rules and become the newest on it (third trust review, finding 1).
 */
export async function baseMoved(client: GitHubClient, event: EventContext, gatedAgainst: string | undefined): Promise<string | null> {
  if (event.pullNumber === null || !gatedAgainst) return null;
  let now: string;
  try {
    now = await client.getPullBaseRef(event.pullNumber);
  } catch (e) {
    return `could not read pull request #${event.pullNumber}'s current base (${e instanceof Error ? e.name : 'error'})`;
  }
  return now === gatedAgainst ? null : `pull request #${event.pullNumber} now targets ${now}, but this run gated it against ${gatedAgainst}'s rules`;
}

export async function main(env: NodeJS.ProcessEnv, fetchImpl?: FetchLike, log: (line: string) => void = (l) => console.log(l)): Promise<number> {
  const token = env.GITHUB_TOKEN;
  const repo = env.GITHUB_REPOSITORY;
  if (!token || !repo) {
    log('publish: GITHUB_TOKEN and GITHUB_REPOSITORY must be set (the Action sets both)');
    return 2;
  }
  const event = readEvent(env.GITHUB_EVENT_PATH);
  // On a pull_request event GITHUB_SHA is the merge commit; the checks belong on the head.
  const headSha = event.headSha ?? env.GITHUB_SHA;
  if (!headSha) {
    log('publish: no head sha — GITHUB_SHA is not set and the event has no pull_request.head.sha');
    return 2;
  }
  let runDir: string;
  if (env.SB_RUN_DIR === '') {
    // The Action sets SB_RUN_DIR from the run core reported; empty means core reported none, and
    // choosing a folder from the checkout instead is exactly what the Action passes it to prevent.
    log('publish: SB_RUN_DIR is set but empty — core reported no run directory; nothing was posted');
    return 2;
  }
  if (env.SB_RUN_DIR !== undefined) {
    runDir = env.SB_RUN_DIR;
    let tracked: boolean;
    try {
      tracked = isTrackedByGit(runDir);
    } catch (e) {
      if (!(e instanceof RunDirError)) throw e;
      log(`publish: ${e.message}; nothing was posted`);
      return 2;
    }
    if (tracked) {
      log(`publish: SB_RUN_DIR ${runDir} is tracked by git — committed by the pull request, not written by core on this runner; nothing was posted`);
      return 2;
    }
  } else {
    const choice = chooseRunDir(join(env.GITHUB_WORKSPACE ?? process.cwd(), 'gate-records', 'runs'), headSha);
    for (const why of choice.skipped) log(`publish: skipped ${why}`);
    if (choice.dir === null) {
      log(`publish: ${choice.reason}; nothing was posted`);
      return 2;
    }
    runDir = choice.dir;
  }
  const client = new GitHubClient({
    token,
    repo,
    ...(fetchImpl ? { fetch: fetchImpl } : {}),
    ...(env.GITHUB_API_URL ? { baseUrl: env.GITHUB_API_URL } : {}),
    ...(env.GITHUB_GRAPHQL_URL ? { graphqlUrl: env.GITHUB_GRAPHQL_URL } : {}),
  });
  const moved = await baseMoved(client, event, env.GITHUB_BASE_REF);
  if (moved) {
    log(`publish: ${moved}; nothing was posted`);
    return 2;
  }
  const outcome = await publish({ runDir, headSha, pullNumber: event.pullNumber, botLogin: env.SB_BOT_LOGIN ?? 'github-actions[bot]', client, log });
  log(`publish: ${outcome.checks.length} check(s), ${outcome.posted} comment(s) posted, ${outcome.skipped} already there, ${outcome.notFound} resolved as not found → exit ${outcome.exitCode}`);
  return outcome.exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.env).then((code) => {
    process.exitCode = code;
  });
}
