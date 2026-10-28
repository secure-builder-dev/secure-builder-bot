// The publisher's command line, run by the component after core/run run:
//   npx tsx src/main.ts [--project-dir DIR] [--run-dir DIR] [--report FILE]
// The run is the one untracked run under <project-dir>/gate-records/runs whose receipt head is
// CI_COMMIT_SHA, or the one --run-dir names, held to the same two tests; anything else is refused
// (run-dir.ts:selectRun) so a run a branch committed is never published as its verdict. The
// report defaults to <project-dir>/gl-code-quality-report.json, where the component's artifacts
// expect it. The merge request comes from the CI variables; the token from the variable whose
// NAME is in SECURE_BUILDER_TOKEN_VARIABLE (default SECURE_BUILDER_TOKEN). Nothing printed here
// ever carries that value.
// Exit 0 published · 1 could not publish (no run, a missing variable, GitLab refused) · 2 refused
// a secret-shaped body or code quality report; nothing was sent and no report was written.
import { rmSync } from "node:fs";
import path from "node:path";
import { writeCodeQualityReport } from "./codequality.js";
import { GitLabApiError, mergeRequestApi, type FetchLike } from "./gitlab-api.js";
import { publish, refuseBodies } from "./publish.js";
import { selectRun } from "./run-dir.js";
import { SecretRefused } from "./secrets.js";

export interface Deps {
  fetch?: FetchLike;
  log?: (line: string) => void;
}

const USAGE = "usage: main.ts [--project-dir DIR] [--run-dir DIR] [--report FILE]";
const REQUIRED = ["CI_PROJECT_ID", "CI_MERGE_REQUEST_IID", "CI_COMMIT_SHA", "CI_API_V4_URL"] as const;

interface Args {
  projectDir: string;
  runDir?: string;
  report?: string;
}

function parseArgs(argv: string[]): Args | string {
  const args: Args = { projectDir: process.cwd() };
  const rest = [...argv];
  while (rest.length > 0) {
    const flag = rest.shift();
    const value = rest.shift();
    if (value === undefined) return `${String(flag)} needs a value\n${USAGE}`;
    if (flag === "--project-dir") args.projectDir = path.resolve(value);
    else if (flag === "--run-dir") args.runDir = path.resolve(value);
    else if (flag === "--report") args.report = path.resolve(value);
    else return `unknown argument ${String(flag)}\n${USAGE}`;
  }
  return args;
}

export async function main(argv: string[], env: Record<string, string | undefined>, deps: Deps = {}): Promise<number> {
  const log = deps.log ?? ((line: string) => void process.stdout.write(line + "\n"));
  const parsed = parseArgs(argv);
  if (typeof parsed === "string") {
    log(`publish: ${parsed}`);
    return 1;
  }
  const reportFile = parsed.report ?? path.join(parsed.projectDir, "gl-code-quality-report.json");
  // A report already at the path is the branch's, never this run's: remove it before any refusal,
  // so a refused run uploads no report at all rather than one the merge request committed.
  rmSync(reportFile, { force: true });
  const vars = new Map(Object.entries(env));
  const missing = REQUIRED.filter((name) => !vars.get(name));
  if (missing.length) {
    log(`publish: not on a merge request pipeline — ${missing.join(", ")} not set; nothing posted`);
    return 1;
  }
  const sha = vars.get("CI_COMMIT_SHA") ?? "";
  const choice = selectRun(parsed.projectDir, sha, parsed.runDir);
  if ("refused" in choice) {
    log(`publish: ${choice.refused}`);
    log("publish: nothing posted and no code quality report written");
    return 1;
  }
  const { run } = choice;
  for (const reason of choice.passedOver) log(`publish: passed over ${reason}`);
  log(`publish: run ${run.runId} for ${sha}`);
  let report;
  try {
    // Every body and the report first: a refusal writes no report and sends nothing.
    refuseBodies(run);
    report = writeCodeQualityReport(run, reportFile);
  } catch (e: unknown) {
    if (e instanceof SecretRefused) {
      log(`publish: ${e.message}; no code quality report was written`);
      return 2;
    }
    throw e;
  }
  log(`publish: code quality report with ${String(report.length)} entr${report.length === 1 ? "y" : "ies"} at ${reportFile}`);

  const tokenVariable = vars.get("SECURE_BUILDER_TOKEN_VARIABLE") ?? "SECURE_BUILDER_TOKEN";
  const token = vars.get(tokenVariable);
  if (!token) {
    log(`publish: the CI/CD variable ${tokenVariable} is not set; it must hold a project access token with the api scope`);
    return 1;
  }
  const api = mergeRequestApi({
    apiV4Url: vars.get("CI_API_V4_URL") ?? "",
    projectId: vars.get("CI_PROJECT_ID") ?? "",
    mergeRequestIid: vars.get("CI_MERGE_REQUEST_IID") ?? "",
    token,
    ...(deps.fetch ? { fetch: deps.fetch } : {}),
  });
  try {
    const outcome = await publish({ api, run, headSha: sha });
    log(`publish: note ${outcome.note.action} (id ${String(outcome.note.id)}) · ${String(outcome.discussions.created)} discussion(s) created, ` +
      `${String(outcome.discussions.alreadyPosted)} already posted, ${String(outcome.discussions.resolved)} resolved as gone · ` +
      `${String(outcome.lineless)} finding(s) without a diff line in the note`);
    return 0;
  } catch (e: unknown) {
    if (e instanceof SecretRefused) {
      log(`publish: ${e.message}`);
      return 2;
    }
    log(`publish: ${e instanceof GitLabApiError ? e.message : `could not publish: ${e instanceof Error ? e.message : String(e)}`}`);
    return 1;
  }
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === import.meta.filename) {
  process.exitCode = await main(process.argv.slice(2), process.env);
}
