// `securebuilderbot init` (docs/PRD.md § The one-command alternative): detect GitHub or GitLab from
// the origin remote, answer the three questions, show the implementation option they imply, write
// `.securebuilderbot.yml` and the platform file from the adapters' own templates, and commit them on
// a new local branch `secure-builder/enable`, never on the branch the user is on. The files are the
// ones the setup pull request writes, byte for byte, because they come from the same functions.
//
// Two refusals stand in front of every write. An existing `.securebuilderbot.yml` (or workflow
// file, or setup branch) is never overwritten without --force (CM-80), and a file that would carry
// the value of a token from the environment is never written (CM-81, redact.ts).
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { GitHubApiError, GitHubClient } from "../../adapter-github/src/github-api.ts";
import { SetupBranchExists as GitHubBranchExists, openSetupPr } from "../../adapter-github/src/setup-pr.ts";
import { CONFIG_PATH, SETUP_BRANCH, WORKFLOW_PATH, effectiveGates, setupFiles, validateAnswers, type SetupAnswers } from "../../adapter-github/src/templates.ts";
import { GitLabApiError } from "../../adapter-gitlab/src/gitlab-api.ts";
import { SecretRefused } from "../../adapter-gitlab/src/secrets.ts";
import { CI_PATH, IncludeNotMergeable, SETUP_MR_TITLE, SetupBranchExists as GitLabBranchExists, mergeInclude, openSetupMr, projectApi } from "../../adapter-gitlab/src/setup-mr.ts";
import { configTemplate as gitlabConfigTemplate, includeSnippet } from "../../adapter-gitlab/src/templates.ts";
import { AnswerError, askPlatform, implementationOption, resolveAnswers } from "./answers.ts";
import { GitError, git, gitOk, gitRaw, repoRoot } from "./git.ts";
import { EXIT, type Command, type Io, type Values } from "./io.ts";
import { platformOf, remoteOf, type Platform, type Remote } from "./platform.ts";
import { TokenInFile, redactTokens, tokenValues, writeRedacted } from "./redact.ts";
import { botHome } from "./run.ts";

export const PUBLISH_TOKEN_VARIABLE = "SECURE_BUILDER_TOKEN";
export const MANIFEST_PATH = "docs/security/CONTROL-MANIFEST.md";
export const PROJECT_CONFIG_PATH = "project.config.yaml";

const DRAFT_HEADER =
  "<!-- Drafted by securebuilderbot init from this repository's code, for the team to confirm in the setup\n" +
  "     pull request: delete each row that is not a security control, add any the draft missed (code that\n" +
  "     hides data, limits abuse, proves identity or fails safely without refusing), check each proving test,\n" +
  "     then merge. Until a list with rows is merged, QA sabotage-tests a fresh draft on every run and stays\n" +
  "     yellow. Rows marked \"suggested\" were found by their names, not by a refusal. -->\n";

const CONFIG_HEADER =
  "# Proposed by securebuilderbot init: no control roots were configured and none of the default ones\n" +
  "# (backend/src/{middleware,services,controllers}) exist, so the control list beside this file was drafted\n" +
  "# from the roots below, inferred from this repository's layout. QA reads these keys once a control list\n" +
  "# with rows is merged: check the roots, the test directory and the suite command before merging.\n";

export interface DraftedList {
  content: string;
  rows: number;
  suggested: number;
  /** The CONTROL_* lines for project.config.yaml when the roots were inferred from the layout, else null. */
  config: string[] | null;
}

/**
 * The control list drafted from the repository's code by the QA module's own derive-controls --draft,
 * from the bot's checkout, or null when it drafts nothing. With no roots configured and none of the
 * default ones, the script infers them from the layout (--infer-roots) and names them in `config`.
 * The script reads the code and runs none of it; it gets no token, since it needs none (only PATH and
 * HOME are passed).
 */
export function draftControlList(root: string, env: Io["env"]): DraftedList | null {
  const script = path.join(botHome(env), "qa", "scripts", "derive-controls.sh");
  if (!existsSync(script)) return null;
  const vars = new Map(Object.entries(env));
  const scratch = mkdtempSync(path.join(tmpdir(), "securebuilderbot-init-"));
  const proposed = path.join(scratch, "config");
  try {
    const r = spawnSync("bash", [script, "--draft", "-", "--infer-roots", "--propose-config", proposed], {
      cwd: root, encoding: "utf8", env: { PATH: vars.get("PATH") ?? "/usr/bin:/bin", HOME: vars.get("HOME") ?? root },
    });
    if (r.status !== 0 && r.status !== 1) return null;  // 1 is the script saying guards are unregistered: the draft is still good
    const table = r.stdout.split("\n").filter((l) => l.startsWith("|"));
    const rows = table.filter((l) => /^\| CM-\d+ /.test(l));
    if (rows.length === 0) return null;
    const lines = existsSync(proposed) ? readFileSync(proposed, "utf8").split("\n").filter((l) => /^CONTROL_[A-Z_]+: \S/.test(l)) : [];
    return { content: DRAFT_HEADER + table.join("\n") + "\n", rows: rows.length, suggested: rows.filter((l) => l.includes(" — suggested: ")).length,
             config: lines.length > 0 ? lines : null };
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

/**
 * The refusal to overwrite the team's project.config.yaml: true when the working tree or the tree the
 * setup starts from has one, a link included (lstat, never existsSync, which a dangling link answers
 * false). init then prints the inferred lines for a person to add, and writes nothing there.
 */
export function keptConfig(root: string, source: string): boolean {
  let here = true;
  try {
    lstatSync(path.join(root, PROJECT_CONFIG_PATH));
  } catch {
    here = false;
  }
  return here || fileAt(root, source, PROJECT_CONFIG_PATH) !== null;
}

/**
 * CM-80. The refusal to overwrite: null when nothing would be overwritten or --force was given,
 * otherwise the line that says what already exists. Nothing is written when this refuses.
 */
export function overwriteRefusal(existing: readonly string[], force: boolean): string | null {
  if (force || existing.length === 0) return null;
  const verb = existing.length === 1 ? "exists" : "exist";
  return `refused: ${existing.join(" and ")} already ${verb} — init never overwrites without --force`;
}

interface PlannedFile {
  path: string;
  content: string;
  write: boolean;
  /** the line in the list of writes */
  note: string;
}

async function choosePlatform(values: Values, remote: Remote | null, io: Io): Promise<{ platform: Platform; how: string }> {
  const flag = values["platform"];
  if (typeof flag === "string") {
    if (flag !== "github" && flag !== "gitlab") throw new AnswerError(`--platform must be github or gitlab, not ${JSON.stringify(flag)}`);
    return { platform: flag, how: "from --platform" };
  }
  const detected = platformOf(remote);
  if (detected !== null) return { platform: detected, how: "from the origin remote" };
  if (values["yes"] === true) throw new AnswerError("the origin remote is neither github.com nor a GitLab host: pass --platform github or --platform gitlab");
  return { platform: await askPlatform(io), how: "as answered" };
}

function planFiles(platform: Platform, setup: SetupAnswers, existing: string | null, group: string | undefined): PlannedFile[] {
  if (platform === "github") {
    return setupFiles(setup).map((f) => ({ ...f, write: true, note: `wrote ${f.path}` }));
  }
  const config = gitlabConfigTemplate({ profile: setup.profile, gates: effectiveGates(setup), sentinel: setup.sentinel, version: "latest" });
  const merged = mergeInclude(existing, includeSnippet({ ...(group === undefined ? {} : { group }), version: "latest" }));
  const ciNote = !merged.changed
    ? `${CI_PATH} already includes the component (unchanged)`
    : existing === null || existing.trim() === ""
      ? `created ${CI_PATH} with the include`
      : `appended the include to ${CI_PATH}`;
  return [
    { path: CONFIG_PATH, content: config, write: true, note: `wrote ${CONFIG_PATH}` },
    { path: CI_PATH, content: merged.content, write: merged.changed, note: ciNote },
  ];
}

function describeAnswers(io: Io, platform: Platform, how: string, setup: SetupAnswers): void {
  const gates = effectiveGates(setup);
  const option = implementationOption(gates);
  io.out(`platform: ${platform} (${how})`);
  io.out(`answers: profile ${setup.profile} · gates ${gates.join(", ")} · sentinel ${setup.sentinel}`);
  io.out(`option: ${option.name} — ${gates.join(", ")}`);
  for (const r of option.requires) io.out(`  requires ${r}`);
  if (platform === "gitlab") io.out(`  requires a project access token with the api scope, as the masked, protected CI/CD variable ${PUBLISH_TOKEN_VARIABLE}, for the publisher`);
  for (const w of option.warnings) io.out(`warning: ${w}`);
}

/**
 * The first part of `rel` under `root` that is a symbolic link, or null (gate cli run 1, N-04).
 * Every write init makes goes to a path under the repository; a link anywhere on that path, the
 * file itself or a directory above it, could send the write anywhere the user can write, so init
 * refuses it whatever --force says. A part that does not exist yet ends the walk: below it, init
 * creates plain directories itself.
 */
function symlinkOnPath(root: string, rel: string, ref: string | null): string | null {
  const parts = rel.split("/");
  const prefixes = parts.map((_, i) => parts.slice(0, i + 1).join("/"));
  for (const prefix of prefixes) {
    let isLink: boolean;
    try {
      isLink = lstatSync(path.join(root, prefix)).isSymbolicLink();
    } catch {
      break;
    }
    if (isLink) return prefix;
  }
  // The setup branch starts from `ref` (N-06), so a link committed there lands in the working tree
  // when init switches to it: git's mode 120000 is a link.
  if (ref === null) return null;
  for (const prefix of prefixes) {
    const entry = gitRaw(root, "ls-tree", ref, "--", prefix) ?? "";
    if (entry === "") return null;
    if (entry.startsWith("120000 ")) return prefix;
  }
  return null;
}

/**
 * The ref the local setup branch starts from (gate cli run 1, N-06): the default branch, as origin
 * names it (origin/HEAD) or by the usual names, origin's copy first because the pull request targets
 * it. Never the branch the user happens to be on, whose unmerged work would ride along. Null when
 * there is none to find.
 */
function defaultBase(root: string): string | null {
  if (gitOk(root, "symbolic-ref", "-q", "refs/remotes/origin/HEAD")) {
    const head = git(root, "symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD");
    if (gitOk(root, "rev-parse", "--verify", "-q", `${head}^{commit}`)) return head;
  }
  const candidates: [string, string][] = [
    ["refs/remotes/origin/main", "origin/main"],
    ["refs/remotes/origin/master", "origin/master"],
    ["refs/heads/main", "main"],
    ["refs/heads/master", "master"],
  ];
  return candidates.find(([ref]) => gitOk(root, "rev-parse", "--verify", "-q", `${ref}^{commit}`))?.[1] ?? null;
}

/** The file's text at `ref`, or null when it is not there. */
function fileAt(root: string, ref: string, rel: string): string | null {
  return gitOk(root, "cat-file", "-e", `${ref}:${rel}`) ? gitRaw(root, "show", `${ref}:${rel}`) : null;
}

/**
 * The setup files with uncommitted changes, untracked ones included (gate cli run 1, N-03). init
 * writes and commits these on its own branch; an edit the user had not committed would be carried
 * there and vanish from their branch when they switch back. --force does not change this.
 */
function uncommittedSetupFiles(root: string): string[] {
  const files = [CONFIG_PATH, WORKFLOW_PATH, CI_PATH];
  const changed = [
    gitOk(root, "rev-parse", "--verify", "-q", "HEAD") ? git(root, "diff", "--name-only", "HEAD", "--", ...files) : "",
    git(root, "diff", "--cached", "--name-only", "--", ...files),
    git(root, "ls-files", "--others", "--exclude-standard", "--", ...files),
  ].flatMap((out) => out.split("\n").filter((l) => l !== ""));
  return [...new Set(changed)].sort();
}

function currentBranch(root: string): string | null {
  try {
    return git(root, "symbolic-ref", "--short", "-q", "HEAD");
  } catch {
    return null;
  }
}

/**
 * The token for the platform, by name from the environment; never asked for. A value holding
 * whitespace or a control character is refused before any request (gate cli run 4, B-01): no
 * token has either, and fetch's header error quotes such a value trimmed, which full-value
 * redaction cannot match. The usual cause is a token read from a file with Windows line endings
 * (CM-88).
 */
function tokenFor(platform: Platform, env: Io["env"]): string | undefined {
  const names = platform === "github" ? ["GITHUB_TOKEN", "GH_TOKEN"] : ["GITLAB_TOKEN"];
  const set = new Map(Object.entries(env));
  const name = names.find((n) => (set.get(n) ?? "") !== "");
  if (name === undefined) return undefined;
  const value = set.get(name) ?? "";
  if (/[\s\u0000-\u001f\u007f]/.test(value)) {
    throw new AnswerError(`${name} holds whitespace or a control character (a token read from a file with Windows line endings?) — remove it and run init again; the token was not sent`);
  }
  return value;
}

/** A host named on the command line: plain https, no credentials, path or query. */
function namedApi(flag: string, raw: string, withPath: boolean): string {
  let url: URL;
  try {
    url = new URL(withPath ? raw : `https://${raw}`);
  } catch {
    throw new AnswerError(`${flag} must be ${withPath ? "an https URL" : "a host name"}, not ${JSON.stringify(raw)}`);
  }
  const plain = url.protocol === "https:" && url.username === "" && url.password === "" && url.search === "" && url.hash === "";
  if (!plain || (!withPath && (url.pathname !== "/" || url.host !== raw.toLowerCase()))) {
    throw new AnswerError(`${flag} must be ${withPath ? "an https URL with no credentials or query" : "a host name, optionally with a port"}, not ${JSON.stringify(raw)}`);
  }
  return withPath ? url.href.replace(/\/+$/, "") : `https://${url.host}/api/v4`;
}

/**
 * Where the platform token may be sent (gate cli run 1, N-02): GITHUB_TOKEN to api.github.com and
 * GITLAB_TOKEN to gitlab.com, and to another host only when the user names it with --github-api or
 * --gitlab-host. The origin remote alone never decides it: a remote URL is not the user saying
 * where their credential goes. Null when the token must not be sent.
 */
function tokenDestination(platform: Platform, remote: Remote, values: Values): string | null {
  const flag = platform === "github" ? values["github-api"] : values["gitlab-host"];
  if (typeof flag === "string") return platform === "github" ? namedApi("--github-api", flag, true) : namedApi("--gitlab-host", flag, false);
  if (platform === "github") return remote.host === "github.com" ? "https://api.github.com" : null;
  return remote.host === "gitlab.com" ? "https://gitlab.com/api/v4" : null;
}

class CouldNotOpen extends Error {}
/** The remote setup branch exists and --force was not given: CM-80's refusal, for the remote. */
class RemoteBranchRefused extends Error {}

/**
 * The setup pull request (GitHub, adapter-github's openSetupPr) or merge request (GitLab,
 * adapter-gitlab's openSetupMr), opened with the token. The adapter builds the remote branch from
 * the default branch's head, so it carries the setup files and nothing else of the local tree.
 * The line for the list of writes.
 *
 * The adapter is asked first never to move an existing setup branch: it may carry edits a person
 * pushed to the setup pull request. When it exists, the overwrite refusal decides (CM-80): without
 * --force nothing is pushed; with it, the adapter is asked again to replace the branch.
 */
async function openRemote(platform: Platform, remote: Remote, apiBase: string, setup: SetupAnswers, group: string | undefined, token: string, force: boolean, io: Io,
  extraFiles: { path: string; content: string }[] = []): Promise<string> {
  const fetchOpt = io.fetch === undefined ? {} : { fetch: io.fetch };
  const decide = (): void => {
    const refusal = overwriteRefusal([`the remote branch ${SETUP_BRANCH} on ${remote.path}`], force);
    if (refusal !== null) {
      throw new RemoteBranchRefused(
        `${refusal}\n  It may carry edits pushed to the setup ${platform === "github" ? "pull" : "merge"} request; nothing was pushed. Review it there, ` +
          `or run init again with --force to replace it with a fresh commit of these answers.`,
      );
    }
  };
  try {
    if (platform === "github") {
      const client = new GitHubClient({ token, repo: remote.path, baseUrl: apiBase, ...fetchOpt });
      let pr;
      try {
        pr = await openSetupPr(client, remote.path, setup, { replaceBranch: false, extraFiles });
      } catch (e: unknown) {
        if (!(e instanceof GitHubBranchExists)) throw e;
        decide();
        pr = await openSetupPr(client, remote.path, setup, { replaceBranch: true, extraFiles });
      }
      return `${pr.created ? "opened" : "updated"} pull request #${String(pr.pull.number)} from ${pr.branch}: ${pr.pull.html_url}`;
    }
    const api = projectApi({ apiV4Url: apiBase, project: remote.path, token, ...fetchOpt });
    const answers = { profile: setup.profile, gates: effectiveGates(setup), sentinel: setup.sentinel, version: "latest" };
    const groupOpt = group === undefined ? {} : { group };
    let mr;
    try {
      mr = await openSetupMr(api, answers, { ...groupOpt, replaceBranch: false, extraFiles });
    } catch (e: unknown) {
      if (!(e instanceof GitLabBranchExists)) throw e;
      decide();
      mr = await openSetupMr(api, answers, { ...groupOpt, replaceBranch: true, extraFiles });
    }
    return `${mr.created ? "opened" : "updated"} merge request !${String(mr.mergeRequest.iid)} from ${mr.branch}: ${mr.mergeRequest.web_url}`;
  } catch (e: unknown) {
    throw openFailure(platform, e) ?? e;
  }
}

/**
 * What init says when the remote could not be opened: the status and the request, never the
 * server's own words (gate cli run 2, N-04; run 3, N-01). A reply's message, the first 200
 * characters of its body, or JSON.parse's error can each quote part of a token, which full-value
 * redaction cannot see. GitLab's error already repeats no reply; a TypeError (fetch's own, which
 * can quote a header value) is named by its cause only. Null when the error is not one of opening
 * the remote (CM-86).
 */
function openFailure(platform: Platform, e: unknown): CouldNotOpen | null {
  const what = `could not open the ${platform === "github" ? "pull" : "merge"} request`;
  if (e instanceof GitHubApiError) return new CouldNotOpen(`${what}: GitHub answered ${String(e.status)} to ${e.method} ${e.path} (the response is not repeated here)`);
  if (e instanceof GitLabApiError) return new CouldNotOpen(`${what}: ${e.message}`);
  // fetch's TypeError can quote a header value, the token's (gate cli run 4, B-01): named by its
  // cause only, and only by a cause this code recognises.
  if (e instanceof TypeError) return new CouldNotOpen(`${what}: the request could not be sent${sendCause(e)}`);
  if (e instanceof SyntaxError) return new CouldNotOpen(`${what}: the server's reply was not JSON`);
  return null;
}

/** Why fetch could not send, from its cause: a refused redirect or a network error code, else nothing. */
function sendCause(e: TypeError): string {
  const cause: unknown = e.cause;
  if (cause instanceof Error && cause.message === "unexpected redirect") return " (the server answered with a redirect, which is refused)";
  const code = typeof cause === "object" && cause !== null && "code" in cause ? cause.code : undefined;
  return typeof code === "string" && /^[A-Z][A-Z0-9_]{1,40}$/.test(code) ? ` (${code})` : "";
}

/**
 * The message init prints for one of its own errors, or null: anything else goes to main, which
 * names its kind and not its message (gate cli run 2, N-04; CM-87).
 */
function ownMessage(e: unknown): string | null {
  const own = e instanceof IncludeNotMergeable || e instanceof TokenInFile || e instanceof SecretRefused || e instanceof RemoteBranchRefused
    || e instanceof AnswerError || e instanceof GitError;
  return own ? e.message : null;
}

function printNextSteps(io: Io, platform: Platform, previous: string | null): void {
  io.out("");
  io.out(`Next, push the branch and open the ${platform === "github" ? "pull request" : "merge request"}:`);
  io.out(`  git push -u origin ${SETUP_BRANCH}`);
  io.out(
    platform === "github"
      ? `  gh pr create --head ${SETUP_BRANCH} --title "${SETUP_MR_TITLE}" --fill`
      : `  glab mr create --source-branch ${SETUP_BRANCH} --title "${SETUP_MR_TITLE}" --fill --yes`,
  );
  io.out(previous === null ? "  git switch -" : `  git switch ${previous}`);
  io.out(`The gates run on that ${platform === "github" ? "pull" : "merge"} request too, under the config it adds; once it is merged, every one after it gets them.`);
}

async function runInit(values: Values, io: Io): Promise<number> {
  const root = repoRoot(io.cwd);
  if (root === null) {
    io.err("init: not inside a git repository — run it in the repository to set up");
    return EXIT.couldNotRun;
  }
  const tokens = tokenValues(io.env);
  const writes: string[] = [];
  const listWrites = (): void => {
    if (writes.length === 0) return;
    io.out("");
    io.out("Every write:");
    for (const w of writes) io.out(`  ${w}`);
  };
  try {
    const remote = remoteOf(root);
    const { platform, how } = await choosePlatform(values, remote, io);
    const setup: SetupAnswers = { ...(await resolveAnswers(values, io)) };
    validateAnswers(setup);
    describeAnswers(io, platform, how, setup);
    // A host named on the command line is checked whether or not a token or a remote will use it.
    if (typeof values["github-api"] === "string") namedApi("--github-api", values["github-api"], true);
    if (typeof values["gitlab-host"] === "string") namedApi("--gitlab-host", values["gitlab-host"], false);
    const apiBase = remote === null ? null : tokenDestination(platform, remote, values);

    const previous = currentBranch(root);
    const onSetupBranch = previous === SETUP_BRANCH;
    const base = onSetupBranch ? null : defaultBase(root);
    // The tree the setup files are written onto: the setup branch itself on a re-run, else the base.
    const source = onSetupBranch ? "HEAD" : (base ?? "HEAD");
    // QA on and no list kept anywhere (working tree or the tree the setup starts from): init drafts one.
    const wantDraft = effectiveGates(setup).includes("qa") && !existsSync(path.join(root, MANIFEST_PATH)) && fileAt(root, source, MANIFEST_PATH) === null;
    // Decided on the tree the user is on, before the switch below: a config there or at the base is the team's.
    const configKept = wantDraft && keptConfig(root, source);
    const linked = [CONFIG_PATH, ...(platform === "github" ? [WORKFLOW_PATH] : [CI_PATH]), ...(wantDraft ? [MANIFEST_PATH] : [])]
      .map((f) => symlinkOnPath(root, f, source)).find((l) => l !== null);
    if (linked !== undefined) {
      io.err(`init: refused: ${linked} is a symbolic link — init never writes through one, since it can point outside the repository; replace it with a plain file or directory first`);
      return EXIT.refused;
    }
    const branchExists = gitOk(root, "show-ref", "--verify", "--quiet", `refs/heads/${SETUP_BRANCH}`);
    const existing = [CONFIG_PATH, ...(platform === "github" ? [WORKFLOW_PATH] : [])].filter((f) => existsSync(path.join(root, f)) || fileAt(root, source, f) !== null);
    if (branchExists && !onSetupBranch) existing.push(`the local branch ${SETUP_BRANCH}`);
    const refusal = overwriteRefusal(existing, values["force"] === true);
    if (refusal !== null) {
      io.err(`init: ${refusal}`);
      return EXIT.refused;
    }
    const uncommitted = uncommittedSetupFiles(root);
    if (uncommitted.length > 0) {
      const verb = uncommitted.length === 1 ? "has" : "have";
      io.err(`init: refused: ${uncommitted.join(" and ")} ${verb} uncommitted changes — init commits these files on its own branch, where they would leave yours; commit or stash them first`);
      return EXIT.refused;
    }

    const group = typeof values["gitlab-group"] === "string" ? values["gitlab-group"] : undefined;
    const files = planFiles(platform, setup, platform === "gitlab" ? fileAt(root, source, CI_PATH) : null, group);
    // Refuse before the first write, so a refusal never leaves half a setup behind.
    for (const f of files) {
      if (f.write && redactTokens(f.content, tokens) !== f.content) throw new TokenInFile(`refused: ${f.path} would carry the value of a token from the environment; nothing was written`);
    }

    if (!onSetupBranch) {
      if (base === null) io.out(`no default branch (origin/HEAD, origin/main, origin/master, main or master) was found: the setup branch starts from ${previous ?? "HEAD"}`);
      const from = base ?? previous ?? "HEAD";
      git(root, "switch", "-q", "--no-track", branchExists ? "-C" : "-c", SETUP_BRANCH, base ?? "HEAD");
      writes.push(branchExists ? `reset the local branch ${SETUP_BRANCH} to ${from} (--force)` : `created the local branch ${SETUP_BRANCH} from ${from}`);
    }
    // Drafted from the setup branch's own tree (the default branch's code), after the switch above.
    const extraFiles: { path: string; content: string }[] = [];
    if (wantDraft) {
      const drafted = draftControlList(root, io.env);
      if (drafted === null) {
        io.out(`found no security controls to draft into ${MANIFEST_PATH}: QA stays yellow until a list with rows is merged. If the controls live outside backend/src, name them with CONTROL_SRC_ROOTS (and CONTROL_SRC_EXT: py for Python) in project.config.yaml and run init again`);
      } else {
        if (redactTokens(drafted.content, tokens) !== drafted.content) throw new TokenInFile(`refused: ${MANIFEST_PATH} would carry the value of a token from the environment; nothing was written`);
        files.push({ path: MANIFEST_PATH, content: drafted.content, write: true,
                     note: `drafted ${MANIFEST_PATH}: ${String(drafted.rows)} control(s), ${String(drafted.suggested)} suggested by name — delete the rows that are not controls and add any it missed before merging` });
        extraFiles.push({ path: MANIFEST_PATH, content: drafted.content });
        if (drafted.config !== null && configKept) {
          io.out(`${PROJECT_CONFIG_PATH} already exists, so init did not write the control roots it inferred; add these lines to it before merging the drafted list:`);
          for (const l of drafted.config) io.out(`  ${l}`);
        } else if (drafted.config !== null) {
          const config = CONFIG_HEADER + drafted.config.join("\n") + "\n";
          if (redactTokens(config, tokens) !== config) throw new TokenInFile(`refused: ${PROJECT_CONFIG_PATH} would carry the value of a token from the environment; nothing was written`);
          files.push({ path: PROJECT_CONFIG_PATH, content: config, write: true,
                       note: `proposed ${PROJECT_CONFIG_PATH} with the control roots inferred from the layout (${drafted.config.join(" · ")}) — check them before merging` });
          extraFiles.push({ path: PROJECT_CONFIG_PATH, content: config });
        }
      }
    }
    for (const f of files) {
      if (f.write) {
        mkdirSync(path.dirname(path.join(root, f.path)), { recursive: true });
        writeRedacted(path.join(root, f.path), f.content, tokens);
      }
      writes.push(f.note);
    }
    const paths = files.map((f) => f.path);
    git(root, "add", "--", ...paths);
    const where = `${branchExists || onSetupBranch ? "the" : "the new"} local branch ${SETUP_BRANCH}`;
    if (gitOk(root, "diff", "--cached", "--quiet", "--", ...paths)) {
      writes.push(`nothing new to commit on ${where}`);
    } else {
      git(root, "commit", "-q", "-m", SETUP_MR_TITLE, "-m", `${paths.join(", ")} from the three setup answers.`, "--", ...paths);
      writes.push(`committed ${git(root, "rev-parse", "--short=7", "HEAD")} on ${where}`);
    }
    if (platform === "gitlab" && group === undefined && files.some((f) => f.write && f.content.includes("<group>"))) {
      io.out(`edit <group> in ${CI_PATH} to the group your GitLab keeps the bot's component in, or pass --gitlab-group next time`);
    }
    const back = onSetupBranch ? null : previous;
    const credential = tokenFor(platform, io.env);
    let opened: string | null = null;
    const usable = remote !== null && (platform === "gitlab" || remote.path.split("/").length === 2);
    if (credential !== undefined && !usable) io.out(`the origin remote names no repository on ${platform}, so the token was not used`);
    if (credential !== undefined && usable && apiBase === null) {
      const home = platform === "github" ? "github.com" : "gitlab.com";
      const flag = platform === "github" ? `--github-api https://${remote.host}/api/v3` : `--gitlab-host ${remote.host}`;
      io.out(`the origin remote is on ${remote.host}, not ${home}: the token was not sent there. To open the ${platform === "github" ? "pull" : "merge"} request on that host, run init again with ${flag}`);
    }
    if (credential !== undefined && usable && apiBase !== null) {
      try {
        opened = await openRemote(platform, remote, apiBase, setup, group, credential, values["force"] === true, io, extraFiles);
      } catch (e: unknown) {
        if (!(e instanceof CouldNotOpen)) throw e;
        io.err(`init: ${e.message}`);
        printNextSteps(io, platform, back);
        listWrites();
        return EXIT.couldNotRun;
      }
    }
    if (opened === null) {
      printNextSteps(io, platform, back);
    } else {
      writes.push(opened);
      io.out("");
      io.out(`The ${platform === "github" ? "pull" : "merge"} request carries the same files; the gates run on it too, under the config it adds.`);
      io.out(`Your local branch ${SETUP_BRANCH} holds them too: git switch ${back ?? "-"} to return.`);
    }
    listWrites();
    return EXIT.ok;
  } catch (e: unknown) {
    const refused = e instanceof IncludeNotMergeable || e instanceof TokenInFile || e instanceof SecretRefused || e instanceof RemoteBranchRefused;
    const message = ownMessage(e);
    if (message !== null) io.err(`init: ${message}`);
    listWrites();
    if (refused) return EXIT.refused;
    if (e instanceof AnswerError || e instanceof GitError) return EXIT.couldNotRun;
    throw e;
  }
}

export const initCommand: Command = {
  options: {
    profile: { type: "string" },
    gates: { type: "string" },
    sentinel: { type: "string" },
    yes: { type: "boolean", short: "y" },
    force: { type: "boolean" },
    platform: { type: "string" },
    "gitlab-group": { type: "string" },
    "gitlab-host": { type: "string" },
    "github-api": { type: "string" },
  },
  run: runInit,
};
