// The setup merge request (docs/PRD.md § The install experience, GitLab): one branch,
// `secure-builder/enable`, carrying `.securebuilderbot.yml` and the include line merged into the
// project's `.gitlab-ci.yml`, and one merge request titled "Enable Secure Builder" whose body
// explains the three answers and that its own pipeline may run the gates already. The `cli` module's `init`
// calls `openSetupMr` with a token, and `mergeInclude` for the local file without one.
//
// Built on the REST API v4: the project for its default branch, the repository files API to choose
// create or update, one commit through the commits API on a new branch from the default branch, and
// the merge requests API to update an open one rather than open a second. A setup branch that
// already exists (or that an open merge request comes from) may carry commits a person pushed, so it
// is refused unless the caller says to replace it (`replaceBranch`); told to, the commit is sent with
// `force: true`, a fresh commit on the current default branch. The token goes in the PRIVATE-TOKEN header and nowhere else; every body is
// passed through the secret refusal before anything is sent.
import { GitLabApiError, tokenRequest, type FetchLike } from "./gitlab-api.js";
import { refuseSecrets } from "./secrets.js";
import { configTemplate, includeSnippet, type Answers } from "./templates.js";

export const SETUP_BRANCH = "secure-builder/enable";
export const SETUP_MR_TITLE = "Enable Secure Builder";
export const CONFIG_PATH = ".securebuilderbot.yml";
export const CI_PATH = ".gitlab-ci.yml";
export const MODEL_KEY_VARIABLE = "SB_MODEL_KEY";

/** An `include:` this code cannot extend as text without guessing; the user adds the lines by hand. */
export class IncludeNotMergeable extends Error {}

const OUR_COMPONENT = /secure-builder-bot\/secure-builder@/;
function blankOrComment(line: string): boolean {
  const t = line.trim();
  return t === "" || t.startsWith("#");
}

/**
 * `.gitlab-ci.yml` with the bot's include in it, and whether that changed anything. Absent or empty:
 * the snippet. Already including the component: unchanged. No top-level `include:`: the snippet is
 * appended. A block-sequence `include:`: the bot's entry goes first in that list, at its
 * indentation, so the file never carries a second `include:` key. Any other shape is refused.
 */
export function mergeInclude(existing: string | null, snippet: string): { content: string; changed: boolean } {
  if (existing === null || existing.trim() === "") return { content: snippet, changed: true };
  if (OUR_COMPONENT.test(existing)) return { content: existing, changed: false };
  const lines = existing.split("\n");
  const at = lines.findIndex((l) => /^include:/.test(l));
  if (at === -1) {
    const base = existing.endsWith("\n") ? existing : existing + "\n";
    return { content: base + "\n" + snippet, changed: true };
  }
  const refusal = `${CI_PATH} has an include: this cannot extend safely as text; add these lines to it by hand:\n${snippet}`;
  const inline = (lines.at(at) ?? "").slice("include:".length).replace(/#.*$/, "").trim();
  if (inline !== "") throw new IncludeNotMergeable(refusal);
  const next = lines.slice(at + 1).find((l) => !blankOrComment(l));
  const item = next === undefined ? null : /^( *)- /.exec(next);
  if (item === null) throw new IncludeNotMergeable(refusal);
  const indent = item[1] ?? "";
  const entries = snippet
    .split("\n")
    .slice(1)
    .filter((l) => l !== "")
    .map((l) => indent + l.slice(2));
  lines.splice(at + 1, 0, ...entries);
  return { content: lines.join("\n"), changed: true };
}

function gatesOf(a: Answers): Answers["gates"] {
  return a.sentinel === "off" ? a.gates.filter((g) => g !== "sentinel") : a.gates;
}

/** The merge request description: the three answers, what to add as CI/CD variables, and that nothing runs yet. */
export function setupMrBody(a: Answers): string {
  const gates = gatesOf(a);
  const where = a.sentinel === "off" ? "off (no model key needed)" : `${a.sentinel}, with your model key`;
  const lines = [
    "This merge request enables Secure Builder Bot on this project with your three answers:",
    "",
    `1. **Compliance profile:** \`${a.profile}\``,
    `2. **Gates:** ${gates.map((g) => `\`${g}\``).join(", ")}`,
    `3. **Sentinel runs:** ${where}`,
    "",
    `It adds \`${CONFIG_PATH}\` (edit any answer there) and the component's include line in \`${CI_PATH}\`.`,
    "The publisher posts with a project access token (`api` scope) stored as the masked, protected CI/CD variable `SECURE_BUILDER_TOKEN`.",
  ];
  if (gates.includes("sentinel")) lines.push(`Sentinel reads your model key from the CI/CD variable \`${MODEL_KEY_VARIABLE}\`, by name; add it before merging.`);
  lines.push("", "**This merge request's own pipeline may run the gates already**, under the config it adds. Once it is merged, every merge request gets every gate you turned on.");
  return lines.join("\n") + "\n";
}

/** The two files the setup writes: the config, and the CI file with the include merged into what is there. */
export function setupMrFiles(a: Answers, existingCi: string | null, opts: { group?: string }): { path: string; content: string }[] {
  const snippet = includeSnippet({ ...(opts.group === undefined ? {} : { group: opts.group }), version: a.version });
  return [
    { path: CONFIG_PATH, content: configTemplate(a) },
    { path: CI_PATH, content: mergeInclude(existingCi, snippet).content },
  ];
}

export interface CommitAction {
  action: "create" | "update";
  file_path: string;
  content: string;
}

export interface MergeRequest {
  iid: number;
  web_url: string;
}

export interface ProjectApi {
  getProject(): Promise<{ default_branch: string }>;
  /** True when the branch exists. */
  branchExists(name: string): Promise<boolean>;
  /** The file's text on a ref, or null when it is not there. */
  getFile(filePath: string, ref: string): Promise<string | null>;
  createCommit(input: { branch: string; start_branch: string; commit_message: string; actions: CommitAction[]; force?: boolean }): Promise<{ id: string }>;
  listOpenMergeRequests(sourceBranch: string): Promise<MergeRequest[]>;
  createMergeRequest(input: { source_branch: string; target_branch: string; title: string; description: string }): Promise<MergeRequest>;
  updateMergeRequest(iid: number, input: { title: string; description: string }): Promise<MergeRequest>;
}

export interface ProjectApiOptions {
  apiV4Url: string; // https://<host>/api/v4
  project: string; // the numeric id or the path, group/name
  token: string;
  fetch?: FetchLike;
}

export function projectApi(opts: ProjectApiOptions): ProjectApi {
  const doFetch: FetchLike = opts.fetch ?? ((input, init) => fetch(input, init));
  const base = `${opts.apiV4Url.replace(/\/+$/, "")}/projects/${encodeURIComponent(opts.project)}`;

  async function send<T>(method: "GET" | "POST" | "PUT", path: string, body?: Record<string, unknown>): Promise<T> {
    const init = tokenRequest(method, opts.token);   // never follows a redirect (CM-74)
    if (body !== undefined) {
      init.headers = { ...init.headers, "Content-Type": "application/json" };
      init.body = JSON.stringify(body);
    }
    const response = await doFetch(base + path, init);
    if (!response.ok) throw new GitLabApiError(response.status, method, new URL(base + path).pathname);
    return (await response.json()) as T;
  }

  return {
    getProject: () => send<{ default_branch: string }>("GET", ""),
    async branchExists(name) {
      try {
        await send<unknown>("GET", `/repository/branches/${encodeURIComponent(name)}`);
        return true;
      } catch (e: unknown) {
        if (e instanceof GitLabApiError && e.status === 404) return false;
        throw e;
      }
    },
    async getFile(filePath, ref) {
      try {
        const file = await send<{ content: string }>("GET", `/repository/files/${encodeURIComponent(filePath)}?ref=${encodeURIComponent(ref)}`);
        return Buffer.from(file.content, "base64").toString("utf8");
      } catch (e: unknown) {
        if (e instanceof GitLabApiError && e.status === 404) return null;
        throw e;
      }
    },
    async createCommit(input) {
      refuseSecrets(input.commit_message, "the setup commit message");
      for (const a of input.actions) refuseSecrets(a.content, `the setup commit's ${a.file_path}`);
      return await send<{ id: string }>("POST", "/repository/commits", { ...input });
    },
    listOpenMergeRequests: (sourceBranch) => send<MergeRequest[]>("GET", `/merge_requests?state=opened&source_branch=${encodeURIComponent(sourceBranch)}`),
    async createMergeRequest(input) {
      refuseSecrets(input.title + "\n" + input.description, "the setup merge request");
      return await send<MergeRequest>("POST", "/merge_requests", { ...input });
    },
    async updateMergeRequest(iid, input) {
      refuseSecrets(input.title + "\n" + input.description, "the setup merge request");
      return await send<MergeRequest>("PUT", `/merge_requests/${String(iid)}`, { ...input });
    },
  };
}

export interface SetupMrResult {
  branch: string;
  commit: string;
  mergeRequest: MergeRequest;
  /** false when an open merge request from the setup branch was updated */
  created: boolean;
  files: string[];
}

/** One commit on the setup branch from the default branch's head, and one merge request: created, or the open one updated. */
/** The setup branch exists and the caller did not say to replace it; nothing was written. */
export class SetupBranchExists extends Error {}

export interface SetupMrOptions {
  group?: string;
  /** Recommit an existing setup branch from the default branch, discarding what is on it. Default false: refuse. */
  replaceBranch?: boolean;
  /** Files added beside the config and the CI file (init's drafted control list), each only where the default branch has none. */
  extraFiles?: { path: string; content: string }[];
}

export async function openSetupMr(api: ProjectApi, answers: Answers, opts: SetupMrOptions): Promise<SetupMrResult> {
  const { default_branch: base } = await api.getProject();
  const open = (await api.listOpenMergeRequests(SETUP_BRANCH))[0];
  const exists = open !== undefined || (await api.branchExists(SETUP_BRANCH));
  if (exists && opts.replaceBranch !== true) {
    throw new SetupBranchExists(`the branch ${SETUP_BRANCH} already exists; it is not moved unless the caller asks to replace it`);
  }
  const existingCi = await api.getFile(CI_PATH, base);
  const files = setupMrFiles(answers, existingCi, opts);
  for (const f of opts.extraFiles ?? []) {
    if ((await api.getFile(f.path, base)) === null) files.push(f);  // a file the team already keeps is never replaced
  }
  const body = setupMrBody(answers);
  // Plan, refuse, then write: one secret-shaped piece stops everything before the first write.
  refuseSecrets(body, "the setup merge request");
  for (const f of files) refuseSecrets(f.content, `the setup commit's ${f.path}`);
  const actions: CommitAction[] = [];
  for (const f of files) {
    const present = f.path === CI_PATH ? existingCi !== null : (await api.getFile(f.path, base)) !== null;
    actions.push({ action: present ? "update" : "create", file_path: f.path, content: f.content });
  }
  const message = `${SETUP_MR_TITLE}\n\n${files.map((f) => f.path).join(", ")} from the three setup answers.`;
  const commit = await api.createCommit({ branch: SETUP_BRANCH, start_branch: base, commit_message: message, actions, ...(exists ? { force: true } : {}) });
  const mergeRequest = open
    ? await api.updateMergeRequest(open.iid, { title: SETUP_MR_TITLE, description: body })
    : await api.createMergeRequest({ source_branch: SETUP_BRANCH, target_branch: base, title: SETUP_MR_TITLE, description: body });
  return { branch: SETUP_BRANCH, commit: commit.id, mergeRequest, created: open === undefined, files: files.map((f) => f.path) };
}
