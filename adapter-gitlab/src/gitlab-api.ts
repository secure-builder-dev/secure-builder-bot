// The GitLab REST API v4, the few calls the publisher needs, over `fetch`. The client is handed
// its fetch so every test runs against an in-memory GitLab, and it is the one place a request
// leaves the process: every body goes through the secret refusal first, and an error names the
// status and the path, never the response.
import { refuseSecrets } from "./secrets.js";

export interface DiffRefs {
  base_sha: string;
  start_sha: string;
  head_sha: string;
}

export interface Position {
  position_type: "text";
  base_sha: string;
  start_sha: string;
  head_sha: string;
  new_path: string;
  old_path: string;
  new_line: number;
}

export interface Note {
  id: number;
  body: string;
  system?: boolean;
  resolvable?: boolean;
  resolved?: boolean;
  position?: Position | null;
}

export interface Discussion {
  id: string;
  individual_note?: boolean;
  notes: Note[];
}

export interface MergeRequestApi {
  diffRefs(): Promise<DiffRefs>;
  listNotes(): Promise<Note[]>;
  createNote(body: string): Promise<Note>;
  updateNote(noteId: number, body: string): Promise<Note>;
  listDiscussions(): Promise<Discussion[]>;
  createDiscussion(body: string, position?: Position): Promise<Discussion>;
  replyToDiscussion(discussionId: string, body: string): Promise<Note>;
  resolveDiscussion(discussionId: string): Promise<void>;
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface ApiOptions {
  apiV4Url: string; // CI_API_V4_URL
  projectId: string; // CI_PROJECT_ID
  mergeRequestIid: string; // CI_MERGE_REQUEST_IID
  token: string; // the value of the variable token_variable names, read from the environment
  fetch?: FetchLike;
}

export class GitLabApiError extends Error {
  constructor(readonly status: number, method: string, path: string) {
    super(`GitLab answered ${String(status)} to ${method} ${path} (the response is not repeated here)`);
  }
}

const PER_PAGE = 100;
/**
 * The most pages a list follows: 5,000 notes or discussions. Past it the list is refused rather
 * than used, because the publisher reads these lists to find its own note and discussions, and a
 * partial list would post a second verdict note or a finding twice.
 */
export const MAX_PAGES = 50;

/**
 * The options of every request that carries the token. redirect "error": fetch drops Authorization
 * on a cross-origin redirect but keeps PRIVATE-TOKEN, so following a 3xx would hand the token to
 * whatever host and scheme it names (gate cli run 3, B-01). setup-mr.ts uses it too.
 */
export function tokenRequest(method: string, token: string): RequestInit {
  return { method, redirect: "error", headers: { "PRIVATE-TOKEN": token, Accept: "application/json" } };
}

export function mergeRequestApi(opts: ApiOptions): MergeRequestApi {
  const doFetch: FetchLike = opts.fetch ?? ((input, init) => fetch(input, init));
  const base = `${opts.apiV4Url.replace(/\/+$/, "")}/projects/${encodeURIComponent(opts.projectId)}/merge_requests/${encodeURIComponent(opts.mergeRequestIid)}`;

  async function send<T>(method: "GET" | "POST" | "PUT", path: string, body?: Record<string, unknown>): Promise<{ data: T; headers: Headers }> {
    const init = tokenRequest(method, opts.token);
    if (body !== undefined) {
      init.headers = { ...init.headers, "Content-Type": "application/json" };
      init.body = JSON.stringify(body);
    }
    const response = await doFetch(base + path, init);
    if (!response.ok) throw new GitLabApiError(response.status, method, new URL(base + path).pathname);
    return { data: (await response.json()) as T, headers: response.headers };
  }

  async function list<T>(path: string): Promise<T[]> {
    const out: T[] = [];
    let page = "1";
    for (let fetched = 0; page !== ""; fetched++) {
      if (fetched === MAX_PAGES) {
        throw new Error(`GitLab listed more than ${String(MAX_PAGES)} pages of ${path}; refusing to act on a partial list`);
      }
      const { data, headers } = await send<T[]>("GET", `${path}?per_page=${String(PER_PAGE)}&page=${page}`);
      out.push(...data);
      page = headers.get("x-next-page") ?? "";
    }
    return out;
  }

  function checked(body: string, where: string): string {
    refuseSecrets(body, where);
    return body;
  }

  return {
    async diffRefs() {
      const { data } = await send<{ diff_refs: DiffRefs }>("GET", "");
      return data.diff_refs;
    },
    listNotes: () => list<Note>("/notes"),
    async createNote(body) {
      return (await send<Note>("POST", "/notes", { body: checked(body, "the merge request note") })).data;
    },
    async updateNote(noteId, body) {
      return (await send<Note>("PUT", `/notes/${String(noteId)}`, { body: checked(body, "the merge request note") })).data;
    },
    listDiscussions: () => list<Discussion>("/discussions"),
    async createDiscussion(body, position) {
      const where = position ? `the discussion on ${position.new_path}:${String(position.new_line)}` : "a discussion";
      const payload: Record<string, unknown> = { body: checked(body, where) };
      if (position) payload["position"] = position;
      return (await send<Discussion>("POST", "/discussions", payload)).data;
    },
    async replyToDiscussion(discussionId, body) {
      return (await send<Note>("POST", `/discussions/${encodeURIComponent(discussionId)}/notes`, { body: checked(body, `the reply on discussion ${discussionId}`) })).data;
    },
    async resolveDiscussion(discussionId) {
      await send<Discussion>("PUT", `/discussions/${encodeURIComponent(discussionId)}`, { resolved: true });
    },
  };
}
