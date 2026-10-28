// A small typed client over global fetch for the handful of GitHub endpoints this adapter uses:
// check runs, pull request files and review comments, the Git Data API for the setup branch, pull
// requests, and the one GraphQL mutation that resolves a review thread (REST has none). No SDK,
// so the dependency list stays at zero at run time, and `fetch` is injectable so every test runs
// against a fake that records what would have reached GitHub. The token goes into the
// Authorization header and nowhere else: an error names the route and the status, never the token.

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export class GitHubApiError extends Error {
  constructor(
    readonly status: number,
    readonly method: string,
    readonly path: string,
    detail: string,
  ) {
    super(`${method} ${path} → HTTP ${status}: ${detail}`);
    this.name = 'GitHubApiError';
  }
}

export interface ClientOptions {
  token: string;
  /** owner/name */
  repo: string;
  fetch?: FetchLike;
  /** https://api.github.com, or a GitHub Enterprise Server's /api/v3 */
  baseUrl?: string;
  graphqlUrl?: string;
}

export interface CheckRunInput {
  name: string;
  head_sha: string;
  status: 'completed';
  conclusion: 'success' | 'failure' | 'neutral';
  output: { title: string; summary: string };
}

export interface ReviewCommentInput {
  body: string;
  commit_id: string;
  path: string;
  line: number;
}

export interface ReviewComment {
  id: number;
  path: string;
  line: number | null;
  original_line?: number | null;
  body: string;
  user: { login: string };
  in_reply_to_id?: number | null;
}

export interface TreeEntry {
  path: string;
  mode: '100644' | '100755';
  type: 'blob';
  sha: string;
}

export interface PullRequest {
  number: number;
  html_url: string;
}

const API_VERSION = '2022-11-28';

export class GitHubClient {
  readonly owner: string;
  readonly name: string;
  private readonly fetchImpl: FetchLike;
  private readonly baseUrl: string;
  private readonly graphqlUrl: string;
  private readonly token: string;

  constructor(options: ClientOptions) {
    const [owner, name, ...rest] = options.repo.split('/');
    if (!owner || !name || rest.length) throw new Error(`repository must be owner/name, not ${JSON.stringify(options.repo)}`);
    this.owner = owner;
    this.name = name;
    this.token = options.token;
    this.fetchImpl = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.baseUrl = (options.baseUrl ?? 'https://api.github.com').replace(/\/+$/, '');
    this.graphqlUrl = options.graphqlUrl ?? `${this.baseUrl}/graphql`;
  }

  private get repoPath(): string {
    return `/repos/${this.owner}/${this.name}`;
  }

  private async send(method: string, url: string, body?: unknown): Promise<{ data: unknown; headers: Headers }> {
    const path = new URL(url).pathname;
    const init: RequestInit = {
      method,
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${this.token}`,
        'x-github-api-version': API_VERSION,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    };
    const response = await this.fetchImpl(url, init);
    const text = await response.text();
    let data: unknown = null;
    if (text.length) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
    }
    if (!response.ok) {
      const detail = typeof data === 'object' && data !== null && 'message' in data ? String((data as { message: unknown }).message) : text.slice(0, 200);
      throw new GitHubApiError(response.status, method, path, detail);
    }
    return { data, headers: response.headers };
  }

  /** One request to a repository-relative or absolute path; the JSON reply, typed by the caller. */
  async request<T>(method: string, path: string, body?: unknown, query?: Record<string, string>): Promise<T> {
    const url = new URL(path.startsWith('http') ? path : `${this.baseUrl}${path}`);
    for (const [k, v] of Object.entries(query ?? {})) url.searchParams.set(k, v);
    return (await this.send(method, url.toString(), body)).data as T;
  }

  /** Every page of a list endpoint, following Link rel="next". */
  async paginate<T>(path: string, query?: Record<string, string>): Promise<T[]> {
    const url = new URL(`${this.baseUrl}${path}`);
    url.searchParams.set('per_page', '100');
    for (const [k, v] of Object.entries(query ?? {})) url.searchParams.set(k, v);
    const out: T[] = [];
    let next: string | null = url.toString();
    while (next) {
      const { data, headers } = await this.send('GET', next);
      if (Array.isArray(data)) out.push(...(data as T[]));
      const link = headers.get('link') ?? '';
      const m = /<([^>]+)>;\s*rel="next"/.exec(link);
      next = m?.[1] ?? null;
    }
    return out;
  }

  // ── checks and review comments ────────────────────────────────────────────

  createCheckRun(input: CheckRunInput): Promise<{ id: number; name: string }> {
    return this.request('POST', `${this.repoPath}/check-runs`, input);
  }

  listPullFiles(pull: number): Promise<{ filename: string; patch?: string }[]> {
    return this.paginate(`${this.repoPath}/pulls/${pull}/files`);
  }

  listReviewComments(pull: number): Promise<ReviewComment[]> {
    return this.paginate(`${this.repoPath}/pulls/${pull}/comments`);
  }

  createReviewComment(pull: number, input: ReviewCommentInput): Promise<{ id: number }> {
    return this.request('POST', `${this.repoPath}/pulls/${pull}/comments`, { ...input, side: 'RIGHT' });
  }

  replyToReviewComment(pull: number, commentId: number, body: string): Promise<{ id: number }> {
    return this.request('POST', `${this.repoPath}/pulls/${pull}/comments/${commentId}/replies`, { body });
  }

  private graphql<T>(query: string, variables: Record<string, unknown>): Promise<T> {
    return this.request('POST', this.graphqlUrl, { query, variables });
  }

  /**
   * Resolve the review thread holding a comment. True when it was resolved now; false when the
   * thread is already resolved, the comment is in no thread, or the token cannot (GraphQL refused):
   * the caller's reply stands on its own either way.
   */
  async resolveThreadOfComment(pull: number, commentId: number): Promise<boolean> {
    interface Threads {
      data?: { repository?: { pullRequest?: { reviewThreads?: { nodes?: { id: string; isResolved: boolean; comments: { nodes: { databaseId: number }[] } }[] } } } };
      errors?: unknown[];
    }
    const query = `query($owner: String!, $name: String!, $pull: Int!) {
      repository(owner: $owner, name: $name) { pullRequest(number: $pull) { reviewThreads(first: 100) {
        nodes { id isResolved comments(first: 100) { nodes { databaseId } } } } } } }`;
    const mutation = `mutation($threadId: ID!) { resolveReviewThread(input: { threadId: $threadId }) { thread { id isResolved } } }`;
    try {
      const threads = await this.graphql<Threads>(query, { owner: this.owner, name: this.name, pull });
      const thread = threads.data?.repository?.pullRequest?.reviewThreads?.nodes?.find((t) => t.comments.nodes.some((c) => c.databaseId === commentId));
      if (!thread || thread.isResolved) return false;
      const result = await this.graphql<{ data?: { resolveReviewThread?: { thread?: { isResolved: boolean } } }; errors?: unknown[] }>(mutation, { threadId: thread.id });
      return result.data?.resolveReviewThread?.thread?.isResolved === true;
    } catch (e) {
      if (e instanceof GitHubApiError) return false;
      throw e;
    }
  }

  // ── repository, Git Data API, pull requests ───────────────────────────────

  getRepo(): Promise<{ default_branch: string }> {
    return this.request('GET', this.repoPath);
  }

  /** The branch a pull request targets now, read live: an event payload is a snapshot a re-run replays. */
  async getPullBaseRef(pull: number): Promise<string> {
    const pr = await this.request<{ base?: { ref?: unknown } }>('GET', `${this.repoPath}/pulls/${pull}`);
    if (typeof pr.base?.ref !== 'string') throw new GitHubApiError(0, 'GET', `${this.repoPath}/pulls/${pull}`, 'no base ref in the reply');
    return pr.base.ref;
  }

  /** Whether a file exists at `path` on `ref`; any answer but 404 is an error, never a guess. */
  async fileExists(path: string, ref: string): Promise<boolean> {
    try {
      await this.request('GET', `${this.repoPath}/contents/${path.split('/').map(encodeURIComponent).join('/')}`, undefined, { ref });
      return true;
    } catch (e) {
      if (e instanceof GitHubApiError && e.status === 404) return false;
      throw e;
    }
  }

  /** A ref such as `heads/main`, or null when it does not exist. */
  async getRef(ref: string): Promise<{ object: { sha: string } } | null> {
    try {
      return await this.request('GET', `${this.repoPath}/git/ref/${ref}`);
    } catch (e) {
      if (e instanceof GitHubApiError && e.status === 404) return null;
      throw e;
    }
  }

  getCommit(sha: string): Promise<{ tree: { sha: string } }> {
    return this.request('GET', `${this.repoPath}/git/commits/${sha}`);
  }

  createBlob(content: string): Promise<{ sha: string }> {
    return this.request('POST', `${this.repoPath}/git/blobs`, { content, encoding: 'utf-8' });
  }

  createTree(baseTree: string, tree: TreeEntry[]): Promise<{ sha: string }> {
    return this.request('POST', `${this.repoPath}/git/trees`, { base_tree: baseTree, tree });
  }

  createCommit(message: string, tree: string, parents: string[]): Promise<{ sha: string }> {
    return this.request('POST', `${this.repoPath}/git/commits`, { message, tree, parents });
  }

  createRef(ref: string, sha: string): Promise<{ ref: string }> {
    return this.request('POST', `${this.repoPath}/git/refs`, { ref, sha });
  }

  updateRef(ref: string, sha: string): Promise<{ ref: string }> {
    return this.request('PATCH', `${this.repoPath}/git/refs/${ref}`, { sha, force: true });
  }

  listPulls(query: { head: string; state: 'open' | 'closed' | 'all' }): Promise<PullRequest[]> {
    return this.request('GET', `${this.repoPath}/pulls`, undefined, query);
  }

  createPull(input: { title: string; head: string; base: string; body: string }): Promise<PullRequest> {
    return this.request('POST', `${this.repoPath}/pulls`, input);
  }

  updatePull(pull: number, input: { title: string; body: string }): Promise<PullRequest> {
    return this.request('PATCH', `${this.repoPath}/pulls/${pull}`, input);
  }
}
