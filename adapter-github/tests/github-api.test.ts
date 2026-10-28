import { describe, expect, it } from 'vitest';

import { GitHubApiError, GitHubClient } from '../src/github-api.ts';
import { fakeFetch } from './fake-fetch.ts';

const REPO = 'acme/widgets';
const client = (routes: Parameters<typeof fakeFetch>[0]) => {
  const fake = fakeFetch(routes);
  return { fake, api: new GitHubClient({ token: 'tok', repo: REPO, fetch: fake.fetch }) };
};

describe('the client over fetch', () => {
  it('sends the token, the API version and a JSON body, and parses the JSON reply', async () => {
    const { fake, api } = client({ 'POST /repos/acme/widgets/check-runs': { status: 201, json: { id: 5, name: 'x' } } });
    const made = await api.createCheckRun({ name: 'x', head_sha: 'abc', status: 'completed', conclusion: 'success', output: { title: 't', summary: 's' } });
    expect(made.id).toBe(5);
    const call = fake.of('POST /repos/acme/widgets/check-runs')[0]!;
    expect(call.headers.authorization).toBe('Bearer tok');
    expect(call.headers['x-github-api-version']).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(call.headers.accept).toContain('application/vnd.github+json');
    expect(call.body).toMatchObject({ name: 'x', head_sha: 'abc', conclusion: 'success' });
  });

  it('raises a GitHubApiError with the status and the route, never the token, on a non-2xx reply', async () => {
    const { api } = client({ 'GET /repos/acme/widgets': { status: 403, json: { message: 'Resource not accessible by integration' } } });
    const err = await api.getRepo().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GitHubApiError);
    expect((err as GitHubApiError).status).toBe(403);
    expect((err as Error).message).toContain('GET /repos/acme/widgets');
    expect((err as Error).message).toContain('Resource not accessible');
    expect((err as Error).message).not.toContain('tok');
  });

  it('follows Link rel="next" when listing', async () => {
    const page = (n: number) => Array.from({ length: 2 }, (_, i) => ({ id: n * 10 + i }));
    const { fake, api } = client({
      'GET /repos/acme/widgets/pulls/3/comments': (call) => {
        const p = Number(new URLSearchParams(call.query).get('page') ?? '1');
        return p < 3
          ? { json: page(p), headers: { link: `<https://api.github.com/repos/acme/widgets/pulls/3/comments?per_page=100&page=${p + 1}>; rel="next"` } }
          : { json: page(p) };
      },
    });
    const all = await api.listReviewComments(3);
    expect(all.map((c) => c.id)).toEqual([10, 11, 20, 21, 30, 31]);
    expect(fake.of('GET /repos/acme/widgets/pulls/3/comments')).toHaveLength(3);
    expect(fake.calls[0]!.query).toContain('per_page=100');
  });

  it('posts a review comment on the right side of a line and a reply under a comment', async () => {
    const { fake, api } = client({
      'POST /repos/acme/widgets/pulls/3/comments': { status: 201, json: { id: 1 } },
      'POST /repos/acme/widgets/pulls/3/comments/1/replies': { status: 201, json: { id: 2 } },
    });
    await api.createReviewComment(3, { body: 'b', commit_id: 'sha', path: 'p.ts', line: 4 });
    await api.replyToReviewComment(3, 1, 'Not found on sha');
    expect(fake.of('POST /repos/acme/widgets/pulls/3/comments')[0]!.body).toEqual({ body: 'b', commit_id: 'sha', path: 'p.ts', line: 4, side: 'RIGHT' });
    expect(fake.of('POST /repos/acme/widgets/pulls/3/comments/1/replies')[0]!.body).toEqual({ body: 'Not found on sha' });
  });

  it('resolves the review thread that holds a comment through GraphQL, and reports when it cannot', async () => {
    const threads = { data: { repository: { pullRequest: { reviewThreads: { nodes: [
      { id: 'T1', isResolved: false, comments: { nodes: [{ databaseId: 1 }, { databaseId: 2 }] } },
      { id: 'T2', isResolved: true, comments: { nodes: [{ databaseId: 9 }] } },
    ] } } } } };
    const { fake, api } = client({
      'POST /graphql': (call) => (String((call.body as { query: string }).query).includes('mutation') ? { json: { data: { resolveReviewThread: { thread: { id: 'T1', isResolved: true } } } } } : { json: threads }),
    });
    expect(await api.resolveThreadOfComment(3, 1)).toBe(true);
    expect(fake.of('POST /graphql')).toHaveLength(2);
    expect((fake.of('POST /graphql')[1]!.body as { variables: { threadId: string } }).variables.threadId).toBe('T1');
    expect(await api.resolveThreadOfComment(3, 9)).toBe(false); // already resolved: nothing to do
    expect(await api.resolveThreadOfComment(3, 77)).toBe(false); // not in any thread
  });

  it('a GraphQL error is reported as not resolved, never thrown past the caller', async () => {
    const { api } = client({ 'POST /graphql': { status: 403, json: { message: 'no' } } });
    expect(await api.resolveThreadOfComment(3, 1)).toBe(false);
  });

  it('wraps the Git Data API: ref, commit, blob, tree, commit, create and update ref, pulls', async () => {
    const { fake, api } = client({
      'GET /repos/acme/widgets': { json: { default_branch: 'main' } },
      'GET /repos/acme/widgets/git/ref/heads/main': { json: { object: { sha: 'base' } } },
      'GET /repos/acme/widgets/git/ref/heads/missing': { status: 404, json: { message: 'Not Found' } },
      'GET /repos/acme/widgets/git/commits/base': { json: { tree: { sha: 'tree0' } } },
      'POST /repos/acme/widgets/git/blobs': { status: 201, json: { sha: 'blob1' } },
      'POST /repos/acme/widgets/git/trees': { status: 201, json: { sha: 'tree1' } },
      'POST /repos/acme/widgets/git/commits': { status: 201, json: { sha: 'c1' } },
      'POST /repos/acme/widgets/git/refs': { status: 201, json: { ref: 'refs/heads/x' } },
      'PATCH /repos/acme/widgets/git/refs/heads/x': { json: { ref: 'refs/heads/x' } },
      'GET /repos/acme/widgets/pulls': { json: [{ number: 12 }] },
      'POST /repos/acme/widgets/pulls': { status: 201, json: { number: 13, html_url: 'u' } },
      'PATCH /repos/acme/widgets/pulls/12': { json: { number: 12, html_url: 'u' } },
    });
    expect((await api.getRepo()).default_branch).toBe('main');
    expect((await api.getRef('heads/main'))?.object.sha).toBe('base');
    expect(await api.getRef('heads/missing')).toBeNull();
    expect((await api.getCommit('base')).tree.sha).toBe('tree0');
    expect((await api.createBlob('hello')).sha).toBe('blob1');
    expect(fake.of('POST /repos/acme/widgets/git/blobs')[0]!.body).toEqual({ content: 'hello', encoding: 'utf-8' });
    expect((await api.createTree('tree0', [{ path: 'a', mode: '100644', type: 'blob', sha: 'blob1' }])).sha).toBe('tree1');
    expect((await api.createCommit('msg', 'tree1', ['base'])).sha).toBe('c1');
    await api.createRef('refs/heads/x', 'c1');
    await api.updateRef('heads/x', 'c1');
    expect(fake.of('PATCH /repos/acme/widgets/git/refs/heads/x')[0]!.body).toEqual({ sha: 'c1', force: true });
    expect((await api.listPulls({ head: 'acme:x', state: 'open' }))[0]!.number).toBe(12);
    expect(fake.of('GET /repos/acme/widgets/pulls')[0]!.query).toContain('head=acme%3Ax');
    expect((await api.createPull({ title: 't', head: 'x', base: 'main', body: 'b' })).number).toBe(13);
    expect((await api.updatePull(12, { title: 't', body: 'b' })).number).toBe(12);
  });

  it('refuses a repository name that is not owner/name', () => {
    expect(() => new GitHubClient({ token: 't', repo: 'nope', fetch: fakeFetch({}).fetch })).toThrow(/owner\/name/);
  });
});
