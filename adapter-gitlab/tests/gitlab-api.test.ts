import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { GitLabApiError, MAX_PAGES, mergeRequestApi } from "../src/gitlab-api.js";
import { SecretRefused } from "../src/secrets.js";
import { DIFF_REFS, FakeGitLab } from "./fake-gitlab.js";

function api(gitlab: FakeGitLab, token = "tok-123") {
  return mergeRequestApi({ apiV4Url: "https://gitlab.example.invalid/api/v4", projectId: "42", mergeRequestIid: "7", token, fetch: gitlab.fetch });
}

describe("the merge request API client", () => {
  it("reads the merge request's diff refs", async () => {
    const gitlab = new FakeGitLab();
    expect(await api(gitlab).diffRefs()).toEqual(DIFF_REFS);
    expect(gitlab.calls[0]).toMatchObject({ method: "GET", path: "/api/v4/projects/42/merge_requests/7" });
  });

  it("sends the token as PRIVATE-TOKEN and JSON bodies", async () => {
    const gitlab = new FakeGitLab();
    const note = await api(gitlab).createNote("hello");
    expect(note.body).toBe("hello");
    expect(gitlab.calls[0]).toEqual({ method: "POST", path: "/api/v4/projects/42/merge_requests/7/notes", body: { body: "hello" } });
    await expect(api(gitlab, "wrong").createNote("x")).rejects.toThrow(GitLabApiError);
  });

  it("follows x-next-page until the list is complete", async () => {
    const gitlab = new FakeGitLab();
    gitlab.pageSize = 2;
    for (let i = 0; i < 5; i++) await api(gitlab).createNote(`note ${String(i)}`);
    gitlab.calls.length = 0;
    const notes = await api(gitlab).listNotes();
    expect(notes.map((n) => n.body)).toEqual(["note 0", "note 1", "note 2", "note 3", "note 4"]);
    expect(gitlab.calls.map((c) => c.path)).toEqual([
      "/api/v4/projects/42/merge_requests/7/notes?per_page=100&page=1",
      "/api/v4/projects/42/merge_requests/7/notes?per_page=100&page=2",
      "/api/v4/projects/42/merge_requests/7/notes?per_page=100&page=3",
    ]);
  });

  it("stops at the page cap and fails closed rather than act on a partial list (gate run 1, N-08)", async () => {
    // A GitLab, or anything answering for it, whose x-next-page never ends.
    let calls = 0;
    const endless = (input: string): Promise<Response> => {
      calls += 1;
      // A bound of the test's own, so a client with no cap fails here instead of looping for ever.
      if (calls > 1000) return Promise.reject(new Error("the client followed 1000 pages and did not stop"));
      const page = Number(new URL(input).searchParams.get("page"));
      return Promise.resolve(new Response("[]", { status: 200, headers: { "content-type": "application/json", "x-next-page": String(page + 1) } }));
    };
    const client = mergeRequestApi({ apiV4Url: "https://gitlab.example.invalid/api/v4", projectId: "42", mergeRequestIid: "7", token: "tok-123", fetch: endless });
    await expect(client.listNotes()).rejects.toThrow(`more than ${String(MAX_PAGES)} pages`);
    expect(calls).toBe(MAX_PAGES);
    calls = 0;
    await expect(client.listDiscussions()).rejects.toThrow(/refusing to act on a partial list/);
    expect(calls).toBe(MAX_PAGES);
  });

  it("reads a list of exactly the cap's pages in full", async () => {
    const gitlab = new FakeGitLab();
    gitlab.pageSize = 1;
    for (let i = 0; i < MAX_PAGES; i++) await api(gitlab).createNote(`note ${String(i)}`);
    expect(await api(gitlab).listNotes()).toHaveLength(MAX_PAGES);
    await api(gitlab).createNote("one more");
    await expect(api(gitlab).listNotes()).rejects.toThrow(/pages/);
  });

  it("updates a note, opens a discussion with a position, replies and resolves", async () => {
    const gitlab = new FakeGitLab();
    const a = api(gitlab);
    const note = await a.createNote("v1");
    expect((await a.updateNote(note.id, "v2")).body).toBe("v2");
    const position = { position_type: "text" as const, ...DIFF_REFS, new_path: "a.ts", old_path: "a.ts", new_line: 3 };
    const discussion = await a.createDiscussion("finding", position);
    expect(discussion.notes[0]?.position).toEqual(position);
    await a.replyToDiscussion(discussion.id, "Not found on abc");
    await a.resolveDiscussion(discussion.id);
    expect(gitlab.writes().slice(-2)).toEqual([
      { method: "POST", path: `/api/v4/projects/42/merge_requests/7/discussions/${discussion.id}/notes`, body: { body: "Not found on abc" } },
      { method: "PUT", path: `/api/v4/projects/42/merge_requests/7/discussions/${discussion.id}`, body: { resolved: true } },
    ]);
    expect((await a.listDiscussions()).find((d) => d.id === discussion.id)?.notes.every((n) => n.resolved)).toBe(true);
  });

  it("refuses to send a secret-shaped body and sends nothing", async () => {
    const gitlab = new FakeGitLab();
    const a = api(gitlab);
    const leak = "ghp_" + "z".repeat(36);
    await expect(a.createNote(`token ${leak}`)).rejects.toThrow(SecretRefused);
    await expect(a.createDiscussion(`token ${leak}`)).rejects.toThrow(SecretRefused);
    await expect(a.replyToDiscussion("d1", `token ${leak}`)).rejects.toThrow(SecretRefused);
    await expect(a.updateNote(1, `token ${leak}`)).rejects.toThrow(SecretRefused);
    expect(gitlab.calls).toEqual([]);
  });

  it("names the status and the path of a failed request, never the response body", async () => {
    const gitlab = new FakeGitLab();
    gitlab.failWith = 500;
    await expect(api(gitlab).listNotes()).rejects.toThrow(/500 .*merge_requests\/7\/notes/);
    await expect(api(gitlab).listNotes()).rejects.not.toThrow(/failed on purpose/);
  });
});

describe("a redirect never carries the token (gate cli run 3, B-01)", () => {
  // Node's fetch drops Authorization on a cross-origin redirect but keeps PRIVATE-TOKEN, so a
  // GitLab (or proxy) answering 302 would hand the token to whatever host and scheme it names.
  // Real fetch, two loopback servers: the first redirects to the second, which must see nothing.
  const PLANTED = ["tok", "redirect"].join("-");
  it("refuses to follow a 3xx, and the redirect target receives no request", async () => {
    const seen: (string | undefined)[] = [];
    const target = createServer((req, res) => {
      seen.push(req.headers["private-token"] as string | undefined);
      res.end("{}");
    });
    await new Promise<void>((ok) => target.listen(0, "127.0.0.1", ok));
    const to = `http://127.0.0.1:${String((target.address() as AddressInfo).port)}/stolen`;
    const origin = createServer((_req, res) => {
      res.writeHead(302, { location: to });
      res.end();
    });
    await new Promise<void>((ok) => origin.listen(0, "127.0.0.1", ok));
    const apiV4Url = `http://127.0.0.1:${String((origin.address() as AddressInfo).port)}/api/v4`;
    try {
      const client = mergeRequestApi({ apiV4Url, projectId: "42", mergeRequestIid: "7", token: PLANTED });
      await expect(client.listNotes()).rejects.toThrow();
      expect(seen).toEqual([]);
    } finally {
      origin.close();
      target.close();
    }
  });
});
