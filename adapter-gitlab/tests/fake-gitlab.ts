// An in-memory GitLab merge request behind `fetch`: the endpoints the publisher uses, with the
// shapes the REST API v4 returns, paginated the way GitLab paginates (per_page, x-next-page).
// Individual notes show up in the discussions list too, as they do on a real GitLab.
import type { DiffRefs, Discussion, Note, Position } from "../src/gitlab-api.js";

export interface Call {
  method: string;
  path: string;
  body: unknown;
}

export const DIFF_REFS: DiffRefs = {
  base_sha: "3fd11a61f4a961faf1196681898ff723ad0e6640",
  start_sha: "3fd11a61f4a961faf1196681898ff723ad0e6640",
  head_sha: "10d3390d943b3ada8a8f80a9a96c9aff334f0f85",
};

export class FakeGitLab {
  readonly calls: Call[] = [];
  readonly notes: Note[] = [];
  readonly discussions: Discussion[] = [];
  diffRefs: DiffRefs = { ...DIFF_REFS };
  pageSize = 100;
  failWith: number | undefined;
  private nextId = 100;

  readonly fetch = (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const method = (init?.method ?? "GET").toUpperCase();
    const body: unknown = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    this.calls.push({ method, path: url.pathname + url.search, body });
    const headers = new Headers(init?.headers);
    if (headers.get("PRIVATE-TOKEN") !== "tok-123") return Promise.resolve(this.json(401, { message: "401 Unauthorized" }));
    if (this.failWith !== undefined) return Promise.resolve(this.json(this.failWith, { message: "failed on purpose" }));
    const prefix = "/api/v4/projects/42/merge_requests/7";
    if (url.pathname !== prefix && !url.pathname.startsWith(prefix + "/")) return Promise.resolve(this.json(404, { message: "404 Not Found" }));
    return Promise.resolve(this.route(method, url.pathname.slice(prefix.length), url.searchParams, body));
  };

  writes(): Call[] {
    return this.calls.filter((c) => c.method !== "GET");
  }

  private route(method: string, rest: string, params: URLSearchParams, body: unknown): Response {
    const b = (body ?? {}) as Record<string, unknown>;
    if (method === "GET" && rest === "") return this.json(200, { iid: 7, diff_refs: this.diffRefs });
    if (method === "GET" && rest === "/notes") return this.page(this.notes, params);
    if (method === "POST" && rest === "/notes") {
      const note = this.note(String(b["body"]));
      this.notes.push(note);
      this.discussions.push({ id: `individual-${String(note.id)}`, individual_note: true, notes: [note] });
      return this.json(201, note);
    }
    const putNote = /^\/notes\/(\d+)$/.exec(rest);
    if (method === "PUT" && putNote) {
      const note = this.notes.find((n) => n.id === Number(putNote[1]));
      if (!note) return this.json(404, { message: "404 Note Not Found" });
      note.body = String(b["body"]);
      return this.json(200, note);
    }
    if (method === "GET" && rest === "/discussions") return this.page(this.discussions, params);
    if (method === "POST" && rest === "/discussions") {
      const position = b["position"] as Position | undefined;
      const note = this.note(String(b["body"]), position);
      const discussion: Discussion = { id: `d${String(note.id)}`, individual_note: false, notes: [note] };
      this.discussions.push(discussion);
      return this.json(201, discussion);
    }
    const reply = /^\/discussions\/([^/]+)\/notes$/.exec(rest);
    if (method === "POST" && reply) {
      const discussion = this.discussions.find((d) => d.id === reply[1]);
      if (!discussion) return this.json(404, { message: "404 Discussion Not Found" });
      const note = this.note(String(b["body"]));
      discussion.notes.push(note);
      return this.json(201, note);
    }
    const resolve = /^\/discussions\/([^/]+)$/.exec(rest);
    if (method === "PUT" && resolve) {
      const discussion = this.discussions.find((d) => d.id === resolve[1]);
      if (!discussion) return this.json(404, { message: "404 Discussion Not Found" });
      for (const n of discussion.notes) n.resolved = b["resolved"] === true;
      return this.json(200, discussion);
    }
    return this.json(404, { message: `404 no route for ${method} ${rest}` });
  }

  private note(body: string, position?: Position): Note {
    const note: Note = { id: this.nextId++, body, system: false, resolvable: position !== undefined, resolved: false, position: position ?? null };
    return note;
  }

  private page<T>(items: T[], params: URLSearchParams): Response {
    const page = Number(params.get("page") ?? "1");
    const perPage = Math.min(Number(params.get("per_page") ?? "20"), this.pageSize);
    const slice = items.slice((page - 1) * perPage, page * perPage);
    const next = page * perPage < items.length ? String(page + 1) : "";
    return this.json(200, slice, { "x-next-page": next, "x-page": String(page) });
  }

  private json(status: number, payload: unknown, extra: Record<string, string> = {}): Response {
    return new Response(JSON.stringify(payload), { status, headers: { "content-type": "application/json", ...extra } });
  }
}
