import { createServer } from "node:http";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { GitLabApiError } from "../src/gitlab-api.js";
import { SecretRefused } from "../src/secrets.js";
import { CI_PATH, IncludeNotMergeable, SETUP_BRANCH, SetupBranchExists, SETUP_MR_TITLE, mergeInclude, openSetupMr, projectApi, setupMrBody, setupMrFiles } from "../src/setup-mr.js";
import { configTemplate, includeSnippet, type Answers } from "../src/templates.js";
import { loadYaml } from "./yaml.js";

const light: Answers = { profile: "il4", gates: ["scan", "qa"], sentinel: "off", version: "latest" };
const SNIPPET = includeSnippet({ group: "tools", version: "latest" });
const COMPONENT = "$CI_SERVER_FQDN/tools/secure-builder-bot/secure-builder@~latest";

function yamlOf(text: string): unknown {
  const file = path.join(mkdtempSync(path.join(tmpdir(), "sb-mr-")), "x.yml");
  writeFileSync(file, text);
  return loadYaml(file);
}

describe("merging the include into .gitlab-ci.yml", () => {
  it("writes the snippet alone when there is no file", () => {
    expect(mergeInclude(null, SNIPPET)).toEqual({ content: SNIPPET, changed: true });
    expect(mergeInclude("  \n", SNIPPET)).toEqual({ content: SNIPPET, changed: true });
  });

  it("appends the snippet to a file with no include, once", () => {
    const existing = "stages: [test]\nunit:\n  stage: test\n  script: [make test]";
    const once = mergeInclude(existing, SNIPPET);
    expect(once.changed).toBe(true);
    expect(once.content.startsWith(existing + "\n")).toBe(true);
    expect(yamlOf(once.content)).toMatchObject({ stages: ["test"], include: [{ component: COMPONENT }] });
    expect(mergeInclude(once.content, SNIPPET)).toEqual({ content: once.content, changed: false });
  });

  it("adds an entry to an existing block include, never a second include key", () => {
    const existing = "include:\n  - local: ci/lint.yml\nstages: [test]\n";
    const merged = mergeInclude(existing, SNIPPET);
    expect(merged.content.match(/^include:/gm)).toHaveLength(1);
    expect(yamlOf(merged.content)).toEqual({ include: [{ component: COMPONENT }, { local: "ci/lint.yml" }], stages: ["test"] });
  });

  it("follows the existing list's indentation, comments between included", () => {
    const existing = "include:   # shared jobs\n\n# the linters\n- local: ci/lint.yml\n";
    const pinned = includeSnippet({ group: "tools", version: "0.4.0" });
    const merged = mergeInclude(existing, pinned);
    expect(yamlOf(merged.content)).toEqual({
      include: [{ component: "$CI_SERVER_FQDN/tools/secure-builder-bot/secure-builder@0.4.0", inputs: { version: "0.4.0" } }, { local: "ci/lint.yml" }],
    });
  });

  it("refuses an include it cannot extend as text, rather than guess", () => {
    expect(() => mergeInclude("include: ci/lint.yml\n", SNIPPET)).toThrow(IncludeNotMergeable);
    expect(() => mergeInclude("include: [ci/a.yml]\n", SNIPPET)).toThrow(/include/);
    expect(() => mergeInclude("include:\n  local: ci/lint.yml\n", SNIPPET)).toThrow(IncludeNotMergeable);
    expect(() => mergeInclude("include:\n", SNIPPET)).toThrow(IncludeNotMergeable);
  });
});

describe("the merge request body and files", () => {
  it("explains the three answers and that its own pipeline may run the gates already", () => {
    const body = setupMrBody(light);
    expect(body).toMatch(/il4/);
    expect(body).toMatch(/`scan`, `qa`/);
    expect(body).toMatch(/off/);
    expect(body).toMatch(/own pipeline may run the gates already/);
    expect(setupMrBody({ ...light, gates: ["scan", "qa", "sentinel"], sentinel: "action" })).toMatch(/SB_MODEL_KEY/);
  });

  it("carries the config template and the merged CI file", () => {
    const files = setupMrFiles(light, "stages: [test]\n", { group: "tools" });
    expect(files).toEqual([
      { path: ".securebuilderbot.yml", content: configTemplate(light) },
      { path: CI_PATH, content: "stages: [test]\n\n" + SNIPPET },
    ]);
  });
});

interface Call {
  method: string;
  path: string;
  query: string;
  body: unknown;
  token: string | null;
}

function fakeProject(opts: { ci?: string; openMr?: boolean; failMr?: number; branch?: boolean; manifest?: boolean } = {}) {
  const calls: Call[] = [];
  const fetch = (input: string, init?: RequestInit): Promise<Response> => {
    const url = new URL(input);
    const method = init?.method ?? "GET";
    const body: unknown = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ method, path: url.pathname, query: url.search, body, token: new Headers(init?.headers).get("PRIVATE-TOKEN") });
    const P = "/api/v4/projects/acme%2Fwidgets";
    const reply = (status: number, json: unknown) => Promise.resolve(new Response(JSON.stringify(json), { status, headers: { "content-type": "application/json" } }));
    const route = `${method} ${url.pathname}`;
    if (route === `GET ${P}`) return reply(200, { id: 9, default_branch: "trunk" });
    if (route === `GET ${P}/repository/files/.securebuilderbot.yml`) return reply(404, { message: "404 File Not Found" });
    if (route === `GET ${P}/repository/files/docs%2Fsecurity%2FCONTROL-MANIFEST.md`) {
      return opts.manifest ? reply(200, { content: Buffer.from("| CM-01 |\n").toString("base64"), encoding: "base64" }) : reply(404, { message: "404 File Not Found" });
    }
    if (route === `GET ${P}/repository/files/.gitlab-ci.yml`) {
      return opts.ci === undefined ? reply(404, { message: "404 File Not Found" }) : reply(200, { content: Buffer.from(opts.ci).toString("base64"), encoding: "base64" });
    }
    if (route === `GET ${P}/repository/branches/secure-builder%2Fenable`) return opts.branch ? reply(200, { name: SETUP_BRANCH }) : reply(404, { message: "404 Branch Not Found" });
    if (route === `POST ${P}/repository/commits`) return reply(201, { id: "c0ffee" });
    if (route === `GET ${P}/merge_requests`) return reply(200, opts.openMr ? [{ iid: 5, web_url: "https://gitlab.example.invalid/mr/5" }] : []);
    if (route === `POST ${P}/merge_requests`) return opts.failMr ? reply(opts.failMr, { message: "nope" }) : reply(201, { iid: 6, web_url: "https://gitlab.example.invalid/mr/6" });
    if (route === `PUT ${P}/merge_requests/5`) return reply(200, { iid: 5, web_url: "https://gitlab.example.invalid/mr/5" });
    return reply(404, { message: "404 Not Found" });
  };
  const api = projectApi({ apiV4Url: "https://gitlab.example.invalid/api/v4/", project: "acme/widgets", token: "tok-123", fetch });
  return { calls, api };
}

describe("opening the setup merge request", () => {
  it("commits both files on the setup branch from the default branch and opens the merge request", async () => {
    const { calls, api } = fakeProject({ ci: "stages: [test]\n" });
    const result = await openSetupMr(api, light, { group: "tools" });
    expect(result).toEqual({ branch: SETUP_BRANCH, commit: "c0ffee", mergeRequest: { iid: 6, web_url: "https://gitlab.example.invalid/mr/6" }, created: true, files: [".securebuilderbot.yml", CI_PATH] });
    expect(calls.every((c) => c.token === "tok-123")).toBe(true);
    const files = calls.filter((c) => c.path.includes("/repository/files/"));
    expect(files.every((c) => c.query === "?ref=trunk")).toBe(true);
    const commit = calls.find((c) => c.method === "POST" && c.path.endsWith("/repository/commits"))!.body as Record<string, unknown>;
    expect(commit).toMatchObject({ branch: SETUP_BRANCH, start_branch: "trunk", commit_message: expect.stringMatching(/^Enable Secure Builder/) as unknown });
    expect(commit).not.toHaveProperty("force");
    expect(commit["actions"]).toEqual([
      { action: "create", file_path: ".securebuilderbot.yml", content: configTemplate(light) },
      { action: "update", file_path: CI_PATH, content: "stages: [test]\n\n" + includeSnippet({ group: "tools", version: "latest" }) },
    ]);
    const mr = calls.find((c) => c.method === "POST" && c.path.endsWith("/merge_requests"))!.body;
    expect(mr).toEqual({ source_branch: SETUP_BRANCH, target_branch: "trunk", title: SETUP_MR_TITLE, description: setupMrBody(light) });
    const list = calls.find((c) => c.method === "GET" && c.path.endsWith("/merge_requests"))!;
    expect(list.query).toBe(`?state=opened&source_branch=${encodeURIComponent(SETUP_BRANCH)}`);
  });

  it("adds a drafted control list when the default branch has none, and never replaces one that is there", async () => {
    const draft = { path: "docs/security/CONTROL-MANIFEST.md", content: "| id | control | implementation | required artifact | proving test | note |\n" };
    const none = fakeProject();
    const added = await openSetupMr(none.api, light, { extraFiles: [draft] });
    const actions = (none.calls.find((c) => c.path.endsWith("/repository/commits"))!.body as { actions: { action: string; file_path: string }[] }).actions;
    expect(actions.map((a) => [a.action, a.file_path])).toEqual([["create", ".securebuilderbot.yml"], ["create", CI_PATH], ["create", draft.path]]);
    expect(added.files).toEqual([".securebuilderbot.yml", CI_PATH, draft.path]);
    const there = fakeProject({ manifest: true });
    const kept = await openSetupMr(there.api, light, { extraFiles: [draft] });
    const keptActions = (there.calls.find((c) => c.path.endsWith("/repository/commits"))!.body as { actions: { file_path: string }[] }).actions;
    expect(keptActions.map((a) => a.file_path)).toEqual([".securebuilderbot.yml", CI_PATH]);
    expect(kept.files).toEqual([".securebuilderbot.yml", CI_PATH]);
  });

  it("creates the CI file when the default branch has none", async () => {
    const { calls, api } = fakeProject();
    await openSetupMr(api, light, {});
    const commit = calls.find((c) => c.path.endsWith("/repository/commits"))!.body as { actions: { action: string; file_path: string; content: string }[] };
    expect(commit.actions[1]).toEqual({ action: "create", file_path: CI_PATH, content: includeSnippet({ version: "latest" }) });
  });

  it("refuses to move a setup branch that already exists, or one an open merge request comes from, unless told to (gate cli run 1, B-01)", async () => {
    for (const state of [{ branch: true }, { openMr: true }]) {
      const { calls, api } = fakeProject(state);
      await expect(openSetupMr(api, light, { group: "tools" })).rejects.toThrow(SetupBranchExists);
      await expect(openSetupMr(api, light, { group: "tools", replaceBranch: false })).rejects.toThrow(/secure-builder\/enable already exists/);
      expect(calls.filter((c) => c.method !== "GET")).toEqual([]);
    }
  });

  it("with replaceBranch, recommits the branch with force and updates the open merge request, creating no second one", async () => {
    const { calls, api } = fakeProject({ openMr: true, branch: true });
    const result = await openSetupMr(api, light, { group: "tools", replaceBranch: true });
    expect(result.created).toBe(false);
    expect(result.mergeRequest.iid).toBe(5);
    expect(calls.find((c) => c.path.endsWith("/repository/commits"))!.body).toMatchObject({ branch: SETUP_BRANCH, force: true });
    expect(calls.filter((c) => c.method === "POST" && c.path.endsWith("/merge_requests"))).toHaveLength(0);
    expect(calls.find((c) => c.method === "PUT")!.body).toEqual({ title: SETUP_MR_TITLE, description: setupMrBody(light) });
  });

  it("refuses a secret-shaped body before it is sent", async () => {
    const { calls, api } = fakeProject();
    const leak = "glpat-" + "q".repeat(20);
    await expect(api.createMergeRequest({ source_branch: "a", target_branch: "b", title: "t", description: leak })).rejects.toThrow(SecretRefused);
    await expect(api.updateMergeRequest(5, { title: "t", description: leak })).rejects.toThrow(SecretRefused);
    await expect(api.createCommit({ branch: "a", start_branch: "b", commit_message: "m", actions: [{ action: "create", file_path: "x", content: leak }] })).rejects.toThrow(SecretRefused);
    await expect(openSetupMr(api, light, { group: leak })).rejects.toThrow(SecretRefused);
    expect(calls.filter((c) => c.method !== "GET")).toEqual([]);
  });

  it("names the status and the path of a failure, never the response", async () => {
    const { api } = fakeProject({ failMr: 403 });
    const failure = openSetupMr(api, light, {});
    await expect(failure).rejects.toThrow(GitLabApiError);
    await expect(openSetupMr(api, light, {})).rejects.toThrow(/403 .*merge_requests/);
  });

  it("refuses a default branch whose include cannot be extended, before any write", async () => {
    const { calls, api } = fakeProject({ ci: "include: ci/a.yml\n" });
    await expect(openSetupMr(api, light, {})).rejects.toThrow(IncludeNotMergeable);
    expect(calls.filter((c) => c.method !== "GET")).toEqual([]);
  });
});

describe("the files it writes validate", () => {
  it("core accepts the config the merge request carries", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "sb-mrcfg-"));
    const file = path.join(dir, ".securebuilderbot.yml");
    writeFileSync(file, setupMrFiles(light, null, {})[0]!.content);
    const out = execFileSync(path.resolve(import.meta.dirname, "..", "..", "core", "run"), ["config", "check", "--config", file], { encoding: "utf8" });
    expect(out).toContain("config ok: profile il4");
  });
});

describe("the setup merge request's client never follows a redirect (gate cli run 3, B-01)", () => {
  // Real fetch, two loopback servers: the first answers 302 to the second, which must see nothing.
  // Node's fetch keeps PRIVATE-TOKEN across a cross-origin redirect, so following one leaks it.
  const PLANTED = ["tok", "setup", "redirect"].join("-");
  it("refuses a 3xx, and the redirect target receives no request", async () => {
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
      await expect(projectApi({ apiV4Url, project: "acme/widgets", token: PLANTED }).getProject()).rejects.toThrow();
      expect(seen).toEqual([]);
    } finally {
      origin.close();
      target.close();
    }
  });
});
