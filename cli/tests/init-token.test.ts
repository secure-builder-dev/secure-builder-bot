import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { configTemplate, workflowTemplate, type SetupAnswers } from "../../adapter-github/src/templates.ts";
import { SETUP_BRANCH } from "../../adapter-gitlab/src/setup-mr.ts";
import { configTemplate as gitlabConfigTemplate, includeSnippet } from "../../adapter-gitlab/src/templates.ts";
import { main } from "../src/main.ts";
import { fakeFetch, type Route } from "./fake-fetch.ts";
import { capture, git, tempRepo } from "./helpers.ts";

// Secret-shaped fake tokens, built at run time so no file carries one.
const GH = "ghp_" + "Zq7Wm2Lx".repeat(4) + "Tn4K";
const GL = "glpat-" + "Rv3Pk8Ns".repeat(3);
const light: SetupAnswers = { profile: "il4", gates: ["scan", "qa"], sentinel: "off" };
const R = "/repos/acme/widgets";

function githubRoutes(over: Record<string, Route> = {}): Record<string, Route> {
  return {
    [`GET ${R}`]: { json: { default_branch: "main" } },
    [`GET ${R}/git/ref/heads/main`]: { json: { object: { sha: "base0" } } },
    [`GET ${R}/git/commits/base0`]: { json: { tree: { sha: "tree0" } } },
    [`POST ${R}/git/blobs`]: { status: 201, json: { sha: "blob1" } },
    [`POST ${R}/git/trees`]: { status: 201, json: { sha: "tree1" } },
    [`POST ${R}/git/commits`]: { status: 201, json: { sha: "commit1" } },
    [`GET ${R}/git/ref/heads/${SETUP_BRANCH}`]: { status: 404, json: { message: "Not Found" } },
    [`POST ${R}/git/refs`]: { status: 201, json: { ref: `refs/heads/${SETUP_BRANCH}` } },
    [`GET ${R}/pulls`]: { json: [] },
    [`POST ${R}/pulls`]: { status: 201, json: { number: 42, html_url: "https://github.example.invalid/acme/widgets/pull/42" } },
    ...over,
  };
}

/** Everything the command left behind that a token could hide in: the files and every commit. */
function everythingWritten(repo: string): string {
  const files = [".securebuilderbot.yml", ".github/workflows/secure-builder.yml", ".gitlab-ci.yml"]
    .filter((f) => existsSync(path.join(repo, f)))
    .map((f) => readFileSync(path.join(repo, f), "utf8"));
  return files.join("\n") + execFileSync("git", ["log", "-p", "--all"], { cwd: repo, encoding: "utf8" });
}

describe("init on GitHub with a token in the environment", () => {
  it("opens the setup pull request through the adapter, and the token is in no file and no output", async () => {
    const repo = tempRepo("https://github.com/acme/widgets.git");
    const fake = fakeFetch(githubRoutes());
    const io = capture({ cwd: repo, env: { GITHUB_TOKEN: GH }, fetch: fake.fetch });
    expect(await main(["init", "--yes"], io)).toBe(0);
    const blobs = fake.of(`POST ${R}/git/blobs`).map((c) => (c.body as { content: string }).content);
    expect(blobs).toEqual([configTemplate(light), workflowTemplate(light)]);
    expect(fake.of(`POST ${R}/pulls`)[0]!.body).toMatchObject({ title: "Enable Secure Builder", head: SETUP_BRANCH, base: "main" });
    expect(fake.calls.every((c) => c.headers["authorization"] === `Bearer ${GH}`)).toBe(true);
    expect(io.text()).toMatch(/opened pull request #42 .*pull\/42/);
    expect(io.text()).not.toContain("gh pr create");
    expect(io.text()).not.toContain(GH);
    expect(everythingWritten(repo)).not.toContain(GH);
    expect(readFileSync(path.join(repo, ".securebuilderbot.yml"), "utf8")).toBe(configTemplate(light));
  });

  it("carries the drafted control list into the pull request it opens", async () => {
    const repo = tempRepo("https://github.com/acme/widgets.git");
    mkdirSync(path.join(repo, "backend", "src", "services"), { recursive: true });
    writeFileSync(path.join(repo, "backend/src/services/notes.ts"), 'export function requireOwner(u) { if (u.id !== 1) throw new AppError(403, "F", "no") }\n');
    git(repo, "add", "-A");
    git(repo, "commit", "-q", "-m", "code");
    const M = "docs/security/CONTROL-MANIFEST.md";
    const fake = fakeFetch(githubRoutes({ [`GET ${R}/contents/${M}`]: { status: 404, json: { message: "Not Found" } } }));
    const io = capture({ cwd: repo, env: { GITHUB_TOKEN: GH }, fetch: fake.fetch });
    expect(await main(["init", "--yes"], io)).toBe(0);
    const blobs = fake.of(`POST ${R}/git/blobs`).map((c) => (c.body as { content: string }).content);
    expect(blobs).toHaveLength(3);
    expect(blobs[2]).toBe(readFileSync(path.join(repo, M), "utf8"));
    expect(blobs[2]).toContain("requireOwner — 403 refusal");
  });

  it("gives the draft script no token and none of the bot's own variables", async () => {
    const repo = tempRepo("https://github.com/acme/widgets.git");
    const home = path.join(repo, "..", path.basename(repo) + "-bot");
    mkdirSync(path.join(home, "qa", "scripts"), { recursive: true });
    const seen = path.join(home, "env.txt");
    writeFileSync(path.join(home, "qa", "scripts", "derive-controls.sh"), `env > "${seen}"\nexit 0\n`);
    const M = "docs/security/CONTROL-MANIFEST.md";
    const fake = fakeFetch(githubRoutes({ [`GET ${R}/contents/${M}`]: { status: 404, json: { message: "Not Found" } } }));
    const io = capture({ cwd: repo, env: { GITHUB_TOKEN: GH, GH_TOKEN: GH, SECUREBUILDERBOT_HOME: home, PATH: process.env.PATH ?? "" }, fetch: fake.fetch });
    expect(await main(["init", "--yes"], io)).toBe(0);
    const env = readFileSync(seen, "utf8");
    expect(env).not.toContain(GH);
    expect(env).not.toMatch(/TOKEN|SECUREBUILDERBOT/);
  });

  it("refuses a remote setup branch that already exists without --force: exit 1, nothing pushed (gate cli run 1, B-01)", async () => {
    const existing = {
      [`GET ${R}/git/ref/heads/${SETUP_BRANCH}`]: { json: { object: { sha: "usercommit" } } },
      [`PATCH ${R}/git/refs/heads/${SETUP_BRANCH}`]: { json: { ref: `refs/heads/${SETUP_BRANCH}` } },
      [`GET ${R}/pulls`]: { json: [{ number: 7, html_url: "https://github.example.invalid/acme/widgets/pull/7" }] },
      [`PATCH ${R}/pulls/7`]: { json: { number: 7, html_url: "https://github.example.invalid/acme/widgets/pull/7" } },
    };
    const fake = fakeFetch(githubRoutes(existing));
    const io = capture({ cwd: tempRepo("git@github.com:acme/widgets.git"), env: { GH_TOKEN: GH }, fetch: fake.fetch });
    expect(await main(["init", "--yes"], io)).toBe(1);
    expect(fake.calls.filter((c) => c.method !== "GET")).toEqual([]);
    expect(io.text()).toMatch(/refused: the remote branch secure-builder\/enable on acme\/widgets already exists/);
    expect(io.text()).toContain("--force");

    // --force replaces it, as before: the same pull request is updated, never a second opened.
    const forced = fakeFetch(githubRoutes(existing));
    const io2 = capture({ cwd: tempRepo("git@github.com:acme/widgets.git"), env: { GH_TOKEN: GH }, fetch: forced.fetch });
    expect(await main(["init", "--yes", "--force"], io2)).toBe(0);
    expect(forced.of(`PATCH ${R}/git/refs/heads/${SETUP_BRANCH}`)[0]!.body).toEqual({ sha: "commit1", force: true });
    expect(forced.of(`POST ${R}/pulls`)).toHaveLength(0);
    expect(io2.text()).toMatch(/updated pull request #7/);
  });

  it("never prints the token when the server's error echoes it, and exits 2 with the commands to finish by hand", async () => {
    const repo = tempRepo("https://github.com/acme/widgets.git");
    const fake = fakeFetch(githubRoutes({ [`POST ${R}/pulls`]: { status: 422, json: { message: `Validation failed for token ${GH}` } } }));
    const io = capture({ cwd: repo, env: { GITHUB_TOKEN: GH }, fetch: fake.fetch });
    expect(await main(["init", "--yes"], io)).toBe(2);
    // The server's own words are never repeated (gate cli run 3, N-01): only the status and request.
    expect(io.text()).toMatch(/could not open the pull request: GitHub answered 422 to POST \/repos\/acme\/widgets\/pulls \(the response is not repeated here\)/);
    expect(io.text()).not.toContain("Validation failed");
    expect(io.text()).not.toContain(GH);
    expect(io.text()).toContain(`git push -u origin ${SETUP_BRANCH}`);
    expect(everythingWritten(repo)).not.toContain(GH);
  });

  it("never prints part of the token when GitHub's error echoes a prefix or a slice of it (gate cli run 3, N-01)", async () => {
    for (const json of [{ message: `bad credentials ${GH.slice(0, 12)}` }, `${"x".repeat(161)}${GH}`]) {
      const fake = fakeFetch(githubRoutes({ [`POST ${R}/pulls`]: { status: 401, json } }));
      const io = capture({ cwd: tempRepo("https://github.com/acme/widgets.git"), env: { GITHUB_TOKEN: GH }, fetch: fake.fetch });
      expect(await main(["init", "--yes"], io)).toBe(2);
      expect(io.text()).toMatch(/GitHub answered 401 to POST/);
      expect(io.text()).not.toContain(GH.slice(0, 10));
      expect(io.text()).not.toContain(GH.slice(4, 14));
    }
  });

  it("does not use the token when the origin remote names no GitHub repository", async () => {
    const repo = tempRepo();
    const fake = fakeFetch(githubRoutes());
    const io = capture({ cwd: repo, env: { GITHUB_TOKEN: GH }, fetch: fake.fetch });
    expect(await main(["init", "--yes", "--platform", "github"], io)).toBe(0);
    expect(fake.calls).toHaveLength(0);
    expect(io.text()).toMatch(/names no repository.*token was not used/);
    expect(io.text()).toContain("gh pr create");
  });

  it("talks to a GitHub Enterprise Server's API when --github-api names it", async () => {
    const repo = tempRepo("https://ghe.example.invalid/acme/widgets.git");
    const fake = fakeFetch(githubRoutes());
    const io = capture({ cwd: repo, env: { GITHUB_TOKEN: GH }, fetch: fake.fetch });
    expect(await main(["init", "--yes", "--platform", "github", "--github-api", "https://ghe.example.invalid/api/v3"], io)).toBe(2);
    expect(fake.calls[0]!.url).toBe("https://ghe.example.invalid/api/v3/repos/acme/widgets");
  });
});

const P = "/api/v4/projects/tools%2Fwidgets";
function gitlabRoutes(over: Record<string, Route> = {}): Record<string, Route> {
  return {
    [`GET ${P}`]: { json: { default_branch: "main" } },
    [`GET ${P}/repository/files/.securebuilderbot.yml`]: { status: 404, json: { message: "404 File Not Found" } },
    [`GET ${P}/repository/files/.gitlab-ci.yml`]: { status: 404, json: { message: "404 File Not Found" } },
    [`POST ${P}/repository/commits`]: { status: 201, json: { id: "c0ffee" } },
    [`GET ${P}/merge_requests`]: { json: [] },
    [`POST ${P}/merge_requests`]: { status: 201, json: { iid: 6, web_url: "https://gitlab.example.invalid/tools/widgets/-/merge_requests/6" } },
    ...over,
  };
}

describe("init on GitLab with a token in the environment", () => {
  const gl = { profile: "il4" as const, gates: ["scan" as const, "qa" as const], sentinel: "off" as const, version: "latest" };

  it("opens the setup merge request through the adapter with the token in PRIVATE-TOKEN only", async () => {
    const repo = tempRepo("https://gitlab.com/tools/widgets.git");
    const fake = fakeFetch(gitlabRoutes());
    const io = capture({ cwd: repo, env: { GITLAB_TOKEN: GL }, fetch: fake.fetch });
    expect(await main(["init", "--yes", "--gitlab-group", "platform"], io)).toBe(0);
    const commit = fake.of(`POST ${P}/repository/commits`)[0]!.body as { actions: { content: string }[] };
    expect(commit.actions.map((a) => a.content)).toEqual([gitlabConfigTemplate(gl), includeSnippet({ group: "platform", version: "latest" })]);
    expect(fake.calls.every((c) => c.headers["private-token"] === GL && c.headers["authorization"] === undefined)).toBe(true);
    expect(io.text()).toMatch(/opened merge request !6 .*merge_requests\/6/);
    expect(io.text()).not.toContain(GL);
    expect(everythingWritten(repo)).not.toContain(GL);
  });

  it("refuses a remote setup branch that already exists without --force, and replaces it with --force (gate cli run 1, B-01)", async () => {
    const branch = { [`GET ${P}/repository/branches/secure-builder%2Fenable`]: { json: { name: SETUP_BRANCH } } };
    const fake = fakeFetch(gitlabRoutes(branch));
    const io = capture({ cwd: tempRepo("https://gitlab.com/tools/widgets.git"), env: { GITLAB_TOKEN: GL }, fetch: fake.fetch });
    expect(await main(["init", "--yes"], io)).toBe(1);
    expect(fake.calls.filter((c) => c.method !== "GET")).toEqual([]);
    expect(io.text()).toMatch(/refused: the remote branch secure-builder\/enable on tools\/widgets already exists/);
    const forced = fakeFetch(gitlabRoutes(branch));
    const io2 = capture({ cwd: tempRepo("https://gitlab.com/tools/widgets.git"), env: { GITLAB_TOKEN: GL }, fetch: forced.fetch });
    expect(await main(["init", "--yes", "--force"], io2)).toBe(0);
    expect(forced.of(`POST ${P}/repository/commits`)[0]!.body).toMatchObject({ branch: SETUP_BRANCH, force: true });
  });

  it("refuses to write a file that would carry the token's value, before any write or request", async () => {
    const repo = tempRepo("https://gitlab.example.invalid/tools/widgets.git", { ".gitlab-ci.yml": `variables:\n  T: ${GL}\n` });
    const fake = fakeFetch(gitlabRoutes());
    const io = capture({ cwd: repo, env: { GITLAB_TOKEN: GL }, fetch: fake.fetch });
    expect(await main(["init", "--yes"], io)).toBe(1);
    expect(io.text()).toMatch(/refused: \.gitlab-ci\.yml would carry the value of a token/);
    expect(io.text()).not.toContain(GL);
    expect(existsSync(path.join(repo, ".securebuilderbot.yml"))).toBe(false);
    expect(git(repo, "rev-parse", "--abbrev-ref", "HEAD")).toBe("main");
    expect(fake.calls).toHaveLength(0);
  });

  it("exits 2 naming the status when GitLab refuses, and 1 when the default branch's include cannot be extended", async () => {
    const failing = fakeFetch(gitlabRoutes({ [`POST ${P}/merge_requests`]: { status: 500, json: { message: "boom" } } }));
    const io = capture({ cwd: tempRepo("git@gitlab.com:tools/widgets.git"), env: { GITLAB_TOKEN: GL }, fetch: failing.fetch });
    expect(await main(["init", "--yes"], io)).toBe(2);
    expect(io.text()).toMatch(/could not open the merge request: GitLab answered 500/);
    const ci = Buffer.from("include: ci/lint.yml\n").toString("base64");
    const odd = fakeFetch(gitlabRoutes({ [`GET ${P}/repository/files/.gitlab-ci.yml`]: { json: { content: ci, encoding: "base64" } } }));
    const io2 = capture({ cwd: tempRepo("git@gitlab.com:tools/widgets.git"), env: { GITLAB_TOKEN: GL }, fetch: odd.fetch });
    expect(await main(["init", "--yes"], io2)).toBe(1);
    expect(odd.calls.filter((c) => c.method !== "GET")).toHaveLength(0);
  });

  it("exits 2 without the token when a 200 reply is not JSON and echoes it (gate cli run 2, N-04)", async () => {
    // GitLab's client parses the reply itself; GitHub's keeps a non-JSON reply as text, so there the
    // refusal names what was missing from it instead. Neither may quote the token's first characters.
    for (const [remote, env, token, said] of [
      ["https://gitlab.com/tools/widgets.git", { GITLAB_TOKEN: GL }, GL, /could not open the merge request: the server's reply was not JSON/],
      ["https://github.com/acme/widgets.git", { GITHUB_TOKEN: GH }, GH, /could not open the pull request: /],
    ] as const) {
      const echo = (): Promise<Response> => Promise.resolve(new Response(`${token} is not authorised here`, { status: 200 }));
      const io = capture({ cwd: tempRepo(remote), env, fetch: echo });
      expect(await main(["init", "--yes"], io)).toBe(2);
      expect(io.text()).toMatch(said);
      expect(io.text()).not.toContain(token.slice(0, 10));
    }
  });

  it("refuses a token holding whitespace or a control character before any request (gate cli run 4, B-01)", async () => {
    // A token read with $(cat file) from a file with Windows line endings: fetch's header error
    // quotes the value trimmed, which full-value redaction does not match, and it printed whole.
    for (const [remote, name, token] of [
      ["https://gitlab.com/tools/widgets.git", "GITLAB_TOKEN", `${GL}\r\n${GL}\r`],
      ["https://gitlab.com/tools/widgets.git", "GITLAB_TOKEN", `${GL}\u0000x `],
      ["https://github.com/acme/widgets.git", "GITHUB_TOKEN", `${GH}\n${GH}\r`],
    ] as const) {
      const fake = fakeFetch(name === "GITHUB_TOKEN" ? githubRoutes() : gitlabRoutes());
      const io = capture({ cwd: tempRepo(remote), env: { [name]: token }, fetch: fake.fetch });
      expect(await main(["init", "--yes"], io)).toBe(2);
      expect(io.text()).toContain(`${name} holds whitespace or a control character`);
      expect(io.text()).not.toContain((name === "GITHUB_TOKEN" ? GH : GL).slice(0, 10));
      expect(fake.calls).toHaveLength(0);
    }
  });

  it("names a request that could not be sent by its cause, never by fetch's message (gate cli run 4, B-01)", async () => {
    const quoting = (): Promise<Response> => Promise.reject(new TypeError(`Headers.append: "${GL.slice(0, 20)}" is an invalid header value.`));
    const io = capture({ cwd: tempRepo("https://gitlab.com/tools/widgets.git"), env: { GITLAB_TOKEN: GL }, fetch: quoting });
    expect(await main(["init", "--yes"], io)).toBe(2);
    expect(io.text()).toMatch(/could not open the merge request: the request could not be sent/);
    expect(io.text()).not.toContain(GL.slice(0, 10));
    const redirect = (): Promise<Response> => Promise.reject(new TypeError("fetch failed", { cause: new Error("unexpected redirect") }));
    const io2 = capture({ cwd: tempRepo("https://gitlab.com/tools/widgets.git"), env: { GITLAB_TOKEN: GL }, fetch: redirect });
    expect(await main(["init", "--yes"], io2)).toBe(2);
    expect(io2.text()).toMatch(/the request could not be sent \(the server answered with a redirect, which is refused\)/);
  });

  it("never lets an unexpected error's message out of main, where it could quote part of a token", async () => {
    const broken = (): Promise<Response> => Promise.reject(new Error(`proxy said: ${GL.slice(0, 12)}…`));
    const io = capture({ cwd: tempRepo("https://gitlab.com/tools/widgets.git"), env: { GITLAB_TOKEN: GL }, fetch: broken });
    expect(await main(["init", "--yes"], io)).toBe(2);
    expect(io.text()).toMatch(/securebuilderbot init: stopped on an unexpected Error/);
    expect(io.text()).not.toContain(GL.slice(0, 10));
  });

  it("refuses a body the adapter finds secret-shaped, and exits 1", async () => {
    const leak = "ghp_" + "Yk2Jd8Qw".repeat(4) + "Hr5M";
    const fake = fakeFetch(gitlabRoutes());
    const io = capture({ cwd: tempRepo("git@gitlab.com:tools/widgets.git"), env: { GITLAB_TOKEN: GL }, fetch: fake.fetch });
    expect(await main(["init", "--yes", "--gitlab-group", leak], io)).toBe(1);
    expect(fake.calls.filter((c) => c.method !== "GET")).toHaveLength(0);
  });
});

describe("where a token may go (gate cli run 1, N-02)", () => {
  it("sends GITLAB_TOKEN nowhere when the remote is not gitlab.com and no --gitlab-host names it", async () => {
    const fake = fakeFetch({});
    const io = capture({ cwd: tempRepo("https://notgitlab.example.invalid/tools/widgets.git"), env: { GITLAB_TOKEN: GL }, fetch: fake.fetch });
    expect(await main(["init", "--yes"], io)).toBe(0);
    expect(fake.calls).toHaveLength(0);
    expect(io.text()).toMatch(/notgitlab\.example\.invalid, not gitlab\.com: the token was not sent/);
    expect(io.text()).toContain("--gitlab-host notgitlab.example.invalid");
    expect(io.text()).toContain("glab mr create");
  });

  it("sends GITHUB_TOKEN nowhere when the remote is not github.com and no --github-api names it", async () => {
    const fake = fakeFetch({});
    const io = capture({ cwd: tempRepo("https://ghe.example.invalid/acme/widgets.git"), env: { GITHUB_TOKEN: GH }, fetch: fake.fetch });
    expect(await main(["init", "--yes", "--platform", "github"], io)).toBe(0);
    expect(fake.calls).toHaveLength(0);
    expect(io.text()).toMatch(/ghe\.example\.invalid, not github\.com: the token was not sent/);
    expect(io.text()).toContain("--github-api https://ghe.example.invalid/api/v3");
  });

  it("sends the token to gitlab.com, and to a host the user names with --gitlab-host or --github-api", async () => {
    const P2 = "/api/v4/projects/tools%2Fwidgets";
    const com = fakeFetch(gitlabRoutes());
    expect(await main(["init", "--yes"], capture({ cwd: tempRepo("git@gitlab.com:tools/widgets.git"), env: { GITLAB_TOKEN: GL }, fetch: com.fetch }))).toBe(0);
    expect(com.calls[0]!.url).toBe(`https://gitlab.com${P2}`);
    const named = fakeFetch(gitlabRoutes());
    const io = capture({ cwd: tempRepo("https://notgitlab.example.invalid/tools/widgets.git"), env: { GITLAB_TOKEN: GL }, fetch: named.fetch });
    expect(await main(["init", "--yes", "--gitlab-host", "gitlab.corp.example.invalid"], io)).toBe(0);
    expect(named.calls.every((c) => c.url.startsWith("https://gitlab.corp.example.invalid/api/v4/"))).toBe(true);
    const ghe = fakeFetch(githubRoutes());
    const io2 = capture({ cwd: tempRepo("https://ghe.example.invalid/acme/widgets.git"), env: { GITHUB_TOKEN: GH }, fetch: ghe.fetch });
    await main(["init", "--yes", "--platform", "github", "--github-api", "https://ghe.example.invalid/api/v3"], io2);
    expect(ghe.calls[0]!.url).toBe("https://ghe.example.invalid/api/v3/repos/acme/widgets");
  });

  it("refuses a named host that is not plain https, exiting 2 before anything is sent", async () => {
    const fake = fakeFetch({});
    const repo = tempRepo("https://github.com/acme/widgets.git");
    expect(await main(["init", "--yes", "--github-api", "http://ghe.example.invalid/api/v3"], capture({ cwd: repo, env: { GITHUB_TOKEN: GH }, fetch: fake.fetch }))).toBe(2);
    expect(await main(["init", "--yes", "--platform", "gitlab", "--gitlab-host", "evil.example.invalid/x"], capture({ cwd: tempRepo(), env: { GITLAB_TOKEN: GL }, fetch: fake.fetch }))).toBe(2);
    expect(await main(["init", "--yes", "--github-api", "not a url"], capture({ cwd: repo, env: { GITHUB_TOKEN: GH }, fetch: fake.fetch }))).toBe(2);
    expect(fake.calls).toHaveLength(0);
  });
});
