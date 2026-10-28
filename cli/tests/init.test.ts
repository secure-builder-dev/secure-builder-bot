import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { configTemplate, workflowTemplate, type SetupAnswers } from "../../adapter-github/src/templates.ts";
import { configTemplate as gitlabConfigTemplate, includeSnippet } from "../../adapter-gitlab/src/templates.ts";
import { overwriteRefusal } from "../src/init.ts";
import { main } from "../src/main.ts";
import { fakeFetch } from "./fake-fetch.ts";
import { capture, git, tempRepo, typed } from "./helpers.ts";

const CORE_RUN = path.resolve(import.meta.dirname, "..", "..", "core", "run");
const light: SetupAnswers = { profile: "il4", gates: ["scan", "qa"], sentinel: "off" };
const GITHUB = "git@github.com:acme/widgets.git";
const GITLAB = "https://gitlab.example.invalid/tools/widgets.git";

function read(repo: string, file: string): string {
  return readFileSync(path.join(repo, file), "utf8");
}

function configCheck(file: string): string {
  return execFileSync(CORE_RUN, ["config", "check", "--config", file], { encoding: "utf8" });
}

async function init(repo: string, ...args: string[]) {
  const io = capture({ cwd: repo });
  const code = await main(["init", ...args], io);
  return { code, out: io.text() };
}

/** A repository whose main holds one function that refuses access and one whose name says it hides data. */
function repoWithControls(remote: string): string {
  const repo = tempRepo(remote);
  mkdirSync(path.join(repo, "backend", "src", "services"), { recursive: true });
  writeFileSync(path.join(repo, "backend/src/services/notes.ts"),
    'export function requireOwner(u) { if (u.id !== 1) throw new AppError(403, "F", "no") }\nexport function redactNotes(row) { return { ...row, notes: null } }\n');
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", "code");
  return repo;
}

describe("the drafted control list", () => {
  const M = "docs/security/CONTROL-MANIFEST.md";

  it("is drafted onto the setup branch when QA is on and the repository has no list, for the team to confirm", async () => {
    const repo = repoWithControls(GITHUB);
    const { code, out } = await init(repo, "--yes");
    expect(code).toBe(0);
    const list = read(repo, M);
    expect(list).toMatch(/^<!-- Drafted by securebuilderbot init/);
    expect(list).toContain("| CM-01 | requireOwner — 403 refusal | `backend/src/services/notes.ts:requireOwner` |");
    expect(list).toContain("| CM-02 | redactNotes — suggested: hides data, check me | `backend/src/services/notes.ts:redactNotes` |");
    expect(git(repo, "show", "--name-only", "--format=%s", "HEAD").split("\n")).toContain(M);
    expect(out).toContain(`drafted ${M}: 2 control(s), 1 suggested by name — delete the rows that are not controls and add any it missed before merging`);
  });

  it("never replaces a list the repository keeps, and drafts nothing when QA is off", async () => {
    const kept = repoWithControls(GITHUB);
    mkdirSync(path.join(kept, "docs", "security"), { recursive: true });
    writeFileSync(path.join(kept, M), "| CM-01 | mine | `x.ts:y` | - | - | n |\n");
    git(kept, "add", "-A");
    git(kept, "commit", "-q", "-m", "our list");
    expect((await init(kept, "--yes")).code).toBe(0);
    expect(read(kept, M)).toBe("| CM-01 | mine | `x.ts:y` | - | - | n |\n");
    expect(git(kept, "show", "--name-only", "--format=%s", "HEAD").split("\n")).not.toContain(M);
    const scanOnly = repoWithControls(GITHUB);
    expect((await init(scanOnly, "--yes", "--gates", "scan")).code).toBe(0);
    expect(existsSync(path.join(scanOnly, M))).toBe(false);
  });

  it("says so when it finds nothing to draft, so QA's yellow is not a surprise", async () => {
    const { out } = await init(tempRepo(GITHUB), "--yes");
    expect(out).toContain(`found no security controls to draft into ${M}: QA stays yellow until a list with rows is merged`);
  });

  it("goes into the GitLab setup branch the same way", async () => {
    const repo = repoWithControls(GITLAB);
    expect((await init(repo, "--yes", "--gitlab-group", "tools")).code).toBe(0);
    expect(read(repo, M)).toContain("requireOwner — 403 refusal");
  });
});

describe("the control roots inferred from the layout", () => {
  const M = "docs/security/CONTROL-MANIFEST.md";
  const P = "project.config.yaml";
  const R = "/repos/acme/widgets";
  // A secret-shaped fake token, built at run time so no file carries one.
  const GH = "ghp_" + "Zq7Wm2Lx".repeat(4) + "Tn4K";
  const routes = {
    [`GET ${R}`]: { json: { default_branch: "main" } },
    [`GET ${R}/git/ref/heads/main`]: { json: { object: { sha: "base0" } } },
    [`GET ${R}/git/commits/base0`]: { json: { tree: { sha: "tree0" } } },
    [`POST ${R}/git/blobs`]: { status: 201, json: { sha: "blob1" } },
    [`POST ${R}/git/trees`]: { status: 201, json: { sha: "tree1" } },
    [`POST ${R}/git/commits`]: { status: 201, json: { sha: "commit1" } },
    [`POST ${R}/git/refs`]: { status: 201, json: { ref: "refs/heads/secure-builder/enable" } },
    [`GET ${R}/pulls`]: { json: [] },
    [`POST ${R}/pulls`]: { status: 201, json: { number: 42, html_url: "https://github.example.invalid/acme/widgets/pull/42" } },
  };

  /** A FastAPI-shaped repository with no project.config.yaml: a package that refuses access, and its tests. */
  function pythonRepo(files: Record<string, string> = {}): string {
    const repo = tempRepo(GITHUB, { "requirements.txt": "fastapi\n", ...files });
    mkdirSync(path.join(repo, "app"), { recursive: true });
    mkdirSync(path.join(repo, "tests"), { recursive: true });
    writeFileSync(path.join(repo, "app/__init__.py"), "");
    writeFileSync(path.join(repo, "app/auth.py"), 'def require_admin(user):\n    if user.role != "admin":\n        raise HTTPException(status_code=403)\n');
    writeFileSync(path.join(repo, "tests/test_auth.py"), "from app.auth import require_admin\n");
    git(repo, "add", "-A");
    git(repo, "commit", "-q", "-m", "code");
    return repo;
  }

  it("proposes the matching project.config.yaml in the setup pull request for a Python repository, and says so", async () => {
    const repo = pythonRepo();
    const fake = fakeFetch(routes);
    const io = capture({ cwd: repo, env: { GITHUB_TOKEN: GH }, fetch: fake.fetch });
    expect(await main(["init", "--yes"], io)).toBe(0);
    const config = read(repo, P);
    expect(config).toMatch(/^# Proposed by securebuilderbot init/);
    expect(config).toContain("CONTROL_SRC_ROOTS: app\nCONTROL_SRC_EXT: py\nCONTROL_TEST_DIR: tests\nCONTROL_TEST_CMD: python3 -m pytest -q -x\n");
    expect(read(repo, M)).toContain("| CM-01 | require_admin — 403 refusal | `app/auth.py:require_admin` | - | `test_auth.py` |");
    const blobs = fake.of(`POST ${R}/git/blobs`).map((c) => (c.body as { content: string }).content);
    expect(blobs).toContain(config);
    expect(blobs).toContain(read(repo, M));
    expect(git(repo, "show", "--name-only", "--format=%s", "HEAD").split("\n")).toContain(P);
    expect(io.text()).toContain(`proposed ${P} with the control roots inferred from the layout (CONTROL_SRC_ROOTS: app · CONTROL_SRC_EXT: py · CONTROL_TEST_DIR: tests · CONTROL_TEST_CMD: python3 -m pytest -q -x) — check them before merging`);
  });

  it("never overwrites a project.config.yaml the repository keeps: it prints the lines to add instead", async () => {
    const repo = pythonRepo({ [P]: "APP_TRACK: web\n" });
    const { code, out } = await init(repo, "--yes");
    expect(code).toBe(0);
    expect(read(repo, P)).toBe("APP_TRACK: web\n");
    expect(git(repo, "show", "--name-only", "--format=%s", "HEAD").split("\n")).not.toContain(P);
    expect(out).toContain(`${P} already exists, so init did not write the control roots it inferred; add these lines to it before merging the drafted list:`);
    expect(out).toContain("  CONTROL_SRC_ROOTS: app");
  });

  it("proposes nothing for a repository whose controls are in the default layout", async () => {
    const repo = repoWithControls(GITHUB);
    expect((await init(repo, "--yes")).code).toBe(0);
    expect(existsSync(path.join(repo, P))).toBe(false);
  });
});

describe("init on a GitHub repository, no token", () => {
  it("writes both files from the adapter's templates, commits them on secure-builder/enable and prints the commands", async () => {
    const repo = tempRepo(GITHUB);
    const { code, out } = await init(repo, "--yes");
    expect(code).toBe(0);
    expect(read(repo, ".securebuilderbot.yml")).toBe(configTemplate(light));
    expect(read(repo, ".github/workflows/secure-builder.yml")).toBe(workflowTemplate(light));
    expect(configCheck(path.join(repo, ".securebuilderbot.yml"))).toContain("config ok: profile il4 (287 controls) · gates scan, qa · version latest");
    expect(git(repo, "rev-parse", "--abbrev-ref", "HEAD")).toBe("secure-builder/enable");
    expect(git(repo, "show", "--name-only", "--format=%s", "HEAD").split("\n")).toEqual(["Enable Secure Builder", "", ".github/workflows/secure-builder.yml", ".securebuilderbot.yml"]);
    expect(git(repo, "rev-parse", "HEAD~1")).toBe(git(repo, "rev-parse", "main"));
    expect(out).toMatch(/platform: github \(from the origin remote\)/);
    expect(out).toMatch(/Standard/);
    expect(out).toMatch(/test suite/);
    expect(out).toContain("git push -u origin secure-builder/enable");
    expect(out).toContain('gh pr create --head secure-builder/enable --title "Enable Secure Builder" --fill');
    expect(out).toContain("git switch main");
    const writes = out.slice(out.indexOf("Every write:"));
    expect(writes).toMatch(/wrote \.securebuilderbot\.yml/);
    expect(writes).toMatch(/wrote \.github\/workflows\/secure-builder\.yml/);
    expect(writes).toMatch(/committed [0-9a-f]{7} on the new local branch secure-builder\/enable/);
  });

  it("refuses a second init without --force and changes nothing; with --force it rewrites the files", async () => {
    const repo = tempRepo(GITHUB);
    expect((await init(repo, "--yes")).code).toBe(0);
    const head = git(repo, "rev-parse", "HEAD");
    writeFileSync(path.join(repo, ".securebuilderbot.yml"), "profile: il6\n");
    const again = await init(repo, "--yes");
    expect(again.code).toBe(1);
    expect(again.out).toMatch(/refused: \.securebuilderbot\.yml.*--force/);
    expect(read(repo, ".securebuilderbot.yml")).toBe("profile: il6\n");
    expect(git(repo, "rev-parse", "HEAD")).toBe(head);
    git(repo, "commit", "-q", "-am", "my own answers");
    const mine = git(repo, "rev-parse", "HEAD");
    const forced = await init(repo, "--yes", "--force", "--profile", "il6");
    expect(forced.code).toBe(0);
    expect(read(repo, ".securebuilderbot.yml")).toBe(configTemplate({ ...light, profile: "il6" }));
    expect(git(repo, "rev-parse", "HEAD~1")).toBe(mine);
    expect(git(repo, "rev-parse", "HEAD~2")).toBe(head);
  });

  it("refuses an existing workflow file, or a setup branch it is not on, without --force", async () => {
    const repo = tempRepo(GITHUB, { "README.md": "x\n" });
    execFileSync("mkdir", ["-p", path.join(repo, ".github", "workflows")]);
    writeFileSync(path.join(repo, ".github/workflows/secure-builder.yml"), "name: mine\n");
    git(repo, "add", "-A");
    git(repo, "commit", "-q", "-m", "my workflow");
    const r = await init(repo, "--yes");
    expect(r.code).toBe(1);
    expect(r.out).toContain(".github/workflows/secure-builder.yml");
    expect(existsSync(path.join(repo, ".securebuilderbot.yml"))).toBe(false);

    const other = tempRepo(GITHUB);
    git(other, "branch", "secure-builder/enable");
    const b = await init(other, "--yes");
    expect(b.code).toBe(1);
    expect(b.out).toContain("the local branch secure-builder/enable");
    expect(git(other, "rev-parse", "--abbrev-ref", "HEAD")).toBe("main");
    expect((await init(other, "--yes", "--force")).code).toBe(0);
    expect(git(other, "rev-parse", "--abbrev-ref", "HEAD")).toBe("secure-builder/enable");
  });

  it("takes the answers from the terminal and shows the Full option's model key", async () => {
    const repo = tempRepo(GITHUB);
    const io = capture({ cwd: repo, interactive: true, input: typed("il6", "scan", "action") });
    expect(await main(["init"], io)).toBe(0);
    const full: SetupAnswers = { profile: "il6", gates: ["scan"], sentinel: "action" };
    expect(read(repo, ".securebuilderbot.yml")).toBe(configTemplate(full));
    expect(read(repo, ".github/workflows/secure-builder.yml")).toBe(workflowTemplate(full));
    expect(io.text()).toMatch(/Full/);
    expect(io.text()).toContain("SB_MODEL_KEY");
  });

  it("warns when scan is off, as the setup does", async () => {
    const { code, out } = await init(tempRepo(GITHUB), "--yes", "--gates", "qa");
    expect(code).toBe(0);
    expect(out).toMatch(/warning: scan is off/);
  });
});

describe("init on a GitLab repository, no token", () => {
  const gl = { profile: "il4" as const, gates: ["scan" as const, "qa" as const], sentinel: "off" as const, version: "latest" };

  it("writes the config and a .gitlab-ci.yml holding the include, and says to edit <group>", async () => {
    const repo = tempRepo(GITLAB);
    const { code, out } = await init(repo, "--yes");
    expect(code).toBe(0);
    expect(read(repo, ".securebuilderbot.yml")).toBe(gitlabConfigTemplate(gl));
    expect(read(repo, ".gitlab-ci.yml")).toBe(includeSnippet({ version: "latest" }));
    expect(configCheck(path.join(repo, ".securebuilderbot.yml"))).toContain("config ok: profile il4");
    expect(out).toMatch(/platform: gitlab/);
    expect(out).toMatch(/edit <group> in \.gitlab-ci\.yml/);
    expect(out).toContain("glab mr create");
    expect(out).toMatch(/created \.gitlab-ci\.yml with the include/);
    expect(out).toContain("SECURE_BUILDER_TOKEN");
  });

  it("names the group when given, and appends to an existing .gitlab-ci.yml exactly once", async () => {
    const existing = "stages: [test]\nunit:\n  script: [make test]\n";
    const repo = tempRepo(GITLAB, { ".gitlab-ci.yml": existing });
    const first = await init(repo, "--yes", "--gitlab-group", "tools");
    expect(first.code).toBe(0);
    const merged = read(repo, ".gitlab-ci.yml");
    expect(merged).toBe(existing + "\n" + includeSnippet({ group: "tools", version: "latest" }));
    expect(first.out).not.toMatch(/edit <group>/);
    expect(first.out).toMatch(/appended the include to \.gitlab-ci\.yml/);
    const second = await init(repo, "--yes", "--gitlab-group", "tools", "--force");
    expect(second.code).toBe(0);
    expect(read(repo, ".gitlab-ci.yml")).toBe(merged);
    expect(merged.match(/^include:/gm)).toHaveLength(1);
    expect(second.out).toMatch(/\.gitlab-ci\.yml already includes the component/);
    expect(second.out).toMatch(/nothing new to commit/);
  });

  it("refuses an include it cannot extend, writing nothing and staying on the branch", async () => {
    const repo = tempRepo(GITLAB, { ".gitlab-ci.yml": "include: ci/lint.yml\n" });
    const r = await init(repo, "--yes");
    expect(r.code).toBe(1);
    expect(r.out).toContain("add these lines to it by hand");
    expect(existsSync(path.join(repo, ".securebuilderbot.yml"))).toBe(false);
    expect(git(repo, "rev-parse", "--abbrev-ref", "HEAD")).toBe("main");
  });

  it("--platform wins over the remote", async () => {
    const repo = tempRepo(GITHUB);
    expect((await init(repo, "--yes", "--platform", "gitlab")).code).toBe(0);
    expect(existsSync(path.join(repo, ".gitlab-ci.yml"))).toBe(true);
    expect(existsSync(path.join(repo, ".github"))).toBe(false);
  });
});

describe("uncommitted setup files (gate cli run 1, N-03)", () => {
  it("refuses an uncommitted edit to .gitlab-ci.yml: exit 1, the edit stays where it was, no branch made", async () => {
    const repo = tempRepo(GITLAB, { ".gitlab-ci.yml": "unit:\n  script: [make test]\n" });
    git(repo, "switch", "-q", "-c", "feature");
    writeFileSync(path.join(repo, ".gitlab-ci.yml"), "unit:\n  script: [make test]\nWIP_UNCOMMITTED: true\n");
    const r = await init(repo, "--yes");
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/refused: \.gitlab-ci\.yml has uncommitted changes/);
    expect(read(repo, ".gitlab-ci.yml")).toContain("WIP_UNCOMMITTED");
    expect(git(repo, "rev-parse", "--abbrev-ref", "HEAD")).toBe("feature");
    expect(git(repo, "branch", "--list", "secure-builder/enable")).toBe("");
  });

  it("refuses an untracked .gitlab-ci.yml, and an edited config even with --force", async () => {
    const repo = tempRepo(GITLAB);
    writeFileSync(path.join(repo, ".gitlab-ci.yml"), "stages: [test]\n");
    expect((await init(repo, "--yes")).code).toBe(1);
    const gh = tempRepo(GITHUB);
    expect((await init(gh, "--yes")).code).toBe(0);
    writeFileSync(path.join(gh, ".securebuilderbot.yml"), "profile: il6\n");
    const forced = await init(gh, "--yes", "--force");
    expect(forced.code).toBe(1);
    expect(forced.out).toMatch(/refused: \.securebuilderbot\.yml has uncommitted changes/);
    expect(read(gh, ".securebuilderbot.yml")).toBe("profile: il6\n");
  });
});

describe("symbolic links (gate cli run 1, N-04)", () => {
  it("refuses a tracked .securebuilderbot.yml that is a symlink out of the repository, writing nothing there", async () => {
    const outside = path.join(mkdtempSync(path.join(tmpdir(), "sb-outside-")), "planted.txt");
    const repo = tempRepo(GITHUB);
    symlinkSync(outside, path.join(repo, ".securebuilderbot.yml"));
    git(repo, "add", "-A");
    git(repo, "commit", "-q", "-m", "link");
    for (const args of [["--yes"], ["--yes", "--force"]]) {
      const r = await init(repo, ...args);
      expect(r.code).toBe(1);
      expect(r.out).toMatch(/refused: \.securebuilderbot\.yml is a symbolic link/);
    }
    expect(existsSync(outside)).toBe(false);
    expect(git(repo, "rev-parse", "--abbrev-ref", "HEAD")).toBe("main");
  });

  it("refuses a directory on the way that is a symlink", async () => {
    const elsewhere = mkdtempSync(path.join(tmpdir(), "sb-elsewhere-"));
    mkdirSync(path.join(elsewhere, "workflows"));
    const repo = tempRepo(GITHUB);
    symlinkSync(elsewhere, path.join(repo, ".github"));
    git(repo, "add", "-A");
    git(repo, "commit", "-q", "-m", "link");
    const r = await init(repo, "--yes");
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/refused: \.github is a symbolic link/);
    expect(existsSync(path.join(elsewhere, "workflows", "secure-builder.yml"))).toBe(false);
    expect(existsSync(path.join(repo, ".securebuilderbot.yml"))).toBe(false);
  });
});

describe("where the local setup branch starts (gate cli run 1, N-06)", () => {
  it("is the default branch, not the branch the user is on", async () => {
    const repo = tempRepo(GITHUB);
    const main = git(repo, "rev-parse", "main");
    git(repo, "switch", "-q", "-c", "feature");
    writeFileSync(path.join(repo, "feature.txt"), "work in progress\n");
    git(repo, "add", "-A");
    git(repo, "commit", "-q", "-m", "feature work");
    const r = await init(repo, "--yes");
    expect(r.code).toBe(0);
    expect(git(repo, "rev-parse", "HEAD~1")).toBe(main);
    expect(git(repo, "ls-tree", "--name-only", "HEAD")).not.toContain("feature.txt");
    expect(r.out).toContain("created the local branch secure-builder/enable from main");
    expect(r.out).toContain("git switch feature");
  });

  it("is origin's default branch when git knows it, and the CI file merged is that branch's", async () => {
    const repo = tempRepo(GITLAB, { ".gitlab-ci.yml": "stages: [test]\n" });
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD");
    git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main");
    const upstream = git(repo, "rev-parse", "origin/main");
    writeFileSync(path.join(repo, ".gitlab-ci.yml"), "stages: [test, local-only]\n");
    git(repo, "commit", "-q", "-am", "local main moves on");
    const r = await init(repo, "--yes", "--gitlab-group", "tools");
    expect(r.code).toBe(0);
    expect(git(repo, "rev-parse", "HEAD~1")).toBe(upstream);
    expect(read(repo, ".gitlab-ci.yml")).toBe("stages: [test]\n\n" + includeSnippet({ group: "tools", version: "latest" }));
    expect(r.out).toContain("from origin/main");
  });

  it("checks the default branch's files too: an existing config there is refused, a link there is refused", async () => {
    const repo = tempRepo(GITHUB, { "README.md": "x\n", ".securebuilderbot.yml": "profile: il6\n" });
    git(repo, "switch", "-q", "-c", "bare");
    git(repo, "rm", "-q", ".securebuilderbot.yml");
    git(repo, "commit", "-q", "-m", "no config on this branch");
    const r = await init(repo, "--yes");
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/refused: \.securebuilderbot\.yml already exists/);

    const linked = tempRepo(GITHUB);
    symlinkSync("/nonexistent/elsewhere", path.join(linked, ".securebuilderbot.yml"));
    git(linked, "add", "-A");
    git(linked, "commit", "-q", "-m", "link on main");
    git(linked, "switch", "-q", "-c", "plain");
    git(linked, "rm", "-q", ".securebuilderbot.yml");
    git(linked, "commit", "-q", "-m", "no link here");
    const l = await init(linked, "--yes", "--force");
    expect(l.code).toBe(1);
    expect(l.out).toMatch(/refused: \.securebuilderbot\.yml is a symbolic link/);
    expect(git(linked, "rev-parse", "--abbrev-ref", "HEAD")).toBe("plain");
  });

  it("is the current branch, said out loud, when there is no default branch to find", async () => {
    const repo = tempRepo(GITHUB);
    git(repo, "branch", "-m", "main", "trunk");
    const r = await init(repo, "--yes");
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/no default branch .* starts from trunk/);
  });
});

describe("init that cannot run", () => {
  it("exits 2 outside a git repository", async () => {
    const r = await init(mkdtempSync(path.join(tmpdir(), "sb-nogit-")), "--yes");
    expect(r.code).toBe(2);
    expect(r.out).toMatch(/not inside a git repository/);
  });

  it("exits 2 when the platform cannot be told and nobody can say", async () => {
    const r = await init(tempRepo("https://git.example.invalid/a/b.git"), "--yes");
    expect(r.code).toBe(2);
    expect(r.out).toContain("--platform");
    expect((await init(tempRepo(), "--yes", "--platform", "bitbucket")).code).toBe(2);
  });

  it("asks for the platform in the terminal when the remote does not say", async () => {
    const repo = tempRepo();
    const io = capture({ cwd: repo, interactive: true, input: typed("github") });
    expect(await main(["init", "--yes"], io)).toBe(2);
    const io2 = capture({ cwd: repo, interactive: true, input: typed("github") });
    expect(await main(["init", "--profile", "il4", "--gates", "scan", "--sentinel", "off"], io2)).toBe(0);
    expect(existsSync(path.join(repo, ".github/workflows/secure-builder.yml"))).toBe(true);
  });

  it("exits 2 on a bad answer or an unknown option", async () => {
    const repo = tempRepo(GITHUB);
    expect((await init(repo, "--yes", "--profile", "il5")).code).toBe(2);
    expect((await init(repo, "--colour")).code).toBe(2);
    expect((await init(repo, "--profile", "il4")).out).toMatch(/--gates, --sentinel, or --yes/);
  });

  it("exits 2 when git cannot commit, naming the git command", async () => {
    const repo = tempRepo(GITHUB);
    writeFileSync(path.join(repo, ".git", "hooks", "pre-commit"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
    const r = await init(repo, "--yes");
    expect(r.code).toBe(2);
    expect(r.out).toMatch(/git commit/);
  });
});

describe("the overwrite refusal", () => {
  it("refuses whatever already exists unless forced", () => {
    expect(overwriteRefusal([], false)).toBeNull();
    expect(overwriteRefusal([".securebuilderbot.yml"], true)).toBeNull();
    expect(overwriteRefusal([".securebuilderbot.yml"], false)).toMatch(/refused: \.securebuilderbot\.yml already exists/);
    expect(overwriteRefusal(["a", "b"], false)).toMatch(/a and b already exist /);
  });
});
