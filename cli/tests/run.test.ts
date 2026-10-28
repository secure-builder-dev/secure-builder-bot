import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { main } from "../src/main.ts";
import { botHome } from "../src/run.ts";
import { capture, git, tempRepo } from "./helpers.ts";

const CHECKOUT = path.resolve(import.meta.dirname, "..", "..");
// The QA gate returns not_run at once in a repository with no test runner ("no test runner
// detected"), so core stops there and exits 1: a real run of core with no scanner needed.
const QA_ONLY = { ".securebuilderbot.yml": "profile: il4\ngates: [qa]\nversion: latest\n", "README.md": "hello\n" };

async function run(cwd: string, args: string[], env: Record<string, string | undefined> = { ...process.env }) {
  const io = capture({ cwd, env });
  const code = await main(["run", ...args], io);
  return { code, out: io.text(), lines: io.lines };
}

describe("run against core", () => {
  it("prints core's verdict block and exits with core's code, the base falling back to main", async () => {
    const repo = tempRepo(undefined, QA_ONLY);
    const { code, out } = await run(repo, []);
    expect(code).toBe(1);
    expect(out).toContain("core/run run --base main --head HEAD");
    expect(out).toMatch(/^QA: NOT RUN — no test runner detected/m);
    expect(out).toMatch(/^Overall: FAIL$/m);
    expect(out).toMatch(/^Receipt: gate-records\/runs\/[0-9TZ]+-[0-9a-f]{7}\/receipt\.md$/m);
  });

  it("--open prints the receipt's full path; --base and --head pass through; origin/main is the default when it exists", async () => {
    const repo = tempRepo(undefined, QA_ONLY);
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD");
    const defaulted = await run(repo, []);
    expect(defaulted.out).toContain("--base origin/main --head HEAD");
    const { code, lines } = await run(repo, ["--base", "main", "--head", "HEAD", "--open"]);
    expect(code).toBe(1);
    const receipt = lines.find((l) => l.startsWith("receipt: "))?.slice("receipt: ".length) ?? "";
    expect(path.isAbsolute(receipt)).toBe(true);
    expect(existsSync(receipt)).toBe(true);
  });

  it("finds core through SECUREBUILDERBOT_HOME, and passes --config through", async () => {
    const repo = tempRepo(undefined, { ...QA_ONLY, "other.yml": "profile: il4\ngates: [qa]\nversion: latest\n" });
    const { code, out } = await run(repo, ["--config", "other.yml"], { ...process.env, SECUREBUILDERBOT_HOME: CHECKOUT });
    expect(code).toBe(1);
    expect(out).toContain(path.join(CHECKOUT, "core", "run"));
    expect(out).toMatch(/^QA: NOT RUN/m);
  });

  it("exits 2, as core does, when the config is bad or missing", async () => {
    const bad = tempRepo(undefined, { ".securebuilderbot.yml": "profile: il4\ngates: [qa]\nversion: latest\ncolour: blue\n" });
    const r = await run(bad, []);
    expect(r.code).toBe(2);
    expect(r.out).toContain("colour");
    expect((await run(tempRepo(), [])).code).toBe(2);
  });

  it("--open says so when core wrote no receipt", async () => {
    const r = await run(tempRepo(), ["--open"]);
    expect(r.code).toBe(2);
    expect(r.out).toMatch(/no receipt/);
  });
});

describe("run that cannot start", () => {
  it("exits 2 outside a git repository", async () => {
    const r = await run(mkdtempSync(path.join(tmpdir(), "sb-nogit-")), []);
    expect(r.code).toBe(2);
    expect(r.out).toMatch(/not inside a git repository/);
  });

  it("exits 2 without python3", async () => {
    const r = await run(tempRepo(undefined, QA_ONLY), [], { PATH: mkdtempSync(path.join(tmpdir(), "sb-nopath-")) });
    expect(r.code).toBe(2);
    expect(r.out).toMatch(/python3/);
  });

  it("exits 2 when SECUREBUILDERBOT_HOME holds no core/run", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "sb-home-"));
    const r = await run(tempRepo(undefined, QA_ONLY), [], { ...process.env, SECUREBUILDERBOT_HOME: home });
    expect(r.code).toBe(2);
    expect(r.out).toContain("SECUREBUILDERBOT_HOME");
  });

  it("exits 2 when core/run cannot be started", async () => {
    const home = mkdtempSync(path.join(tmpdir(), "sb-home-"));
    const { mkdirSync, writeFileSync } = await import("node:fs");
    mkdirSync(path.join(home, "core"));
    writeFileSync(path.join(home, "core", "run"), "not a program\n", { mode: 0o644 });
    const r = await run(tempRepo(undefined, QA_ONLY), [], { ...process.env, SECUREBUILDERBOT_HOME: home });
    expect(r.code).toBe(2);
    expect(r.out).toMatch(/could not start/);
  });
});

describe("what core prints and returns", () => {
  it("passes stderr through, and reads an exit code that is not 0, 1 or 2 as could not run", async () => {
    const { mkdirSync, writeFileSync } = await import("node:fs");
    const home = mkdtempSync(path.join(tmpdir(), "sb-home-"));
    mkdirSync(path.join(home, "core"));
    writeFileSync(path.join(home, "core", "run"), "#!/bin/sh\necho from-core-stderr >&2\nexit 3\n", { mode: 0o755 });
    const r = await run(tempRepo(undefined, QA_ONLY), [], { ...process.env, SECUREBUILDERBOT_HOME: home });
    expect(r.code).toBe(2);
    expect(r.out).toContain("from-core-stderr");
  });
});

describe("where the bot's checkout is", () => {
  it("is the checkout this CLI is in, unless SECUREBUILDERBOT_HOME names one", () => {
    expect(botHome({})).toBe(CHECKOUT);
    expect(botHome({ SECUREBUILDERBOT_HOME: "" })).toBe(CHECKOUT);
    expect(botHome({ SECUREBUILDERBOT_HOME: "/opt/bot" })).toBe("/opt/bot");
  });
});
