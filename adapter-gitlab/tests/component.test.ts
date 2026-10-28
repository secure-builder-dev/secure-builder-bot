import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { asRecord, loadYamlDocuments } from "./yaml.js";

const TEMPLATE = path.resolve(import.meta.dirname, "..", "templates", "secure-builder.yml");

const GATES = "secure-builder";
const PUBLISH = "secure-builder-publish";
const VERDICT = "secure-builder-verdict";

interface Component {
  spec: Record<string, unknown>;
  jobs: Map<string, Record<string, unknown>>;
  gates: Record<string, unknown>;
  publish: Record<string, unknown>;
  text: string;
}

function component(): Component {
  const docs = loadYamlDocuments(TEMPLATE);
  expect(docs, "a component is two YAML documents: spec, then the jobs").toHaveLength(2);
  const spec = asRecord(asRecord(docs[0], "spec document")["spec"], "spec");
  const jobs = new Map(Object.entries(asRecord(docs[1], "jobs document")).map(([k, v]) => [k, asRecord(v, `job ${k}`)]));
  const job = (name: string): Record<string, unknown> => asRecord(jobs.get(name), `${name} job`);
  return { spec, jobs, gates: job(GATES), publish: job(PUBLISH), text: readFileSync(TEMPLATE, "utf8") };
}

function script(job: Record<string, unknown>): string[] {
  return ["before_script", "script", "after_script"].flatMap((k) => (new Map(Object.entries(job)).get(k) as string[] | undefined) ?? []);
}

function sh(dir: string, ...args: string[]): string {
  return execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", ...args], { encoding: "utf8" }).trim();
}

/**
 * A stand-in for the bot's repository: a `main` branch ahead of every release, release tags out of
 * lexical order, a pre-release tag and a branch named like a release, so only a resolver that
 * reads release tags and sorts them by version lands on v0.10.0.
 */
function botRemote(opts: { tags: boolean }): string {
  const dir = mkdtempSync(path.join(tmpdir(), "sb-bot-remote-"));
  sh(dir, "init", "-q", "-b", "main");
  const commit = (msg: string): void => void sh(dir, "commit", "-q", "--allow-empty", "-m", msg);
  commit("first");
  if (opts.tags) {
    for (const tag of ["v0.2.0", "v0.9.0", "v0.10.0"]) {
      commit(`release ${tag}`);
      sh(dir, "tag", "-a", tag, "-m", tag);
    }
    commit("a release candidate");
    sh(dir, "tag", "v1.0.0-rc1");
    sh(dir, "branch", "v9.9.9");
  }
  commit("unreleased work on main");
  // A maintenance branch named exactly like the newest release, on an unreleased commit: git clone
  // --branch prefers refs/heads/ over refs/tags/, so a resolver that clones by name lands here
  // (adapter-gitlab gate run 2, B-01).
  if (opts.tags) sh(dir, "branch", "v0.10.0");
  return dir;
}

/** The job's lines that choose the bot's ref and clone it, run as GitLab runs them, into a temp dir. */
function runClone(jobName: string, env: Record<string, string>, preexisting = false): { status: number; stderr: string; clone: string } {
  const docs = loadYamlDocuments(TEMPLATE);
  const job = asRecord(new Map(Object.entries(asRecord(docs[1], "jobs document"))).get(jobName), jobName);
  const script = job["script"] as string[];
  const from = script.findIndex((l) => l.includes("SECURE_BUILDER_SOURCE"));
  const to = script.findIndex((l) => l.includes("git -C /tmp/secure-builder-bot fetch"));
  expect(from, `${jobName} sets the bot's source`).toBeGreaterThanOrEqual(0);
  expect(to, `${jobName} clones the bot`).toBeGreaterThan(from);
  const clone = path.join(mkdtempSync(path.join(tmpdir(), "sb-clone-")), "bot");
  if (preexisting) execFileSync("git", ["init", "-q", clone]);
  const steps = script.slice(from, to + 1).join("\n").split("/tmp/secure-builder-bot").join(clone);
  try {
    execFileSync("bash", ["-eo", "pipefail", "-c", steps], { env: { ...process.env, ...env }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return { status: 0, stderr: "", clone };
  } catch (e: unknown) {
    const err = e as { status?: number; stderr?: string };
    return { status: err.status ?? 1, stderr: err.stderr ?? "", clone };
  }
}

function clonedJobs(): string[] {
  const jobs = asRecord(loadYamlDocuments(TEMPLATE)[1], "jobs document");
  return Object.entries(jobs).filter(([, j]) => (asRecord(j, "job")["script"] as string[]).some((l) => l.includes("git -C /tmp/secure-builder-bot fetch"))).map(([n]) => n);
}

describe("the CI/CD component", () => {
  it("declares the four inputs with the documented defaults", () => {
    const inputs = asRecord(component().spec["inputs"], "spec.inputs");
    const defaults = Object.fromEntries(Object.entries(inputs).map(([k, v]) => [k, asRecord(v, k)["default"]]));
    expect(defaults).toEqual({
      version: "latest",
      base: "$CI_MERGE_REQUEST_DIFF_BASE_SHA",
      python_version: "3.12",
      token_variable: "SECURE_BUILDER_TOKEN",
    });
    for (const [name, input] of Object.entries(inputs)) {
      expect(typeof asRecord(input, name)["description"], `${name} has a description`).toBe("string");
    }
  });

  it("has exactly three jobs: the gates, the verdict, then the publisher", () => {
    expect([...component().jobs.keys()]).toEqual([GATES, VERDICT, PUBLISH]);
  });

  it("runs every job on merge request pipelines only, the verdict and the publisher whatever the gates' result", () => {
    const { gates, publish, jobs } = component();
    const verdict = asRecord(jobs.get(VERDICT), "verdict job");
    expect(gates["rules"]).toEqual([{ if: '$CI_PIPELINE_SOURCE == "merge_request_event"' }]);
    for (const job of [verdict, publish]) expect(job["rules"]).toEqual([{ if: '$CI_PIPELINE_SOURCE == "merge_request_event"', when: "always" }]);
    expect(verdict["needs"]).toEqual([{ job: GATES, artifacts: true }]);
    expect(publish["needs"]).toEqual([{ job: VERDICT, artifacts: true }]);
  });

  const FETCH_TARGET = 'git fetch -q origin "+refs/heads/${CI_MERGE_REQUEST_TARGET_BRANCH_NAME}:refs/remotes/origin/${CI_MERGE_REQUEST_TARGET_BRANCH_NAME}"';
  const CORE = '"/tmp/secure-builder-bot/core/run" run --base "$SECURE_BUILDER_BASE" --config-ref "refs/remotes/origin/${CI_MERGE_REQUEST_TARGET_BRANCH_NAME}" --head "$CI_COMMIT_SHA"';

  it("runs Scan and QA in the gates job as core's untrusted part, whose exit code is core's", () => {
    const lines = script(component().gates);
    expect(lines.at(-2)).toBe(`rc=0; ${CORE} --part untrusted > /tmp/secure-builder-core.out 2>&1 || rc=$?; cat /tmp/secure-builder-core.out`);
    expect(lines.at(-3), "the target branch's tip is fetched, so the rules are read from it").toBe(FETCH_TARGET);
    expect(lines.join("\n"), "the gates job never runs the publisher").not.toContain("src/main.ts");
  });

  it("hands on the one run core reported, at a fixed path, never a folder the merge request's code wrote", () => {
    const lines = script(component().gates);
    const ws = mkdtempSync(path.join(tmpdir(), "sb-gl-gates-"));
    const fake = path.join(ws, "fake-core");
    // A fake core: its real run, a newer folder standing in for one the tests wrote, and a reason line
    // that forges a Receipt line before core's own last one.
    writeFileSync(fake, [
      "#!/usr/bin/env bash",
      "mkdir -p gate-records/runs/20261023T120000Z-7474ee1 gate-records/runs/20261023T235959Z-7474ee1",
      "echo real > gate-records/runs/20261023T120000Z-7474ee1/receipt.json",
      "echo forged > gate-records/runs/20261023T235959Z-7474ee1/receipt.json",
      'echo "QA: FAIL — Receipt: gate-records/runs/20261023T235959Z-7474ee1/receipt.md"',
      'echo "Receipt: gate-records/runs/20261023T120000Z-7474ee1/receipt.md"',
      "exit 1",
    ].join("\n") + "\n", { mode: 0o755 });
    mkdirSync(path.join(ws, "secure-builder-untrusted"));
    writeFileSync(path.join(ws, "secure-builder-untrusted", "receipt.json"), "committed by the branch");
    const body = lines.slice(-2).join("\n").split('"/tmp/secure-builder-bot/core/run"').join(JSON.stringify(fake));
    const r = spawnSync("bash", ["-c", body], { cwd: ws, encoding: "utf8" });
    expect(r.status, "core's exit code is the job's").toBe(1);
    expect(readFileSync(path.join(ws, "secure-builder-untrusted", "receipt.json"), "utf8")).toBe("real\n");
    expect(r.stdout).toContain("QA: FAIL");
  });

  it("decides the verdict in its own job: core's trusted part, on the gates job's handed-on run, running no merge request code", () => {
    const verdict = asRecord(component().jobs.get(VERDICT), "verdict job");
    const lines = script(verdict);
    expect(lines.at(-1)).toBe(`${CORE} --part trusted --untrusted-run "$CI_PROJECT_DIR/secure-builder-untrusted"`);
    expect(lines.at(-2)).toBe(FETCH_TARGET);
    expect(lines.join("\n")).not.toContain("src/main.ts");
    // Its only installs come from the bot's own clone; nothing the merge request carries is installed or run.
    for (const line of lines.filter((l) => /\b(pip|npm|npx|make|python3?)\b/.test(l))) expect(line).toMatch(/\/tmp\/secure-builder-bot\//);
    expect(asRecord(verdict["variables"], "variables")["GIT_DEPTH"]).toBe("0");
  });

  it("refuses a fork's pipeline, where origin is the fork and its branch would pass for the target's rules", () => {
    const lines = script(component().gates);
    const i = lines.findIndex((l) => l.includes("git fetch -q origin"));
    expect(lines[i - 1]).toBe('if [ "$CI_PROJECT_ID" != "$CI_MERGE_REQUEST_PROJECT_ID" ]; then echo "secure-builder: this pipeline runs in a fork; the gates read their rules from the target project, so run the pipeline in the parent project" >&2; exit 1; fi');
  });

  it("runs the publisher in the publish job, which runs no merge request code (gate run 1, B-03)", () => {
    const lines = script(component().publish);
    const joined = lines.join("\n");
    expect(lines.at(-1)).toBe('cd /tmp/secure-builder-bot/adapter-gitlab && npx tsx src/main.ts --project-dir "$CI_PROJECT_DIR" --report "$CI_PROJECT_DIR/gl-code-quality-report.json"');
    expect(joined, "the publish job never runs the gates").not.toContain("core/run");
    expect(joined).not.toMatch(/pip install/);
    // The merge request's checkout is only ever read: every command runs from /tmp or the bot's clone.
    for (const line of lines) {
      for (const cd of line.matchAll(/\bcd\s+("?)([^"\s&;]+)\1/g)) expect(cd[2], line).toMatch(/^\/tmp(\/|$)/);
      expect(line, "an npm command in the publish job runs in the bot's clone").not.toMatch(/\bnpm\b(?!.*--prefix \/tmp\/secure-builder-bot\/)/);
    }
  });

  it("publishes one pipeline at a time per merge request, so two runs never post two verdict notes (gate run 1, N-02)", () => {
    const { gates, publish } = component();
    expect(publish["resource_group"]).toBe("secure-builder/mr-$CI_MERGE_REQUEST_IID");
    expect(gates["resource_group"], "the gates of two pipelines may run at once").toBeUndefined();
  });

  it("has script lines bash can parse", () => {
    for (const job of component().jobs.values()) {
      expect(() => execFileSync("bash", ["-n"], { input: script(job).join("\n"), encoding: "utf8" })).not.toThrow();
    }
  });

  it("clones the bot at the pinned version in both jobs", () => {
    const { gates, publish, text } = component();
    for (const job of [gates, publish]) {
      expect(asRecord(job["variables"], "variables")["SECURE_BUILDER_VERSION"]).toBe("$[[ inputs.version ]]");
    }
    expect(asRecord(gates["variables"], "variables")["SECURE_BUILDER_BASE"]).toBe("$[[ inputs.base ]]");
    expect(text).toContain('fetch -q --depth 1 "$src" "+refs/tags/${ref}:refs/tags/${ref}"');
    expect(text).not.toMatch(/git clone[^\n]*--branch/);
    expect(text).not.toMatch(/--branch\s+main\b/);
  });

  it("refuses to reuse a bot directory that already exists, so no planted hook or config runs (gate run 3, N-01)", () => {
    // On a shell executor /tmp outlives the job: a .git left by the gates job, which ran the merge
    // request's code, would be reused by the publish job, which holds the token.
    const remote = botRemote({ tags: true });
    for (const job of clonedJobs()) {
      const r = runClone(job, { SECURE_BUILDER_SOURCE: remote, SECURE_BUILDER_VERSION: "latest" }, true);
      expect(r.status, `${job} refuses an existing directory`).not.toBe(0);
      expect(r.stderr).toMatch(/already exists/);
    }
  });

  it("the publish job removes any code quality report before anything else can fail (gate run 3, N-02)", () => {
    const jobs = asRecord(loadYamlDocuments(TEMPLATE)[1], "jobs document");
    const script = asRecord(jobs["secure-builder-publish"], "publish job")["script"] as string[];
    // Run the first line itself: a report the branch committed, as a file or as a directory with
    // something in it (gate run 4, N-02: `rm -f` stopped the job on a directory, and the artifact
    // is uploaded when: always), is gone and the line succeeds.
    for (const plant of ["file", "directory"] as const) {
      const dir = mkdtempSync(path.join(tmpdir(), "sb-publish-"));
      const report = path.join(dir, "gl-code-quality-report.json");
      if (plant === "file") writeFileSync(report, "[]");
      else {
        mkdirSync(report);
        writeFileSync(path.join(report, "forged.json"), "[]");
      }
      execFileSync("bash", ["-ec", script[0]!], { env: { ...process.env, CI_PROJECT_DIR: dir } });
      expect(existsSync(report), `a committed report ${plant} survives`).toBe(false);
    }
  });

  it("resolves latest to the newest release tag, never a branch (gate run 1, B-02)", () => {
    const remote = "file://" + botRemote({ tags: true });
    const jobs = clonedJobs();
    expect(jobs.length).toBeGreaterThan(0);
    for (const job of jobs) {
      const latest = runClone(job, { SECURE_BUILDER_SOURCE: remote, SECURE_BUILDER_VERSION: "latest" });
      expect(latest.status, `${job}: ${latest.stderr}`).toBe(0);
      expect(() => sh(latest.clone, "symbolic-ref", "-q", "HEAD"), `${job} checked out a branch`).toThrow();
      expect(sh(latest.clone, "describe", "--exact-match", "--tags", "HEAD")).toBe("v0.10.0");
      const pinned = runClone(job, { SECURE_BUILDER_SOURCE: remote, SECURE_BUILDER_VERSION: "0.9.0" });
      expect(pinned.status, `${job}: ${pinned.stderr}`).toBe(0);
      expect(() => sh(pinned.clone, "symbolic-ref", "-q", "HEAD"), `${job} checked out a branch`).toThrow();
      expect(sh(pinned.clone, "describe", "--exact-match", "--tags", "HEAD")).toBe("v0.9.0");
    }
  });

  it("fails closed when the bot's source has no release tag (gate run 1, B-02)", () => {
    const remote = "file://" + botRemote({ tags: false });
    for (const job of clonedJobs()) {
      const r = runClone(job, { SECURE_BUILDER_SOURCE: remote, SECURE_BUILDER_VERSION: "latest" });
      expect(r.status, `${job} ran without a release`).not.toBe(0);
      expect(r.stderr).toMatch(/no release tag/);
      expect(existsSync(r.clone), `${job} cloned something`).toBe(false);
    }
    const tagged = "file://" + botRemote({ tags: true });
    for (const job of clonedJobs()) {
      for (const version of ["main", "9.9.9", "v9.9.9", "1.0.0-rc1"]) {
        const r = runClone(job, { SECURE_BUILDER_SOURCE: tagged, SECURE_BUILDER_VERSION: version });
        expect(r.status, `${job} ran version ${version}`).not.toBe(0);
        expect(r.stderr).toMatch(/no release tag/);
        expect(existsSync(r.clone), `${job} cloned ${version}`).toBe(false);
      }
    }
  });

  it("uploads the handed-on run from the gates job, the verdict job's run, and the code quality report from the publisher", () => {
    const { gates, publish, jobs } = component();
    expect(asRecord(gates["artifacts"], "gates artifacts")).toEqual({ when: "always", paths: ["secure-builder-untrusted/"] });
    expect(asRecord(asRecord(jobs.get(VERDICT), "verdict")["artifacts"], "verdict artifacts")).toEqual({ when: "always", paths: ["gate-records/runs/"] });
    const publishArtifacts = asRecord(publish["artifacts"], "publish artifacts");
    expect(publishArtifacts["when"]).toBe("always");
    expect(publishArtifacts["paths"]).toEqual(["gl-code-quality-report.json"]);
    expect(asRecord(publishArtifacts["reports"], "reports")["codequality"]).toBe("gl-code-quality-report.json");
  });

  it("gives the token, and the name of its variable, to the publish job alone (gate run 1, B-03)", () => {
    const { jobs, gates, publish, text } = component();
    // A project CI/CD variable reaches every job unless it is scoped to an environment, so the
    // publisher declares one and the gates job, which runs the merge request's tests, declares none.
    const environment = asRecord(publish["environment"], "publish environment");
    expect(environment["name"]).toBe("secure-builder");
    expect(environment["action"], "the publisher is not a deployment").toBe("prepare");
    expect(gates["environment"]).toBeUndefined();
    for (const [name, job] of jobs) {
      const body = JSON.stringify(job);
      const named = /SECURE_BUILDER_TOKEN|inputs\.token_variable|PRIVATE-TOKEN/.test(body);
      expect(named, `${name} names the token`).toBe(name === PUBLISH);
      // The publisher's environment scopes the token; the verdict job's scopes Sentinel's model key.
      expect(job["environment"] !== undefined, `${name} declares an environment`).toBe(name !== GATES);
    }
    expect(asRecord(publish["variables"], "variables")["SECURE_BUILDER_TOKEN_VARIABLE"]).toBe("$[[ inputs.token_variable ]]");
    // The one interpolation of the input is that variable's value; nothing else names it.
    expect(text.match(/\$\[\[ inputs\.token_variable \]\]/g)).toHaveLength(1);
    // The default name is never expanded as a shell variable, written to a file, or echoed.
    expect(text).not.toMatch(/\$\{?SECURE_BUILDER_TOKEN\b/);
    for (const line of script(publish)) {
      expect(line, "no script line writes a token anywhere").not.toMatch(/TOKEN.*(>|tee|echo|printf)/i);
    }
  });

  it("tells the user to scope the token to the publish job's environment and not to protect it (gate run 1, B-03, N-05)", () => {
    const readme = readFileSync(path.resolve(import.meta.dirname, "..", "templates", "README.md"), "utf8");
    const environment = String(asRecord(component().publish["environment"], "publish environment")["name"]);
    expect(readme).toContain(`| Environments | \`${environment}\` |`);
    expect(readme).toMatch(/\| Protect variable \| \*\*Off\*\* \|/);
    expect(readme, "a protected variable never reaches a merge request pipeline on an unprotected branch").not.toMatch(/masked and protected/i);
  });

  it("passes a model key to no job, so none ever shares a job with the merge request's tests (gate run 1, B-03)", () => {
    const { spec, jobs } = component();
    const inputs = Object.keys(asRecord(spec["inputs"], "spec.inputs"));
    expect(inputs.filter((i) => /key|secret/i.test(i))).toEqual([]);
    for (const [name, job] of jobs) {
      expect(JSON.stringify(job), `${name} names a model key`).not.toMatch(/MODEL_KEY|key_secret|ANTHROPIC|OPENAI|API_KEY/i);
    }
  });

  it("uses the python image the input names and pins the Node tarball by checksum", () => {
    const { gates, publish, text } = component();
    expect(gates["image"]).toBe("python:$[[ inputs.python_version ]]");
    expect(publish["image"]).toBe("python:$[[ inputs.python_version ]]");
    expect(script(gates).join("\n"), "the gates job needs no Node").not.toContain("nodejs.org");
    expect(text).toContain("SHASUMS256.txt");
    expect(text).toMatch(/sha256sum -c/);
  });
});
