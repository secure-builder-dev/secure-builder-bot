import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { COMMANDS, main, processIo, type Values } from "../src/main.ts";
import { capture } from "./helpers.ts";

const BIN = path.resolve(import.meta.dirname, "..", "bin", "securebuilderbot.js");
const VERSION = (JSON.parse(readFileSync(path.resolve(import.meta.dirname, "..", "package.json"), "utf8")) as { version: string }).version;

describe("--help", () => {
  it("lists both commands and the three questions' flags", async () => {
    const io = capture();
    expect(await main(["--help"], io)).toBe(0);
    const text = io.text();
    for (const word of ["init", "run", "--profile", "--gates", "--sentinel", "--yes", "--force", "--platform", "--gitlab-group", "--github-api", "--gitlab-host", "--base", "--head", "--open", "SECUREBUILDERBOT_HOME", "GITHUB_TOKEN", "GITLAB_TOKEN"]) {
      expect(text, word).toContain(word);
    }
    expect(text).toMatch(/0 ok.*1 refused.*2 could not run/s);
  });

  it("is what the command prints with no arguments, exiting 2 because nothing ran", async () => {
    const io = capture();
    expect(await main([], io)).toBe(2);
    expect(io.text()).toContain("securebuilderbot init");
  });
});

describe("--version", () => {
  it("prints the package version", async () => {
    const io = capture();
    expect(await main(["--version"], io)).toBe(0);
    expect(io.text().trim()).toBe(`securebuilderbot ${VERSION}`);
  });
});

describe("arguments it does not know", () => {
  it("an unknown command exits 2 and says which", async () => {
    const io = capture();
    expect(await main(["deploy"], io)).toBe(2);
    expect(io.text()).toContain("deploy");
  });
});

describe("the bin stub", () => {
  it("runs src/main.ts through tsx: --help and --version from a real process", () => {
    const help = spawnSync(process.execPath, [BIN, "--help"], { encoding: "utf8" });
    expect(help.status).toBe(0);
    expect(help.stdout).toContain("securebuilderbot run");
    expect(help.stdout).toContain("--sentinel");
    const version = spawnSync(process.execPath, [BIN, "--version"], { encoding: "utf8" });
    expect(version.stdout.trim()).toBe(`securebuilderbot ${VERSION}`);
    const bad = spawnSync(process.execPath, [BIN, "nope"], { encoding: "utf8" });
    expect(bad.status).toBe(2);
  });
});

describe("a subcommand's options", () => {
  const seen: Values[] = [];
  COMMANDS.set("probe", {
    options: { name: { type: "string" }, loud: { type: "boolean" } },
    run: (values) => {
      seen.push(values);
      return Promise.resolve(0);
    },
  });

  it("are parsed strictly: known ones reach the command, an unknown one exits 2 and is named", async () => {
    expect(await main(["probe", "--name", "x", "--loud"], capture())).toBe(0);
    expect(seen.at(-1)).toMatchObject({ name: "x", loud: true });
    const io = capture();
    expect(await main(["probe", "--colour"], io)).toBe(2);
    expect(io.text()).toContain("--colour");
    expect(await main(["probe", "stray"], capture())).toBe(2);
  });

  it("--help after a command prints the help and runs nothing", async () => {
    const before = seen.length;
    const io = capture();
    expect(await main(["probe", "--help"], io)).toBe(0);
    expect(io.text()).toContain("securebuilderbot init");
    expect(seen.length).toBe(before);
  });
});

describe("the real process's io", () => {
  it("is the process's environment, directory and terminal", () => {
    const io = processIo();
    expect(io.env).toBe(process.env);
    expect(io.cwd).toBe(process.cwd());
    expect(io.input).toBe(process.stdin);
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    io.out("to stdout");
    io.err("to stderr");
    expect(stdout).toHaveBeenCalledWith("to stdout\n");
    expect(stderr).toHaveBeenCalledWith("to stderr\n");
    stdout.mockRestore();
    stderr.mockRestore();
  });
});
