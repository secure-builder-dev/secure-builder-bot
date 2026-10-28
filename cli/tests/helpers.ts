// What every test hands the command: an environment, a working directory, and two sinks that keep
// every line printed, so a test can assert on all of the output. No test reaches the network or
// the user's terminal; the fetch and the input stream are injected where a test needs them.
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import type { Io } from "../src/main.ts";

export interface Captured extends Io {
  lines: string[];
  text(): string;
}

export function capture(over: Partial<Io> = {}): Captured {
  const lines: string[] = [];
  return {
    env: {},
    cwd: process.cwd(),
    interactive: false,
    out: (l) => lines.push(l),
    err: (l) => lines.push(l),
    ...over,
    lines,
    text: () => lines.join("\n"),
  };
}

/** Answers typed at the terminal, one per line. */
export function typed(...answers: string[]): Readable {
  return Readable.from([answers.map((a) => a + "\n").join("")]);
}

export function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
}

/** A fresh repository with one commit on main and, when given, an origin remote URL. */
export function tempRepo(remote?: string, files: Record<string, string> = { "README.md": "hello\n" }): string {
  const dir = mkdtempSync(path.join(tmpdir(), "sb-cli-"));
  git(dir, "init", "-q", "-b", "main");
  git(dir, "config", "user.email", "dev@example.invalid");
  git(dir, "config", "user.name", "Dev");
  git(dir, "config", "commit.gpgsign", "false");
  for (const [name, content] of Object.entries(files)) writeFileSync(path.join(dir, name), content);
  git(dir, "add", "-A");
  git(dir, "commit", "-q", "-m", "init");
  if (remote !== undefined) git(dir, "remote", "add", "origin", remote);
  return dir;
}
