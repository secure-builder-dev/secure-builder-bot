// git, run as a child process in the user's repository. A failure is a GitError naming the command
// and git's own message, which the command prints and exits 2 on: git could not do it, nothing was
// refused.
import { spawnSync } from "node:child_process";

export class GitError extends Error {}

export function git(cwd: string, ...args: string[]): string {
  const out = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (out.status !== 0) {
    const why = (out.stderr || out.stdout || out.error?.message || "failed").trim().split("\n").slice(-3).join(" / ");
    throw new GitError(`git ${args.join(" ")}: ${why}`);
  }
  return out.stdout.trim();
}

/** True when git exits 0: a question, not a command that must succeed. */
export function gitOk(cwd: string, ...args: string[]): boolean {
  return spawnSync("git", args, { cwd, encoding: "utf8" }).status === 0;
}

/** The repository's top level, or null outside a repository. */
export function repoRoot(cwd: string): string | null {
  const out = spawnSync("git", ["rev-parse", "--show-toplevel"], { cwd, encoding: "utf8" });
  return out.status === 0 ? out.stdout.trim() : null;
}

/** git's output exactly as written, or null when git fails: for file contents, where trimming would change them. */
export function gitRaw(cwd: string, ...args: string[]): string | null {
  const out = spawnSync("git", args, { cwd, encoding: "utf8" });
  return out.status === 0 ? out.stdout : null;
}
