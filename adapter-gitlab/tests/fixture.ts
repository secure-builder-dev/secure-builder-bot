// The run directory core itself produced (scan pass, qa fail), shared by every test file. It is
// tracked in this repository, so a test that publishes it copies it somewhere untracked first.
import { cpSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

export const FIXTURE = path.resolve(import.meta.dirname, "fixtures", "run-dir");

/** A copy of the fixture run outside any git work tree, as core writes it in a CI job. */
export function untrackedRun(): string {
  const dir = path.join(mkdtempSync(path.join(tmpdir(), "sb-run-")), "20261023T061246Z-10d3390");
  cpSync(FIXTURE, dir, { recursive: true });
  return dir;
}
