import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { isTrackedByGit, RunDirError } from '../src/run-dir.ts';

// CM-64 refuses a run directory the pull request committed. When git cannot answer, the docstring
// says the directory is refused; it used to read as untracked, so a committed run passed the check
// (adapter-github gate run 2, N-02).
describe('isTrackedByGit', () => {
  const path = process.env.PATH;
  afterEach(() => { process.env.PATH = path; });

  function repoWithRun(commit: boolean): string {
    const repo = mkdtempSync(join(tmpdir(), 'sb-tracked-'));
    const git = (...a: string[]) => execFileSync('git', ['-C', repo, ...a], { stdio: 'ignore' });
    git('init', '-q');
    const dir = join(repo, 'gate-records', 'runs', 'r1');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'receipt.json'), '{}');
    if (commit) {
      git('add', '-A');
      git('-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-q', '-m', 'forged run');
    }
    return dir;
  }

  it('says a committed run is tracked and an uncommitted one is not', () => {
    expect(isTrackedByGit(repoWithRun(true))).toBe(true);
    expect(isTrackedByGit(repoWithRun(false))).toBe(false);
  });

  it('says a directory outside any repository holds nothing a commit put there', () => {
    expect(isTrackedByGit(mkdtempSync(join(tmpdir(), 'sb-norepo-')))).toBe(false);
  });

  it('refuses, never answers untracked, when git itself cannot run', () => {
    const dir = repoWithRun(true);
    process.env.PATH = mkdtempSync(join(tmpdir(), 'sb-nogit-'));
    expect(() => isTrackedByGit(dir)).toThrow(RunDirError);
  });
});
