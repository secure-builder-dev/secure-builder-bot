// The lines a pull request changes, read from the patches GitHub serves for its files. A review
// comment can only sit on a line the diff shows (GitHub refuses any other), so a finding is placed
// on the diff only when its path and line are here; the rest are listed in the check summary.

/** path → the right-hand-side line numbers the diff shows (added and context lines). */
export type DiffLines = Map<string, Set<number>>;

export interface PullFile {
  filename: string;
  patch?: string | undefined;
}

/** The right-hand-side lines of one unified patch. Removed lines have no right-hand number. */
export function parsePatch(patch: string): Set<number> {
  const lines = new Set<number>();
  let right = 0;
  // A patch that ends in a newline splits into a last empty string that is no line at all; an empty
  // line anywhere else is a blank context line whose leading space was trimmed, and counts.
  const rows = patch.split('\n');
  if (rows.at(-1) === '') rows.pop();
  for (const raw of rows) {
    if (raw.startsWith('@@ ')) {
      // "@@ -<old>[,n] +<new>[,n] @@": the right-hand start is the third token, after its "+".
      const plus = raw.split(' ')[2] ?? '';
      right = Number(plus.replace(/^\+/, '').split(',')[0]);
      continue;
    }
    if (raw.startsWith('-') || raw.startsWith('\\')) continue;
    if (raw.startsWith('+') || raw.startsWith(' ') || raw === '') {
      lines.add(right);
      right += 1;
    }
  }
  return lines;
}

export function diffLines(files: readonly PullFile[]): DiffLines {
  const out: DiffLines = new Map();
  for (const f of files) {
    if (typeof f.patch === 'string' && f.patch.length > 0) out.set(f.filename, parsePatch(f.patch));
  }
  return out;
}

export function inDiff(diff: DiffLines, path: string, line: number): boolean {
  return diff.get(path)?.has(line) ?? false;
}
