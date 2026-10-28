#!/usr/bin/env node
// floor-guard.mjs — diff-scoped enforcement of the CONSTRAINTS.md floor.
// Adapted from the constraint-driven-development skill's reference (MIT, Addy Osmani); the diff
// plumbing, the CONSTRAINTS.md checks and the exit codes are the reference's, the patterns are
// this repository's (shell and Python).
// Usage: node scripts/floor-guard.mjs [--base <ref>]   (default base: origin/main)
// Exit: 0 clean · 1 a floor violation · 2 the guard could not run (never read as clean)
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';

// Base: --base, else the first of origin/main and main that exists (a fresh clone of an empty
// repo has no remote-tracking ref yet). On main itself the merge base is HEAD and the diff is
// the uncommitted work, which is still the right thing to guard.
const base = (() => {
  const i = process.argv.indexOf('--base');
  if (i > -1) return process.argv[i + 1];
  for (const b of ['origin/main', 'main']) {
    try { execFileSync('git', ['rev-parse', '--verify', '-q', b], { stdio: 'ignore' }); return b; } catch { /* next */ }
  }
  return 'origin/main';
})();

const git = (args, { diffExit = false } = {}) => {
  // An epic's diff passes Node's 1 MB default buffer once a few modules land (a 1.2 MB range made
  // every check-fast exit 2, "could not diff"); the guard has to read the whole diff it judges.
  try { return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 256 * 1024 * 1024 }); }
  catch (e) { return diffExit && e.status === 1 && typeof e.stdout === 'string' ? e.stdout : null; }
};
const bail = (msg) => { console.error('floor-guard: ' + msg); process.exit(2); };

const top = git(['rev-parse', '--show-toplevel'])?.trim();
if (!top) bail('not inside a git work tree');
process.chdir(top);

const mergeBase = git(['merge-base', base, 'HEAD'])?.trim();
if (!mergeBase) bail('no merge base against ' + base);

const tracked = git(['diff', '--unified=0', mergeBase, '--']);
if (tracked === null) bail('could not diff against ' + mergeBase);
const untrackedFiles = git(['ls-files', '--others', '--exclude-standard']);
if (untrackedFiles === null) bail('could not list untracked files');
const untracked = untrackedFiles.split('\n').filter(Boolean).map((f) => {
  const d = git(['diff', '--no-index', '--unified=0', '/dev/null', f], { diffExit: true });
  if (d === null) bail('could not diff untracked file ' + f);
  return d;
}).join('\n');
const diff = tracked + '\n' + untracked;

// .constraintsignore: one glob-ish prefix per line; a line in a matching file is never flagged.
const ignore = existsSync('.constraintsignore')
  ? readFileSync('.constraintsignore', 'utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))
  : [];
const ignored = (f) => ignore.some((p) => f.startsWith(p.replace(/\*+$/, '')));

const added = [], removed = [], deleted = [];
const pathOf = (s) => s.replace(/^[ab]\//, '');
let file = '', oldFile = '', inHeader = false;
for (const line of diff.split('\n')) {
  if (line.startsWith('diff ')) inHeader = true;
  else if (line.startsWith('@@')) inHeader = false;
  else if (inHeader) {
    if (line.startsWith('--- ')) oldFile = pathOf(line.slice(4));
    else if (line.startsWith('+++ ')) {
      const newFile = pathOf(line.slice(4));
      file = newFile === '/dev/null' ? oldFile : newFile;
      if (newFile === '/dev/null') deleted.push(file);
    }
  }
  else if (line.startsWith('+')) added.push({ file, text: line.slice(1) });
  else if (line.startsWith('-')) removed.push({ file, text: line.slice(1) });
}

const findings = [];
const flag = (rule, f, text) => { if (!ignored(f)) findings.push({ rule, file: f, text: text.trim().slice(0, 120) }); };
const isTest = (f) => /(^|\/)tests?\/|-test\.sh$|selftest[^/]*\.sh$|test-runner\.sh$|\.(test|spec)\.|_test\.|(^|\/)test_/.test(f);
const isConstraints = (f) => /CONSTRAINTS\.md$/.test(f);

// 1. Silenced checker. shellcheck, ruff/flake8, mypy, semgrep, gitleaks, and this repo's own two.
const SUPPRESSIONS = /shellcheck +disable|# *noqa|# *type: *ignore|# *ruff: *noqa|nosemgrep|gitleaks:allow|secrets-scan: *allow|citations: *allow|@ts-ignore|@ts-nocheck|eslint-disable/;
// 4. Unfinished work.
const STUBS = /throw new (Error|NotImplemented).*[Nn]ot implemented|catch\s*\(\w*\)\s*\{\s*\}|catch\s*\{\s*\}|\bTODO\b|\bFIXME\b|\bpass\s*# *stub|raise NotImplementedError|: *# *not implemented/;
// 2. A test made easier (added skips). The bash suites skip with _skip; pytest with mark.skip.
// `.skip(` and `.todo(` as calls — it.skip(...), describe.skip(...) — not every property named skip:
// a config key like scan.skip is not a skipped test. `.skip.each(` and the tagged-template
// form `it.skip.each`...`` are calls too (gate finding N-10). xfail, and `.only` / fit( / fdescribe(
// that silence every sibling test, lower the bar the same way (run #2, N-07).
const SKIPS = /\b_skip\b|@pytest\.mark\.(skip|xfail)|\bpytest\.(skip|xfail)\(|\.(skip|todo|only)(\.each)?\s*[(`]|\b[xf]it\(|\b[xf]describe\(|t\.Skip\(/;

const isDoc = (f) => /\.md$/.test(f);
for (const { file, text } of added) {
  if (isDoc(file)) { if (isConstraints(file) && /^\| *(W|E)\d+ *\|/.test(text)) flag('new-exception', file, text); continue; }
  if (SUPPRESSIONS.test(text)) flag('silenced-checker', file, text);
  if (STUBS.test(text)) flag('unfinished-work', file, text);
  if (SKIPS.test(text) && !/^\s*#/.test(text)) flag('test-made-easier', file, text);
}

// CONSTRAINTS.md allows a deleted test or a removed assertion WITH A REASON IN THE COMMIT MESSAGE.
// The diff cannot carry that reason, so the commit does: a line `Test-removed: <path> — <reason>`
// in a commit on this branch that touches <path>. No reason after the path, no excuse. Working-tree
// changes have no commit message yet, so they are never excused.
const excused = (() => {
  const log = git(['log', '--format=%x00%B', `${mergeBase}..HEAD`]) ?? '';
  const ok = new Set();
  for (const m of log.matchAll(/^Test-removed:\s*(\S+)\s+[—-]+\s*\S.*$/gm)) ok.add(m[1]);
  return (f) => ok.has(f) && (git(['log', '--format=%H', `${mergeBase}..HEAD`, '--', f]) ?? '').trim() !== '';
})();
for (const f of deleted) if (isTest(f) && !excused(f)) flag('test-deleted', f, 'file deleted (no Test-removed: line naming it)');
for (const { file, text } of removed) {
  if (isTest(file) && !deleted.includes(file) && !excused(file) && /\b(expect|assert|assert_has|assert_not|assert_eq|_pass|_fail|should)\b/.test(text)) {
    flag('assertion-removed', file, text);
  }
}

const ruleKey = (t) => {
  const s = t.trim();
  if (s.startsWith('|')) return s.split('|').map((c) => c.trim()).filter(Boolean)[0] ?? '';
  if (/^[-*] /.test(s)) return s.slice(2).split(':')[0].trim();
  return null;
};
const isException = (t) => /^\| *(W|E)\d+ *\|/.test(t.trim());
const MIN_BEFORE = /(>=|>|≥|at least|minimum|\bmin\b|no less than|not fall|not drop)\s*$/;
const MAX_BEFORE = /(<=|<|≤|at most|maximum|\bmax\b|no more than|under|below|not grow|not exceed)\s*$/;
const MIN_AFTER = /^\s*\S*\s*(or more|or higher|must not fall|must not drop)/;
const MAX_AFTER = /^\s*\S*\s*(or less|or lower|must not grow|must not exceed)/;
const thresholds = (t) => {
  const out = [], re = /\d+(?:\.\d+)?/g;
  let m;
  while ((m = re.exec(t))) {
    const before = t.slice(Math.max(0, m.index - 24), m.index).toLowerCase();
    const after = t.slice(m.index + m[0].length, m.index + m[0].length + 40).toLowerCase();
    const dir = MIN_BEFORE.test(before) || MIN_AFTER.test(after) ? 'min'
      : MAX_BEFORE.test(before) || MAX_AFTER.test(after) ? 'max' : null;
    out.push({ n: Number(m[0]), dir });
  }
  return out;
};
const removedRules = removed.filter((l) => isConstraints(l.file) && ruleKey(l.text) !== null);
const addedRules = added.filter((l) => isConstraints(l.file) && ruleKey(l.text) !== null);
for (const r of removedRules) {
  const a = addedRules.find((x) => ruleKey(x.text) === ruleKey(r.text));
  if (!a) {
    if (!isException(r.text)) flag('rule-removed', r.file, r.text);
    continue;
  }
  const before = thresholds(r.text), after = thresholds(a.text);
  let verdict = null;
  for (const dir of ['min', 'max', null]) {
    const was = before.filter((x) => x.dir === dir), now = after.filter((x) => x.dir === dir);
    was.forEach((b, i) => {
      const n = now[i];
      if (verdict) return;
      if (!n) verdict = 'threshold-removed';
      else if (n.n === b.n) return;
      else if (dir === 'min' ? n.n < b.n : dir === 'max' ? n.n > b.n : true) {
        verdict = dir ? 'threshold-loosened' : 'threshold-changed';
      }
    });
  }
  if (verdict) flag(verdict, r.file, r.text + '  ->  ' + a.text);
}

if (findings.length === 0) { console.log('floor-guard: clean'); process.exit(0); }
console.error('floor-guard: ' + findings.length + ' floor violation(s):');
for (const f of findings) console.error(`  [${f.rule}] ${f.file}: ${f.text}`);
if (findings.some((f) => f.rule === 'rule-removed')) {
  console.error('\nA rule-removed finding can also mean the rule\'s label changed: rename a rule in one commit and change its thresholds in another.');
}
if (findings.some((f) => f.rule === 'threshold-removed')) {
  console.error('\nA threshold-removed finding can also mean a number gained or lost its direction words: compare the two lines before assuming a threshold was deleted.');
}
console.error('\nEach is a move that lowers the bar. Fix the code, or route it through a tracked exception in CONSTRAINTS.md.');
process.exit(1);
