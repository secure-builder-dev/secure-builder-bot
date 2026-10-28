// The setup pull request (PRD § The install experience): one branch, `secure-builder/enable`,
// carrying the two files, and one pull request titled "Enable Secure Builder" whose body explains
// the three answers and that nothing runs until it is merged. Built with the Git Data API (blob,
// tree, commit, ref) on top of the default branch's head. A setup branch that already exists may
// carry commits a person pushed to it (the PRD has users edit their answers on this pull request),
// so it is refused unless the caller says to replace it (`replaceBranch`): nothing is written then.
// Told to replace it, the branch is reset to one fresh commit on the current default head and the
// open pull request's body is rewritten; a pull request is never duplicated.
import type { GitHubClient, PullRequest } from './github-api.ts';
import { SETUP_BRANCH, setupFiles, setupPrBody, validateAnswers, type SetupAnswers } from './templates.ts';

export const SETUP_PR_TITLE = 'Enable Secure Builder';

export interface SetupResult {
  branch: string;
  commit: string;
  pull: PullRequest;
  /** false when the branch and pull request already existed and were updated */
  created: boolean;
  files: string[];
}

/** The setup branch exists and the caller did not say to replace it; nothing was written. */
export class SetupBranchExists extends Error {}

export interface SetupOptions {
  /** Reset an existing setup branch to a fresh commit, discarding what is on it. Default false: refuse. */
  replaceBranch?: boolean;
  /** Files added beside the two templates (init's drafted control list), each only where the default branch has none. */
  extraFiles?: { path: string; content: string }[];
}

export async function openSetupPr(client: GitHubClient, repo: string, answers: SetupAnswers, opts: SetupOptions = {}): Promise<SetupResult> {
  if (repo !== `${client.owner}/${client.name}`) throw new Error(`the client is for ${client.owner}/${client.name}, not ${repo}`);
  validateAnswers(answers);
  const files = setupFiles(answers);

  const { default_branch: base } = await client.getRepo();
  const baseRef = await client.getRef(`heads/${base}`);
  if (!baseRef) throw new Error(`the default branch ${base} has no ref`);
  const baseSha = baseRef.object.sha;
  const baseTree = (await client.getCommit(baseSha)).tree.sha;
  for (const f of opts.extraFiles ?? []) {
    if (!(await client.fileExists(f.path, base))) files.push(f);  // a file the team already keeps is never replaced
  }
  const branchRef = await client.getRef(`heads/${SETUP_BRANCH}`);
  if (branchRef && opts.replaceBranch !== true) {
    throw new SetupBranchExists(`the branch ${SETUP_BRANCH} already exists on ${repo}; it is not moved unless the caller asks to replace it`);
  }

  const entries = [];
  for (const f of files) {
    const blob = await client.createBlob(f.content);
    entries.push({ path: f.path, mode: '100644' as const, type: 'blob' as const, sha: blob.sha });
  }
  const tree = await client.createTree(baseTree, entries);
  const commit = await client.createCommit(`${SETUP_PR_TITLE}\n\n${files.map((f) => f.path).join(', ')} from the three setup answers.`, tree.sha, [baseSha]);

  if (branchRef) await client.updateRef(`heads/${SETUP_BRANCH}`, commit.sha);
  else await client.createRef(`refs/heads/${SETUP_BRANCH}`, commit.sha);

  const body = setupPrBody(answers);
  const open = await client.listPulls({ head: `${client.owner}:${SETUP_BRANCH}`, state: 'open' });
  const existing = open[0];
  const pull = existing
    ? await client.updatePull(existing.number, { title: SETUP_PR_TITLE, body })
    : await client.createPull({ title: SETUP_PR_TITLE, head: SETUP_BRANCH, base, body });
  return { branch: SETUP_BRANCH, commit: commit.sha, pull, created: !existing, files: files.map((f) => f.path) };
}
