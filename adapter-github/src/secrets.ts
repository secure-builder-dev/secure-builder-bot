// Secret shapes: a port of core's SECRET pattern (core/securebuilderbot_core/receipt.py), applied
// to everything this adapter is about to post. Core redacts gate output before it is written, so
// a run directory should already be clean; the publisher checks again because a check summary or a
// review comment is the one output a repository's whole team reads (PRD § Security of the bot
// itself: a secrets scan runs on the bot's own output before it is published). Nothing is posted
// when any piece matches, and the refusal names the piece, never the string. One shape is wider
// than core's: every GitHub token prefix (ghp_ personal, gho_ OAuth, ghu_ user-to-server, ghs_
// server-to-server, which is the Actions token this adapter itself holds, ghr_ refresh), not ghp_ only.

const SECRET =
  /AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}|(password|passwd|secret|api[_-]?key|client[_-]?secret|token)\s*[:=]\s*["'][A-Za-z0-9+/=_@#$%^&*!.-]{12,}["']/i;

/** True when the text carries a string shaped like a credential. */
export function hasSecretShape(text: string): boolean {
  return SECRET.test(text);
}

/**
 * The label of the first piece that carries a secret-shaped string, or null when every piece is
 * clean. Labels are what the refusal prints; the matched text never is.
 */
export function findSecretShaped(pieces: ReadonlyArray<readonly [label: string, text: string]>): string | null {
  for (const [label, text] of pieces) {
    if (hasSecretShape(text)) {
      return label;
    }
  }
  return null;
}
