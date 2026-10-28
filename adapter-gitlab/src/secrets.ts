// Nothing the bot posts is ever a secret value (docs/PRD.md § Security of the bot itself). Core
// redacts every gate's text before it is written (core/securebuilderbot_core/receipt.py:SECRET); the
// publisher refuses, as a second refusal, any body that still matches those patterns, plus GitLab's
// own token shapes (every prefixed GitLab token: glpat-, gldt-, glrt-, glcbt-, glptt-, glft-,
// glffct-, gloas-, glimt-, glagent-, glsoat-, and the legacy GR1348941 runner token), before a single request is sent. The refusal names where,
// never what.
export const SECRET =
  /AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}|gl(?:pat|dt|rt|cbt|ptt|ft|ffct|oas|imt|agent|soat)-[A-Za-z0-9_-]{20,}|GR1348941[A-Za-z0-9_-]{20,}|(password|passwd|secret|api[_-]?key|client[_-]?secret|token)\s*[:=]\s*["'][A-Za-z0-9+/=_@#$%^&*!.-]{12,}["']/i;

export class SecretRefused extends Error {}

export function hasSecret(text: string): boolean {
  return SECRET.test(text);
}

/** Throws SecretRefused when the body carries a secret-shaped string. `where` says which body; the value is never repeated. */
export function refuseSecrets(body: string, where: string): void {
  if (hasSecret(body)) {
    throw new SecretRefused(`refused to post ${where}: the body carries a secret-shaped string; nothing was sent`);
  }
}
