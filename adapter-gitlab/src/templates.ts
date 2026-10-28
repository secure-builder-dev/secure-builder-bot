// What `securebuilderbot init` writes on GitLab, from the three answers (docs/PRD.md § The install
// experience): the one include line for .gitlab-ci.yml and the commented .securebuilderbot.yml.
// The config holds the NAME of the CI/CD variable that holds the model key, never a value.
import type { GateName } from "./run-dir.js";

export type Profile = "none" | "il4" | "il6";
export type SentinelWhere = "ci" | "action" | "self-hosted" | "off";

export interface Answers {
  profile: Profile;
  gates: GateName[];
  sentinel: SentinelWhere;
  version: string; // latest, or x.y.z
}

export interface IncludeOptions {
  group?: string; // the group the bot's project lives in on this GitLab; a placeholder when unknown
  version: string;
}

const COMPONENT = "secure-builder-bot/secure-builder";

/** The include line a user adds to .gitlab-ci.yml. A pinned version pins the component and the bot together. */
export function includeSnippet(opts: IncludeOptions): string {
  const ref = opts.version === "latest" ? "~latest" : opts.version;
  const lines = ["include:", `  - component: $CI_SERVER_FQDN/${opts.group ?? "<group>"}/${COMPONENT}@${ref}`];
  if (opts.version !== "latest") lines.push("    inputs:", `      version: ${opts.version}`);
  return lines.join("\n") + "\n";
}

/** The commented config: three answers, and a sentinel block only when Sentinel is on. */
export function configTemplate(a: Answers): string {
  const gates = a.sentinel === "off" ? a.gates.filter((g) => g !== "sentinel") : a.gates;
  const version = a.version === "latest" ? "latest" : `"${a.version}"`;
  const lines = [
    "# .securebuilderbot.yml — Secure Builder Bot",
    "# Which compliance profile? none (OWASP only) | il4 (NIST 800-53 Moderate) | il6 (High)",
    `profile: ${a.profile}`,
    "# Which gates? any of scan, qa, sentinel. A gate that is off is absent, never skipped-green.",
    `gates: [${gates.join(", ")}]`,
    "# Which bot release? latest, or a pinned x.y.z",
    `version: ${version}`,
  ];
  if (a.sentinel !== "off" && gates.includes("sentinel")) {
    lines.push(
      "",
      "# Where Sentinel runs, and the NAME of the CI/CD variable holding your model key — never the value",
      "sentinel:",
      `  provider: ${a.sentinel === "self-hosted" ? "self-hosted" : "anthropic"}   # anthropic | openai | self-hosted`,
      "  key_secret: SB_MODEL_KEY",
      "  depth: auto             # auto | always-deep | always-light",
    );
  }
  return lines.join("\n") + "\n";
}
