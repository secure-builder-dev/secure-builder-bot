// Which platform `init` sets up, from the repository's origin remote (docs/PRD.md § The one-command
// alternative: detects GitHub or GitLab from the remote). github.com is GitHub; a host with gitlab
// in its name is GitLab; anything else is asked, or named with --platform.
import { spawnSync } from "node:child_process";

export type Platform = "github" | "gitlab";

export interface Remote {
  host: string;
  /** owner/name on GitHub, group[/subgroup]/name on GitLab */
  path: string;
}

function cleanPath(p: string): string {
  let out = p.trim();
  while (out.startsWith("/")) out = out.slice(1);
  while (out.endsWith("/")) out = out.slice(0, -1);
  if (out.endsWith(".git")) out = out.slice(0, -".git".length);
  return out;
}

/** The host and project path of an https, ssh or scp-like remote URL; null for a local path. */
export function parseRemote(url: string): Remote | null {
  let host: string;
  let rawPath: string;
  if (url.includes("://")) {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return null;
    }
    host = parsed.hostname;
    rawPath = parsed.pathname;
  } else {
    const colon = url.indexOf(":");
    if (colon <= 0) return null;
    const hostPart = url.slice(0, colon);
    host = hostPart.slice(hostPart.lastIndexOf("@") + 1);
    rawPath = url.slice(colon + 1);
  }
  const path = cleanPath(rawPath);
  if (host === "" || path === "") return null;
  return { host: host.toLowerCase(), path };
}

export function platformOf(remote: Remote | null): Platform | null {
  if (remote === null) return null;
  if (remote.host === "github.com") return "github";
  if (remote.host.includes("gitlab")) return "gitlab";
  return null;
}

/** The repository's origin remote, or null when it has none git can read. */
export function remoteOf(repo: string): Remote | null {
  const out = spawnSync("git", ["remote", "get-url", "origin"], { cwd: repo, encoding: "utf8" });
  return out.status === 0 ? parseRemote(out.stdout.trim()) : null;
}
