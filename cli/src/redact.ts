// The token never leaves the process (docs/PRD.md § Security of the bot itself: secrets are names,
// never values). init reads a platform token by name from the environment to open the setup pull
// request; nothing asks for one and nothing writes one. This module is the second refusal behind
// that rule: every line the command prints, and every file it is about to write, is checked for the
// token values themselves. A printed line has them replaced; a file that would carry one is refused
// whole, because a redacted config file is a broken one. The GitHub client puts the server's error
// message into its exception, so a server that echoes the credential reaches the output this way.
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { Io } from "./io.ts";

export const TOKEN_VARIABLES = ["GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN"] as const;
export const REDACTED = "[redacted]";
/** No platform issues a credential this short; a shorter value would redact ordinary words. */
const MIN_TOKEN_LENGTH = 8;

/** The values of the token variables that are set, longest first so no token is redacted by a part of it. */
export function tokenValues(env: Readonly<Record<string, string | undefined>>): string[] {
  const values = new Set<string>();
  const set = new Map(Object.entries(env));
  for (const name of TOKEN_VARIABLES) {
    const value = set.get(name);
    if (value !== undefined && value.length >= MIN_TOKEN_LENGTH) values.add(value);
  }
  return [...values].sort((a, b) => b.length - a.length);
}

/** The text with every occurrence of every token replaced by [redacted]. */
export function redactTokens(text: string, tokens: readonly string[]): string {
  let out = text;
  for (const token of tokens) out = out.split(token).join(REDACTED);
  return out;
}

/** The same sinks, every line redacted on the way through. */
export function redactingIo(io: Io, tokens: readonly string[]): Io {
  return { ...io, out: (line) => io.out(redactTokens(line, tokens)), err: (line) => io.err(redactTokens(line, tokens)) };
}

export class TokenInFile extends Error {}

/** Write a file only when redaction would leave it unchanged; otherwise refuse and write nothing. */
export function writeRedacted(file: string, content: string, tokens: readonly string[]): void {
  if (redactTokens(content, tokens) !== content) {
    throw new TokenInFile(`refused to write ${path.basename(file)}: it would carry the value of a token from the environment`);
  }
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, content);
}
