// What every command is handed, and what it hands back. Everything a command touches outside its
// own code comes in through `Io` (the environment, the working directory, the output sinks, the
// terminal, fetch), so the tests run the real commands against temporary repositories and a fake
// network. Exit codes are core's: 0 ok, 1 refused, 2 could not run.
import type { ParseArgsConfig } from "node:util";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface Io {
  env: Record<string, string | undefined>;
  cwd: string;
  out(line: string): void;
  err(line: string): void;
  fetch?: FetchLike;
  /** Where the three questions are read from; the terminal when the command runs for real. */
  input?: NodeJS.ReadableStream;
  /** True when a person can answer questions on `input`. */
  interactive?: boolean;
}

export const EXIT = { ok: 0, refused: 1, couldNotRun: 2 } as const;

export type Options = NonNullable<ParseArgsConfig["options"]>;
export type Values = Record<string, string | boolean | undefined>;

export interface Command {
  options: Options;
  run(values: Values, io: Io): Promise<number>;
}
