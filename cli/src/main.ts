// The `securebuilderbot` command line: `init` and `run`, `--help` and `--version`. Exit codes are
// core's: 0 ok, 1 refused, 2 could not run. The command types and `Io` are in io.ts.
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { EXIT, type Command, type Io, type Values } from "./io.ts";
import { initCommand } from "./init.ts";
import { redactingIo, tokenValues } from "./redact.ts";
import { runCommand } from "./run.ts";

export { EXIT, type Command, type FetchLike, type Io, type Values } from "./io.ts";

export function version(): string {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
  return pkg.version;
}

export const HELP = `securebuilderbot — Secure Builder Bot from the terminal

Usage:
  securebuilderbot init [options]   answer the three questions, write .securebuilderbot.yml and the
                                    platform file, then open the setup pull request
  securebuilderbot run [options]    run the enabled gates on this repository and print the verdict
  securebuilderbot --help | --version

init: the three questions, asked in the terminal unless a flag answers them
  --profile <none|il4|il6>              which compliance profile (default il4)
  --gates <scan,qa,sentinel>            which gates, comma-separated (default scan,qa)
  --sentinel <action|self-hosted|off>   where Sentinel runs (default off until a model key is added)
  --yes                                 take the default for every question no flag answers
  --platform <github|gitlab>            skip detecting the platform from the origin remote
  --gitlab-group <group>                the group your GitLab keeps the bot's component in
  --github-api <https-url>              send GITHUB_TOKEN to this API (GitHub Enterprise Server) instead of
                                        api.github.com, the only host it goes to otherwise
  --gitlab-host <host>                  send GITLAB_TOKEN to this GitLab instead of gitlab.com, the only
                                        host it goes to otherwise
  --force                               overwrite an existing .securebuilderbot.yml
  With GITHUB_TOKEN or GH_TOKEN (GitHub), or GITLAB_TOKEN (GitLab), in the environment, init opens
  the pull request; the token is read by name, never asked for and never written. Without one it
  commits the files on a new local branch secure-builder/enable and prints the commands to push.

run: the gates on a range, locally; nothing is published
  --base <ref>       the base of the range (default origin/main, or main without it)
  --head <ref>       the head of the range (default HEAD)
  --config <file>    the config (default .securebuilderbot.yml at the repository root)
  --open             print the full path of the receipt
  SECUREBUILDERBOT_HOME names the bot's checkout holding core/run (default: the one this CLI is in).

Exit codes: 0 ok · 1 refused (a gate failed or did not run, or init refused) · 2 could not run`;

/** The subcommands, registered by their modules (init.ts, run.ts). */
export const COMMANDS = new Map<string, Command>([
  ["init", initCommand],
  ["run", runCommand],
]);

export async function main(argv: string[], raw: Io): Promise<number> {
  // Every line any command prints goes through the token redaction (CM-81), whatever printed it.
  const io = redactingIo(raw, tokenValues(raw.env));
  const [first, ...rest] = argv;
  if (first === undefined) {
    io.out(HELP);
    return EXIT.couldNotRun;
  }
  if (first === "--help" || first === "-h") {
    io.out(HELP);
    return EXIT.ok;
  }
  if (first === "--version" || first === "-v") {
    io.out(`securebuilderbot ${version()}`);
    return EXIT.ok;
  }
  const command = COMMANDS.get(first);
  if (command === undefined) {
    io.err(`securebuilderbot: unknown command ${JSON.stringify(first)} — init or run (securebuilderbot --help)`);
    return EXIT.couldNotRun;
  }
  let values: Values;
  try {
    values = parseArgs({ args: rest, options: { ...command.options, help: { type: "boolean", short: "h" } }, strict: true, allowPositionals: false }).values;
  } catch (e: unknown) {
    io.err(`securebuilderbot ${first}: ${e instanceof Error ? e.message : String(e)} (securebuilderbot --help)`);
    return EXIT.couldNotRun;
  }
  if (values["help"] === true) {
    io.out(HELP);
    return EXIT.ok;
  }
  try {
    return await command.run(values, io);
  } catch (e: unknown) {
    io.err(unexpectedLine(first, e));
    return EXIT.couldNotRun;
  }
}

/**
 * The line for an error nothing below expected: its kind only. Its message may quote a server's
 * reply, and a reply can echo part of a token, which full-value redaction cannot see (gate cli
 * run 2, N-04; CM-85).
 */
export function unexpectedLine(command: string, e: unknown): string {
  return `securebuilderbot ${command}: stopped on an unexpected ${e instanceof Error ? e.name : "error"}; its message is not printed, because it may quote a server's reply`;
}

export function processIo(): Io {
  return {
    env: process.env,
    cwd: process.cwd(),
    out: (line) => process.stdout.write(line + "\n"),
    err: (line) => process.stderr.write(line + "\n"),
    input: process.stdin,
    interactive: process.stdin.isTTY,
  };
}
