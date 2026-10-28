// `securebuilderbot run`: the gates on this repository, locally, through core's own entry point
// (`core/run run`), and nothing else: no check, no comment, no publishing, which is the adapters'
// job in CI. The bot's checkout holding `core/run` is the one this CLI lives in (`../core/run` from
// the package); when the CLI is installed on its own, SECUREBUILDERBOT_HOME names the checkout.
// Core's verdict block is printed line by line as it arrives, through the token redaction like
// every other line, and core's exit code is the command's.
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { gitOk, repoRoot } from "./git.ts";
import { EXIT, type Command, type Io, type Values } from "./io.ts";

/** The bot's checkout: SECUREBUILDERBOT_HOME when set, else the checkout holding this package. */
export function botHome(env: Io["env"]): string {
  const named = new Map(Object.entries(env)).get("SECUREBUILDERBOT_HOME");
  return named !== undefined && named !== "" ? named : fileURLToPath(new URL("../..", import.meta.url)).replace(/\/$/, "");
}

const RECEIPT = "Receipt: ";

/** Run core, every line of its output to the sinks as it comes; core's exit code, or 2 when it could not start. */
function streamCore(coreRun: string, args: string[], cwd: string, io: Io, seen: (line: string) => void): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(coreRun, args, { cwd, env: io.env, stdio: ["ignore", "pipe", "pipe"] });
    const out = createInterface({ input: child.stdout });
    const err = createInterface({ input: child.stderr });
    out.on("line", (line) => {
      seen(line);
      io.out(line);
    });
    err.on("line", (line) => io.err(line));
    child.on("error", (e) => {
      io.err(`run: could not start ${coreRun}: ${e.message}`);
      resolve(EXIT.couldNotRun);
    });
    child.on("close", (code) => resolve(code === 0 || code === 1 || code === 2 ? code : EXIT.couldNotRun));
  });
}

async function runGates(values: Values, io: Io): Promise<number> {
  const root = repoRoot(io.cwd);
  if (root === null) {
    io.err("run: not inside a git repository — run it in the repository whose gates you want");
    return EXIT.couldNotRun;
  }
  const python = spawnSync("python3", ["--version"], { env: io.env, encoding: "utf8" });
  if (python.status !== 0) {
    io.err("run: python3 is not on the PATH — core runs on Python 3.12 with PyYAML (pip install -r core/requirements.txt)");
    return EXIT.couldNotRun;
  }
  const home = botHome(io.env);
  const coreRun = path.join(home, "core", "run");
  if (!existsSync(coreRun)) {
    io.err(`run: no core/run under ${home} — set SECUREBUILDERBOT_HOME to a checkout of the bot`);
    return EXIT.couldNotRun;
  }
  const base = typeof values["base"] === "string" ? values["base"] : gitOk(root, "rev-parse", "--verify", "-q", "origin/main^{commit}") ? "origin/main" : "main";
  const head = typeof values["head"] === "string" ? values["head"] : "HEAD";
  const args = ["run", "--base", base, "--head", head];
  if (typeof values["config"] === "string") args.push("--config", path.resolve(io.cwd, values["config"]));
  io.out(`run: ${coreRun} ${args.join(" ")} in ${root}`);
  let receipt: string | null = null;
  const code = await streamCore(coreRun, args, root, io, (line) => {
    if (line.startsWith(RECEIPT)) receipt = line.slice(RECEIPT.length);
  });
  if (values["open"] === true) {
    io.out(receipt === null ? "run: core wrote no receipt" : `receipt: ${path.join(root, receipt)}`);
  }
  return code;
}

export const runCommand: Command = {
  options: {
    base: { type: "string" },
    head: { type: "string" },
    config: { type: "string" },
    open: { type: "boolean" },
  },
  run: runGates,
};
