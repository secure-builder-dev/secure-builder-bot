// The three questions (docs/PRD.md § The install experience), answered by a flag, by --yes (the
// PRD's defaults), or in the terminal; and the implementation option the answers imply (Light,
// Standard, Full) with what each requires. The options are adapter-github's, the one list both
// platforms' setups validate against; the gates are computed with its `effectiveGates`.
import { createInterface } from "node:readline/promises";
import { GATES, type GateName } from "../../adapter-github/src/run-dir.ts";
import { MODEL_KEY_SECRET, type Profile, type SentinelMode } from "../../adapter-github/src/templates.ts";
import type { Io, Values } from "./io.ts";
import type { Platform } from "./platform.ts";

export interface Answers {
  profile: Profile;
  gates: GateName[];
  sentinel: SentinelMode;
}

export const DEFAULTS: Readonly<Answers> = { profile: "il4", gates: ["scan", "qa"], sentinel: "off" };
const PROFILES: readonly Profile[] = ["none", "il4", "il6"];
const SENTINEL_MODES: readonly SentinelMode[] = ["action", "self-hosted", "off"];
const TRIES = 3;

/** An answer that is not one of the options, or no answer at all: the command could not run. */
export class AnswerError extends Error {}

function oneOf<T extends string>(what: string, options: readonly T[], raw: string): T {
  const value = raw.trim().toLowerCase();
  const found = options.find((o) => o === value);
  if (found === undefined) throw new AnswerError(`${what} must be one of ${options.join(", ")}, not ${JSON.stringify(raw.trim())}`);
  return found;
}

export const parseProfile = (raw: string): Profile => oneOf("profile", PROFILES, raw);
export const parseSentinel = (raw: string): SentinelMode => oneOf("sentinel", SENTINEL_MODES, raw);

/** Gates, comma- or space-separated, in the fixed order scan, qa, sentinel. */
export function parseGates(raw: string): GateName[] {
  const words = raw.split(/[\s,]+/).filter((w) => w !== "");
  if (words.length === 0) throw new AnswerError(`gates must name at least one of ${GATES.join(", ")}`);
  const wanted = new Set(words.map((w) => oneOf("each gate", GATES, w)));
  return GATES.filter((g) => wanted.has(g));
}

interface Question<T> {
  flag: string;
  text: string;
  fallback: string;
  parse(raw: string): T;
}

/** One line at a time from the terminal, shared across the questions; closed when the answers are in. */
class Terminal {
  private readonly lines: AsyncIterator<string>;
  private readonly close: () => void;

  constructor(input: NodeJS.ReadableStream) {
    const rl = createInterface({ input, terminal: false });
    this.lines = rl[Symbol.asyncIterator]();
    this.close = () => rl.close();
  }

  async ask<T>(io: Io, q: Question<T>): Promise<T> {
    let last = "";
    for (let i = 0; i < TRIES; i += 1) {
      io.out(`${q.text} [${q.fallback}]`);
      const next = await this.lines.next();
      if (next.done === true) throw new AnswerError(`no answer to "${q.text}" — the terminal closed (pass ${q.flag}, or --yes for the defaults)`);
      const raw = next.value.trim() === "" ? q.fallback : next.value;
      try {
        return q.parse(raw);
      } catch (e: unknown) {
        last = e instanceof Error ? e.message : String(e);
        io.out(`  ${last}`);
      }
    }
    throw new AnswerError(last);
  }

  done(): void {
    this.close();
  }
}

function canAsk(io: Io): io is Io & { input: NodeJS.ReadableStream } {
  return io.interactive === true && io.input !== undefined;
}

/** The three answers: each flag given wins; --yes takes the default for the rest; otherwise they are asked. */
export async function resolveAnswers(values: Values, io: Io): Promise<Answers> {
  const flag = (name: string): string | undefined => {
    const v = new Map(Object.entries(values)).get(name);
    return typeof v === "string" ? v : undefined;
  };
  const yes = values["yes"] === true;
  const questions = {
    profile: { flag: "--profile", text: "Which compliance profile? il4 (NIST 800-53 Moderate), il6 (High), none (OWASP only)", fallback: DEFAULTS.profile, parse: parseProfile },
    gates: { flag: "--gates", text: "Which gates? any of scan, qa, sentinel, comma-separated", fallback: DEFAULTS.gates.join(", "), parse: parseGates },
    sentinel: { flag: "--sentinel", text: "Where does Sentinel run? action (in CI, your model key), self-hosted (your own runner), off", fallback: DEFAULTS.sentinel, parse: parseSentinel },
  };
  const unanswered = Object.entries(questions)
    .filter(([name]) => flag(name) === undefined)
    .map(([, q]) => q.flag);
  if (!yes && unanswered.length > 0 && !canAsk(io)) {
    throw new AnswerError(`nobody can answer here: pass ${unanswered.join(", ")}, or --yes for the defaults`);
  }
  const terminal = !yes && canAsk(io) && unanswered.length > 0 ? new Terminal(io.input) : null;
  try {
    async function answer<T>(name: keyof typeof questions, q: Question<T>): Promise<T> {
      const given = flag(name);
      if (given !== undefined) return q.parse(given);
      if (terminal === null) return q.parse(q.fallback);
      return terminal.ask(io, q);
    }
    return {
      profile: await answer("profile", questions.profile),
      gates: await answer("gates", questions.gates),
      sentinel: await answer("sentinel", questions.sentinel),
    };
  } finally {
    terminal?.done();
  }
}

/** Asked only when the origin remote does not say which platform this is. */
export async function askPlatform(io: Io): Promise<Platform> {
  if (!canAsk(io)) throw new AnswerError("the origin remote is neither github.com nor a GitLab host: pass --platform github or --platform gitlab");
  const terminal = new Terminal(io.input);
  try {
    return await terminal.ask(io, { flag: "--platform", text: "Which platform hosts this repository? github or gitlab", fallback: "", parse: (raw) => oneOf<Platform>("platform", ["github", "gitlab"], raw) });
  } finally {
    terminal.done();
  }
}

export interface ImplementationOption {
  name: "Light" | "Standard" | "Full";
  requires: string[];
  warnings: string[];
}

/** PRD § Three implementation options: Light is scan alone, Standard adds qa, Full adds sentinel. */
export function implementationOption(gates: readonly GateName[]): ImplementationOption {
  const requires: string[] = [];
  if (gates.includes("qa")) {
    requires.push("a test suite the bot can run, and a control manifest at docs/security/CONTROL-MANIFEST.md (init drafts one into the setup pull request for you to confirm; until one is merged, QA tests a fresh draft and stays yellow)");
  }
  if (gates.includes("sentinel")) {
    requires.push(`a model API key stored as the CI secret ${MODEL_KEY_SECRET} (a repository secret on GitHub, a masked and protected CI/CD variable on GitLab)`);
  }
  if (requires.length === 0) requires.push("nothing: no test suite, no model key");
  const warnings = gates.includes("scan") ? [] : ["scan is off: the scan gate needs nothing from you and is where most real findings come from"];
  const name = gates.includes("sentinel") ? "Full" : gates.includes("qa") ? "Standard" : "Light";
  return { name, requires, warnings };
}
