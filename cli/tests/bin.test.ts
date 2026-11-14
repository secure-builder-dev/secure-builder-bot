// The bin stub, in-process: the file the `securebuilderbot` command runs. main.test.ts spawns it
// as a real process, which proves the tsx wiring end to end but leaves the stub unmeasured, since
// coverage only sees this process. Here the stub is imported under a stubbed argv and stdout, with
// tsx's tsImport replaced by a recorder that loads the module it names through vitest, so what the
// stub does is asserted line by line: which module it loads and from where, that it hands main the
// arguments after the script name and the process's own io, and that main's code becomes the exit code.
import path from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const loads = vi.hoisted(() => [] as { spec: string; parent: string }[]);
vi.mock("tsx/esm/api", () => ({
  tsImport: async (spec: string, parent: string): Promise<unknown> => {
    loads.push({ spec, parent });
    return import(new URL(spec, parent).href);
  },
}));

const BIN = pathToFileURL(path.resolve(import.meta.dirname, "..", "bin", "securebuilderbot.js")).href;
const VERSION = "0.1.2";

let argv: string[];
let out: string[];
let err: string[];

beforeEach(() => {
  vi.resetModules();
  loads.length = 0;
  argv = process.argv;
  out = [];
  err = [];
  vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => (out.push(String(chunk)), true));
  vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => (err.push(String(chunk)), true));
});

afterEach(() => {
  process.argv = argv;
  process.exitCode = undefined;
  vi.restoreAllMocks();
});

async function runBin(...args: string[]): Promise<void> {
  process.argv = [process.execPath, "/usr/local/bin/securebuilderbot", ...args];
  await import(BIN);
}

describe("bin/securebuilderbot.js", () => {
  it("loads src/main.ts relative to itself through tsx, once", async () => {
    await runBin("--version");
    expect(loads).toEqual([{ spec: "../src/main.ts", parent: BIN }]);
  });

  it("hands main the arguments after the script name and prints through the process's stdout", async () => {
    await runBin("--version");
    expect(out.join("")).toBe(`securebuilderbot ${VERSION}\n`);
    expect(err).toEqual([]);
    expect(process.exitCode).toBe(0);
  });

  it("sets the exit code to what main returned: 2 for a command it does not know", async () => {
    await runBin("deploy");
    expect(process.exitCode).toBe(2);
    expect(out.join("") + err.join("")).toContain("deploy");
  });
});
