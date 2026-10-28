import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { COMMANDS, main } from "../src/main.ts";
import { REDACTED, TokenInFile, redactTokens, redactingIo, tokenValues, writeRedacted } from "../src/redact.ts";
import { capture } from "./helpers.ts";

// Secret shapes are built at run time, so no test file carries one.
const GH = "ghp_" + "A1b2C3d4".repeat(4) + "zZ9y";
const GL = "glpat-" + "x".repeat(20);

describe("the token values", () => {
  it("come from GITHUB_TOKEN, GH_TOKEN and GITLAB_TOKEN only, longest first", () => {
    expect(tokenValues({ GITHUB_TOKEN: GH, GITLAB_TOKEN: GL, OTHER_TOKEN: "o".repeat(30) })).toEqual([GH, GL]);
    expect(tokenValues({ GH_TOKEN: GH, GITHUB_TOKEN: GH })).toEqual([GH]);
  });

  it("ignore an empty value and one too short to be a credential", () => {
    expect(tokenValues({ GITHUB_TOKEN: "", GH_TOKEN: "short", GITLAB_TOKEN: undefined })).toEqual([]);
  });
});

describe("redactTokens", () => {
  it("replaces every occurrence of every token", () => {
    expect(redactTokens(`a ${GH} b ${GL} c ${GH}`, [GH, GL])).toBe(`a ${REDACTED} b ${REDACTED} c ${REDACTED}`);
  });

  it("leaves text without a token as it is", () => {
    expect(redactTokens("nothing here", [GH])).toBe("nothing here");
    expect(redactTokens(`x ${GH}`, [])).toBe(`x ${GH}`);
  });
});

describe("every printed line", () => {
  it("is redacted before it reaches either sink", () => {
    const io = capture();
    const safe = redactingIo(io, [GH]);
    safe.out(`out ${GH}`);
    safe.err(`err ${GH}`);
    expect(io.lines).toEqual([`out ${REDACTED}`, `err ${REDACTED}`]);
  });

  it("goes through the redaction for every command main runs", async () => {
    COMMANDS.set("echo-token", {
      options: {},
      run: (_values, io) => {
        io.out(`the token is ${io.env["GITHUB_TOKEN"] ?? ""}`);
        io.err(`and again ${io.env["GITHUB_TOKEN"] ?? ""}`);
        return Promise.resolve(0);
      },
    });
    const io = capture({ env: { GITHUB_TOKEN: GH } });
    expect(await main(["echo-token"], io)).toBe(0);
    expect(io.text()).not.toContain(GH);
    expect(io.text()).toContain(REDACTED);
  });
});

describe("every file before it is written", () => {
  it("is written when redaction would not change it", () => {
    const file = path.join(mkdtempSync(path.join(tmpdir(), "sb-red-")), "deep", "a.yml");
    writeRedacted(file, "profile: il4\n", [GH]);
    expect(readFileSync(file, "utf8")).toBe("profile: il4\n");
  });

  it("is refused, and nothing written, when it would carry a token's value", () => {
    const file = path.join(mkdtempSync(path.join(tmpdir(), "sb-red-")), "a.yml");
    expect(() => writeRedacted(file, `token: ${GH}\n`, [GH])).toThrow(TokenInFile);
    let message = "";
    try {
      writeRedacted(file, `token: ${GH}\n`, [GH]);
    } catch (e: unknown) {
      message = e instanceof Error ? e.message : "";
    }
    expect(message).toContain("a.yml");
    expect(message).not.toContain(GH);
    expect(existsSync(file)).toBe(false);
  });
});
