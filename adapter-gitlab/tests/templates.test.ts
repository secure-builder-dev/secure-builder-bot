import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { configTemplate, includeSnippet } from "../src/templates.js";
import { loadYaml } from "./yaml.js";

const CORE_RUN = path.resolve(import.meta.dirname, "..", "..", "core", "run");
const README = path.resolve(import.meta.dirname, "..", "templates", "README.md");
const KEY_NAME = "SB_MODEL_KEY"; // the NAME of the CI/CD variable, which is what the config holds

function configCheck(text: string): { code: number; out: string } {
  const dir = mkdtempSync(path.join(tmpdir(), "sb-cfg-"));
  const file = path.join(dir, ".securebuilderbot.yml");
  writeFileSync(file, text);
  try {
    return { code: 0, out: execFileSync(CORE_RUN, ["config", "check", "--config", file], { cwd: dir, encoding: "utf8" }) };
  } catch (e: unknown) {
    const err = e as { status?: number; stdout?: string; stderr?: string };
    return { code: err.status ?? 1, out: `${err.stdout ?? ""}${err.stderr ?? ""}` };
  }
}

describe("the include snippet", () => {
  it("is the one include line with the component path and the version", () => {
    const snippet = includeSnippet({ group: "security-tools", version: "latest" });
    expect(snippet).toBe("include:\n  - component: $CI_SERVER_FQDN/security-tools/secure-builder-bot/secure-builder@~latest\n");
    const yaml = loadYaml(writeTmp(snippet)) as { include: { component: string }[] };
    expect(yaml.include[0]!.component).toContain("secure-builder-bot/secure-builder@~latest");
  });

  it("pins the component and the bot release together when a version is given", () => {
    const snippet = includeSnippet({ group: "platform/tools", version: "0.4.0" });
    expect(snippet).toContain("secure-builder@0.4.0");
    expect(snippet).toContain("inputs:\n      version: 0.4.0");
    expect(loadYaml(writeTmp(snippet))).toEqual({ include: [{ component: "$CI_SERVER_FQDN/platform/tools/secure-builder-bot/secure-builder@0.4.0", inputs: { version: "0.4.0" } }] });
  });

  it("keeps a placeholder group when none is known", () => {
    expect(includeSnippet({ version: "latest" })).toContain("$CI_SERVER_FQDN/<group>/secure-builder-bot/secure-builder@~latest");
  });

  it("is the line the README shows", () => {
    expect(readFileSync(README, "utf8")).toContain("component: $CI_SERVER_FQDN/<group>/secure-builder-bot/secure-builder@0.4.0");
    expect(includeSnippet({ version: "0.4.0" })).toContain("component: $CI_SERVER_FQDN/<group>/secure-builder-bot/secure-builder@0.4.0");
  });
});

describe("the config template", () => {
  it("answers the three questions, each with a comment, and no sentinel block when Sentinel is off", () => {
    const text = configTemplate({ profile: "il4", gates: ["scan", "qa"], sentinel: "off", version: "latest" });
    expect(text).not.toContain("sentinel:");
    expect(text).not.toContain("key_secret");
    const parsed = loadYaml(writeTmp(text));
    expect(parsed).toEqual({ profile: "il4", gates: ["scan", "qa"], version: "latest" });
    for (const key of ["profile:", "gates:", "version:"]) {
      const line = text.split("\n").findIndex((l) => l.startsWith(key));
      expect(text.split("\n")[line - 1]!.startsWith("#"), `a comment above ${key}`).toBe(true);
    }
    expect(configCheck(text).code).toBe(0);
  });

  it("adds the sentinel block, with the key by secret name, only when Sentinel is on", () => {
    const text = configTemplate({ profile: "il6", gates: ["scan", "qa", "sentinel"], sentinel: "self-hosted", version: "latest" });
    expect(loadYaml(writeTmp(text))).toEqual({
      profile: "il6",
      gates: ["scan", "qa", "sentinel"],
      version: "latest",
      sentinel: { provider: "self-hosted", key_secret: KEY_NAME, depth: "auto" },
    });
    const check = configCheck(text);
    expect(check.out).toContain("config ok: profile il6");
    expect(check.code).toBe(0);
  });

  it("names the anthropic provider when Sentinel runs in CI, and a pinned version is quoted", () => {
    const text = configTemplate({ profile: "none", gates: ["scan", "sentinel"], sentinel: "ci", version: "1.2.3" });
    expect(loadYaml(writeTmp(text))).toMatchObject({ version: "1.2.3", sentinel: { provider: "anthropic" } });
    expect(configCheck(text).code).toBe(0);
  });

  it("drops sentinel from the gates when Sentinel is off, so the file it writes always validates", () => {
    const text = configTemplate({ profile: "il4", gates: ["scan", "sentinel"], sentinel: "off", version: "latest" });
    expect(loadYaml(writeTmp(text))).toEqual({ profile: "il4", gates: ["scan"], version: "latest" });
    expect(configCheck(text).code).toBe(0);
  });

  it("is the file the README shows", () => {
    const readme = readFileSync(README, "utf8");
    for (const line of configTemplate({ profile: "il4", gates: ["scan", "qa"], sentinel: "off", version: "latest" }).trimEnd().split("\n")) {
      expect(readme).toContain(line);
    }
  });
});

function writeTmp(text: string): string {
  const file = path.join(mkdtempSync(path.join(tmpdir(), "sb-yaml-")), "x.yml");
  writeFileSync(file, text);
  return file;
}
