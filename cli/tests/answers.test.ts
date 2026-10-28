import { describe, expect, it } from "vitest";
import { AnswerError, DEFAULTS, askPlatform, implementationOption, parseGates, parseProfile, parseSentinel, resolveAnswers } from "../src/answers.ts";
import { capture, typed } from "./helpers.ts";

describe("parsing an answer", () => {
  it("accepts the PRD's options and refuses anything else", () => {
    expect(parseProfile(" IL6 ")).toBe("il6");
    expect(() => parseProfile("il5")).toThrow(AnswerError);
    expect(parseGates("scan, qa")).toEqual(["scan", "qa"]);
    expect(parseGates("sentinel scan,scan")).toEqual(["scan", "sentinel"]);
    expect(() => parseGates("scan, lint")).toThrow(/lint/);
    expect(() => parseGates(" , ")).toThrow(AnswerError);
    expect(parseSentinel("self-hosted")).toBe("self-hosted");
    expect(() => parseSentinel("ci")).toThrow(/action, self-hosted, off/);
  });
});

describe("the three answers", () => {
  it("are the PRD's defaults with --yes", async () => {
    expect(await resolveAnswers({ yes: true }, capture())).toEqual(DEFAULTS);
    expect(DEFAULTS).toEqual({ profile: "il4", gates: ["scan", "qa"], sentinel: "off" });
  });

  it("take each flag over the default", async () => {
    expect(await resolveAnswers({ yes: true, profile: "il6", gates: "scan", sentinel: "action" }, capture())).toEqual({ profile: "il6", gates: ["scan"], sentinel: "action" });
  });

  it("refuse a bad flag rather than fall back to a default", async () => {
    await expect(resolveAnswers({ yes: true, profile: "high" }, capture())).rejects.toThrow(/profile/);
  });

  it("are asked in the terminal for every question no flag answers, an empty answer taking the default", async () => {
    const io = capture({ interactive: true, input: typed("il6", "", "nonsense", "self-hosted") });
    expect(await resolveAnswers({ gates: undefined }, io)).toEqual({ profile: "il6", gates: ["scan", "qa"], sentinel: "self-hosted" });
    expect(io.text()).toMatch(/Which compliance profile\?.*\[il4\]/);
    expect(io.text()).toMatch(/Which gates\?.*\[scan, qa\]/);
    expect(io.text()).toMatch(/Where does Sentinel run\?.*\[off\]/);
    expect(io.text()).toMatch(/nonsense/);
  });

  it("skip a question its flag answers", async () => {
    const io = capture({ interactive: true, input: typed("") });
    expect(await resolveAnswers({ profile: "none", gates: "scan" }, io)).toEqual({ profile: "none", gates: ["scan"], sentinel: "off" });
    expect(io.text()).not.toMatch(/compliance profile/);
  });

  it("give up after three bad answers, and when the terminal closes", async () => {
    await expect(resolveAnswers({}, capture({ interactive: true, input: typed("x", "y", "z") }))).rejects.toThrow(/profile/);
    await expect(resolveAnswers({}, capture({ interactive: true, input: typed() }))).rejects.toThrow(/no answer/);
  });

  it("need --yes or the flags when nobody can answer", async () => {
    await expect(resolveAnswers({ profile: "il4" }, capture())).rejects.toThrow(/--gates.*--yes/);
  });
});

describe("the platform question", () => {
  it("is asked when the remote does not say, and needs --platform when nobody can answer", async () => {
    expect(await askPlatform(capture({ interactive: true, input: typed("GitLab") }))).toBe("gitlab");
    await expect(askPlatform(capture())).rejects.toThrow(/--platform/);
  });
});

describe("the implementation option the answers imply", () => {
  it("is Light for scan alone, needing nothing", () => {
    const o = implementationOption(["scan"]);
    expect(o.name).toBe("Light");
    expect(o.requires.join(" ")).toMatch(/nothing/i);
  });

  it("is Standard with qa, needing a test suite and a control manifest", () => {
    const o = implementationOption(["scan", "qa"]);
    expect(o.name).toBe("Standard");
    expect(o.requires.join(" ")).toMatch(/test suite/);
    expect(o.requires.join(" ")).toMatch(/CONTROL-MANIFEST\.md/);
  });

  it("is Full with sentinel, needing a model key as the CI secret SB_MODEL_KEY", () => {
    const o = implementationOption(["scan", "qa", "sentinel"]);
    expect(o.name).toBe("Full");
    expect(o.requires.join(" ")).toMatch(/SB_MODEL_KEY/);
    expect(o.warnings).toEqual([]);
  });

  it("warns when scan is off", () => {
    expect(implementationOption(["qa"]).warnings.join(" ")).toMatch(/scan is off/);
  });
});
