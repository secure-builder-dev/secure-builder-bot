import { describe, expect, it } from "vitest";
import { SecretRefused, hasSecret, refuseSecrets } from "../src/secrets.js";

// Each shape is assembled from pieces so this file never carries a secret-shaped string itself.
const SHAPES: [string, string][] = [
  ["an AWS access key id", "AKIA" + "ABCDEFGHIJKLMNOP"],
  ["a private key block", "-----BEGIN " + "RSA PRIVATE KEY-----"],
  ["a GitHub token", "ghp_" + "a".repeat(36)],
  ["a fine-grained GitHub token", "github_pat_" + "b".repeat(30)],
  ["a Slack token", "xoxb-" + "1234567890-abc"],
  ["an Anthropic key", "sk-ant-" + "c".repeat(24)],
  ["an OpenAI-shaped key", "sk-" + "d".repeat(40)],
  ["a quoted password assignment", 'password = "' + "e".repeat(16) + '"'],
  ["a quoted api key assignment", "api_key: '" + "f".repeat(14) + "'"],
  ["a GitLab personal or project access token", "glpat-" + "g".repeat(20)],
  // GitLab's other prefixed tokens (gate run 1, N-06).
  ["a GitLab deploy token", "gldt-" + "h".repeat(20)],
  ["a GitLab runner authentication token", "glrt-" + "i".repeat(20)],
  ["a GitLab CI/CD job token", "glcbt-" + "64_" + "j".repeat(20)],
  ["a GitLab pipeline trigger token", "glptt-" + "k".repeat(40)],
  ["a GitLab feed token", "glft-" + "l".repeat(20)],
  ["a GitLab OAuth application secret", "gloas-" + "m".repeat(64)],
  ["a GitLab incoming email token", "glimt-" + "n".repeat(25)],
  ["a GitLab agent for Kubernetes token", "glagent-" + "o".repeat(50)],
  ["a GitLab SCIM token", "glsoat-" + "p".repeat(20)],
  // The shapes core's receipt.SECRET also carries (adapter-gitlab gate run 2, N-06).
  ["a GitLab feature-flag client token", "glffct-" + "q".repeat(20)],
  ["a legacy GitLab runner registration token", "GR1348941" + "r".repeat(20)],
  ["a GitHub Actions job token", "ghs_" + "s".repeat(36)],
];

describe("refuseSecrets", () => {
  it.each(SHAPES)("refuses %s without repeating it", (_name, value) => {
    const body = `Finding on line 3: ${value} was committed`;
    expect(hasSecret(body)).toBe(true);
    expect(() => refuseSecrets(body, "discussion on a.ts:3")).toThrow(SecretRefused);
    try {
      refuseSecrets(body, "discussion on a.ts:3");
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SecretRefused);
      expect((e as Error).message).toContain("discussion on a.ts:3");
      expect((e as Error).message).not.toContain(value);
    }
  });

  it("lets an ordinary body through, including the names of secrets", () => {
    for (const body of [
      "**[BLOCKING]** `CM-03` — QA gate\n\nadd a test that fails when _check_secret_shaped is disabled",
      "key_secret: SB_MODEL_KEY is the name of the CI secret, never the value",
      "token_variable: SECURE_BUILDER_TOKEN",
      "GitLab deploy tokens start with gldt- and runner tokens with glrt-",
      "",
    ]) {
      expect(hasSecret(body)).toBe(false);
      expect(() => refuseSecrets(body, "note")).not.toThrow();
    }
  });
});
