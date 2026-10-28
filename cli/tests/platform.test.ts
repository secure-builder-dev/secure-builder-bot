import { describe, expect, it } from "vitest";
import { parseRemote, platformOf, remoteOf } from "../src/platform.ts";
import { tempRepo } from "./helpers.ts";

describe("parsing the origin remote", () => {
  it("reads https, ssh and scp-like URLs into a host and a project path", () => {
    expect(parseRemote("https://github.com/acme/widgets.git")).toEqual({ host: "github.com", path: "acme/widgets" });
    expect(parseRemote("https://user@github.com/acme/widgets/")).toEqual({ host: "github.com", path: "acme/widgets" });
    expect(parseRemote("git@github.com:acme/widgets.git")).toEqual({ host: "github.com", path: "acme/widgets" });
    expect(parseRemote("ssh://git@gitlab.example.invalid:2222/group/sub/proj.git")).toEqual({ host: "gitlab.example.invalid", path: "group/sub/proj" });
    expect(parseRemote("gitlab.com:group/proj")).toEqual({ host: "gitlab.com", path: "group/proj" });
  });

  it("is null for a local path or a URL with no project", () => {
    expect(parseRemote("/srv/git/widgets.git")).toBeNull();
    expect(parseRemote("file:///srv/git/widgets.git")).toBeNull();
    expect(parseRemote("https://github.com/")).toBeNull();
    expect(parseRemote(":nothing")).toBeNull();
    expect(parseRemote("")).toBeNull();
  });
});

describe("the platform a remote implies", () => {
  it("is github for github.com, gitlab for a gitlab host, and unknown otherwise", () => {
    expect(platformOf({ host: "github.com", path: "a/b" })).toBe("github");
    expect(platformOf({ host: "gitlab.com", path: "a/b" })).toBe("gitlab");
    expect(platformOf({ host: "gitlab.corp.example.invalid", path: "a/b" })).toBe("gitlab");
    expect(platformOf({ host: "git.example.invalid", path: "a/b" })).toBeNull();
    expect(platformOf(null)).toBeNull();
  });
});

describe("the origin remote of a repository", () => {
  it("is read with git, and null when there is none", () => {
    expect(remoteOf(tempRepo("git@github.com:acme/widgets.git"))).toEqual({ host: "github.com", path: "acme/widgets" });
    expect(remoteOf(tempRepo())).toBeNull();
  });
});
