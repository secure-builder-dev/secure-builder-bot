// A YAML reader for the tests, with no YAML dependency in the package: PyYAML is already core's one
// approved dependency, so the tests hand the file to it and read back JSON.
import { execFileSync } from "node:child_process";

export function loadYamlDocuments(path: string): unknown[] {
  const script = "import json, sys, yaml\nprint(json.dumps(list(yaml.safe_load_all(open(sys.argv[1], encoding='utf-8')))))";
  const out = execFileSync("python3", ["-I", "-c", script, path], { encoding: "utf8" });
  return JSON.parse(out) as unknown[];
}

export function loadYaml(path: string): unknown {
  const docs = loadYamlDocuments(path);
  if (docs.length !== 1) throw new Error(`${path}: expected one YAML document, found ${String(docs.length)}`);
  return docs[0];
}

export function asRecord(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${what} is not a mapping`);
  return value as Record<string, unknown>;
}
