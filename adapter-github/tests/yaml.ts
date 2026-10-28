// YAML for the tests, through python3's PyYAML (core's one dependency, installed wherever core
// runs), so this package adds no YAML parser of its own.
import { spawnSync } from 'node:child_process';

export function parseYaml(text: string): unknown {
  const out = spawnSync('python3', ['-I', '-c', 'import json, sys, yaml; print(json.dumps(yaml.safe_load(sys.stdin.read())))'], { input: text, encoding: 'utf8' });
  if (out.status !== 0) throw new Error(`not valid YAML: ${out.stderr}`);
  return JSON.parse(out.stdout);
}
