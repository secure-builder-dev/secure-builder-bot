# Capability Map: Secure Builder Bot

Approved 2026-10-14 by the maintainer. Module ids are stable and never renamed; specs, plans and
tasks select work by them. Each module's spec is `SPEC-<id>.md` beside this file; this map, not
filename guessing, is the index of what exists. Code lives in a directory named by the module id;
the engine scripts under `engine/` migrate into those directories module by module, and `engine/`
disappears when the last piece moves.

| Module id | Responsibility | Depends on | Spec |
|---|---|---|---|
| `core` | Config schema and profiles, the gate runner (order, stop on first red, light/deep classify), receipts, verdicts, the gate log | — | `SPEC-core.md` |
| `scanners` | The seven scanner wrappers and pins, CVE-freshness check, per-scanner receipts, the scan verdict line | core | `SPEC-scanners.md` |
| `standards` | Vendored NIST OSCAL, STIG and OWASP indexes, the index builders, the citation verifier, the weekly refresh | — | `SPEC-standards.md` |
| `qa` | Coverage on changed lines, negative-test detection, control derivation and manifest drafting, mutation; one adapter per test runner | core | `SPEC-qa.md` |
| `sentinel` | The cold-reviewer agent, the checklist per profile, Control Completeness, the review skills, the proof set, the model-provider interface | core, standards, qa | `SPEC-sentinel.md` |
| `adapter-github` | The Action, the setup PR, the checks and review-comment publisher | core | `SPEC-adapter-github.md` |
| `adapter-gitlab` | The CI component, the merge-request publisher | core | `SPEC-adapter-gitlab.md` |
| `cli` | `securebuilderbot init` and `securebuilderbot run` | core, adapter-github, adapter-gitlab | `SPEC-cli.md` |

Build order: `core` → `scanners`, `standards` → `adapter-github` → `cli` → `qa` → `sentinel` → `adapter-gitlab`

Dependencies point one way. A module that needs its dependent is the same module. The contract
between two modules lives in the provider's spec: the gate interface every gate implements is in
`SPEC-core.md`.
