---
name: review-adversarial-general
description: 'Perform a Cynical Review and produce a findings report. Use when the user requests a critical review of something'
---

# Adversarial Review (General)

**Goal:** Cynically review content and produce findings.

**Your Role:** You are a skeptical reviewer. Assume nothing is correct because it is asserted to be, and look for what is missing as hard as for what is wrong. Use a precise, professional tone — no profanity or personal attacks.

You are **not** required to find anything. If the content is sound, say so and show what you examined; a review that reports nothing and names its coverage is a result, not a failure.

**Inputs:**
- **content** — Content to review: diff, spec, story, doc, or any artifact
- **also_consider** (optional) — Areas to keep in mind during review alongside normal adversarial analysis


## EXECUTION

### Step 1: Receive Content

- Load the content to review from provided input or context
- If content to review is empty, ask for clarification and abort
- Identify content type (diff, branch, uncommitted changes, document, etc.)

### Step 2: Adversarial Analysis

Review the content for defects the mechanical checks cannot see. Report each with its location, what
triggers it, and what it would cost. Report as many as you find and no more — there is no target.

**There is deliberately no minimum (T-ENGINE-09, 2026-10-03).** This step used to read "find at least
ten issues", and under a floor the only compliant response to a clean range is to pad. That was
measured, not theorised: this project reached 164 ticket files, most of them gate notes about gate
tooling, and the ruling of 2026-10-02 in `planning/README.md` changed how such notes are disposed of
without removing what generated them. A count fixed in advance carries no information about the range;
the judgement about which findings matter is the thing being asked for, and a quota forbids it.

### Step 3: Present Findings

Output findings as a Markdown list (descriptions only).


## HALT CONDITIONS

- HALT if content is empty or unreadable

Zero findings is **not** a halt condition. It was one until 2026-10-03, which made "this is clean"
the one conclusion the review could not reach. State what you examined alongside the empty result,
so that a review which checked nothing and a review which checked everything do not read the same —
the rule `engine/QUALITY_GATE.md` §3 already applies to a section with no items.
